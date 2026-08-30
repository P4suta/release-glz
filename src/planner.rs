use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api;
use crate::artifact;
use crate::changelog::{self, ReleaseNotesConfig};
use crate::config::{ApprovalMode, Manifest};
use crate::git::{Commit, GitRepo};
use crate::gleam::Gleam;
use crate::model::{
    ApiDiff, ApiStatus, ApprovalKind, ApprovalRequirement, Baseline, BaselineSource, Bump,
    ChangeEntry, Diagnostic, DiagnosticLevel, ReasonKind, ReleasePlan, ReleaseReason, ReleaseStage,
    ReleaseState,
};
use crate::registry::{HexRegistry, PackageState, Registry};
use crate::version::{bump_between, effective_bump, select_version};

const DEFAULT_BASELINE_SEARCH_LIMIT: usize = 2_048;
const MAX_BASELINE_CACHE_BYTES: u64 = 16 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineCacheEntry {
    schema: String,
    package: String,
    version: Version,
    artifact_fingerprint: String,
    sha: String,
}

struct BaselineSearch<'a> {
    manifest: &'a Manifest,
    repo: &'a GitRepo,
    package_relative: &'a std::path::Path,
    version: &'a Version,
    retired: bool,
    published: &'a artifact::NormalizedArtifact,
    published_fingerprint: &'a str,
}

fn default_baseline_cache_dir() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME").filter(|path| !path.is_empty()) {
        return Some(PathBuf::from(path));
    }
    #[cfg(windows)]
    if let Some(path) = std::env::var_os("LOCALAPPDATA").filter(|path| !path.is_empty()) {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("HOME")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .map(|path| path.join(".cache"))
}

#[derive(Debug, Clone)]
pub struct PlanOptions {
    pub manifest_path: PathBuf,
    /// Used by `set-version` to validate a proposed value before writing it.
    pub version_override: Option<Version>,
    /// `Some(None)` means promote the active prerelease train to stable.
    pub prerelease_override: Option<Option<crate::model::PrereleaseChannel>>,
    /// Prerelease train commands replace an unmerged candidate version.
    pub ignore_manifest_version: bool,
}

impl Default for PlanOptions {
    fn default() -> Self {
        Self {
            manifest_path: PathBuf::from("gleam.toml"),
            version_override: None,
            prerelease_override: None,
            ignore_manifest_version: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Planner<R = HexRegistry> {
    registry: R,
    gleam: Gleam,
    baseline_search_limit: usize,
    baseline_cache_dir: Option<PathBuf>,
}

impl Default for Planner<HexRegistry> {
    fn default() -> Self {
        Self {
            registry: HexRegistry::default(),
            gleam: Gleam::default(),
            baseline_search_limit: DEFAULT_BASELINE_SEARCH_LIMIT,
            baseline_cache_dir: default_baseline_cache_dir(),
        }
    }
}

impl<R: Registry> Planner<R> {
    pub fn new(registry: R, gleam: Gleam) -> Self {
        Self {
            registry,
            gleam,
            baseline_search_limit: DEFAULT_BASELINE_SEARCH_LIMIT,
            baseline_cache_dir: default_baseline_cache_dir(),
        }
    }

    pub fn with_baseline_search_limit(mut self, limit: usize) -> Self {
        assert!(limit > 0, "baseline search limit must be greater than zero");
        self.baseline_search_limit = limit;
        self
    }

    pub fn with_baseline_cache_dir(mut self, directory: Option<PathBuf>) -> Self {
        self.baseline_cache_dir = directory;
        self
    }

    pub async fn plan(&self, options: &PlanOptions) -> Result<ReleasePlan> {
        let compiler = self.gleam.ensure_supported()?;
        let requested_manifest = if options.manifest_path.is_absolute() {
            options.manifest_path.canonicalize()?
        } else {
            std::env::current_dir()?
                .join(&options.manifest_path)
                .canonicalize()?
        };
        let requested_package_dir = requested_manifest
            .parent()
            .context("manifest path has no package directory")?;
        let repo = GitRepo::discover(requested_package_dir)?;
        let relative_manifest = requested_manifest
            .strip_prefix(repo.root().canonicalize()?)
            .context("manifest is outside the git repository")?
            .to_path_buf();
        let package_relative = relative_manifest
            .parent()
            .unwrap_or_else(|| std::path::Path::new(""));
        let head = repo.head()?;
        let committed = self
            .gleam
            .snapshot_from_git(&repo, &head, package_relative)?;
        let manifest = Manifest::load(committed.package_dir().join("gleam.toml"))?;
        if manifest.release.schema == 2 && compiler != manifest.release.compiler {
            bail!(
                "configured Gleam compiler {} is required; found {compiler}",
                manifest.release.compiler
            );
        }
        let package_state = self.registry.package(&manifest.package).await?;

        let mut plan = match package_state {
            None => self.initial_plan(&manifest, &repo, options).await,
            Some(state) if state.latest().is_none() => {
                self.initial_plan(&manifest, &repo, options).await
            }
            Some(state) => {
                self.existing_plan(&manifest, &repo, package_relative, state, options)
                    .await
            }
        }?;
        plan.manifest_path = relative_manifest.to_string_lossy().replace('\\', "/");
        Ok(plan)
    }

    async fn initial_plan(
        &self,
        manifest: &Manifest,
        repo: &GitRepo,
        options: &PlanOptions,
    ) -> Result<ReleasePlan> {
        if let Some(explicit) = &options.version_override
            && explicit < &manifest.version
        {
            bail!(
                "release policy forbids lowering the manifest version from {} to {explicit}",
                manifest.version
            );
        }
        let mut version = options
            .version_override
            .as_ref()
            .unwrap_or(&manifest.version)
            .clone();
        let prerelease = options
            .prerelease_override
            .unwrap_or(manifest.release.prerelease);
        if let Some(channel) = prerelease {
            if version.pre.is_empty() {
                version.pre = semver::Prerelease::new(&format!("{}.1", channel.as_str()))?;
            } else if version.pre.as_str().split('.').next() != Some(channel.as_str()) {
                bail!(
                    "initial version {version} does not belong to the configured {} prerelease train",
                    channel.as_str()
                );
            }
        } else if options.prerelease_override == Some(None) {
            version.pre = semver::Prerelease::EMPTY;
        }
        enforce_version_zero(&version, manifest)?;
        // Exporting in a temporary snapshot validates exactly what the initial
        // publication would contain while keeping `plan` read-only.
        let snapshot = self.gleam.snapshot(manifest.package_dir())?;
        self.gleam.export_hex_tarball(snapshot.package_dir())?;
        self.gleam
            .export_package_interface(snapshot.package_dir())?;
        let commits = repo.commits_since(None)?;
        let changes = commit_entries(&commits);
        Ok(ReleasePlan {
            schema: ReleasePlan::SCHEMA.into(),
            state: ReleaseState::Planned,
            package: manifest.package.clone(),
            manifest_path: String::new(),
            published_version: None,
            manifest_version: manifest.version.clone(),
            version: version.clone(),
            bump: Bump::None,
            release_required: true,
            artifacts_changed: true,
            prerelease,
            tag: manifest.repository.tag_for(&version),
            baseline: Baseline {
                version: None,
                git_ref: None,
                sha: None,
                source: BaselineSource::Initial,
                retired: false,
            },
            reasons: vec![ReleaseReason {
                kind: ReasonKind::InitialRelease,
                bump: Bump::None,
                summary: format!("{} has not been published to Hex", manifest.package),
            }],
            api: ApiDiff::default(),
            changes,
            warnings: plan_warnings(manifest, &version),
            required_approvals: required_approvals(manifest),
            stages: planned_stages(manifest),
            intent_digest: None,
            pr_url: None,
            hex_url: Some(format!("https://hex.pm/packages/{}", manifest.package)),
            github_release_url: None,
        })
    }

    async fn existing_plan(
        &self,
        manifest: &Manifest,
        repo: &GitRepo,
        package_relative: &std::path::Path,
        state: PackageState,
        options: &PlanOptions,
    ) -> Result<ReleasePlan> {
        let latest = state.latest().expect("checked above").clone();
        let candidate = options
            .version_override
            .as_ref()
            .unwrap_or(&manifest.version);
        if candidate < &latest.version {
            bail!(
                "manifest version {} is behind the latest Hex release {}; run `release-glz update` or set a higher version",
                candidate,
                latest.version
            );
        }
        // Validate a structured escape hatch before any potentially long
        // artifact-fingerprint history scan. An expired or unresolvable
        // exception is never silently weakened to the legacy boolean form.
        let api_exception = validated_api_exception(manifest, repo, &latest.version)?;
        let source = self
            .registry
            .source_tarball(&manifest.package, &latest.version)
            .await?;
        let published_artifact = artifact::normalize_hex_tarball(&source)?;
        let baseline = self
            .find_baseline(BaselineSearch {
                manifest,
                repo,
                package_relative,
                version: &latest.version,
                retired: latest.retired,
                published: &published_artifact,
                published_fingerprint: &artifact::fingerprint_hex_tarball(&source)?,
            })
            .await?;

        let snapshot = self.gleam.snapshot(manifest.package_dir())?;
        let local_tarball = self.gleam.export_hex_tarball(snapshot.package_dir())?;
        let local_interface = self
            .gleam
            .export_package_interface(snapshot.package_dir())?;
        let artifacts_changed =
            artifact::normalize_hex_tarball(&local_tarball)? != published_artifact;

        let commits = repo.commits_since(baseline.sha.as_deref())?;
        let mut required = Bump::None;
        let mut reasons = Vec::new();
        if latest.retired {
            reasons.push(ReleaseReason {
                kind: ReasonKind::RetiredBaseline,
                bump: Bump::None,
                summary: format!(
                    "the latest Hex release {} is retired but remains the version baseline",
                    latest.version
                ),
            });
        }
        if artifacts_changed {
            required = required.max(Bump::Patch);
            reasons.push(ReleaseReason {
                kind: ReasonKind::ArtifactChanged,
                bump: Bump::Patch,
                summary: "the normalized Hex publication contents changed".into(),
            });
        }
        for commit in &commits {
            let bump = commit.conventional_bump();
            if bump != Bump::None {
                required = required.max(bump);
                reasons.push(ReleaseReason {
                    kind: ReasonKind::ConventionalCommit,
                    bump,
                    summary: format!("{} ({})", commit.subject, short_sha(&commit.sha)),
                });
            }
        }

        let api = match self
            .baseline_interface(manifest, &latest.version, &source)
            .await
        {
            Ok(old_interface) => api::compare(&old_interface, &local_interface)?,
            Err(error) => {
                if let Some(exception) = api_exception {
                    reasons.push(ReleaseReason {
                        kind: ReasonKind::ApiAdded,
                        bump: Bump::None,
                        summary: format!(
                            "API compatibility is unknown for {} and was allowed by {exception}: {error:#}",
                            latest.version
                        ),
                    });
                    ApiDiff {
                        status: ApiStatus::UnknownAllowed,
                        ..ApiDiff::default()
                    }
                } else {
                    bail!(
                        "could not determine the public API for baseline {}: {error:#}\nAdd a version-scoped `[[tools.release-glz.api_exceptions]]` entry with a resolvable baseline, reason, and expiry only when reconstruction is impossible",
                        latest.version,
                    )
                }
            }
        };
        if api.impact == Bump::Major {
            required = required.max(Bump::Major);
            reasons.push(ReleaseReason {
                kind: ReasonKind::ApiBreaking,
                bump: Bump::Major,
                summary: format!(
                    "{} breaking public API change(s)",
                    api.changes.iter().filter(|change| change.breaking).count()
                ),
            });
        } else if api.impact == Bump::Minor {
            required = required.max(Bump::Minor);
            reasons.push(ReleaseReason {
                kind: ReasonKind::ApiAdded,
                bump: Bump::Minor,
                summary: format!("{} additive public API change(s)", api.changes.len()),
            });
        }

        let explicit =
            (!options.ignore_manifest_version && candidate > &latest.version).then_some(candidate);
        let configured_prerelease = options
            .prerelease_override
            .unwrap_or(manifest.release.prerelease);
        let published_channel = latest
            .version
            .pre
            .as_str()
            .split('.')
            .next()
            .filter(|value| !value.is_empty());
        let configured_channel = configured_prerelease.map(|channel| channel.as_str());
        let train_transition = if latest.version.pre.is_empty() {
            configured_channel.is_some()
        } else {
            configured_channel != published_channel
        };
        if train_transition && required == Bump::None && latest.version.pre.is_empty() {
            // A prerelease must sort after an already-published stable version.
            required = Bump::Patch;
        }

        required = effective_bump(&latest.version, required);
        let release_required = required != Bump::None || explicit.is_some() || train_transition;
        let selected = if release_required {
            select_version(
                &latest.version,
                state.latest_stable().map(|release| &release.version),
                required,
                explicit,
                configured_prerelease,
            )?
        } else {
            latest.version.clone()
        };
        enforce_version_zero(&selected, manifest)?;
        if let Some(explicit) = explicit {
            reasons.push(ReleaseReason {
                kind: ReasonKind::ExplicitVersion,
                bump: bump_between(&latest.version, &selected),
                summary: format!(
                    "manifest explicitly requests {explicit}; the selected release is {selected}"
                ),
            });
        }
        if train_transition {
            reasons.push(ReleaseReason {
                kind: ReasonKind::Prerelease,
                bump: Bump::None,
                summary: match configured_prerelease {
                    Some(channel) => format!("move to the {} prerelease train", channel.as_str()),
                    None => format!("promote {} to a stable release", latest.version),
                },
            });
        }

        let bump = if release_required {
            bump_between(&latest.version, &selected).max(required)
        } else {
            Bump::None
        };
        let changes = commit_entries(&commits);
        Ok(ReleasePlan {
            schema: ReleasePlan::SCHEMA.into(),
            state: if release_required {
                ReleaseState::Planned
            } else {
                ReleaseState::UpToDate
            },
            package: manifest.package.clone(),
            manifest_path: String::new(),
            published_version: Some(latest.version.clone()),
            manifest_version: manifest.version.clone(),
            version: selected.clone(),
            bump,
            release_required,
            artifacts_changed,
            prerelease: configured_prerelease,
            tag: manifest.repository.tag_for(&selected),
            baseline,
            reasons,
            api,
            changes,
            warnings: plan_warnings(manifest, &selected),
            required_approvals: if release_required {
                required_approvals(manifest)
            } else {
                Vec::new()
            },
            stages: if release_required {
                planned_stages(manifest)
            } else {
                Vec::new()
            },
            intent_digest: None,
            pr_url: None,
            hex_url: Some(format!(
                "https://hex.pm/packages/{}/{}",
                manifest.package, selected
            )),
            github_release_url: None,
        })
    }

    async fn find_baseline(&self, search: BaselineSearch<'_>) -> Result<Baseline> {
        let BaselineSearch {
            manifest,
            repo,
            package_relative,
            version,
            retired,
            published,
            published_fingerprint,
        } = search;
        let tag = manifest.repository.tag_for(version);
        if let Some(sha) = repo.tag_sha(&tag)? {
            return Ok(Baseline {
                version: Some(version.clone()),
                git_ref: Some(tag),
                sha: Some(sha),
                source: BaselineSource::Tag,
                retired,
            });
        }

        if let Some(git_ref) = manifest.release.baseline_refs.get(version) {
            let sha = repo.resolve(git_ref)?.with_context(|| {
                format!("configured baseline ref `{git_ref}` cannot be resolved")
            })?;
            return Ok(Baseline {
                version: Some(version.clone()),
                git_ref: Some(git_ref.clone()),
                sha: Some(sha),
                source: BaselineSource::Config,
                retired,
            });
        }
        let cache_path = self.baseline_cache_path(
            manifest,
            repo,
            package_relative,
            version,
            published_fingerprint,
        );
        if let Some(sha) = self.validated_cached_baseline(
            cache_path.as_deref(),
            manifest,
            repo,
            package_relative,
            version,
            published_fingerprint,
            published,
        ) {
            eprintln!("release-glz: using validated artifact baseline cache");
            return Ok(Baseline {
                version: Some(version.clone()),
                git_ref: None,
                sha: Some(sha),
                source: BaselineSource::ArtifactFingerprint,
                retired,
            });
        }

        let (commits, truncated) = repo.rev_list_bounded(self.baseline_search_limit)?;
        let count = commits.len();
        for (index, sha) in commits.into_iter().enumerate() {
            let progress = index + 1;
            if progress == 1 || progress == count || progress % 100 == 0 {
                eprintln!(
                    "release-glz: searching artifact baseline {progress}/{count} (bounded at {})",
                    self.baseline_search_limit
                );
            }
            let Ok(snapshot) = self.gleam.snapshot_from_git(repo, &sha, package_relative) else {
                continue;
            };
            let Ok(candidate) = artifact::normalize_package_dir(snapshot.package_dir()) else {
                continue;
            };
            if &candidate == published {
                self.write_baseline_cache(
                    cache_path.as_deref(),
                    manifest,
                    version,
                    published_fingerprint,
                    &sha,
                );
                return Ok(Baseline {
                    version: Some(version.clone()),
                    git_ref: None,
                    sha: Some(sha),
                    source: BaselineSource::ArtifactFingerprint,
                    retired,
                });
            }
        }

        if truncated {
            bail!(
                "bounded artifact baseline search inspected {} commits without a match; add `[tools.release-glz.baseline_refs]` for {version} instead of expanding an unbounded history scan",
                self.baseline_search_limit
            );
        }

        bail!(
            "the Hex artifact for {version} does not match any commit and tag `{tag}` is missing; add `[tools.release-glz.baseline_refs]` with `\"{version}\" = \"<sha>\"`"
        )
    }

    fn baseline_cache_path(
        &self,
        manifest: &Manifest,
        repo: &GitRepo,
        package_relative: &std::path::Path,
        version: &Version,
        published_fingerprint: &str,
    ) -> Option<PathBuf> {
        let root = self.baseline_cache_dir.as_ref()?;
        let mut digest = Sha256::new();
        digest.update(b"release-glz-baseline-cache-v1\0");
        digest.update(repo.root().to_string_lossy().as_bytes());
        digest.update(b"\0");
        digest.update(package_relative.to_string_lossy().as_bytes());
        digest.update(b"\0");
        digest.update(manifest.package.as_bytes());
        digest.update(b"\0");
        digest.update(version.to_string().as_bytes());
        digest.update(b"\0");
        digest.update(published_fingerprint.as_bytes());
        Some(
            root.join("release-glz")
                .join("baselines")
                .join(format!("{:x}.json", digest.finalize())),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn validated_cached_baseline(
        &self,
        path: Option<&std::path::Path>,
        manifest: &Manifest,
        repo: &GitRepo,
        package_relative: &std::path::Path,
        version: &Version,
        published_fingerprint: &str,
        published: &artifact::NormalizedArtifact,
    ) -> Option<String> {
        let path = path?;
        let metadata = fs::symlink_metadata(path).ok()?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_BASELINE_CACHE_BYTES {
            return None;
        }
        let bytes = fs::read(path).ok()?;
        let cached: BaselineCacheEntry = serde_json::from_slice(&bytes).ok()?;
        if cached.schema != "baseline-cache/v1"
            || cached.package != manifest.package
            || cached.version != *version
            || cached.artifact_fingerprint != published_fingerprint
        {
            return None;
        }
        if repo.resolve(&cached.sha).ok().flatten().as_deref() != Some(cached.sha.as_str()) {
            return None;
        }
        let snapshot = self
            .gleam
            .snapshot_from_git(repo, &cached.sha, package_relative)
            .ok()?;
        let candidate = artifact::normalize_package_dir(snapshot.package_dir()).ok()?;
        (candidate == *published).then_some(cached.sha)
    }

    fn write_baseline_cache(
        &self,
        path: Option<&std::path::Path>,
        manifest: &Manifest,
        version: &Version,
        published_fingerprint: &str,
        sha: &str,
    ) {
        let Some(path) = path else { return };
        let Some(parent) = path.parent() else { return };
        if fs::create_dir_all(parent).is_err() {
            return;
        }
        let entry = BaselineCacheEntry {
            schema: "baseline-cache/v1".into(),
            package: manifest.package.clone(),
            version: version.clone(),
            artifact_fingerprint: published_fingerprint.into(),
            sha: sha.into(),
        };
        let Ok(bytes) = serde_json::to_vec(&entry) else {
            return;
        };
        let Ok(mut temporary) = tempfile::NamedTempFile::new_in(parent) else {
            return;
        };
        if temporary.write_all(&bytes).is_err() || temporary.as_file().sync_all().is_err() {
            return;
        }
        let _ = temporary.persist(path);
    }

    async fn baseline_interface(
        &self,
        manifest: &Manifest,
        version: &Version,
        source: &[u8],
    ) -> Result<Vec<u8>> {
        if let Some(docs) = self
            .registry
            .docs_tarball(&manifest.package, version)
            .await?
            && let Some(interface) = artifact::interface_from_docs_tarball(&docs)?
        {
            return Ok(interface);
        }

        let temp = tempfile::tempdir()?;
        artifact::unpack_hex_source(source, temp.path())?;
        self.gleam
            .export_package_interface(temp.path())
            .context("HexDocs had no package interface and regenerating it from Hex source failed")
    }
}

fn validated_api_exception(
    manifest: &Manifest,
    repo: &GitRepo,
    version: &Version,
) -> Result<Option<String>> {
    if let Some(exception) = manifest
        .release
        .api_exceptions
        .iter()
        .find(|exception| &exception.version == version)
    {
        let expires = chrono::NaiveDate::parse_from_str(&exception.expires, "%Y-%m-%d")
            .expect("API exception dates are validated while parsing configuration");
        if expires < chrono::Utc::now().date_naive() {
            bail!(
                "API exception for {version} expired on {}; remove it or complete a newly reviewed exception",
                exception.expires
            );
        }
        repo.resolve(&exception.baseline)?.with_context(|| {
            format!(
                "API exception baseline `{}` for {version} cannot be resolved",
                exception.baseline
            )
        })?;
        return Ok(Some(format!(
            "the reviewed exception using baseline `{}` through {} because {}",
            exception.baseline, exception.expires, exception.reason
        )));
    }

    // v1.x can still read the legacy flat configuration, but schema 2 never
    // derives authority from the compatibility field alone.
    Ok(
        (manifest.release.schema != 2 && manifest.release.allow_unknown_api_for.contains(version))
            .then(|| "the legacy version-scoped override".into()),
    )
}

fn plan_warnings(manifest: &Manifest, version: &Version) -> Vec<Diagnostic> {
    let mut warnings: Vec<_> = manifest
        .release
        .compatibility_warnings
        .iter()
        .map(|message| Diagnostic {
            code: "legacy_config".into(),
            level: DiagnosticLevel::Warning,
            message: message.clone(),
            detail: None,
        })
        .collect();
    if version.major == 0 {
        warnings.push(Diagnostic {
            code: "version_zero".into(),
            level: DiagnosticLevel::Warning,
            message: "Gleam recommends starting packages at version 1.0.0".into(),
            detail: Some(
                "release-glz applies Hex's 0.x rule: breaking changes use a minor release".into(),
            ),
        });
    }
    warnings
}

fn required_approvals(manifest: &Manifest) -> Vec<ApprovalRequirement> {
    let environment = || ApprovalRequirement {
        kind: ApprovalKind::Environment,
        environment: Some(manifest.release.approval.environment.clone()),
    };
    match manifest.release.approval.normal {
        ApprovalMode::ReleasePrAndEnvironment => vec![
            ApprovalRequirement {
                kind: ApprovalKind::ReleasePr,
                environment: None,
            },
            environment(),
        ],
        ApprovalMode::Environment => vec![environment()],
    }
}

fn planned_stages(manifest: &Manifest) -> Vec<ReleaseStage> {
    let mut stages = vec![
        ReleaseStage::VerifyHooks,
        ReleaseStage::PrepareGitTag,
        ReleaseStage::PrepareGithubDraft,
        ReleaseStage::PublishPackage,
    ];
    if manifest.release.outputs.docs {
        stages.push(ReleaseStage::PublishDocs);
    }
    if manifest.release.outputs.github_release {
        stages.push(ReleaseStage::FinalizeGithubRelease);
    }
    if !manifest.release.hooks.notify.is_empty() {
        stages.push(ReleaseStage::NotifyHooks);
    }
    stages
}

pub fn prepare_release_files(
    manifest: &Manifest,
    repo: &GitRepo,
    plan: &ReleasePlan,
    entries: &[ChangeEntry],
) -> Result<BTreeMap<String, Vec<u8>>> {
    let release_config = ReleaseNotesConfig::load(&repo.root().join(".github/release.yml"))?;
    let changelog_path = manifest
        .package_dir()
        .join(&manifest.release.changelog_path);
    let existing = fs::read_to_string(&changelog_path).ok();
    let entries = release_config.apply(entries.iter().cloned());
    let historical_changelog = existing
        .as_deref()
        .map(|existing| changelog::without_release_section(existing, &plan.version.to_string()));
    let notes = changelog::load_structured_notes(
        manifest.package_dir(),
        &manifest.release.changelog.notes_dir,
        historical_changelog.as_deref(),
    )?;
    let entries = changelog::merge_supplemental_notes(entries, notes);
    let changelog = changelog::render(existing.as_deref(), &plan.version.to_string(), &entries);
    let manifest_relative = manifest
        .path()
        .canonicalize()
        .or_else(|_| Ok::<_, std::io::Error>(manifest.path().to_path_buf()))?
        .strip_prefix(repo.root().canonicalize()?)
        .context("manifest is outside git repository")?
        .to_string_lossy()
        .replace('\\', "/");
    let changelog_relative = if changelog_path.exists() {
        changelog_path.canonicalize()?
    } else {
        manifest
            .package_dir()
            .canonicalize()?
            .join(&manifest.release.changelog_path)
    }
    .strip_prefix(repo.root().canonicalize()?)
    .context("changelog is outside git repository")?
    .to_string_lossy()
    .replace('\\', "/");
    Ok(BTreeMap::from([
        (
            manifest_relative,
            manifest.render_with_version(&plan.version).into_bytes(),
        ),
        (changelog_relative, changelog.into_bytes()),
    ]))
}

pub fn update_local(manifest: &mut Manifest, plan: &ReleasePlan) -> Result<Vec<PathBuf>> {
    let repo = GitRepo::discover(manifest.package_dir())?;
    let files = prepare_release_files(manifest, &repo, plan, &plan.changes)?;
    let mut written = Vec::new();
    for (relative, contents) in files {
        let path = repo.root().join(relative);
        if fs::read(&path).ok().as_deref() != Some(&contents) {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, contents)?;
            written.push(path);
        }
    }
    manifest.set_version(plan.version.clone());
    Ok(written)
}

fn enforce_version_zero(version: &Version, manifest: &Manifest) -> Result<()> {
    if version.major == 0 && !manifest.release.allow_version_zero {
        bail!(
            "refusing release {version}: set `allow_version_zero = true` under `[tools.release-glz]` to acknowledge Gleam's pre-1.0 warning"
        );
    }
    Ok(())
}

fn short_sha(sha: &str) -> &str {
    sha.get(..7).unwrap_or(sha)
}

fn commit_entries(commits: &[Commit]) -> Vec<ChangeEntry> {
    commits
        .iter()
        .filter(|commit| !commit.subject.starts_with("chore(release):"))
        .map(|commit| ChangeEntry {
            title: commit.subject.clone(),
            pull_request: None,
            author: Some(commit.author_name.clone()),
            url: None,
            labels: vec![],
            category: changelog::default_category(&commit.subject),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApprovalMode, HookConfig};

    fn manifest() -> Manifest {
        Manifest::parse(
            PathBuf::from("gleam.toml"),
            "name = \"widget\"\nversion = \"1.2.3\"\n".into(),
        )
        .unwrap()
    }

    #[test]
    fn approval_and_stage_helpers_cover_every_policy_combination() {
        let mut manifest = manifest();
        let approvals = required_approvals(&manifest);
        assert_eq!(approvals.len(), 2);
        assert_eq!(approvals[0].kind, ApprovalKind::ReleasePr);
        assert_eq!(approvals[1].kind, ApprovalKind::Environment);
        assert_eq!(approvals[1].environment.as_deref(), Some("release"));

        manifest.release.approval.normal = ApprovalMode::Environment;
        let approvals = required_approvals(&manifest);
        assert_eq!(approvals.len(), 1);
        assert_eq!(approvals[0].kind, ApprovalKind::Environment);

        manifest.release.outputs.docs = false;
        manifest.release.outputs.github_release = false;
        manifest.release.hooks.notify.clear();
        assert_eq!(
            planned_stages(&manifest),
            [
                ReleaseStage::VerifyHooks,
                ReleaseStage::PrepareGitTag,
                ReleaseStage::PrepareGithubDraft,
                ReleaseStage::PublishPackage,
            ]
        );

        manifest.release.outputs.docs = true;
        manifest.release.outputs.github_release = true;
        manifest.release.hooks.notify.push(HookConfig {
            id: "announce".into(),
            argv: vec!["notify".into()],
            timeout_seconds: 30,
            required: false,
            env: vec![],
        });
        let stages = planned_stages(&manifest);
        assert!(stages.contains(&ReleaseStage::PublishDocs));
        assert!(stages.contains(&ReleaseStage::FinalizeGithubRelease));
        assert_eq!(stages.last(), Some(&ReleaseStage::NotifyHooks));
    }

    #[test]
    fn warnings_and_zero_version_policy_cover_both_major_lines() {
        let mut manifest = manifest();
        let stable = plan_warnings(&manifest, &Version::new(1, 0, 0));
        assert_eq!(stable.len(), 1);
        assert_eq!(stable[0].code, "legacy_config");

        let zero = plan_warnings(&manifest, &Version::new(0, 9, 0));
        assert_eq!(zero.len(), 2);
        assert_eq!(zero[1].code, "version_zero");
        assert!(
            zero[1]
                .detail
                .as_deref()
                .unwrap()
                .contains("breaking changes")
        );

        let error = enforce_version_zero(&Version::new(0, 1, 0), &manifest)
            .unwrap_err()
            .to_string();
        assert!(error.contains("allow_version_zero"), "{error}");
        manifest.release.allow_version_zero = true;
        enforce_version_zero(&Version::new(0, 1, 0), &manifest).unwrap();
        enforce_version_zero(&Version::new(1, 0, 0), &manifest).unwrap();
    }

    #[test]
    fn commit_entries_filter_release_commits_and_classify_every_fallback_category() {
        let commits = [
            commit("123456789", "feat: add API"),
            commit("abcdefghi", "fix: correct bug"),
            commit("987654321", "perf: faster"),
            commit("short", "feat!: remove API"),
            commit("7654321", "docs: explain"),
            commit("0000000", "chore(release): widget 1.2.3"),
        ];
        let entries = commit_entries(&commits);
        assert_eq!(entries.len(), 5);
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.category.as_str())
                .collect::<Vec<_>>(),
            ["Added", "Fixed", "Fixed", "Removed", "Changed"]
        );
        assert!(
            entries
                .iter()
                .all(|entry| entry.author.as_deref() == Some("Author"))
        );
        assert_eq!(short_sha("123456789"), "1234567");
        assert_eq!(short_sha("short"), "short");
    }

    fn commit(sha: &str, subject: &str) -> Commit {
        Commit {
            sha: sha.into(),
            author_name: "Author".into(),
            author_email: "author@example.com".into(),
            subject: subject.into(),
            body: String::new(),
        }
    }
}
