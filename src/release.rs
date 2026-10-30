//! Publication: the live adapter and the Candidate release runner.
//!
//! The runner verifies a sealed Candidate, asks the reconciler what is still missing, and applies only those effects, using bytes loaded from the Candidate itself.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::candidate::{Candidate, CandidateManifest, SealedPolicy};
use crate::canonical::SHA256_HEX_LEN;
use crate::config::{Manifest, RegistryConfig};
use crate::failure::{FailureClass, classified};
use crate::forge::{GitHubClient, GitHubRelease, GitHubReleaseAsset, GitHubRepository};
use crate::git::GitRepo;
use crate::gleam::Gleam;
use crate::hooks::{HookContext, HookRunner};
use crate::model::ReleaseState;
use crate::reconciler::{
    ApprovalEvidence, ExternalReleaseState, NotifyObservation, Observation, ObservedArtifact,
    ObservedGithubRelease, ObservedTag, ReconcileEffect, ReconcilePlan, ReleaseIntent, approves,
    notification_key, preview,
};
use crate::registry::{HexRegistry, PublishOutcome, Registry};
use release_glz_core::{Run, Step};

/// What a run of the release loop acts under.
#[derive(Clone, Copy)]
enum Authority<'a> {
    /// Verified evidence, which may approve the effects it reconciles to.
    Approval(&'a ApprovalEvidence),
    /// No evidence, so the run reports the effects an approval would unlock and applies none.
    Inspection,
}

/// What one release run did, and what is left.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReleaseReport {
    /// Always `release/v1`.
    pub schema: String,
    /// State the release reached.
    pub state: ReleaseState,
    /// Candidate that was published.
    pub candidate_digest: String,
    /// Effects this run applied.
    pub applied: Vec<ReconcileEffect>,
    /// Effects still outstanding, in order.
    pub remaining: Vec<ReconcileEffect>,
}

/// The sealed bytes handed to an effect.
///
/// Borrowed from the verified Candidate, never rebuilt, so an adapter has nothing else it could publish.
#[derive(Debug, Clone, Copy)]
pub struct ReleasePayload<'a> {
    /// Package tarball.
    pub package: &'a [u8],
    /// Documentation tarball, when docs are published.
    pub docs: Option<&'a [u8]>,
    /// Assets for the GitHub Release.
    pub release_assets: &'a [ReleaseAssetPayload<'a>],
}

/// One asset, with the bytes to upload.
#[derive(Debug, Clone, Copy)]
pub struct ReleaseAssetPayload<'a> {
    /// Hook that produced it.
    pub hook_id: &'a str,
    /// File name.
    pub name: &'a str,
    /// Declared media type.
    pub media_type: &'a str,
    /// Asset bytes.
    pub bytes: &'a [u8],
}

/// The external systems a release is applied to.
///
/// Observation and application are separate so the reconciler can decide what remains before anything is changed.
#[async_trait]
pub trait ReleaseTarget: Send + Sync {
    /// Observe everything that already exists for this release.
    async fn observe(&self, intent: &ReleaseIntent) -> Result<ExternalReleaseState>;

    /// Apply one effect using the sealed bytes.
    async fn apply(
        &self,
        effect: &ReconcileEffect,
        intent: &ReleaseIntent,
        payload: ReleasePayload<'_>,
    ) -> Result<()>;
}

/// Production adapter for the monotonic Candidate reconciler.
/// It observes all remote state before every effect and publishes only bytes loaded from the sealed Candidate by `CandidateReleaseRunner`.
pub struct LiveReleaseTarget {
    manifest: CandidateManifest,
    repo: GitRepo,
    registry: HexRegistry,
    github: GitHubClient,
    hooks: HookRunner,
}

/// A verified Candidate in a checkout of its source commit, whose policy equals the policy that commit states.
///
/// Only [`SourceBoundCandidate::bind`] creates one, and a live target starts only from one.
/// The registry, credential variable, hooks, and approval policy of a publication therefore come from the source commit, never from the Candidate alone.
#[derive(Debug, Clone)]
pub struct SourceBoundCandidate {
    manifest: CandidateManifest,
    repo: GitRepo,
}

impl SourceBoundCandidate {
    /// Bind `manifest` to the checkout whose package manifest is at `manifest_path`.
    ///
    /// The checkout has to be at the Candidate's source commit.
    /// Every field of [`SealedPolicy`] has to equal what the configuration committed at `manifest_path` states, so neither the working tree nor a path that the Candidate names can supply the policy.
    pub fn bind(manifest: CandidateManifest, manifest_path: &Path) -> Result<Self> {
        let (repo, relative_manifest) = crate::rehearse::locate_manifest(manifest_path)?;
        if repo.head()? != manifest.source.commit_sha {
            return Err(classified(
                FailureClass::ImmutableStateConflict,
                "checked-out commit does not match the sealed Candidate source",
            ));
        }
        let package_relative = relative_manifest.parent().unwrap_or_else(|| Path::new(""));
        let snapshot = Gleam::default().snapshot_from_git(
            &repo,
            &manifest.source.commit_sha,
            package_relative,
        )?;
        let source = SealedPolicy::from_source(
            &Manifest::load(snapshot.package_dir().join("gleam.toml"))?,
            snapshot.package_dir(),
            &crate::rehearse::manifest_path_text(&relative_manifest),
        )?;
        let differences = SealedPolicy::of(&manifest).differences(&source);
        if !differences.is_empty() {
            return Err(classified(
                FailureClass::ImmutableStateConflict,
                format!(
                    "the Candidate's policy differs from the configuration at its source commit in: {}",
                    differences.join(", ")
                ),
            ));
        }
        Ok(Self { manifest, repo })
    }

    /// The bound Candidate.
    pub fn manifest(&self) -> &CandidateManifest {
        &self.manifest
    }
}

impl LiveReleaseTarget {
    /// Build a live target from a Candidate bound to its source commit.
    pub fn from_candidate(candidate: SourceBoundCandidate) -> Result<Self> {
        let SourceBoundCandidate { manifest, repo } = candidate;
        let repository = GitHubRepository::parse(&manifest.github_repository)?;
        let github = GitHubClient::from_environment(repository)?;
        let registry_config = RegistryConfig {
            provider: manifest.registry.provider,
            repository: manifest.registry.repository.clone(),
            api_url: manifest.registry.api_url.clone(),
            repository_url: manifest.registry.repository_url.clone(),
            docs_url: manifest.registry.docs_url.clone(),
            credential_env: manifest.registry.credential_env.clone(),
            auth: manifest.registry.auth,
            allow_http_loopback: manifest.registry.allow_http_loopback,
        };
        if manifest.private && std::env::var_os(&registry_config.credential_env).is_none() {
            bail!(
                "private registry credential environment `{}` is not set",
                registry_config.credential_env
            );
        }
        let registry = HexRegistry::from_environment(&registry_config)?;
        Ok(Self {
            manifest,
            repo,
            registry,
            github,
            hooks: HookRunner::default(),
        })
    }

    /// Build a live target from explicit adapters, for loopback tests.
    ///
    /// The adapters still have to match the sealed Candidate, so a test cannot point a real Candidate at a different repository.
    pub fn with_adapters(
        manifest: CandidateManifest,
        repo: GitRepo,
        registry: HexRegistry,
        github: GitHubClient,
    ) -> Result<Self> {
        if github.repository.full_name() != manifest.github_repository {
            bail!("GitHub adapter repository does not match the sealed Candidate");
        }
        Ok(Self {
            manifest,
            repo,
            registry,
            github,
            hooks: HookRunner::default(),
        })
    }

    async fn exact_package_observation(
        &self,
        intent: &ReleaseIntent,
    ) -> Result<Option<ObservedArtifact>> {
        let Some(release) = self
            .registry
            .release(&intent.package, &intent.version)
            .await?
        else {
            return Ok(None);
        };
        let sha256 = match release.outer_checksum {
            Some(checksum) if is_sha256(&checksum) => checksum.to_ascii_lowercase(),
            _ => sha256(
                &self
                    .registry
                    .source_tarball(&intent.package, &intent.version)
                    .await?,
            ),
        };
        Ok(Some(ObservedArtifact { sha256 }))
    }

    async fn exact_docs_observation(
        &self,
        intent: &ReleaseIntent,
    ) -> Result<Option<ObservedArtifact>> {
        let Some(release) = self
            .registry
            .release(&intent.package, &intent.version)
            .await?
        else {
            return Ok(None);
        };
        if !release.has_docs {
            return Ok(None);
        }
        let bytes = self
            .registry
            .docs_tarball(&intent.package, &intent.version)
            .await?
            .context("registry reports documentation but its archive is missing")?;
        Ok(Some(ObservedArtifact {
            sha256: sha256(&bytes),
        }))
    }

    fn hook_context(&self, intent: &ReleaseIntent, idempotency_key: Option<String>) -> HookContext {
        HookContext {
            package: intent.package.clone(),
            version: intent.version.clone(),
            source_sha: intent.source_sha.clone(),
            intent_digest: Some(intent.intent_digest.clone()),
            candidate_digest: Some(intent.candidate_digest.clone()),
            idempotency_key,
        }
    }
}

#[async_trait]
impl ReleaseTarget for LiveReleaseTarget {
    async fn observe(&self, intent: &ReleaseIntent) -> Result<ExternalReleaseState> {
        let package = self.exact_package_observation(intent).await?;
        // Docs for a Candidate without docs contradict it, so the observation looks for docs either way.
        let docs = self.exact_docs_observation(intent).await?;
        let tag = self
            .github
            .tag_state(&intent.tag)
            .await?
            .map(|tag| ObservedTag {
                target_sha: tag.target_sha,
                annotated: tag.annotated,
            });
        let github = self.github.release_details_for_tag(&intent.tag).await?;
        let mut release_assets = BTreeMap::new();
        let mut unfinished_release_assets = BTreeSet::new();
        if let Some(release) = &github {
            for asset in &release.assets {
                if release_assets.contains_key(&asset.name)
                    || unfinished_release_assets.contains(&asset.name)
                {
                    bail!("GitHub Release contains duplicate asset `{}`", asset.name);
                }
                if asset.state != "uploaded" {
                    if let Some(refusal) = unfinished_asset_refusal(release, asset, intent) {
                        return Err(classified(FailureClass::ImmutableStateConflict, refusal));
                    }
                    unfinished_release_assets.insert(asset.name.clone());
                    continue;
                }
                let sha256 = asset.sha256.clone().with_context(|| {
                    format!(
                        "GitHub Release asset `{}` has no SHA-256 digest",
                        asset.name
                    )
                })?;
                release_assets.insert(asset.name.clone(), ObservedArtifact { sha256 });
            }
        }
        let github_release = github.map(|release| ObservedGithubRelease {
            target_sha: release.target_commitish,
            candidate_digest: release.candidate_digest.unwrap_or_default(),
            draft: release.draft,
        });
        let mut notifications = BTreeMap::new();
        let core_released = package.is_some()
            && (intent.docs_sha256.is_none() || docs.is_some())
            && tag.is_some()
            && (!intent.github_release
                || github_release
                    .as_ref()
                    .is_some_and(|release| !release.draft));
        if core_released {
            for hook in self.manifest.notify_hook_definitions.iter() {
                let key = notification_key(&intent.candidate_digest, &hook.id);
                let context = self.hook_context(intent, Some(key.clone()));
                let complete = match self
                    .hooks
                    .observe_notify(hook, self.repo.root(), &context)
                    .await
                {
                    Ok(complete) => complete,
                    Err(_) if !hook.required => false,
                    Err(error) => {
                        return Err(crate::failure::classified(
                            crate::failure::FailureClass::Hook,
                            error,
                        ));
                    }
                };
                notifications.insert(
                    hook.id.clone(),
                    NotifyObservation {
                        idempotency_key: key,
                        complete,
                    },
                );
            }
        }
        Ok(ExternalReleaseState {
            schema: "state/v1".into(),
            package,
            docs,
            tag,
            github_release,
            release_assets,
            unfinished_release_assets,
            notifications,
        })
    }

    async fn apply(
        &self,
        effect: &ReconcileEffect,
        intent: &ReleaseIntent,
        payload: ReleasePayload<'_>,
    ) -> Result<()> {
        match effect {
            ReconcileEffect::PrepareAnnotatedTag => {
                match self.github.tag_state(&intent.tag).await? {
                    Some(tag) if tag.target_sha == intent.source_sha && tag.annotated => {}
                    Some(_) => bail!("GitHub release tag conflicts with the sealed Candidate"),
                    None => {
                        self.github
                            .create_annotated_tag(
                                &intent.tag,
                                &intent.source_sha,
                                &format!("Release {} {}", intent.package, intent.version),
                            )
                            .await?
                    }
                }
            }
            ReconcileEffect::PrepareGithubDraft => {
                self.github
                    .create_draft_release(
                        &intent.tag,
                        &intent.source_sha,
                        &self.manifest.release_notes,
                        &intent.candidate_digest,
                        !intent.version.pre.is_empty(),
                    )
                    .await?;
            }
            ReconcileEffect::PublishPackage => {
                let outcome = self.registry.publish_package(payload.package).await?;
                self.registry
                    .wait_for(&intent.package, &intent.version, false)
                    .await
                    .with_context(|| ambiguous_publish_context("package", outcome))?;
                let observed = self
                    .exact_package_observation(intent)
                    .await?
                    .context("published package is not observable")?;
                if observed.sha256 != intent.package_sha256 {
                    bail!("published package checksum conflicts with the Candidate");
                }
            }
            ReconcileEffect::PublishDocs => {
                let bytes = payload
                    .docs
                    .context("Candidate has no documentation archive")?;
                let outcome = self
                    .registry
                    .publish_docs(&intent.package, &intent.version, bytes)
                    .await?;
                self.registry
                    .wait_for(&intent.package, &intent.version, true)
                    .await
                    .with_context(|| ambiguous_publish_context("documentation", outcome))?;
                let observed = self
                    .exact_docs_observation(intent)
                    .await?
                    .context("published documentation is not observable")?;
                if Some(observed.sha256) != intent.docs_sha256 {
                    bail!("published documentation checksum conflicts with the Candidate");
                }
            }
            ReconcileEffect::UploadGithubAsset {
                hook_id,
                name,
                sha256: expected_digest,
            } => {
                let expected = intent
                    .release_assets
                    .iter()
                    .find(|asset| &asset.hook_id == hook_id && &asset.name == name)
                    .context("release asset is not sealed in the Candidate intent")?;
                let payload = payload
                    .release_assets
                    .iter()
                    .find(|asset| asset.hook_id == hook_id && asset.name == name)
                    .context("release asset bytes are not sealed in the Candidate")?;
                if payload.media_type != expected.media_type
                    || payload.bytes.len() as u64 != expected.size
                    || sha256(payload.bytes) != *expected_digest
                {
                    bail!("release asset payload differs from the sealed Candidate");
                }
                let release = self
                    .github
                    .release_details_for_tag(&intent.tag)
                    .await?
                    .context("GitHub draft Release disappeared before asset upload")?;
                if let Some(existing) = release.assets.iter().find(|asset| asset.name == *name) {
                    if existing.state == "uploaded" {
                        if existing.sha256.as_deref() == Some(expected_digest.as_str()) {
                            return Ok(());
                        }
                        bail!(
                            "GitHub Release asset `{name}` already exists with different content"
                        );
                    }
                    if !candidate_release(&release, intent) {
                        return Err(classified(
                            FailureClass::ImmutableStateConflict,
                            format!(
                                "GitHub Release asset `{name}` is unfinished on a Release that the Candidate didn't draft"
                            ),
                        ));
                    }
                    // The preceding read is the newest, so the delete happens only while it shows a draft and an unfinished asset.
                    self.github
                        .delete_unfinished_release_asset(&release, name)
                        .await?;
                }
                self.github
                    .upload_release_asset(&release, name, &expected.media_type, payload.bytes)
                    .await?;
            }
            ReconcileEffect::FinalizeGithubRelease => {
                let release = self
                    .github
                    .release_details_for_tag(&intent.tag)
                    .await?
                    .context("GitHub draft Release disappeared")?;
                self.github.finalize_release(release.id).await?;
            }
            ReconcileEffect::Notify {
                hook_id,
                idempotency_key,
                ..
            } => {
                let hook = self
                    .manifest
                    .notify_hook_definitions
                    .iter()
                    .find(|hook| &hook.id == hook_id)
                    .context("notify hook is not sealed in the Candidate")?;
                let context = self.hook_context(intent, Some(idempotency_key.clone()));
                self.hooks
                    .apply_notify(hook, self.repo.root(), &context)
                    .await
                    .map_err(|error| {
                        crate::failure::classified(crate::failure::FailureClass::Hook, error)
                    })?;
            }
        }
        Ok(())
    }
}

fn ambiguous_publish_context(kind: &str, outcome: PublishOutcome) -> String {
    match outcome {
        PublishOutcome::Accepted => format!("accepted {kind} publish did not become observable"),
        PublishOutcome::Unknown => format!(
            "{kind} publish response was ambiguous and did not become observable; refusing to POST again"
        ),
    }
}

fn sha256(bytes: &[u8]) -> String {
    crate::hex::lower(&Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether `release` is the Release that the Candidate of `intent` drafted, as its target and its recorded digest show.
fn candidate_release(release: &GitHubRelease, intent: &ReleaseIntent) -> bool {
    release.target_commitish == intent.source_sha
        && release.candidate_digest.as_deref() == Some(intent.candidate_digest.as_str())
}

/// What a person has to do about `asset`, which GitHub reports as unfinished, or `None` when the release completes it.
///
/// A release completes only an asset that the Candidate seals, on the Candidate's own draft, and it never changes a published Release.
/// The reconciler reports a Release of another Candidate before any of its assets, so this leaves that Release to it.
fn unfinished_asset_refusal(
    release: &GitHubRelease,
    asset: &GitHubReleaseAsset,
    intent: &ReleaseIntent,
) -> Option<String> {
    if !candidate_release(release, intent) {
        return None;
    }
    let name = &asset.name;
    match intent
        .release_assets
        .iter()
        .find(|sealed| &sealed.name == name)
    {
        None => Some(format!(
            "GitHub Release asset `{name}` is unfinished, and the Candidate doesn't seal it; delete it from the Release on GitHub, then run the release again"
        )),
        Some(sealed) if !release.draft => Some(format!(
            "GitHub Release asset `{name}` is unfinished on the published Release, which a release never changes; delete the asset on GitHub, upload `sidecars/{}/{name}` from the Candidate directory under the same name, then run the release again",
            sealed.hook_id
        )),
        Some(_) => None,
    }
}

/// A failed release run, carrying the state it stopped in.
#[derive(Debug)]
pub struct ReleaseRunError {
    state: ReleaseState,
    class: crate::failure::FailureClass,
    source: anyhow::Error,
}

impl ReleaseRunError {
    /// State the release was left in.
    pub fn state(&self) -> ReleaseState {
        self.state
    }

    /// Failure class, which decides the exit status.
    pub fn failure_class(&self) -> crate::failure::FailureClass {
        self.class
    }
}

impl std::fmt::Display for ReleaseRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {:#}", state_label(self.state), self.source)
    }
}

impl std::error::Error for ReleaseRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.source()
    }
}

/// Publishes a verified Candidate through a [`ReleaseTarget`].
pub struct CandidateReleaseRunner<T> {
    target: T,
}

impl<T> CandidateReleaseRunner<T>
where
    T: ReleaseTarget,
{
    /// Wrap a target.
    pub fn new(target: T) -> Self {
        Self { target }
    }

    /// Verify the Candidate, then apply what is still missing under `approval`.
    ///
    /// The Candidate is re-verified on every run, so a resumed release publishes exactly the bytes the first run sealed.
    pub async fn run(
        &self,
        candidate_directory: &std::path::Path,
        approval: &ApprovalEvidence,
    ) -> std::result::Result<ReleaseReport, ReleaseRunError> {
        self.execute(candidate_directory, Authority::Approval(approval))
            .await
    }

    /// Verify the Candidate, then report what an approved run would still do, without doing any of it.
    ///
    /// It holds no approval evidence, so nothing it reports came from an identity that verification didn't produce.
    pub async fn inspect(
        &self,
        candidate_directory: &std::path::Path,
    ) -> std::result::Result<ReleaseReport, ReleaseRunError> {
        self.execute(candidate_directory, Authority::Inspection)
            .await
    }

    async fn execute(
        &self,
        candidate_directory: &std::path::Path,
        authority: Authority<'_>,
    ) -> std::result::Result<ReleaseReport, ReleaseRunError> {
        let manifest = Candidate::verify(candidate_directory).map_err(|source| {
            run_error(
                ReleaseState::Blocked,
                crate::failure::classified(
                    crate::failure::FailureClass::ImmutableStateConflict,
                    source,
                ),
            )
        })?;
        let package =
            Candidate::package_bytes(candidate_directory, &manifest).map_err(|source| {
                run_error(
                    ReleaseState::Blocked,
                    crate::failure::classified(
                        crate::failure::FailureClass::ImmutableStateConflict,
                        source,
                    ),
                )
            })?;
        let docs = Candidate::docs_bytes(candidate_directory, &manifest).map_err(|source| {
            run_error(
                ReleaseState::Blocked,
                crate::failure::classified(
                    crate::failure::FailureClass::ImmutableStateConflict,
                    source,
                ),
            )
        })?;
        let intent = release_intent(&manifest);
        let sidecars =
            Candidate::sidecar_bytes(candidate_directory, &manifest).map_err(|source| {
                run_error(
                    ReleaseState::Blocked,
                    crate::failure::classified(
                        crate::failure::FailureClass::ImmutableStateConflict,
                        source,
                    ),
                )
            })?;
        let release_assets = sidecars
            .iter()
            .filter(|(descriptor, _)| {
                intent.release_assets.iter().any(|asset| {
                    asset.hook_id == descriptor.hook_id && asset.name == descriptor.name
                })
            })
            .map(|(descriptor, bytes)| ReleaseAssetPayload {
                hook_id: &descriptor.hook_id,
                name: &descriptor.name,
                media_type: &descriptor.media_type,
                bytes,
            })
            .collect::<Vec<_>>();
        let payload = ReleasePayload {
            package: &package,
            docs: docs.as_deref(),
            release_assets: &release_assets,
        };
        let mut observed = self
            .target
            .observe(&intent)
            .await
            .map_err(|source| unobservable(ReleaseState::Blocked, source))?;
        let approval = match authority {
            Authority::Approval(approval) => approval,
            Authority::Inspection => {
                let plan = preview(&intent, &observed)
                    .map_err(|source| run_error(source.state(), source.into()))?;
                return Ok(report(&manifest, plan, Vec::new()));
            }
        };
        let approved = approves(&intent, approval);
        let objects = Observation::new(&intent, &observed)
            .map_err(|source| run_error(source.state(), source.into()))?
            .objects()
            .len();
        let mut attempted = vec![false; objects];
        let mut run = Run::new(&mut attempted, approved);
        let mut applied = Vec::new();
        let mut failure = None;
        loop {
            let world = Observation::new(&intent, &observed)
                .map_err(|source| run_error(source.state(), source.into()))?;
            let step = run.observed(world.objects());
            // A timed-out POST may already have committed, so an effect whose call failed counts once the world holds it, and the run never repeats it blindly.
            if let Some(index) = run.landed() {
                applied.push(effect_of(&world, index)?);
            }
            match step {
                Step::Apply(index) => {
                    let effect = effect_of(&world, index)?;
                    match self.target.apply(&effect, &intent, payload).await {
                        Ok(()) => {
                            run.applied(true);
                            applied.push(effect);
                        }
                        Err(source) => {
                            run.applied(false);
                            failure = Some(source);
                        }
                    }
                }
                Step::Finish(_) => {
                    let plan = world
                        .plan(approved)
                        .map_err(|source| run_error(source.state(), source.into()))?;
                    return Ok(report(&manifest, plan, applied));
                }
                Step::Conflict(index) => {
                    return Err(run_error(
                        ReleaseState::Conflict,
                        world.conflict(index).into(),
                    ));
                }
                Step::Failed { state, .. } => {
                    return Err(run_error(
                        state,
                        failure.take().unwrap_or_else(|| {
                            anyhow::anyhow!("a release effect failed without a reported cause")
                        }),
                    ));
                }
                Step::Diverged(state) => {
                    return Err(run_error(
                        state,
                        crate::failure::classified(
                            crate::failure::FailureClass::Internal,
                            "release reconciliation did not converge",
                        ),
                    ));
                }
                Step::Reshaped(state) => {
                    return Err(run_error(
                        state,
                        crate::failure::classified(
                            crate::failure::FailureClass::Internal,
                            "the release's objects changed in number during the run",
                        ),
                    ));
                }
            }
            observed = self
                .target
                .observe(&intent)
                .await
                .map_err(|source| unobservable(run.unobserved(), source))?;
        }
    }
}

/// The effect of the object at `index`, which the run chose because the plan listed it.
fn effect_of(
    world: &Observation<'_>,
    index: usize,
) -> std::result::Result<ReconcileEffect, ReleaseRunError> {
    world.effect(index).ok_or_else(|| {
        run_error(
            ReleaseState::Blocked,
            crate::failure::classified(
                crate::failure::FailureClass::Internal,
                format!("the run chose object {index}, which has no effect"),
            ),
        )
    })
}

fn release_intent(manifest: &CandidateManifest) -> ReleaseIntent {
    ReleaseIntent {
        package: manifest.package.clone(),
        version: manifest.version.clone(),
        source_sha: manifest.source.commit_sha.clone(),
        tag: manifest.tag.clone(),
        intent_digest: manifest.intent_digest.clone(),
        candidate_digest: manifest.candidate_digest.clone(),
        approval_environment: manifest.approval.environment.clone(),
        manual_refs: manifest.approval.manual_refs.clone(),
        github_repository: manifest.github_repository.clone(),
        workflow_path: ".github/workflows/release-glz.yml".into(),
        github_release: manifest.outputs.github_release,
        package_sha256: manifest.artifacts.package.sha256.clone(),
        docs_sha256: manifest
            .artifacts
            .docs
            .as_ref()
            .map(|artifact| artifact.sha256.clone()),
        release_assets: manifest
            .sidecars
            .iter()
            .filter(|artifact| {
                artifact.public
                    && manifest.outputs.github_release
                    && (!manifest.private || manifest.outputs.allow_private_evidence_upload)
            })
            .map(|artifact| crate::reconciler::ReleaseAsset {
                hook_id: artifact.hook_id.clone(),
                name: artifact.name.clone(),
                media_type: artifact.media_type.clone(),
                sha256: artifact.sha256.clone(),
                size: artifact.size,
            })
            .collect(),
        notify_hooks: manifest
            .notify_hook_definitions
            .iter()
            .map(|hook| crate::reconciler::NotifyHookIntent {
                id: hook.id.clone(),
                required: hook.required,
            })
            .collect(),
    }
}

fn report(
    manifest: &CandidateManifest,
    plan: ReconcilePlan,
    applied: Vec<ReconcileEffect>,
) -> ReleaseReport {
    ReleaseReport {
        schema: "release/v1".into(),
        state: plan.state,
        candidate_digest: manifest.candidate_digest.clone(),
        applied,
        remaining: plan.effects,
    }
}

/// The error for an observation that failed while the release was in `state`, unless the world itself contradicts the Candidate, which is a conflict.
fn unobservable(state: ReleaseState, source: anyhow::Error) -> ReleaseRunError {
    if crate::failure::classify(&source) == crate::failure::FailureClass::ImmutableStateConflict {
        run_error(ReleaseState::Conflict, source)
    } else {
        run_error(state, source)
    }
}

fn run_error(state: ReleaseState, source: anyhow::Error) -> ReleaseRunError {
    let source_class = crate::failure::classify(&source);
    let explicitly_classified = source
        .downcast_ref::<crate::failure::ClassifiedFailure>()
        .is_some();
    let class = match state {
        ReleaseState::Conflict => crate::failure::FailureClass::ImmutableStateConflict,
        ReleaseState::PartiallyReleased => crate::failure::FailureClass::PartialRelease,
        ReleaseState::AwaitingApproval => crate::failure::FailureClass::PolicyOrApproval,
        _ if source_class == crate::failure::FailureClass::Internal && !explicitly_classified => {
            crate::failure::FailureClass::TemporaryExternal
        }
        _ => source_class,
    };
    ReleaseRunError {
        state,
        class,
        source,
    }
}

fn state_label(state: ReleaseState) -> &'static str {
    match state {
        ReleaseState::Conflict => "immutable state conflict",
        ReleaseState::PartiallyReleased => "partial release",
        ReleaseState::Blocked => "release blocked",
        _ => "release failed",
    }
}
