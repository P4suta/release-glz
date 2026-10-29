//! Rehearsal: build one committed snapshot and seal it as a `candidate/v1`.
//!
//! The snapshot comes from `git archive`, so uncommitted and ignored working-tree files cannot enter the Candidate.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::candidate::{
    Candidate, CandidateInput, CandidateManifest, CandidateSource, SealedPolicy,
};
use crate::canonical::SHA256_HEX_LEN;
use crate::config::Manifest;
use crate::git::{GitRepo, OBJECT_HEX_LEN};
use crate::gleam::Gleam;
use crate::hooks::{HookContext, HookRunner};

/// Inputs for one rehearsal.
#[derive(Debug, Clone)]
pub struct RehearseOptions {
    /// Path to the `gleam.toml` that selects the package.
    pub manifest_path: PathBuf,
    /// The exact full commit SHA to seal; abbreviated and symbolic refs are rejected.
    pub source_ref: String,
    /// Directory that receives the sealed Candidate.
    pub output: PathBuf,
}

/// Builds a Candidate from a committed snapshot.
#[derive(Debug, Clone, Default)]
pub struct Rehearsal {
    gleam: Gleam,
}

impl Rehearsal {
    /// Build the requested commit, run the verify hooks, and seal the result.
    ///
    /// The configured compiler must match the installed one exactly, so the bytes a reviewer approved are the bytes that can later be published.
    pub async fn run(&self, options: &RehearseOptions) -> Result<CandidateManifest> {
        validate_full_sha(&options.source_ref)?;
        let (repo, relative_manifest) = locate_manifest(&options.manifest_path)?;
        let package_relative = relative_manifest.parent().unwrap_or_else(|| Path::new(""));
        let resolved = repo
            .resolve(&options.source_ref)?
            .context("requested source commit does not exist")?;
        if resolved != options.source_ref {
            bail!(
                "rehearse requires the exact full commit SHA, not an abbreviated or symbolic ref"
            );
        }

        let snapshot = self
            .gleam
            .snapshot_from_git(&repo, &resolved, package_relative)?;
        let manifest = Manifest::load(snapshot.package_dir().join("gleam.toml"))?;
        if manifest.release.schema != 2 {
            bail!("rehearse requires `[tools.release-glz] schema = 2`; run migrate first");
        }
        let compiler = self.gleam.ensure_supported()?;
        if compiler != manifest.release.compiler {
            bail!(
                "configured Gleam compiler {} is required; found {compiler}",
                manifest.release.compiler
            );
        }
        let hook_runner = HookRunner::default();
        let hook_evidence = hook_runner
            .run_verify(
                &manifest.release.hooks.verify,
                snapshot.package_dir(),
                &HookContext {
                    package: manifest.package.clone(),
                    version: manifest.version.clone(),
                    source_sha: resolved.clone(),
                    intent_digest: None,
                    candidate_digest: None,
                    idempotency_key: None,
                },
            )
            .await
            .map_err(|error| {
                crate::failure::classified(crate::failure::FailureClass::Hook, error)
            })?;

        let package_tarball = self.gleam.export_hex_tarball(snapshot.package_dir())?;
        let package_interface = self
            .gleam
            .export_package_interface(snapshot.package_dir())?;
        let docs_tarball = manifest
            .release
            .outputs
            .docs
            .then(|| self.gleam.export_docs_tarball(snapshot.package_dir()))
            .transpose()?;
        // Publication derives the same policy from the same commit and refuses a Candidate that differs, so both sides use one derivation.
        let SealedPolicy {
            package,
            version,
            tag,
            manifest_path,
            compiler: _,
            registry,
            private,
            github_repository,
            release_branch_prefix,
            release_notes,
            approval,
            outputs,
            verify_hook_definitions,
            sidecar_hook_definitions,
            notify_hooks,
            notify_hook_definitions,
        } = SealedPolicy::from_source(
            &manifest,
            snapshot.package_dir(),
            &manifest_path_text(&relative_manifest),
        )?;
        let sidecar_hooks = sidecar_hook_definitions.clone();
        let mut input = CandidateInput {
            package,
            version,
            tag,
            source: CandidateSource {
                commit_sha: resolved,
                manifest_path,
            },
            compiler,
            registry,
            private,
            github_repository,
            release_branch_prefix,
            release_notes,
            approval,
            outputs,
            package_tarball,
            docs_tarball,
            package_interface,
            verify_hook_definitions,
            sidecar_hook_definitions,
            hook_evidence,
            sidecars: vec![],
            notify_hooks,
            notify_hook_definitions,
        };
        // Evidence, the intent digest, and the seal all describe the same archives, so they are validated and expanded once here rather than once per step.
        let (built_in_evidence, artifacts) = Candidate::built_in_evidence_and_artifacts(&input)?;
        let intent_digest = Candidate::core_intent_digest_prepared(&input, Some(&artifacts))?;
        let sidecars = hook_runner
            .run_sidecars(
                &sidecar_hooks,
                snapshot.package_dir(),
                &HookContext {
                    package: input.package.clone(),
                    version: input.version.clone(),
                    source_sha: input.source.commit_sha.clone(),
                    intent_digest: Some(intent_digest),
                    candidate_digest: None,
                    idempotency_key: None,
                },
            )
            .await
            .map_err(|error| {
                crate::failure::classified(crate::failure::FailureClass::Hook, error)
            })?;
        input.hook_evidence.extend(sidecars.evidence);
        input.sidecars = built_in_evidence;
        input.sidecars.extend(sidecars.artifacts);
        Candidate::seal_prepared(&options.output, input, Some(artifacts)).map_err(|error| {
            crate::failure::classified(crate::failure::FailureClass::ImmutableStateConflict, error)
        })
    }
}

/// The repository that contains `manifest_path`, and the manifest's path relative to that repository's root.
///
/// Rehearsal records this path in the Candidate, and publication resolves its own manifest path the same way before it compares the two.
pub(crate) fn locate_manifest(manifest_path: &Path) -> Result<(GitRepo, PathBuf)> {
    let requested_manifest = absolute(manifest_path)?;
    let package_directory = requested_manifest
        .parent()
        .context("manifest path has no package directory")?;
    let repo = GitRepo::discover(package_directory)?;
    let root = repo.root().canonicalize()?;
    let relative_manifest = requested_manifest
        .strip_prefix(&root)
        .context("manifest is outside the git repository")?
        .to_path_buf();
    Ok((repo, relative_manifest))
}

/// A repository-relative manifest path as a Candidate records it, with `/` separators on every OS.
pub(crate) fn manifest_path_text(relative_manifest: &Path) -> String {
    relative_manifest.to_string_lossy().replace('\\', "/")
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.canonicalize()?)
    } else {
        Ok(std::env::current_dir()?.join(path).canonicalize()?)
    }
}

fn validate_full_sha(value: &str) -> Result<()> {
    if !matches!(value.len(), OBJECT_HEX_LEN | SHA256_HEX_LEN)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("--ref must be a full lowercase commit SHA");
    }
    Ok(())
}
