use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::candidate::{Candidate, CandidateManifest};
use crate::config::RegistryConfig;
use crate::forge::{GitHubClient, GitHubRepository};
use crate::git::GitRepo;
use crate::hooks::{HookContext, HookRunner};
use crate::model::ReleaseState;
use crate::reconciler::{
    ApprovalEvidence, ExternalReleaseState, NotifyObservation, ObservedArtifact,
    ObservedGithubRelease, ObservedTag, ReconcileEffect, ReconcilePlan, ReleaseIntent,
    notification_key, reconcile,
};
use crate::registry::{HexRegistry, PublishOutcome, Registry};

#[derive(Debug, Clone, Copy, Default)]
pub struct ReleaseExecutionOptions {
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReleaseReport {
    pub schema: String,
    pub state: ReleaseState,
    pub candidate_digest: String,
    pub applied: Vec<ReconcileEffect>,
    pub remaining: Vec<ReconcileEffect>,
}

#[derive(Debug, Clone, Copy)]
pub struct ReleasePayload<'a> {
    pub package: &'a [u8],
    pub docs: Option<&'a [u8]>,
    pub release_assets: &'a [ReleaseAssetPayload<'a>],
}

#[derive(Debug, Clone, Copy)]
pub struct ReleaseAssetPayload<'a> {
    pub hook_id: &'a str,
    pub name: &'a str,
    pub media_type: &'a str,
    pub bytes: &'a [u8],
}

#[async_trait]
pub trait ReleaseTarget: Send + Sync {
    async fn observe(&self, intent: &ReleaseIntent) -> Result<ExternalReleaseState>;

    async fn apply(
        &self,
        effect: &ReconcileEffect,
        intent: &ReleaseIntent,
        payload: ReleasePayload<'_>,
    ) -> Result<()>;
}

/// Production adapter for the monotonic Candidate reconciler. It observes all
/// remote state before every effect and publishes only bytes loaded from the
/// sealed Candidate by `CandidateReleaseRunner`.
pub struct LiveReleaseTarget {
    manifest: CandidateManifest,
    repo: GitRepo,
    registry: HexRegistry,
    github: GitHubClient,
    hooks: HookRunner,
}

impl LiveReleaseTarget {
    pub fn from_candidate(manifest: CandidateManifest, repo: GitRepo) -> Result<Self> {
        let head = repo.head()?;
        if head != manifest.source.commit_sha {
            bail!(
                "checked out commit {head} does not match Candidate source {}",
                manifest.source.commit_sha
            );
        }
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
        let docs = if intent.docs_sha256.is_some() {
            self.exact_docs_observation(intent).await?
        } else {
            None
        };
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
        if let Some(release) = &github {
            for asset in &release.assets {
                if asset.state != "uploaded" {
                    bail!(
                        "GitHub Release asset `{}` is not fully uploaded",
                        asset.name
                    );
                }
                let sha256 = asset.sha256.clone().with_context(|| {
                    format!(
                        "GitHub Release asset `{}` has no SHA-256 digest",
                        asset.name
                    )
                })?;
                if release_assets
                    .insert(asset.name.clone(), ObservedArtifact { sha256 })
                    .is_some()
                {
                    bail!("GitHub Release contains duplicate asset `{}`", asset.name);
                }
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
                    if existing.state == "uploaded"
                        && existing.sha256.as_deref() == Some(expected_digest.as_str())
                    {
                        return Ok(());
                    }
                    bail!("GitHub Release asset `{name}` already exists with different content");
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
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug)]
pub struct ReleaseRunError {
    state: ReleaseState,
    class: crate::failure::FailureClass,
    source: anyhow::Error,
}

impl ReleaseRunError {
    pub fn state(&self) -> ReleaseState {
        self.state
    }

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

pub struct CandidateReleaseRunner<T> {
    target: T,
}

impl<T> CandidateReleaseRunner<T>
where
    T: ReleaseTarget,
{
    pub fn new(target: T) -> Self {
        Self { target }
    }

    pub async fn run(
        &self,
        candidate_directory: &std::path::Path,
        approval: &ApprovalEvidence,
        options: ReleaseExecutionOptions,
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
        let mut applied = Vec::new();
        let mut attempted_optional_notifications = BTreeSet::new();

        for _ in 0..128 {
            let observed = self
                .target
                .observe(&intent)
                .await
                .map_err(|source| run_error(ReleaseState::Blocked, source))?;
            let plan = reconcile(&intent, &observed, approval)
                .map_err(|source| run_error(source.state(), source.into()))?;
            if options.dry_run || plan.state == ReleaseState::AwaitingApproval {
                return Ok(report(&manifest, plan, applied));
            }
            let Some(effect) = plan
                .effects
                .iter()
                .find(|effect| {
                    !matches!(
                        effect,
                        ReconcileEffect::Notify {
                            hook_id,
                            required: false,
                            ..
                        } if attempted_optional_notifications.contains(hook_id)
                    )
                })
                .cloned()
            else {
                return Ok(report(&manifest, plan, applied));
            };
            if let ReconcileEffect::Notify {
                hook_id,
                required: false,
                ..
            } = &effect
            {
                attempted_optional_notifications.insert(hook_id.clone());
            }
            match self.target.apply(&effect, &intent, payload).await {
                Ok(()) => applied.push(effect),
                Err(source) => {
                    // A timed-out POST may already have committed. Re-observe
                    // before returning and never blindly repeat it.
                    let refreshed = self
                        .target
                        .observe(&intent)
                        .await
                        .map_err(|observe| run_error(plan.state, observe))?;
                    let refreshed = reconcile(&intent, &refreshed, approval)
                        .map_err(|conflict| run_error(conflict.state(), conflict.into()))?;
                    if refreshed.effects.contains(&effect) {
                        if matches!(
                            effect,
                            ReconcileEffect::Notify {
                                required: false,
                                ..
                            }
                        ) {
                            continue;
                        }
                        return Err(run_error(refreshed.state, source));
                    }
                    applied.push(effect);
                }
            }
        }
        Err(run_error(
            ReleaseState::Blocked,
            crate::failure::classified(
                crate::failure::FailureClass::Internal,
                "release reconciliation did not converge",
            ),
        ))
    }
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
