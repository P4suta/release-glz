//! The monotonic reconciler: the pure core of publication.
//!
//! Given what a Candidate intends, what the world already contains, and what
//! has been approved, it returns the effects that are still missing. It never
//! replaces an existing object, so a resumed release completes rather than
//! republishes.

use std::collections::BTreeMap;
use std::fmt;

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authorization::VerifiedGithubOidc;
use crate::model::ReleaseState;

/// What one release is supposed to accomplish.
///
/// Derived from the sealed Candidate, so the reconciler compares the
/// world against approved bytes rather than against a checkout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseIntent {
    /// Package name.
    pub package: String,
    /// Version being released.
    pub version: Version,
    /// Commit the Candidate was built from.
    pub source_sha: String,
    /// Release tag.
    pub tag: String,
    /// Digest of the release decision.
    pub intent_digest: String,
    /// Digest of the sealed Candidate.
    pub candidate_digest: String,
    /// Environment that has to release the publish job.
    pub approval_environment: String,
    /// Refs a manual release may be dispatched from.
    pub manual_refs: Vec<String>,
    /// The `owner/name` GitHub slug.
    pub github_repository: String,
    /// Workflow the publication has to run from.
    pub workflow_path: String,
    /// Whether a GitHub Release is part of this publication.
    pub github_release: bool,
    /// Digest of the package tarball to publish.
    pub package_sha256: String,
    /// Digest of the documentation tarball, when docs are published.
    pub docs_sha256: Option<String>,
    /// Assets to attach to the GitHub Release.
    pub release_assets: Vec<ReleaseAsset>,
    /// Notifications to deliver after publication.
    pub notify_hooks: Vec<NotifyHookIntent>,
}

/// One notification this release owes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyHookIntent {
    /// Hook that delivers it.
    pub id: String,
    /// Whether failing to deliver fails the release.
    pub required: bool,
}

/// One asset to attach to the GitHub Release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAsset {
    /// Hook that produced it.
    pub hook_id: String,
    /// File name.
    pub name: String,
    /// Declared media type.
    pub media_type: String,
    /// Digest of the bytes.
    pub sha256: String,
    /// Size in bytes.
    pub size: u64,
}

/// The authority a publication is running under.
///
/// Each field is something that was actually observed; absent evidence
/// blocks rather than defaults to permitted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApprovalEvidence {
    /// Intent digest recorded on the merged Release PR.
    pub release_pr_intent_digest: Option<String>,
    /// Candidate digest the environment approved.
    pub environment_candidate_digest: Option<String>,
    /// Environment that released the job.
    pub environment: Option<String>,
    /// Commit the approval was granted for.
    pub source_sha: Option<String>,
    /// Reason recorded for a manually dispatched release.
    pub manual_reason: Option<String>,
    /// Verified OIDC claims of the publishing run.
    pub github_oidc: Option<VerifiedGithubOidc>,
}

/// An artifact that already exists externally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedArtifact {
    /// Digest of the bytes that are published.
    pub sha256: String,
}

/// A tag that already exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedTag {
    /// Commit the tag points at.
    pub target_sha: String,
    /// Whether it is an annotated tag.
    pub annotated: bool,
}

/// A GitHub Release that already exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedGithubRelease {
    /// Commit the release points at.
    pub target_sha: String,
    /// Candidate digest recorded in the release body.
    pub candidate_digest: String,
    /// Whether the release is still a draft.
    pub draft: bool,
}

/// What is known about one notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyObservation {
    /// Key that identifies this delivery across retries.
    pub idempotency_key: String,
    /// Whether the delivery has been observed to complete.
    pub complete: bool,
}

/// Everything observed about a release in the outside world.
///
/// This is an observation, never a cache: a resumed run re-observes
/// before deciding what is still missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalReleaseState {
    /// Always `state/v1`.
    pub schema: String,
    /// Published package, when the registry already has it.
    pub package: Option<ObservedArtifact>,
    /// Published documentation, when the registry already has it.
    pub docs: Option<ObservedArtifact>,
    /// Existing tag, when there is one.
    pub tag: Option<ObservedTag>,
    /// Existing GitHub Release, when there is one.
    pub github_release: Option<ObservedGithubRelease>,
    /// Assets already attached, keyed by name.
    #[serde(default)]
    pub release_assets: BTreeMap<String, ObservedArtifact>,
    /// Notifications already observed, keyed by idempotency key.
    pub notifications: BTreeMap<String, NotifyObservation>,
}

impl Default for ExternalReleaseState {
    fn default() -> Self {
        Self {
            schema: "state/v1".into(),
            package: None,
            docs: None,
            tag: None,
            github_release: None,
            release_assets: BTreeMap::new(),
            notifications: BTreeMap::new(),
        }
    }
}

/// One remaining effect, in the order v1 permits them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReconcileEffect {
    /// Create the annotated release tag.
    PrepareAnnotatedTag,
    /// Create the draft GitHub Release.
    PrepareGithubDraft,
    /// Publish the package tarball.
    PublishPackage,
    /// Publish the documentation tarball.
    PublishDocs,
    /// Attach one asset to the draft Release.
    UploadGithubAsset {
        /// Hook that produced the asset.
        hook_id: String,
        /// File name.
        name: String,
        /// Digest of the bytes.
        sha256: String,
    },
    /// Publish the draft Release.
    FinalizeGithubRelease,
    /// Deliver one notification.
    Notify {
        /// Hook that delivers it.
        hook_id: String,
        /// Key that identifies this delivery across retries.
        idempotency_key: String,
        /// Whether failing to deliver fails the release.
        required: bool,
    },
}

impl ReconcileEffect {
    /// The idempotency key, for effects that have one.
    pub fn idempotency_key(&self) -> Option<&str> {
        match self {
            Self::Notify {
                idempotency_key, ..
            } => Some(idempotency_key),
            _ => None,
        }
    }
}

/// The remaining work, and the state it implies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcilePlan {
    /// Always `reconcile/v1`.
    pub schema: String,
    /// State the release is in once this plan was computed.
    pub state: ReleaseState,
    /// Effects still to apply, in order.
    pub effects: Vec<ReconcileEffect>,
}

/// An observation that contradicts the Candidate.
///
/// Reported rather than resolved: v1 never replaces a published object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileError {
    message: String,
}

impl ReconcileError {
    /// Always [`ReleaseState::Conflict`].
    pub fn state(&self) -> ReleaseState {
        ReleaseState::Conflict
    }
}

impl fmt::Display for ReconcileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ReconcileError {}

/// Decide what is left to do, given intent, observation, and approval.
///
/// The function is pure, and every effect it returns is one that has
/// not been observed yet, which is what makes a resumed release
/// monotonic rather than repeated.
pub fn reconcile(
    intent: &ReleaseIntent,
    observed: &ExternalReleaseState,
    approval: &ApprovalEvidence,
) -> Result<ReconcilePlan, ReconcileError> {
    if observed.schema != "state/v1" {
        return conflict(format!(
            "unsupported external state schema `{}`",
            observed.schema
        ));
    }
    validate_existing(intent, observed)?;
    if !approved(intent, approval) {
        return Ok(ReconcilePlan {
            schema: "reconcile/v1".into(),
            state: ReleaseState::AwaitingApproval,
            effects: Vec::new(),
        });
    }

    let already_started = observed.package.is_some()
        || observed.docs.is_some()
        || observed.tag.is_some()
        || observed.github_release.is_some()
        || !observed.release_assets.is_empty()
        || !observed.notifications.is_empty();
    let mut effects = Vec::new();
    if observed.tag.is_none() {
        effects.push(ReconcileEffect::PrepareAnnotatedTag);
    }
    if intent.github_release && observed.github_release.is_none() {
        effects.push(ReconcileEffect::PrepareGithubDraft);
    }
    if observed.package.is_none() {
        effects.push(ReconcileEffect::PublishPackage);
    }
    if intent.docs_sha256.is_some() && observed.docs.is_none() {
        effects.push(ReconcileEffect::PublishDocs);
    }
    for asset in &intent.release_assets {
        if !observed.release_assets.contains_key(&asset.name) {
            effects.push(ReconcileEffect::UploadGithubAsset {
                hook_id: asset.hook_id.clone(),
                name: asset.name.clone(),
                sha256: asset.sha256.clone(),
            });
        }
    }
    if intent.github_release
        && observed
            .github_release
            .as_ref()
            .is_none_or(|release| release.draft)
    {
        effects.push(ReconcileEffect::FinalizeGithubRelease);
    }
    for hook in &intent.notify_hooks {
        let key = notification_key(&intent.candidate_digest, &hook.id);
        if !observed
            .notifications
            .get(&hook.id)
            .is_some_and(|notification| {
                notification.complete && notification.idempotency_key == key
            })
        {
            effects.push(ReconcileEffect::Notify {
                hook_id: hook.id.clone(),
                idempotency_key: key,
                required: hook.required,
            });
        }
    }

    let has_blocking_effect = effects.iter().any(|effect| {
        !matches!(
            effect,
            ReconcileEffect::Notify {
                required: false,
                ..
            }
        )
    });
    let state = if effects.is_empty() || !has_blocking_effect {
        ReleaseState::Released
    } else if already_started {
        ReleaseState::PartiallyReleased
    } else {
        ReleaseState::CandidateReady
    };
    Ok(ReconcilePlan {
        schema: "reconcile/v1".into(),
        state,
        effects,
    })
}

fn approved(intent: &ReleaseIntent, approval: &ApprovalEvidence) -> bool {
    let environment = approval.environment.as_deref() == Some(intent.approval_environment.as_str());
    let candidate =
        approval.environment_candidate_digest.as_deref() == Some(intent.candidate_digest.as_str());
    let intent_approved =
        approval.release_pr_intent_digest.as_deref() == Some(intent.intent_digest.as_str());
    let manual = intent_approved
        && approval.source_sha.as_deref() == Some(intent.source_sha.as_str())
        && approval
            .manual_reason
            .as_deref()
            .is_some_and(|reason| !reason.trim().is_empty())
        && approval.github_oidc.as_ref().is_some_and(|identity| {
            intent
                .manual_refs
                .iter()
                .any(|allowed| allowed == identity.git_ref())
        });
    let workflow_prefix = format!("{}/{}@", intent.github_repository, intent.workflow_path);
    let oidc = approval.github_oidc.as_ref().filter(|identity| {
        identity.repository() == intent.github_repository
            && identity.environment() == intent.approval_environment
            && identity.source_sha() == intent.source_sha
            && identity.workflow_ref().starts_with(&workflow_prefix)
    });
    let path_approved = match oidc.map(VerifiedGithubOidc::event_name) {
        Some("push") => intent_approved,
        Some("workflow_dispatch") => manual,
        _ => false,
    };
    environment && candidate && oidc.is_some() && path_approved
}

fn validate_existing(
    intent: &ReleaseIntent,
    observed: &ExternalReleaseState,
) -> Result<(), ReconcileError> {
    if let Some(package) = &observed.package
        && package.sha256 != intent.package_sha256
    {
        return conflict("the published package checksum differs from the Candidate".into());
    }
    match (&intent.docs_sha256, &observed.docs) {
        (Some(expected), Some(docs)) if &docs.sha256 != expected => {
            return conflict(
                "the published documentation checksum differs from the Candidate".into(),
            );
        }
        (None, Some(_)) => {
            return conflict("documentation exists but the Candidate contains none".into());
        }
        _ => {}
    }
    if let Some(tag) = &observed.tag
        && (tag.target_sha != intent.source_sha || !tag.annotated)
    {
        return conflict("the existing git tag has a different immutable identity".into());
    }
    if !intent.github_release && observed.github_release.is_some() {
        return conflict("a GitHub Release exists but the Candidate disables it".into());
    }
    if !intent.github_release && !intent.release_assets.is_empty() {
        return conflict(
            "the Candidate requests release assets while GitHub Releases are disabled".into(),
        );
    }
    if let Some(release) = &observed.github_release
        && (release.target_sha != intent.source_sha
            || release.candidate_digest != intent.candidate_digest)
    {
        return conflict("the existing GitHub Release differs from the Candidate".into());
    }
    let mut expected_assets = BTreeMap::new();
    for asset in &intent.release_assets {
        if expected_assets.insert(&asset.name, asset).is_some() {
            return conflict(format!(
                "duplicate Candidate release asset `{}`",
                asset.name
            ));
        }
    }
    for (name, observed_asset) in &observed.release_assets {
        let Some(expected) = expected_assets.get(name) else {
            return conflict(format!("GitHub Release contains unsealed asset `{name}`"));
        };
        if observed_asset.sha256 != expected.sha256 {
            return conflict(format!(
                "GitHub Release asset `{name}` differs from the Candidate"
            ));
        }
    }
    for hook in &intent.notify_hooks {
        if let Some(notification) = observed.notifications.get(&hook.id)
            && notification.complete
            && notification.idempotency_key != notification_key(&intent.candidate_digest, &hook.id)
        {
            return conflict(format!(
                "notify hook `{}` completed under a different idempotency key",
                hook.id
            ));
        }
    }
    Ok(())
}

/// The idempotency key for one notification of one Candidate.
pub fn notification_key(candidate_digest: &str, hook_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"release-glz-notify-v1\0");
    digest.update(candidate_digest.as_bytes());
    digest.update(b"\0");
    digest.update(hook_id.as_bytes());
    crate::hex::lower(&digest.finalize())
}

fn conflict<T>(message: String) -> Result<T, ReconcileError> {
    Err(ReconcileError { message })
}
