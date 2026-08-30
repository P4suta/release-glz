use std::collections::BTreeMap;
use std::fmt;

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authorization::VerifiedGithubOidc;
use crate::model::ReleaseState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseIntent {
    pub package: String,
    pub version: Version,
    pub source_sha: String,
    pub tag: String,
    pub intent_digest: String,
    pub candidate_digest: String,
    pub approval_environment: String,
    pub manual_refs: Vec<String>,
    pub github_repository: String,
    pub workflow_path: String,
    pub github_release: bool,
    pub package_sha256: String,
    pub docs_sha256: Option<String>,
    pub release_assets: Vec<ReleaseAsset>,
    pub notify_hooks: Vec<NotifyHookIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyHookIntent {
    pub id: String,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAsset {
    pub hook_id: String,
    pub name: String,
    pub media_type: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApprovalEvidence {
    pub release_pr_intent_digest: Option<String>,
    pub environment_candidate_digest: Option<String>,
    pub environment: Option<String>,
    pub source_sha: Option<String>,
    pub manual_reason: Option<String>,
    pub github_oidc: Option<VerifiedGithubOidc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedArtifact {
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedTag {
    pub target_sha: String,
    pub annotated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedGithubRelease {
    pub target_sha: String,
    pub candidate_digest: String,
    pub draft: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyObservation {
    pub idempotency_key: String,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalReleaseState {
    pub schema: String,
    pub package: Option<ObservedArtifact>,
    pub docs: Option<ObservedArtifact>,
    pub tag: Option<ObservedTag>,
    pub github_release: Option<ObservedGithubRelease>,
    #[serde(default)]
    pub release_assets: BTreeMap<String, ObservedArtifact>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReconcileEffect {
    PrepareAnnotatedTag,
    PrepareGithubDraft,
    PublishPackage,
    PublishDocs,
    UploadGithubAsset {
        hook_id: String,
        name: String,
        sha256: String,
    },
    FinalizeGithubRelease,
    Notify {
        hook_id: String,
        idempotency_key: String,
        required: bool,
    },
}

impl ReconcileEffect {
    pub fn idempotency_key(&self) -> Option<&str> {
        match self {
            Self::Notify {
                idempotency_key, ..
            } => Some(idempotency_key),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcilePlan {
    pub schema: String,
    pub state: ReleaseState,
    pub effects: Vec<ReconcileEffect>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileError {
    message: String,
}

impl ReconcileError {
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
    let normal =
        approval.release_pr_intent_digest.as_deref() == Some(intent.intent_digest.as_str());
    let manual = approval.source_sha.as_deref() == Some(intent.source_sha.as_str())
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
        Some("push") => normal,
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

pub fn notification_key(candidate_digest: &str, hook_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"release-glz-notify-v1\0");
    digest.update(candidate_digest.as_bytes());
    digest.update(b"\0");
    digest.update(hook_id.as_bytes());
    format!("{:x}", digest.finalize())
}

fn conflict<T>(message: String) -> Result<T, ReconcileError> {
    Err(ReconcileError { message })
}
