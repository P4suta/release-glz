//! The monotonic reconciler: the pure core of publication.
//!
//! Given what a Candidate intends, what the world already contains, and what has been approved, it returns the effects that are still missing.
//! It never replaces an existing object, so a resumed release completes rather than republishes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use release_glz_core::{Approval, Object, Outcome, Presence, RunIdentity, Trigger};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::authorization::VerifiedGithubOidc;
use crate::model::ReleaseState;

/// What one release is supposed to accomplish.
///
/// Derived from the sealed Candidate, so the reconciler compares the world against approved bytes rather than against a checkout.
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
/// Each field is something that was actually observed; absent evidence blocks rather than defaults to permitted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApprovalEvidence {
    /// Intent digest that the approval covers.
    ///
    /// For a push it is the one the merged Release PR's marker recorded, and for a manual release the verified Candidate's own.
    pub approved_intent_digest: Option<String>,
    /// Candidate digest the environment approved.
    pub environment_candidate_digest: Option<String>,
    /// Commit the approval was granted for.
    pub source_sha: Option<String>,
    /// Reason recorded for a manually dispatched release.
    pub manual_reason: Option<String>,
    /// Verified OIDC claims of the publishing run, which also name the Environment that released the job.
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
/// This is an observation, never a cache: a resumed run re-observes before deciding what is still missing.
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
/// The function is pure, and every effect it returns is one that has not been observed yet, which is what makes a resumed release monotonic rather than repeated.
pub fn reconcile(
    intent: &ReleaseIntent,
    observed: &ExternalReleaseState,
    approval: &ApprovalEvidence,
) -> Result<ReconcilePlan, ReconcileError> {
    Observation::new(intent, observed)?.plan(approves(intent, approval))
}

/// The plan an approved release would follow, for an inspection that holds no approval.
///
/// It checks the observed state like [`reconcile`], but it authorizes nothing, so a caller has to report its effects instead of applying them.
pub fn preview(
    intent: &ReleaseIntent,
    observed: &ExternalReleaseState,
) -> Result<ReconcilePlan, ReconcileError> {
    Observation::new(intent, observed)?.plan(true)
}

/// The objects of a release as one observation shows them, in publication order, with the effect and the conflict that each one names.
pub struct Observation<'a> {
    items: Vec<(Item<'a>, Object)>,
    objects: Vec<Object>,
}

impl<'a> Observation<'a> {
    /// Describe `observed` in the objects of `intent`.
    ///
    /// It refuses an observation in another format and a Candidate that describes its own assets inconsistently.
    pub fn new(
        intent: &'a ReleaseIntent,
        observed: &'a ExternalReleaseState,
    ) -> Result<Self, ReconcileError> {
        validate_inputs(intent, observed)?;
        let items = items(intent, observed);
        let objects = items.iter().map(|(_, object)| *object).collect();
        Ok(Self { items, objects })
    }

    /// The objects, in publication order.
    pub fn objects(&self) -> &[Object] {
        &self.objects
    }

    /// The effect that publishes or completes the object at `index`, which an unsealed asset doesn't have.
    pub fn effect(&self, index: usize) -> Option<ReconcileEffect> {
        self.items.get(index).and_then(|(item, _)| item.effect())
    }

    /// Why the object at `index` stops the release.
    pub fn conflict(&self, index: usize) -> ReconcileError {
        ReconcileError {
            message: match self.items.get(index) {
                Some((item, object)) => item.conflict(object.wanted),
                None => format!("the release has no object {index}"),
            },
        }
    }

    /// The plan under `approved`: the state the release is in, and the effects it still owes.
    pub fn plan(&self, approved: bool) -> Result<ReconcilePlan, ReconcileError> {
        let (state, effects) = match release_glz_core::reconcile(&self.objects, approved) {
            Outcome::Conflict(index) => return Err(self.conflict(index)),
            Outcome::AwaitingApproval => (ReleaseState::AwaitingApproval, Vec::new()),
            Outcome::Proceed { state, effects } => (
                state,
                effects.filter_map(|index| self.effect(index)).collect(),
            ),
        };
        Ok(ReconcilePlan {
            schema: "reconcile/v1".into(),
            state,
            effects,
        })
    }
}

/// Refuse an observation in another format and a Candidate that describes its own assets inconsistently.
fn validate_inputs(
    intent: &ReleaseIntent,
    observed: &ExternalReleaseState,
) -> Result<(), ReconcileError> {
    if observed.schema != "state/v1" {
        return conflict(format!(
            "unsupported external state schema `{}`",
            observed.schema
        ));
    }
    if !intent.github_release && !intent.release_assets.is_empty() {
        return conflict(
            "the Candidate requests release assets while GitHub Releases are disabled".into(),
        );
    }
    let mut names = BTreeSet::new();
    for asset in &intent.release_assets {
        if !names.insert(&asset.name) {
            return conflict(format!(
                "duplicate Candidate release asset `{}`",
                asset.name
            ));
        }
    }
    Ok(())
}

/// One object that a release publishes, as the reconciler names it in effects and conflicts.
enum Item<'a> {
    Tag,
    Draft,
    Package,
    Docs,
    Asset(&'a ReleaseAsset),
    UnsealedAsset(&'a str),
    Finalize,
    Notify(&'a NotifyHookIntent, String),
}

impl Item<'_> {
    /// The effect that publishes or completes this object, which an unsealed asset doesn't have because the Candidate never wants one.
    fn effect(&self) -> Option<ReconcileEffect> {
        Some(match self {
            Self::Tag => ReconcileEffect::PrepareAnnotatedTag,
            Self::Draft => ReconcileEffect::PrepareGithubDraft,
            Self::Package => ReconcileEffect::PublishPackage,
            Self::Docs => ReconcileEffect::PublishDocs,
            Self::Asset(asset) => ReconcileEffect::UploadGithubAsset {
                hook_id: asset.hook_id.clone(),
                name: asset.name.clone(),
                sha256: asset.sha256.clone(),
            },
            Self::UnsealedAsset(_) => return None,
            Self::Finalize => ReconcileEffect::FinalizeGithubRelease,
            Self::Notify(hook, key) => ReconcileEffect::Notify {
                hook_id: hook.id.clone(),
                idempotency_key: key.clone(),
                required: hook.required,
            },
        })
    }

    /// Why this object stops the release, given whether the Candidate wants it.
    fn conflict(&self, wanted: bool) -> String {
        match self {
            Self::Tag => "the existing git tag has a different immutable identity".into(),
            Self::Draft | Self::Finalize if !wanted => {
                "a GitHub Release exists but the Candidate disables it".into()
            }
            Self::Draft | Self::Finalize => {
                "the existing GitHub Release differs from the Candidate".into()
            }
            Self::Package => "the published package checksum differs from the Candidate".into(),
            Self::Docs if !wanted => "documentation exists but the Candidate contains none".into(),
            Self::Docs => "the published documentation checksum differs from the Candidate".into(),
            Self::Asset(asset) => format!(
                "GitHub Release asset `{}` differs from the Candidate",
                asset.name
            ),
            Self::UnsealedAsset(name) => {
                format!("GitHub Release contains unsealed asset `{name}`")
            }
            Self::Notify(hook, _) => format!(
                "notify hook `{}` completed under a different idempotency key",
                hook.id
            ),
        }
    }
}

/// The objects of the release in publication order, each with how the world holds it.
fn items<'a>(
    intent: &'a ReleaseIntent,
    observed: &'a ExternalReleaseState,
) -> Vec<(Item<'a>, Object)> {
    let object = |wanted, presence| Object {
        wanted,
        presence,
        blocking: true,
    };
    let release_matches = |release: &ObservedGithubRelease| {
        release.target_sha == intent.source_sha
            && release.candidate_digest == intent.candidate_digest
    };
    let mut items = vec![
        (
            Item::Tag,
            object(
                true,
                presence(observed.tag.as_ref(), |tag| {
                    tag.target_sha == intent.source_sha && tag.annotated
                }),
            ),
        ),
        (
            Item::Draft,
            object(
                intent.github_release,
                presence(observed.github_release.as_ref(), release_matches),
            ),
        ),
        (
            Item::Package,
            object(
                true,
                presence(observed.package.as_ref(), |package| {
                    package.sha256 == intent.package_sha256
                }),
            ),
        ),
        (
            Item::Docs,
            object(
                intent.docs_sha256.is_some(),
                presence(observed.docs.as_ref(), |docs| {
                    intent.docs_sha256.as_ref() == Some(&docs.sha256)
                }),
            ),
        ),
    ];
    for asset in &intent.release_assets {
        let observed_asset = observed.release_assets.get(&asset.name);
        items.push((
            Item::Asset(asset),
            object(
                true,
                presence(observed_asset, |found| found.sha256 == asset.sha256),
            ),
        ));
    }
    for name in observed.release_assets.keys() {
        if !intent
            .release_assets
            .iter()
            .any(|asset| &asset.name == name)
        {
            items.push((Item::UnsealedAsset(name), object(false, Presence::Differs)));
        }
    }
    // A Release that differs from the Candidate already conflicts as the draft, which comes first.
    let finalized = match &observed.github_release {
        None => Presence::Absent,
        Some(release) if release.draft => Presence::Pending,
        Some(_) => Presence::Matches,
    };
    items.push((Item::Finalize, object(intent.github_release, finalized)));
    for hook in &intent.notify_hooks {
        let key = notification_key(&intent.candidate_digest, &hook.id);
        let delivered = match observed.notifications.get(&hook.id) {
            None => Presence::Absent,
            Some(notification) if !notification.complete => Presence::Pending,
            Some(notification) if notification.idempotency_key == key => Presence::Matches,
            Some(_) => Presence::Differs,
        };
        items.push((
            Item::Notify(hook, key),
            Object {
                wanted: true,
                presence: delivered,
                blocking: hook.required,
            },
        ));
    }
    items
}

/// How the world holds an object that `matches` compares with the Candidate.
fn presence<T>(observed: Option<&T>, matches: impl FnOnce(&T) -> bool) -> Presence {
    match observed {
        None => Presence::Absent,
        Some(found) if matches(found) => Presence::Matches,
        Some(_) => Presence::Differs,
    }
}

/// Compare the approval evidence with the Candidate, and let the core decide whether it approves.
pub fn approves(intent: &ReleaseIntent, approval: &ApprovalEvidence) -> bool {
    let workflow_prefix = format!("{}/{}@", intent.github_repository, intent.workflow_path);
    Approval {
        candidate: approval.environment_candidate_digest.as_deref()
            == Some(intent.candidate_digest.as_str()),
        intent: approval.approved_intent_digest.as_deref() == Some(intent.intent_digest.as_str()),
        identity: approval.github_oidc.as_ref().map(|identity| RunIdentity {
            repository: identity.repository() == intent.github_repository,
            environment: identity.environment() == intent.approval_environment,
            source: identity.source_sha() == intent.source_sha,
            workflow: identity.workflow_ref().starts_with(&workflow_prefix),
            trigger: match identity.event_name() {
                "push" => Trigger::Push,
                "workflow_dispatch" => Trigger::ManualDispatch,
                _ => Trigger::Other,
            },
            manual_ref: intent
                .manual_refs
                .iter()
                .any(|allowed| allowed == identity.git_ref()),
        }),
        manual_source: approval.source_sha.as_deref() == Some(intent.source_sha.as_str()),
        manual_reason: approval
            .manual_reason
            .as_deref()
            .is_some_and(|reason| !reason.trim().is_empty()),
    }
    .approves()
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
