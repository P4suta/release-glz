//! The stable v1 vocabulary: the plan, its reasons, and the lifecycle states.
//!
//! Types here are the wire format of `plan/v2` and of the `command/v2`
//! envelope, so a rename is a compatibility break rather than a refactor.

use std::fmt;

use semver::Version;
use serde::{Deserialize, Serialize};

/// The externally visible lifecycle of one package release.
///
/// Normal states only move forward. `conflict` and `blocked` are terminal
/// observations rather than rollback states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseState {
    /// The published release already matches the manifest.
    UpToDate,
    /// A release is required and a version has been selected.
    Planned,
    /// A Candidate has been sealed and passes offline verification.
    CandidateReady,
    /// The Candidate is waiting for the approvals the manifest requires.
    AwaitingApproval,
    /// Some publication stages succeeded and the rest can be resumed.
    PartiallyReleased,
    /// Every required stage completed; the release is immutable.
    Released,
    /// A published object differs from what this Candidate would write.
    Conflict,
    /// A policy, API, or configuration requirement prevents release.
    Blocked,
}

impl ReleaseState {
    /// Whether `next` is a legal successor of this state.
    ///
    /// A state may always repeat itself, which is what makes resuming a
    /// partial release safe.
    pub fn can_advance_to(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        if matches!(next, Self::Conflict | Self::Blocked) {
            return !matches!(self, Self::Released | Self::Conflict | Self::Blocked);
        }
        rank(next) >= rank(self) && !matches!(self, Self::Released | Self::Conflict | Self::Blocked)
    }
}

fn rank(state: ReleaseState) -> u8 {
    match state {
        ReleaseState::UpToDate => 0,
        ReleaseState::Planned => 1,
        ReleaseState::CandidateReady => 2,
        ReleaseState::AwaitingApproval => 3,
        ReleaseState::PartiallyReleased => 4,
        ReleaseState::Released => 5,
        ReleaseState::Conflict | ReleaseState::Blocked => u8::MAX,
    }
}

/// Monotonic effects in the order in which v1 permits them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStage {
    /// Run the configured verify hooks against the sealed bytes.
    VerifyHooks,
    /// Create the annotated tag for the sealed source commit.
    PrepareGitTag,
    /// Create the draft GitHub Release that later stages fill in.
    PrepareGithubDraft,
    /// Upload the sealed package tarball to the registry.
    PublishPackage,
    /// Upload the sealed documentation tarball.
    PublishDocs,
    /// Publish the GitHub Release once every artifact exists.
    FinalizeGithubRelease,
    /// Run the configured notification hooks.
    NotifyHooks,
}

/// Severity of one [`Diagnostic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLevel {
    /// Context that does not change the outcome.
    Info,
    /// Something the operator should see; the command still succeeds.
    Warning,
    /// The reason the command failed.
    Error,
}

/// One machine-readable message attached to a command result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Stable identifier. Consumers branch on this, never on `message`.
    pub code: String,
    /// How much the message matters.
    pub level: DiagnosticLevel,
    /// Single-line human-readable summary.
    pub message: String,
    /// Longer explanation, when one adds anything.
    pub detail: Option<String>,
}

/// The next safe step, offered to humans and machines separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextAction {
    /// Canonical process argv. Consumers must execute this array directly and
    /// must never parse `command` as shell input.
    pub argv: Vec<String>,
    /// Human-readable rendering only.
    pub command: String,
    /// Why this is the next safe step.
    pub description: String,
}

impl NextAction {
    /// Build an action a consumer can execute directly from `argv`.
    pub fn executable(
        argv: impl IntoIterator<Item = impl Into<String>>,
        description: impl Into<String>,
    ) -> Self {
        let argv = argv.into_iter().map(Into::into).collect::<Vec<_>>();
        let command = display_argv(&argv);
        Self {
            argv,
            command,
            description: description.into(),
        }
    }

    /// Build an action only a human can carry out.
    ///
    /// `argv` stays empty, so a consumer cannot mistake the rendered text
    /// for something it may run.
    pub fn guidance(command: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            argv: Vec::new(),
            command: command.into(),
            description: description.into(),
        }
    }
}

fn display_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|argument| {
            if !argument.is_empty()
                && argument.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
                })
            {
                argument.clone()
            } else {
                format!("{argument:?}")
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// An approval that publication can be made to depend on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// The rolling Release PR was reviewed and merged.
    ReleasePr,
    /// A protected GitHub Environment released the publish job.
    Environment,
    /// The approved digest equals the digest being published.
    CandidateDigest,
}

/// One approval that has to exist before publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequirement {
    /// Which approval is required.
    pub kind: ApprovalKind,
    /// The environment that grants it, for an environment approval.
    pub environment: Option<String>,
}

/// Stable machine-readable envelope shared by every command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandEnvelope<T> {
    /// Always `command/v2`.
    pub schema: String,
    /// Whether the command succeeded.
    pub ok: bool,
    /// The command that produced this envelope, such as `plan`.
    pub command: String,
    /// Command-specific payload; absent on failure.
    pub result: Option<T>,
    /// Warnings, and the reason for a failure.
    pub diagnostics: Vec<Diagnostic>,
    /// Ordered next safe steps.
    pub next_actions: Vec<NextAction>,
}

impl<T> CommandEnvelope<T> {
    /// Wrap a successful result.
    pub fn success(
        command: impl Into<String>,
        result: T,
        diagnostics: Vec<Diagnostic>,
        next_actions: Vec<NextAction>,
    ) -> Self {
        Self {
            schema: "command/v2".into(),
            ok: true,
            command: command.into(),
            result: Some(result),
            diagnostics,
            next_actions,
        }
    }

    /// Wrap a failure, which carries diagnostics instead of a result.
    pub fn failure(
        command: impl Into<String>,
        diagnostics: Vec<Diagnostic>,
        next_actions: Vec<NextAction>,
    ) -> Self {
        Self {
            schema: "command/v2".into(),
            ok: false,
            command: command.into(),
            result: None,
            diagnostics,
            next_actions,
        }
    }
}

/// The ordered SemVer release requirement lattice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bump {
    /// No release is required.
    #[default]
    None,
    /// A backwards-compatible fix.
    Patch,
    /// A backwards-compatible feature or an API addition.
    Minor,
    /// A breaking API change.
    Major,
}

impl Bump {
    /// The stronger of two requirements.
    ///
    /// Signals combine by maximum, so no single signal can lower what
    /// another one already requires.
    pub fn max(self, other: Self) -> Self {
        std::cmp::max(self, other)
    }
}

impl fmt::Display for Bump {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Patch => "patch",
            Self::Minor => "minor",
            Self::Major => "major",
        })
    }
}

/// A prerelease train.
///
/// Channels only move forward: alpha, beta, rc, then stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrereleaseChannel {
    /// The `alpha` channel.
    Alpha,
    /// The `beta` channel.
    Beta,
    /// The `rc` channel.
    Rc,
}

impl PrereleaseChannel {
    /// The wire form used in versions and in configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alpha => "alpha",
            Self::Beta => "beta",
            Self::Rc => "rc",
        }
    }
}

impl std::str::FromStr for PrereleaseChannel {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "alpha" => Ok(Self::Alpha),
            "beta" => Ok(Self::Beta),
            "rc" => Ok(Self::Rc),
            _ => Err(format!("unknown prerelease channel `{value}`")),
        }
    }
}

/// Why the planner arrived at the version it selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonKind {
    /// Nothing has been published yet.
    InitialRelease,
    /// The publication inputs differ from the published artifact.
    ArtifactChanged,
    /// A commit message declared the intent.
    ConventionalCommit,
    /// The public API gained items.
    ApiAdded,
    /// The public API removed or changed items.
    ApiBreaking,
    /// An operator requested a specific version.
    ExplicitVersion,
    /// A prerelease channel is in effect.
    Prerelease,
    /// The baseline release was retired, so comparison restarted.
    RetiredBaseline,
}

/// One signal that contributed to the selected version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseReason {
    /// Which signal this is.
    pub kind: ReasonKind,
    /// The release step this signal alone requires.
    pub bump: Bump,
    /// Human-readable explanation.
    pub summary: String,
}

/// Outcome of comparing the public API against the baseline.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiStatus {
    /// No comparison was attempted.
    #[default]
    NotChecked,
    /// The API is unchanged, or only gained items.
    Compatible,
    /// The API differs from the baseline.
    Changed,
    /// The baseline API is unavailable and an exception permits it.
    UnknownAllowed,
}

/// How one API item differs from the baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiChangeKind {
    /// An item the baseline did not expose.
    Added,
    /// An item the baseline exposed that is now gone.
    Removed,
    /// An item whose signature changed.
    Changed,
    /// A new constructor on an existing type.
    ConstructorAdded,
}

/// One difference between the Candidate API and the baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiChange {
    /// What kind of difference this is.
    pub kind: ApiChangeKind,
    /// Dotted path of the affected item.
    pub path: String,
    /// Whether this difference alone requires a major release.
    pub breaking: bool,
    /// Human-readable description.
    pub summary: String,
}

/// The complete result of the public API comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiDiff {
    /// Whether a comparison happened, and what it concluded.
    pub status: ApiStatus,
    /// The release step the API alone requires.
    pub impact: Bump,
    /// Every individual difference that was found.
    pub changes: Vec<ApiChange>,
}

/// How the baseline for comparison was located.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineSource {
    /// An annotated release tag.
    Tag,
    /// The fingerprint of the published artifact.
    ArtifactFingerprint,
    /// A configured API exception pinned the baseline.
    Config,
    /// Nothing is published, so there is no baseline to compare against.
    Initial,
}

/// The published release the Candidate is compared against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    /// Published version, absent before the first release.
    pub version: Option<Version>,
    /// Ref that identifies the baseline, when one is known.
    pub git_ref: Option<String>,
    /// Commit the baseline was built from, when one is known.
    pub sha: Option<String>,
    /// How the baseline was located.
    pub source: BaselineSource,
    /// Whether the baseline release has been retired on the registry.
    pub retired: bool,
}

/// One entry of the change list collected since the baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeEntry {
    /// Single-line title of the change.
    pub title: String,
    /// Pull request number, when the change arrived through one.
    pub pull_request: Option<u64>,
    /// Author login, when the forge reported one.
    pub author: Option<String>,
    /// Link to the change, when the forge reported one.
    pub url: Option<String>,
    /// Labels that were used to place the entry in a category.
    #[serde(default)]
    pub labels: Vec<String>,
    /// Changelog section this entry belongs to.
    pub category: String,
}

/// Versioned and stable machine-readable output of every release operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleasePlan {
    /// Always `plan/v2`.
    pub schema: String,
    /// Where the package currently is in the release lifecycle.
    pub state: ReleaseState,
    /// Package name taken from `gleam.toml`.
    pub package: String,
    /// Repository-relative path of the manifest this plan describes.
    pub manifest_path: String,
    /// Highest version already published, if any.
    pub published_version: Option<Version>,
    /// Version currently written in the manifest.
    pub manifest_version: Version,
    /// Version this release would publish.
    pub version: Version,
    /// Release step between the published version and `version`.
    pub bump: Bump,
    /// Whether anything has to be published at all.
    pub release_required: bool,
    /// Whether the publication inputs differ from the published bytes.
    pub artifacts_changed: bool,
    /// Prerelease channel of `version`, when it is on one.
    pub prerelease: Option<PrereleaseChannel>,
    /// Git tag that identifies this release.
    pub tag: String,
    /// Release that the comparison was made against.
    pub baseline: Baseline,
    /// Every signal that contributed to the selected version.
    pub reasons: Vec<ReleaseReason>,
    /// Result of the public API comparison.
    pub api: ApiDiff,
    /// Change entries collected since the baseline.
    #[serde(default)]
    pub changes: Vec<ChangeEntry>,
    /// Non-fatal diagnostics raised while planning.
    #[serde(default)]
    pub warnings: Vec<Diagnostic>,
    /// Approvals that have to exist before publication.
    #[serde(default)]
    pub required_approvals: Vec<ApprovalRequirement>,
    /// Publication stages this release needs, in order.
    #[serde(default)]
    pub stages: Vec<ReleaseStage>,
    /// Digest of the decision itself.
    ///
    /// An approval binds to this value, so a plan that changes after
    /// approval can no longer be published under it.
    pub intent_digest: Option<String>,
    /// Rolling Release PR, once one exists.
    pub pr_url: Option<String>,
    /// Published package page, once publication reached the registry.
    pub hex_url: Option<String>,
    /// GitHub Release, once one exists.
    pub github_release_url: Option<String>,
}

impl ReleasePlan {
    /// The schema identifier every plan carries.
    pub const SCHEMA: &'static str = "plan/v2";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_next_actions_quote_empty_and_unsafe_display_arguments() {
        let action = NextAction::executable(
            ["release-glz", "", "path with space", "safe/path-1.0"],
            "Retry safely.",
        );
        assert_eq!(
            action.argv,
            ["release-glz", "", "path with space", "safe/path-1.0"]
        );
        assert_eq!(
            action.command,
            "release-glz \"\" \"path with space\" safe/path-1.0"
        );
    }
}
