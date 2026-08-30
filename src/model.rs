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
    UpToDate,
    Planned,
    CandidateReady,
    AwaitingApproval,
    PartiallyReleased,
    Released,
    Conflict,
    Blocked,
}

impl ReleaseState {
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
    VerifyHooks,
    PrepareGitTag,
    PrepareGithubDraft,
    PublishPackage,
    PublishDocs,
    FinalizeGithubRelease,
    NotifyHooks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticLevel {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub level: DiagnosticLevel,
    pub message: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextAction {
    /// Canonical process argv. Consumers must execute this array directly and
    /// must never parse `command` as shell input.
    pub argv: Vec<String>,
    /// Human-readable rendering only.
    pub command: String,
    pub description: String,
}

impl NextAction {
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
                format!("{:?}", argument)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    ReleasePr,
    Environment,
    CandidateDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequirement {
    pub kind: ApprovalKind,
    pub environment: Option<String>,
}

/// Stable machine-readable envelope shared by every command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandEnvelope<T> {
    pub schema: String,
    pub ok: bool,
    pub command: String,
    pub result: Option<T>,
    pub diagnostics: Vec<Diagnostic>,
    pub next_actions: Vec<NextAction>,
}

impl<T> CommandEnvelope<T> {
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
    #[default]
    None,
    Patch,
    Minor,
    Major,
}

impl Bump {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrereleaseChannel {
    Alpha,
    Beta,
    Rc,
}

impl PrereleaseChannel {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonKind {
    InitialRelease,
    ArtifactChanged,
    ConventionalCommit,
    ApiAdded,
    ApiBreaking,
    ExplicitVersion,
    Prerelease,
    RetiredBaseline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseReason {
    pub kind: ReasonKind,
    pub bump: Bump,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiStatus {
    #[default]
    NotChecked,
    Compatible,
    Changed,
    UnknownAllowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiChangeKind {
    Added,
    Removed,
    Changed,
    ConstructorAdded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiChange {
    pub kind: ApiChangeKind,
    pub path: String,
    pub breaking: bool,
    pub summary: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiDiff {
    pub status: ApiStatus,
    pub impact: Bump,
    pub changes: Vec<ApiChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineSource {
    Tag,
    ArtifactFingerprint,
    Config,
    Initial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    pub version: Option<Version>,
    pub git_ref: Option<String>,
    pub sha: Option<String>,
    pub source: BaselineSource,
    pub retired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeEntry {
    pub title: String,
    pub pull_request: Option<u64>,
    pub author: Option<String>,
    pub url: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    pub category: String,
}

/// Versioned and stable machine-readable output of every release operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleasePlan {
    pub schema: String,
    pub state: ReleaseState,
    pub package: String,
    pub manifest_path: String,
    pub published_version: Option<Version>,
    pub manifest_version: Version,
    pub version: Version,
    pub bump: Bump,
    pub release_required: bool,
    pub artifacts_changed: bool,
    pub prerelease: Option<PrereleaseChannel>,
    pub tag: String,
    pub baseline: Baseline,
    pub reasons: Vec<ReleaseReason>,
    pub api: ApiDiff,
    #[serde(default)]
    pub changes: Vec<ChangeEntry>,
    #[serde(default)]
    pub warnings: Vec<Diagnostic>,
    #[serde(default)]
    pub required_approvals: Vec<ApprovalRequirement>,
    #[serde(default)]
    pub stages: Vec<ReleaseStage>,
    pub intent_digest: Option<String>,
    pub pr_url: Option<String>,
    pub hex_url: Option<String>,
    pub github_release_url: Option<String>,
}

impl ReleasePlan {
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
