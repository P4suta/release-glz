//! GitHub: pull requests, tags, releases, environments, and Actions artifacts.
//!
//! Everything observable is read before anything is written, so a resumed release recognizes what it already created instead of duplicating it.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use base64::Engine;
use chrono::Utc;
use release_glz_core::{Answer, GITHUB_READS, MARKER_PREFIX, MARKER_SUFFIX, Next, RunRefusal};
use reqwest::{
    Method, StatusCode,
    header::{CONTENT_TYPE, RETRY_AFTER},
};
use semver::Version;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::changelog::default_category;
use crate::config::url_is_http_loopback;
use crate::git::Commit;
use crate::model::{ChangeEntry, ReleasePlan, bump_name};
use crate::units::GIB;

/// REST API version this client pins its requests to.
const GITHUB_API_VERSION: &str = "2026-03-10";

/// Seconds a single GitHub request may take before it is abandoned.
const REQUEST_TIMEOUT_SECONDS: u64 = 60;

/// Size an Actions artifact may reach before it is refused.
const MAX_ACTIONS_ARTIFACT_BYTES: u64 = GIB;

/// Characters a GitHub account name may use.
const MAX_OWNER_LEN: usize = 39;

/// Characters a Release asset name may use.
const MAX_ASSET_NAME_LEN: usize = 256;

/// Characters a Release asset media type may use.
const MAX_MEDIA_TYPE_LEN: usize = 128;

/// The port an `https` URL uses when it names none.
const HTTPS_PORT: u16 = 443;

const MAX_GITHUB_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_GITHUB_ERROR_BYTES: usize = 64 * 1024;
const OPEN_PULL_REQUEST_PAGE_SIZE: usize = 100;

/// Files a generated commit changes at most, which bounds the blobs that recognizing one reads.
const MAX_GENERATED_FILES: usize = 2;

/// Bytes a file in a generated commit may hold, so its base64 blob fits in one bounded GitHub response.
const MAX_GENERATED_FILE_BYTES: usize = 2 * 1024 * 1024;

/// The object ID that a ref update moves a branch to in order to delete it.
const NULL_OBJECT_ID: &str = "0000000000000000000000000000000000000000";
const MAX_OPEN_PULL_REQUEST_PAGES: usize = 100;

/// Releases on one page of the release list, which GitHub caps at 100.
const RELEASE_PAGE_SIZE: usize = 100;

/// Pages of the release list that one lookup reads, which bounds it at the newest 1000 Releases.
const MAX_RELEASE_PAGES: usize = 10;

/// Commits whose pull requests one Release PR update looks up, which bounds its API requests on a long history.
///
/// A release normally holds far fewer, and a first release over a long history lists its commits by subject instead.
pub const MAX_ATTRIBUTED_COMMITS: usize = 200;

/// Characters a GitHub repository name may have.
const MAX_NAME_LEN: usize = 100;

/// Seconds a GitHub connection may take to open.
const CONNECT_TIMEOUT_SECONDS: u64 = 10;

/// The public GitHub REST API, when `GITHUB_API_URL` names none.
const DEFAULT_GITHUB_API_URL: &str = "https://api.github.com";

/// The public GitHub GraphQL endpoint, when `GITHUB_GRAPHQL_URL` names none.
const DEFAULT_GITHUB_GRAPHQL_URL: &str = "https://api.github.com/graphql";

/// The `intent` of a managed marker before a Candidate binds one.
const PENDING_INTENT: &str = "pending";

/// An `owner/name` repository on GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubRepository {
    /// Repository owner.
    pub owner: String,
    /// Repository name.
    pub name: String,
}

impl GitHubRepository {
    /// Parse an `owner/name` slug, rejecting anything unsafe in a URL path.
    pub fn parse(value: &str) -> Result<Self> {
        let (owner, name) = value
            .split_once('/')
            .context("GitHub repository must be `owner/name`")?;
        let owner_valid = (1..=MAX_OWNER_LEN).contains(&owner.len())
            && owner
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && owner
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && owner
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && !owner.contains("--");
        let name_valid = (1..=MAX_NAME_LEN).contains(&name.len())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && !matches!(name, "." | "..");
        if !owner_valid || !name_valid {
            bail!("GitHub repository must be `owner/name`");
        }
        Ok(Self {
            owner: owner.to_owned(),
            name: name.to_owned(),
        })
    }

    /// The `owner/name` slug.
    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

/// A GitHub REST and GraphQL client.
///
/// Redirects are refused so a token cannot follow one to another host,
/// and a token is required explicitly by the calls that change state.
#[derive(Clone)]
pub struct GitHubClient {
    client: reqwest::Client,
    token: Option<String>,
    api_url: String,
    graphql_url: String,
    /// Repository every request is scoped to.
    pub repository: GitHubRepository,
}

/// A pull request, as far as release-glz reads it.
#[derive(Debug, Clone, Deserialize)]
pub struct PullRequest {
    /// Pull request number.
    pub number: u64,
    /// Title.
    pub title: String,
    /// Body, when it has one.
    pub body: Option<String>,
    /// Page for humans.
    pub html_url: String,
    /// Merge commit, once the pull request is merged.
    pub merge_commit_sha: Option<String>,
    /// Merge timestamp, once it is merged.
    pub merged_at: Option<String>,
    /// Author.
    pub user: User,
    /// Labels, used to place a change in a changelog category.
    #[serde(default)]
    pub labels: Vec<Label>,
    /// Head branch and commit.
    pub head: PullHead,
    /// Branch the pull request merges into.
    #[serde(default)]
    pub base: Option<PullBase>,
}

/// A managed Release PR that merged, whose head has the shape of the commit that release-glz generates.
///
/// Anyone who can push to the repository can make a commit of that shape, so the review of the merge and the Environment approval stay the controls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedReleasePr {
    /// Page for humans.
    pub html_url: String,
    /// Intent digest that the marker recorded when the pull request merged, if its intent was bound by then.
    pub intent_digest: Option<String>,
}

impl PullRequest {
    /// Whether the head branch lives in `repository` and the pull request targets its default branch.
    ///
    /// Pushing a branch to the repository itself takes write access, which a fork contributor lacks.
    fn is_internal_to(&self, repository: &GitHubRepository) -> bool {
        let full_name = repository.full_name();
        let Some(base) = &self.base else {
            return false;
        };
        self.head
            .repo
            .as_ref()
            .is_some_and(|head| head.full_name.eq_ignore_ascii_case(&full_name))
            && base.repo.full_name.eq_ignore_ascii_case(&full_name)
            && base.branch == base.repo.default_branch
    }
}

/// The branch that the rolling Release PR targets, as GitHub reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultBranch {
    /// Branch name.
    pub name: String,
    /// Commit at the tip of the branch.
    pub tip: String,
    /// GraphQL node id of the repository, which ref updates name.
    pub repository_id: String,
}

/// A server-verified commit on top of one parent with the shape of the commit that this tool generates.
struct GeneratedCommit {
    digest: String,
    parent: String,
}

/// What binding a Candidate intent to the rolling Release PR did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentBinding {
    /// The open Release PR at the Candidate head carries the intent.
    Bound {
        /// Page of the Release PR.
        url: String,
    },
    /// No open managed Release PR has the Candidate head, because a newer head replaced it; nothing was written.
    Superseded,
}

/// What one rolling Release PR update left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePrUpdate {
    /// Page of the Release PR.
    pub url: String,
    /// Commit at the head of the Release PR, which the managed marker names.
    pub head: String,
}

/// A GitHub account.
#[derive(Debug, Clone, Deserialize)]
pub struct User {
    /// Account login.
    pub login: String,
}

/// A label on a pull request.
#[derive(Debug, Clone, Deserialize)]
pub struct Label {
    /// Label name.
    pub name: String,
}

/// The head of a pull request.
#[derive(Debug, Clone, Deserialize)]
pub struct PullHead {
    /// Branch name.
    #[serde(rename = "ref")]
    pub branch: String,
    /// Commit the branch points at.
    pub sha: String,
    /// Repository the branch lives in, or `None` once its fork is deleted.
    #[serde(default)]
    pub repo: Option<PullRepository>,
}

/// The base of a pull request.
#[derive(Debug, Clone, Deserialize)]
pub struct PullBase {
    /// Branch name.
    #[serde(rename = "ref")]
    pub branch: String,
    /// Repository the pull request merges into.
    pub repo: PullRepository,
}

/// A repository that a pull request names.
#[derive(Debug, Clone, Deserialize)]
pub struct PullRepository {
    /// The `owner/name` slug.
    pub full_name: String,
    /// The repository's default branch.
    pub default_branch: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GitRefObject {
    object: GitObject,
}

#[derive(Debug, Clone, Deserialize)]
struct GitObject {
    sha: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ReleaseResponse {
    #[serde(default)]
    id: u64,
    html_url: String,
    #[serde(default)]
    tag_name: String,
    #[serde(default)]
    target_commitish: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    upload_url: String,
    #[serde(default)]
    assets: Vec<ReleaseAssetResponse>,
}

#[derive(Debug, Clone, Deserialize)]
struct ReleaseAssetResponse {
    #[serde(default)]
    id: u64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    content_type: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    digest: Option<String>,
}

/// A GitHub Release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubRelease {
    /// Release identifier.
    pub id: u64,
    /// Page for humans.
    pub html_url: String,
    /// Tag this release belongs to.
    pub tag_name: String,
    /// Commit the tag points at.
    pub target_commitish: String,
    /// Candidate digest recorded in the release body, when present.
    ///
    /// It is what lets a resumed run recognize its own draft instead of adopting one that was created for different bytes.
    pub candidate_digest: Option<String>,
    /// Whether the release is still a draft.
    pub draft: bool,
    /// Endpoint that accepts asset uploads.
    pub upload_url: String,
    /// Assets already attached.
    pub assets: Vec<GitHubReleaseAsset>,
}

/// One asset attached to a GitHub Release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubReleaseAsset {
    /// Asset identifier.
    pub id: u64,
    /// File name.
    pub name: String,
    /// Upload state reported by GitHub.
    pub state: String,
    /// Declared media type.
    pub media_type: String,
    /// Size in bytes.
    pub size: u64,
    /// Digest GitHub recorded, when it reports one.
    pub sha256: Option<String>,
}

/// What the protections around a publish environment look like.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitHubEnvironmentAudit {
    /// Whether the repository is private.
    pub private_repository: bool,
    /// Plan the repository is on, when GitHub reports one.
    pub plan: Option<String>,
    /// Default branch name.
    pub default_branch: String,
    /// Whether the default branch is protected.
    pub default_branch_protected: bool,
    /// How many reviewers the environment requires.
    pub required_reviewers: usize,
    /// Whether the environment forbids self-review.
    pub prevent_self_review: bool,
    /// Whether the environment is restricted to protected branches.
    pub protected_branches_only: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct RepositoryResponse {
    #[serde(default)]
    private: bool,
    default_branch: String,
    #[serde(default)]
    plan: Option<RepositoryPlanResponse>,
}

#[derive(Debug, Clone, Deserialize)]
struct RepositoryPlanResponse {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct EnvironmentResponse {
    #[serde(default)]
    protection_rules: Vec<EnvironmentProtectionRuleResponse>,
    #[serde(default)]
    deployment_branch_policy: Option<DeploymentBranchPolicyResponse>,
}

#[derive(Debug, Clone, Deserialize)]
struct EnvironmentProtectionRuleResponse {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    prevent_self_review: bool,
    #[serde(default)]
    reviewers: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct DeploymentBranchPolicyResponse {
    #[serde(default)]
    protected_branches: bool,
    #[serde(default)]
    custom_branch_policies: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct BranchResponse {
    #[serde(default)]
    protected: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct ActionsArtifactResponse {
    id: u64,
    name: String,
    size_in_bytes: u64,
    expired: bool,
    digest: String,
    workflow_run: ActionsArtifactWorkflowRunResponse,
}

#[derive(Debug, Clone, Deserialize)]
struct ActionsArtifactWorkflowRunResponse {
    id: u64,
    head_sha: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ActionsWorkflowRunResponse {
    id: u64,
    path: String,
    head_sha: String,
    status: String,
    #[serde(default)]
    conclusion: Option<String>,
    repository: ActionsWorkflowRepositoryResponse,
}

#[derive(Debug, Clone, Deserialize)]
struct ActionsWorkflowRepositoryResponse {
    full_name: String,
}

/// Which run may have produced the Candidate that a publish job consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateRun {
    /// The run that is publishing now, which prepared the Candidate in an earlier job and is still in progress.
    Current,
    /// An earlier run that prepared the Candidate and completed with success.
    Completed,
}

impl CandidateRun {
    /// The run a publish job may consume, given its OIDC-verified event and run and the Candidate's run.
    ///
    /// A push publishes only the Candidate that its own run prepared, and a manual promotion only one from an earlier run.
    pub fn for_event(
        event_name: &str,
        current_run_id: &str,
        candidate_run_id: &str,
    ) -> Result<Self> {
        match release_glz_core::candidate_run(
            event_name.as_bytes(),
            current_run_id == candidate_run_id,
        ) {
            Ok(run) => Ok(run.into()),
            Err(RunRefusal::PushFromAnotherRun) => {
                bail!("a push publishes only the Candidate that its own run prepared")
            }
            Err(RunRefusal::PromotionOfItsOwnRun) => {
                bail!(
                    "manual promotion must consume a Candidate from a completed prior prepare run"
                )
            }
            Err(RunRefusal::OtherEvent) => {
                bail!("only a push or a manual promotion publishes a Candidate, not `{event_name}`")
            }
        }
    }

    fn admits(self, status: &str, conclusion: Option<&str>) -> bool {
        release_glz_core::CandidateRun::from(self)
            .admits(status.as_bytes(), conclusion.map(str::as_bytes))
    }
}

impl From<release_glz_core::CandidateRun> for CandidateRun {
    fn from(run: release_glz_core::CandidateRun) -> Self {
        match run {
            release_glz_core::CandidateRun::Current => Self::Current,
            release_glz_core::CandidateRun::Completed => Self::Completed,
        }
    }
}

impl From<CandidateRun> for release_glz_core::CandidateRun {
    fn from(run: CandidateRun) -> Self {
        match run {
            CandidateRun::Current => Self::Current,
            CandidateRun::Completed => Self::Completed,
        }
    }
}

/// An Actions artifact whose identity has been checked.
///
/// The fields are private because the type exists to prove that the digest, run, and source commit were verified together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedActionsArtifact {
    id: u64,
    sha256: String,
    run_id: String,
    source_sha: String,
    repository: String,
    workflow_path: String,
}

impl VerifiedActionsArtifact {
    /// Artifact identifier.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Digest of the artifact bytes.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Run that produced it.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Commit it was built from.
    pub fn source_sha(&self) -> &str {
        &self.source_sha
    }

    /// Repository that produced it.
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Workflow that produced it.
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }
}

/// What a tag points at on GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubTagState {
    /// Commit the tag resolves to.
    pub target_sha: String,
    /// Whether the tag is an annotated tag object.
    pub annotated: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct GitObjectResponse {
    #[serde(rename = "type")]
    kind: String,
    sha: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GitReferenceResponse {
    object: GitObjectResponse,
}

#[derive(Debug, Clone, Deserialize)]
struct GitTagObjectResponse {
    #[serde(default)]
    sha: String,
    object: GitObjectResponse,
}

impl From<ReleaseResponse> for GitHubRelease {
    fn from(value: ReleaseResponse) -> Self {
        Self {
            id: value.id,
            html_url: value.html_url,
            tag_name: value.tag_name,
            target_commitish: value.target_commitish,
            candidate_digest: value.body.as_deref().and_then(parse_candidate_digest),
            draft: value.draft,
            upload_url: value.upload_url,
            assets: value.assets.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<ReleaseAssetResponse> for GitHubReleaseAsset {
    fn from(value: ReleaseAssetResponse) -> Self {
        let sha256 = value.digest.and_then(|digest| {
            digest
                .strip_prefix("sha256:")
                .filter(|digest| valid_sha256(digest))
                .map(str::to_owned)
        });
        Self {
            id: value.id,
            name: value.name,
            state: value.state,
            media_type: value.content_type,
            size: value.size,
            sha256,
        }
    }
}

impl std::fmt::Debug for GitHubClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GitHubClient")
            .field("api_url", &self.api_url)
            .field("graphql_url", &self.graphql_url)
            .field("repository", &self.repository)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
struct CommitResponse {
    commit: CommitDetails,
    parents: Vec<GitObject>,
    files: Vec<CommitFile>,
}

#[derive(Debug, Clone, Deserialize)]
struct CommitDetails {
    message: String,
    verification: CommitVerification,
}

#[derive(Debug, Clone, Deserialize)]
struct CommitVerification {
    verified: bool,
}

/// One file that a commit changed relative to its parent.
#[derive(Debug, Clone, Deserialize)]
struct CommitFile {
    filename: String,
    status: String,
    sha: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct BlobResponse {
    content: String,
    encoding: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedMarker {
    package: String,
    branch: String,
    head: String,
    digest: String,
    version: String,
    intent_digest: Option<String>,
}

impl GitHubClient {
    /// Build a client for explicit endpoints and an optional token.
    pub fn new(
        repository: GitHubRepository,
        api_url: String,
        graphql_url: String,
        token: Option<String>,
    ) -> Result<Self> {
        validate_github_url(&api_url)?;
        validate_github_url(&graphql_url)?;
        let loopback_only = [&api_url, &graphql_url]
            .into_iter()
            .all(|raw| reqwest::Url::parse(raw).is_ok_and(|url| url_is_http_loopback(&url)));
        let mut client = reqwest::Client::builder()
            .user_agent(concat!("release-glz/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(CONNECT_TIMEOUT_SECONDS))
            .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECONDS))
            .redirect(reqwest::redirect::Policy::none());
        if loopback_only {
            client = client.no_proxy();
        }
        Ok(Self {
            client: client.build()?,
            token,
            api_url: api_url.trim_end_matches('/').to_owned(),
            graphql_url,
            repository,
        })
    }

    /// Build a client from the ambient GitHub Actions environment.
    pub fn from_environment(repository: GitHubRepository) -> Result<Self> {
        let token = std::env::var("GITHUB_TOKEN")
            .or_else(|_| std::env::var("GH_TOKEN"))
            .ok();
        let api_url =
            std::env::var("GITHUB_API_URL").unwrap_or_else(|_| DEFAULT_GITHUB_API_URL.into());
        let graphql_url = std::env::var("GITHUB_GRAPHQL_URL")
            .unwrap_or_else(|_| DEFAULT_GITHUB_GRAPHQL_URL.into());
        Self::new(repository, api_url, graphql_url, token)
    }

    /// Collect the change entries for a range of commits.
    ///
    /// Over [`MAX_ATTRIBUTED_COMMITS`] commits, every entry comes from its commit subject without a lookup.
    pub async fn changes_for_commits(&self, commits: &[Commit]) -> Result<Vec<ChangeEntry>> {
        if commits.len() > MAX_ATTRIBUTED_COMMITS {
            return Ok(commits.iter().map(commit_change).collect());
        }
        let mut seen = BTreeSet::new();
        let mut output = Vec::new();
        for commit in commits {
            let path = format!("commits/{}/pulls", commit.sha);
            let pulls: Vec<PullRequest> = self.get(&path).await?;
            if let Some(pull) = pulls.into_iter().find(|pull| pull.merged_at.is_some()) {
                if seen.insert(pull.number) {
                    output.push(ChangeEntry {
                        category: default_category(&pull.title),
                        title: pull.title,
                        pull_request: Some(pull.number),
                        author: Some(pull.user.login),
                        url: Some(pull.html_url),
                        labels: pull.labels.into_iter().map(|label| label.name).collect(),
                    });
                }
            } else {
                output.push(commit_change(commit));
            }
        }
        Ok(output)
    }

    /// Observe the protections around a publish environment.
    ///
    /// `doctor --online` reports these so a missing protection is found before a release depends on it.
    pub async fn environment_audit(&self, environment: &str) -> Result<GitHubEnvironmentAudit> {
        if environment.is_empty() {
            bail!("GitHub Environment name must not be empty");
        }
        let repository: RepositoryResponse = self.get("").await?;
        if repository.default_branch.is_empty() {
            bail!("GitHub repository has no default branch");
        }
        let environment: EnvironmentResponse = self
            .get(&format!("environments/{}", encode_segment(environment)))
            .await?;
        let branch: BranchResponse = self
            .get(&format!(
                "branches/{}",
                encode_segment(&repository.default_branch)
            ))
            .await?;

        let reviewer_rules: Vec<_> = environment
            .protection_rules
            .iter()
            .filter(|rule| rule.kind == "required_reviewers")
            .collect();
        let required_reviewers = reviewer_rules.iter().map(|rule| rule.reviewers.len()).sum();
        let prevent_self_review = reviewer_rules.iter().any(|rule| rule.prevent_self_review);
        let protected_branches_only = environment
            .deployment_branch_policy
            .is_some_and(|policy| policy.protected_branches && !policy.custom_branch_policies);

        Ok(GitHubEnvironmentAudit {
            private_repository: repository.private,
            plan: repository.plan.map(|plan| plan.name),
            default_branch: repository.default_branch,
            default_branch_protected: branch.protected,
            required_reviewers,
            prevent_self_review,
            protected_branches_only,
        })
    }

    /// Check that an Actions artifact is the one this release expects.
    ///
    /// Digest, run, and source commit must all agree, so the publish job cannot be handed an artifact built somewhere else.
    /// `run` states whether that run is the one publishing now, which is still in progress, or an earlier one that succeeded.
    pub async fn verify_actions_artifact(
        &self,
        artifact_id: u64,
        expected_sha256: &str,
        expected_run_id: &str,
        expected_source_sha: &str,
        run_state: CandidateRun,
    ) -> Result<VerifiedActionsArtifact> {
        self.require_token()?;
        if artifact_id == 0 || !valid_sha256(expected_sha256) {
            bail!("GitHub Actions artifact identity is invalid");
        }
        let expected_run_number = expected_run_id
            .parse::<u64>()
            .context("GitHub Actions run ID is invalid")?;
        if expected_run_number.to_string() != expected_run_id {
            bail!("GitHub Actions run ID is not canonical");
        }
        let artifact: ActionsArtifactResponse = self
            .get(&format!("actions/artifacts/{artifact_id}"))
            .await?;
        if artifact.expired {
            bail!("GitHub Actions Candidate artifact has expired");
        }
        if artifact.id != artifact_id
            || artifact.name
                != format!(
                    "{}{expected_run_id}",
                    crate::workflow::CANDIDATE_ARTIFACT_PREFIX
                )
            || artifact.size_in_bytes == 0
            || artifact.size_in_bytes > MAX_ACTIONS_ARTIFACT_BYTES
            || artifact.digest != format!("sha256:{expected_sha256}")
            || artifact.workflow_run.id != expected_run_number
            || artifact.workflow_run.head_sha != expected_source_sha
        {
            bail!(
                "GitHub Actions Candidate artifact does not match its sealed run, source, and digest"
            );
        }
        let run: ActionsWorkflowRunResponse =
            self.get(&format!("actions/runs/{expected_run_id}")).await?;
        if run.id != expected_run_number
            || run.repository.full_name != self.repository.full_name()
            || run.path != crate::workflow::WORKFLOW_PATH
            || run.head_sha != expected_source_sha
            || !run_state.admits(&run.status, run.conclusion.as_deref())
        {
            bail!(
                "GitHub Actions Candidate run does not match the repository, managed workflow, source, and successful conclusion"
            );
        }
        Ok(VerifiedActionsArtifact {
            id: artifact.id,
            sha256: expected_sha256.to_owned(),
            run_id: expected_run_id.to_owned(),
            source_sha: expected_source_sha.to_owned(),
            repository: run.repository.full_name,
            workflow_path: run.path,
        })
    }

    /// The default branch as GitHub reports it now, with the commit at its tip.
    pub async fn default_branch(&self) -> Result<DefaultBranch> {
        #[derive(Deserialize)]
        struct RepositoryNode {
            node_id: String,
            full_name: String,
            default_branch: String,
        }
        let repository: RepositoryNode = self.get("").await?;
        // GitHub resolves a slug in any letter case, but OIDC and the Actions run checks compare it exactly, so a difference would fail only at publication.
        if repository.full_name != self.repository.full_name() {
            bail!(
                "the configured repository `{}` differs from GitHub's `{}`; use GitHub's spelling",
                self.repository.full_name(),
                repository.full_name
            );
        }
        let tip = self
            .ref_sha(&repository.default_branch)
            .await?
            .with_context(|| {
                format!(
                    "GitHub default branch `{}` does not exist",
                    repository.default_branch
                )
            })?;
        Ok(DefaultBranch {
            name: repository.default_branch,
            tip,
            repository_id: repository.node_id,
        })
    }

    /// Create or update the rolling Release PR for a package on the tip of `base`.
    ///
    /// One pull request is maintained per package, so a superseded plan updates it in place instead of leaving stale proposals open.
    /// Its branch always holds exactly one generated commit on top of `base.tip`, so merging it brings in nothing that the rehearsed head lacks.
    pub async fn upsert_release_pr(
        &self,
        plan: &ReleasePlan,
        base: &DefaultBranch,
        branch_prefix: &str,
        files: &BTreeMap<String, Vec<u8>>,
    ) -> Result<ReleasePrUpdate> {
        self.require_token()?;
        // A commit outside the bounds that recognize a generated commit would count as human on the next run.
        if files.is_empty() || files.len() > MAX_GENERATED_FILES {
            bail!(
                "a Release PR commit changes 1 to {MAX_GENERATED_FILES} files, not {}",
                files.len()
            );
        }
        if let Some(path) = files.iter().find_map(|(path, contents)| {
            (contents.len() > MAX_GENERATED_FILE_BYTES).then_some(path)
        }) {
            bail!("Release PR file `{path}` exceeds 2 MiB");
        }
        let digest = files_digest(files);
        let pulls = self.open_pull_requests().await?;
        // A pull request that only copies the marker names a branch other than its own, and closing it would close someone else's work.
        let mut managed = pulls.into_iter().find(|pull| {
            pull.is_internal_to(&self.repository)
                && pull.head.branch.starts_with(branch_prefix)
                && pull
                    .body
                    .as_deref()
                    .and_then(parse_marker)
                    .is_some_and(|marker| {
                        marker.package == plan.package && marker.branch == pull.head.branch
                    })
        });

        if let Some(pull) = managed.as_ref()
            && let Some(marker) = pull.body.as_deref().and_then(parse_marker)
        {
            let actual = match marker.branch == pull.head.branch {
                true => self.ref_sha(&pull.head.branch).await?,
                false => None,
            };
            let generated = match actual.as_deref() {
                Some(actual) => self.generated_commit(actual).await?,
                None => None,
            };
            match (actual, generated) {
                (Some(actual), Some(commit))
                    if commit.digest == digest && commit.parent == base.tip =>
                {
                    if actual == marker.head
                        && marker.digest == digest
                        && marker.version == plan.version.to_string()
                    {
                        return Ok(ReleasePrUpdate {
                            url: pull.html_url.clone(),
                            head: actual,
                        });
                    }
                    // The verified commit succeeded but updating the PR body failed.
                    // Repair the marker without creating another commit.
                    // An intent belongs to the rehearsal of one head, so it survives only when the head stays.
                    let intent_digest = marker.intent_digest.filter(|_| marker.head == actual);
                    let body = pull_body(
                        plan,
                        &ManagedMarker {
                            package: plan.package.clone(),
                            branch: marker.branch,
                            head: actual.clone(),
                            digest: digest.clone(),
                            version: plan.version.to_string(),
                            intent_digest,
                        },
                    )?;
                    let updated: PullRequest = self
                        .patch(
                            &format!("pulls/{}", pull.number),
                            &serde_json::json!({
                                "title": format!("chore(release): {} {}", plan.package, plan.version),
                                "body": body
                            }),
                        )
                        .await?;
                    return Ok(ReleasePrUpdate {
                        url: updated.html_url,
                        head: actual,
                    });
                }
                (Some(actual), Some(_)) => {
                    // The branch holds this tool's commit for an older plan or an older tip.
                    // Move it back to the tip only if it still holds exactly that commit.
                    self.reset_branch(base, &pull.head.branch, &actual).await?;
                }
                _ => {
                    self.post_empty(
                        &format!("issues/{}/comments", pull.number),
                        &serde_json::json!({"body": "release-glz detected commits not created by the bot. This PR is being closed without overwriting them; a new managed branch will be opened."}),
                    )
                    .await?;
                    self.patch_empty(
                        &format!("pulls/{}", pull.number),
                        &serde_json::json!({"state": "closed"}),
                    )
                    .await?;
                    managed = None;
                }
            }
        }

        let branch = if let Some(pull) = managed.as_ref() {
            pull.head.branch.clone()
        } else {
            let desired = format!("{branch_prefix}{}", plan.package);
            let branch = if self.ref_sha(&desired).await?.is_some() {
                format!("{desired}-{}", Utc::now().timestamp())
            } else {
                desired
            };
            self.create_ref(&branch, &base.tip).await?;
            branch
        };
        let head = self.create_commit(&branch, &base.tip, plan, files).await?;
        let body = pull_body(
            plan,
            &ManagedMarker {
                package: plan.package.clone(),
                branch: branch.clone(),
                head: head.clone(),
                digest,
                version: plan.version.to_string(),
                intent_digest: None,
            },
        )?;
        let title = format!("chore(release): {} {}", plan.package, plan.version);

        let url = if let Some(pull) = managed {
            let updated: PullRequest = self
                .patch(
                    &format!("pulls/{}", pull.number),
                    &serde_json::json!({"title": title, "body": body}),
                )
                .await?;
            updated.html_url
        } else {
            let created: PullRequest = self
                .post(
                    "pulls",
                    &serde_json::json!({
                        "title": title,
                        "head": branch,
                        "base": base.name,
                        "body": body,
                        "maintainer_can_modify": false
                    }),
                )
                .await?;
            created.html_url
        };
        Ok(ReleasePrUpdate { url, head })
    }

    /// Close the managed Release PR and remove its unchanged branch.
    ///
    /// The branch is deleted only while it still holds the verified generated commit, so a commit pushed after the check stays, and the pull request stays open.
    pub async fn close_managed_release_pr(
        &self,
        package: &str,
        branch_prefix: &str,
        base: &DefaultBranch,
    ) -> Result<bool> {
        self.require_token()?;
        let pulls = self.open_pull_requests().await?;
        for pull in pulls {
            let Some(marker) = pull.body.as_deref().and_then(parse_marker) else {
                continue;
            };
            if !pull.is_internal_to(&self.repository)
                || marker.package != package
                || marker.branch != pull.head.branch
                || marker.head != pull.head.sha
                || !marker.branch.starts_with(branch_prefix)
            {
                continue;
            }
            let Some(actual) = self.ref_sha(&marker.branch).await? else {
                continue;
            };
            if actual != marker.head
                || self.generated_commit_digest(&actual).await?.as_deref()
                    != Some(marker.digest.as_str())
            {
                continue;
            }
            self.update_ref(
                "delete the Release PR branch",
                base,
                &marker.branch,
                &actual,
                NULL_OBJECT_ID,
            )
            .await?;
            self.patch_empty(
                &format!("pulls/{}", pull.number),
                &serde_json::json!({"state": "closed"}),
            )
            .await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// The managed Release PR for `version` whose merge produced `sha`, and the intent its marker recorded.
    ///
    /// The pull request counts only when it came from this repository and its head has the shape of the commit that release-glz generates.
    /// A writer could push such a commit too, which the review of the merge has to catch.
    /// The marker's intent digest is reported rather than compared, so the caller decides what the merge approved.
    pub async fn merged_release_pr(
        &self,
        sha: &str,
        package: &str,
        version: &str,
        branch_prefix: &str,
    ) -> Result<Option<MergedReleasePr>> {
        let pulls: Vec<PullRequest> = self.get(&format!("commits/{sha}/pulls")).await?;
        for pull in pulls {
            let Some(marker) = pull.body.as_deref().and_then(parse_marker) else {
                continue;
            };
            let structurally_valid = pull.is_internal_to(&self.repository)
                && pull.merged_at.is_some()
                && pull.merge_commit_sha.as_deref() == Some(sha)
                && marker.package == package
                && marker.version == version
                && marker.branch == pull.head.branch
                && marker.head == pull.head.sha
                && pull.head.branch.starts_with(branch_prefix);
            if !structurally_valid {
                continue;
            }
            let verified_digest = self.generated_commit_digest(&pull.head.sha).await?;
            if verified_digest.as_deref() == Some(marker.digest.as_str()) {
                return Ok(Some(MergedReleasePr {
                    html_url: pull.html_url,
                    intent_digest: marker.intent_digest,
                }));
            }
        }
        Ok(None)
    }

    /// Record the intent digest on the managed Release PR whose head is `head_sha`.
    ///
    /// Approval is bound to that digest, so a plan that changes afterwards can no longer claim the review the pull request carries.
    /// When no open managed Release PR for the package has that head, a newer head replaced it, and nothing is written.
    pub async fn bind_release_pr_intent(
        &self,
        head_sha: &str,
        package: &str,
        version: &str,
        branch_prefix: &str,
        intent_digest: &str,
    ) -> Result<IntentBinding> {
        self.require_token()?;
        if !valid_sha256(intent_digest) {
            bail!("Candidate intent digest is not a lowercase SHA-256 digest");
        }
        let pulls = self.open_pull_requests().await?;
        for pull in pulls {
            if pull.head.sha != head_sha
                || !pull.is_internal_to(&self.repository)
                || !pull.head.branch.starts_with(branch_prefix)
            {
                continue;
            }
            let Some(mut marker) = pull.body.as_deref().and_then(parse_marker) else {
                continue;
            };
            if marker.package != package {
                continue;
            }
            let describes_candidate = marker.version == version
                && marker.branch == pull.head.branch
                && marker.head == pull.head.sha
                && pull.merged_at.is_none()
                && pull.merge_commit_sha.is_none();
            if !describes_candidate {
                bail!("the managed Release PR at the Candidate head describes another release");
            }
            if self.generated_commit_digest(head_sha).await?.as_deref()
                != Some(marker.digest.as_str())
            {
                bail!("managed Release PR head is not the server-verified generated commit");
            }
            if let Some(existing) = &marker.intent_digest {
                if existing == intent_digest {
                    return Ok(IntentBinding::Bound { url: pull.html_url });
                }
                bail!("managed Release PR is already bound to a different Candidate intent");
            }
            marker.intent_digest = Some(intent_digest.to_owned());
            let body = replace_managed_marker(
                pull.body
                    .as_deref()
                    .context("managed Release PR has no body")?,
                &marker,
            )?;
            // The Release PR update serializes in another group, so a newer run may have rewritten the pull request since the list was read.
            let current: PullRequest = self.get(&format!("pulls/{}", pull.number)).await?;
            if current.head.sha != pull.head.sha {
                return Ok(IntentBinding::Superseded);
            }
            if current.body != pull.body {
                bail!(
                    "the managed Release PR changed while its intent was being bound; the next run binds it"
                );
            }
            let updated: PullRequest = self
                .patch(
                    &format!("pulls/{}", pull.number),
                    &serde_json::json!({"body": body}),
                )
                .await?;
            return Ok(IntentBinding::Bound {
                url: updated.html_url,
            });
        }
        Ok(IntentBinding::Superseded)
    }

    async fn open_pull_requests(&self) -> Result<Vec<PullRequest>> {
        let mut pulls = Vec::new();
        for page in 1..=MAX_OPEN_PULL_REQUEST_PAGES {
            let path = if page == 1 {
                format!("pulls?state=open&per_page={OPEN_PULL_REQUEST_PAGE_SIZE}")
            } else {
                format!("pulls?state=open&per_page={OPEN_PULL_REQUEST_PAGE_SIZE}&page={page}")
            };
            let page_pulls: Vec<PullRequest> = self.get(&path).await?;
            if page_pulls.len() > OPEN_PULL_REQUEST_PAGE_SIZE {
                bail!("GitHub returned an oversized open pull-request page");
            }
            let complete = page_pulls.len() < OPEN_PULL_REQUEST_PAGE_SIZE;
            pulls.extend(page_pulls);
            if complete {
                return Ok(pulls);
            }
        }
        bail!("GitHub open pull-request search exceeded its bounded page limit")
    }

    /// Page of the GitHub Release for a tag, if one exists.
    pub async fn release_for_tag(&self, tag: &str) -> Result<Option<String>> {
        Ok(self
            .release_details_for_tag(tag)
            .await?
            .map(|release| release.html_url))
    }

    /// What a tag points at, and whether it is annotated.
    pub async fn tag_state(&self, tag: &str) -> Result<Option<GitHubTagState>> {
        let Some(reference) = self
            .get_optional::<GitReferenceResponse>(&format!("git/ref/tags/{}", encode_segment(tag)))
            .await?
        else {
            return Ok(None);
        };
        match reference.object.kind.as_str() {
            "commit" => Ok(Some(GitHubTagState {
                target_sha: reference.object.sha,
                annotated: false,
            })),
            "tag" => {
                let tag_object: GitTagObjectResponse = self
                    .get(&format!(
                        "git/tags/{}",
                        encode_segment(&reference.object.sha)
                    ))
                    .await?;
                if tag_object.object.kind != "commit" {
                    bail!("GitHub annotated tag does not directly target a commit");
                }
                Ok(Some(GitHubTagState {
                    target_sha: tag_object.object.sha,
                    annotated: true,
                }))
            }
            kind => bail!("GitHub tag ref has unsupported object type `{kind}`"),
        }
    }

    /// Create an annotated tag object and the ref that points at it.
    pub async fn create_annotated_tag(&self, tag: &str, sha: &str, message: &str) -> Result<()> {
        self.require_token()?;
        let object: GitTagObjectResponse = self
            .post(
                "git/tags",
                &serde_json::json!({
                    "tag": tag,
                    "message": message,
                    "object": sha,
                    "type": "commit"
                }),
            )
            .await?;
        if object.sha.is_empty() || object.object.kind != "commit" || object.object.sha != sha {
            bail!("GitHub created an unexpected annotated tag object");
        }
        self.post_empty(
            "git/refs",
            &serde_json::json!({
                "ref": format!("refs/tags/{tag}"),
                "sha": object.sha
            }),
        )
        .await
    }

    /// The full GitHub Release for a tag, if one exists, draft or published.
    ///
    /// GitHub's tag endpoint answers only with a published Release, so the lookup reads the release list, which shows drafts to a token that can write contents.
    /// Two Releases with the tag make the Candidate's Release ambiguous, which is a conflict.
    pub async fn release_details_for_tag(&self, tag: &str) -> Result<Option<GitHubRelease>> {
        let mut found = Vec::new();
        for page in 1..=MAX_RELEASE_PAGES {
            let releases: Vec<ReleaseResponse> = self
                .get(&format!(
                    "releases?per_page={RELEASE_PAGE_SIZE}&page={page}"
                ))
                .await?;
            if releases.len() > RELEASE_PAGE_SIZE {
                bail!("GitHub returned an oversized release page");
            }
            let complete = releases.len() < RELEASE_PAGE_SIZE;
            found.extend(
                releases
                    .into_iter()
                    .filter(|release| release.tag_name == tag),
            );
            if complete {
                return match found.len() {
                    0 | 1 => Ok(found.pop().map(Into::into)),
                    count => Err(crate::failure::classified(
                        crate::failure::FailureClass::ImmutableStateConflict,
                        format!(
                            "{count} GitHub Releases have the tag `{tag}`, so the Candidate's Release is ambiguous"
                        ),
                    )),
                };
            }
        }
        bail!("GitHub release search exceeded its bounded page limit")
    }

    /// Create the draft Release that later stages fill in.
    ///
    /// Assets are attached while the release is a draft, so consumers never see a published release that is still missing artifacts.
    pub async fn create_draft_release(
        &self,
        tag: &str,
        sha: &str,
        body: &str,
        candidate_digest: &str,
        prerelease: bool,
    ) -> Result<GitHubRelease> {
        self.require_token()?;
        let body = format!(
            "{}{}release-glz-candidate-digest: {candidate_digest}",
            body,
            if body.is_empty() { "" } else { "\n\n" }
        );
        let release: ReleaseResponse = self
            .post(
                "releases",
                &serde_json::json!({
                    "tag_name": tag,
                    "target_commitish": sha,
                    "name": tag,
                    "body": body,
                    "draft": true,
                    "prerelease": prerelease,
                    "generate_release_notes": false
                }),
            )
            .await?;
        Ok(release.into())
    }

    /// Publish a draft Release.
    pub async fn finalize_release(&self, id: u64) -> Result<GitHubRelease> {
        self.require_token()?;
        let release: ReleaseResponse = self
            .patch(
                &format!("releases/{id}"),
                &serde_json::json!({"draft": false}),
            )
            .await?;
        Ok(release.into())
    }

    /// Attach one asset to a draft Release.
    pub async fn upload_release_asset(
        &self,
        release: &GitHubRelease,
        name: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<GitHubReleaseAsset> {
        self.require_token()?;
        if !release.draft {
            bail!("GitHub Release assets may only be added to the sealed draft");
        }
        validate_release_asset_identity(name, media_type)?;
        let mut upload_url = validate_release_upload_url(
            &release.upload_url,
            &self.api_url,
            &self.repository,
            release.id,
        )?;
        upload_url.query_pairs_mut().append_pair("name", name);
        let url = upload_url.to_string();
        let response = checked(
            self.request(Method::POST, &url)
                .header(CONTENT_TYPE, media_type)
                .body(bytes.to_vec())
                .send()
                .await?,
            &url,
        )
        .await?;
        let uploaded: ReleaseAssetResponse = json_response(response, &url)
            .await
            .context("invalid GitHub release asset response")?;
        let uploaded: GitHubReleaseAsset = uploaded.into();
        let expected_sha256 = crate::hex::lower(&Sha256::digest(bytes));
        if uploaded.name != name
            || uploaded.state != "uploaded"
            || uploaded.media_type != media_type
            || uploaded.size != bytes.len() as u64
            || uploaded.sha256.as_deref() != Some(expected_sha256.as_str())
        {
            bail!("GitHub uploaded a Release asset with an unexpected immutable identity");
        }
        Ok(uploaded)
    }

    /// Delete the asset `name` that a failed upload left unfinished on the draft `release`, which the caller has just read.
    ///
    /// GitHub keeps the name of such an asset, so no upload can take the name until this call removes the asset.
    /// The call refuses an asset that GitHub reports as uploaded and every asset of a published Release.
    pub async fn delete_unfinished_release_asset(
        &self,
        release: &GitHubRelease,
        name: &str,
    ) -> Result<()> {
        self.require_token()?;
        if !release.draft {
            bail!(
                "GitHub Release asset `{name}` belongs to a published Release, which stays as it is"
            );
        }
        let mut found = release.assets.iter().filter(|asset| asset.name == name);
        let asset = match (found.next(), found.next()) {
            (Some(asset), None) => asset,
            (Some(_), Some(_)) => bail!("GitHub Release contains duplicate asset `{name}`"),
            (None, _) => bail!("GitHub Release has no asset `{name}` to delete"),
        };
        if asset.state == "uploaded" {
            bail!(
                "GitHub Release asset `{name}` is uploaded, and a release never deletes an uploaded asset"
            );
        }
        if asset.id == 0 {
            bail!("GitHub Release asset `{name}` has no id");
        }
        let url = self.url(&format!("releases/assets/{}", asset.id));
        checked(self.request(Method::DELETE, &url).send().await?, &url).await?;
        Ok(())
    }

    async fn create_ref(&self, branch: &str, sha: &str) -> Result<()> {
        self.post_empty(
            "git/refs",
            &serde_json::json!({"ref": format!("refs/heads/{branch}"), "sha": sha}),
        )
        .await
    }

    async fn ref_sha(&self, branch: &str) -> Result<Option<String>> {
        Ok(self
            .get_optional::<GitRefObject>(&format!("git/ref/heads/{}", encode_segment(branch)))
            .await?
            .map(|reference| reference.object.sha))
    }

    async fn create_commit(
        &self,
        branch: &str,
        parent: &str,
        plan: &ReleasePlan,
        files: &BTreeMap<String, Vec<u8>>,
    ) -> Result<String> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct GraphData {
            create_commit_on_branch: GraphCommitPayload,
        }
        #[derive(Deserialize)]
        struct GraphCommitPayload {
            commit: GraphCommit,
        }
        #[derive(Deserialize)]
        struct GraphCommit {
            oid: String,
        }

        let additions: Vec<_> = files
            .iter()
            .map(|(path, contents)| {
                serde_json::json!({
                    "path": path,
                    "contents": base64::engine::general_purpose::STANDARD.encode(contents)
                })
            })
            .collect();
        let digest = files_digest(files);
        let body = serde_json::json!({
            "query": "mutation CreateReleaseCommit($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid } } }",
            "variables": {
                "input": {
                    "branch": {
                        "repositoryNameWithOwner": self.repository.full_name(),
                        "branchName": branch
                    },
                    "message": {
                        "headline": format!("chore(release): {} {}", plan.package, plan.version),
                        "body": format!("Generated by release-glz.\n\nrelease-glz-digest: {digest}")
                    },
                    "expectedHeadOid": parent,
                    "fileChanges": {"additions": additions}
                }
            }
        });
        let data: GraphData = self
            .graphql("create verified release commit", &body)
            .await?;
        Ok(data.create_commit_on_branch.commit.oid)
    }

    /// Move `branch` from `from` back to the tip of `base`, refusing if it no longer points at `from`.
    ///
    /// The compare-and-swap keeps a commit that someone pushed after `from` was verified.
    async fn reset_branch(&self, base: &DefaultBranch, branch: &str, from: &str) -> Result<()> {
        self.update_ref("reset the Release PR branch", base, branch, from, &base.tip)
            .await
    }

    /// Move `branch` from `from` to `to`, where the null object ID deletes it, failing when the branch no longer holds `from`.
    async fn update_ref(
        &self,
        purpose: &str,
        base: &DefaultBranch,
        branch: &str,
        from: &str,
        to: &str,
    ) -> Result<()> {
        let body = serde_json::json!({
            "query": "mutation UpdateReleaseBranch($input: UpdateRefsInput!) { updateRefs(input: $input) { clientMutationId } }",
            "variables": {
                "input": {
                    "repositoryId": base.repository_id,
                    "refUpdates": [{
                        "name": format!("refs/heads/{branch}"),
                        "beforeOid": from,
                        "afterOid": to,
                        "force": true
                    }]
                }
            }
        });
        self.graphql::<serde_json::Value>(purpose, &body).await?;
        Ok(())
    }

    /// Run one GraphQL operation and return its data, refusing a response that reports any error.
    async fn graphql<T: DeserializeOwned>(
        &self,
        purpose: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        #[derive(Deserialize)]
        struct GraphResponse<T> {
            data: Option<T>,
            #[serde(default)]
            errors: Vec<GraphError>,
        }
        #[derive(Deserialize)]
        struct GraphError {
            message: String,
        }

        let response = self
            .request(Method::POST, &self.graphql_url)
            .json(body)
            .send()
            .await?;
        let status = response.status();
        let response: GraphResponse<T> = json_response(response, &self.graphql_url)
            .await
            .context("invalid GitHub GraphQL response")?;
        if !status.is_success() || !response.errors.is_empty() {
            let errors = response
                .errors
                .into_iter()
                .map(|error| error.message)
                .collect::<Vec<_>>()
                .join("; ");
            let errors = crate::secrets::redact(&errors);
            bail!("GitHub could not {purpose}: {errors}");
        }
        response.data.context("GitHub GraphQL response had no data")
    }

    /// The files digest of a commit with the shape that release-glz generates, or `None` for any other commit.
    async fn generated_commit_digest(&self, sha: &str) -> Result<Option<String>> {
        Ok(self
            .generated_commit(sha)
            .await?
            .map(|commit| commit.digest))
    }

    /// The digest and parent of a commit with the shape that release-glz generates, or `None` for any other commit.
    ///
    /// The check can't tell who made the commit, since anyone who can push can make one of this shape.
    /// A generated commit is server-verified and has exactly one parent, since a merge commit could bring in other work.
    /// It only adds or modifies files, and the files digest of their contents equals the digest its message records, so an amended commit that keeps the message doesn't count.
    /// A failure to read a file is an error rather than `None`, because `None` leads a caller to close the Release PR.
    async fn generated_commit(&self, sha: &str) -> Result<Option<GeneratedCommit>> {
        let commit: CommitResponse = self.get(&format!("commits/{sha}")).await?;
        let [parent] = commit.parents.as_slice() else {
            return Ok(None);
        };
        if !commit.commit.verification.verified {
            return Ok(None);
        }
        let Some(digest) = commit.commit.message.lines().find_map(|line| {
            line.strip_prefix("release-glz-digest: ")
                .filter(|digest| valid_sha256(digest))
        }) else {
            return Ok(None);
        };
        if commit.files.len() > MAX_GENERATED_FILES {
            return Ok(None);
        }
        let mut blobs = BTreeMap::new();
        for file in &commit.files {
            let blob = match (file.status.as_str(), file.sha.as_deref()) {
                ("added" | "modified", Some(blob)) if valid_object_id(blob) => blob,
                _ => return Ok(None),
            };
            if blobs.insert(file.filename.as_str(), blob).is_some() {
                return Ok(None);
            }
        }
        let mut files = BTreeMap::new();
        for (path, blob) in blobs {
            let contents = self.blob(blob).await?;
            if contents.len() > MAX_GENERATED_FILE_BYTES {
                return Ok(None);
            }
            files.insert(path.to_owned(), contents);
        }
        if files_digest(&files) != digest {
            return Ok(None);
        }
        Ok(Some(GeneratedCommit {
            digest: digest.to_owned(),
            parent: parent.sha.clone(),
        }))
    }

    /// The bytes of a blob, which GitHub sends as base64 broken into lines.
    async fn blob(&self, sha: &str) -> Result<Vec<u8>> {
        let blob: BlobResponse = self.get(&format!("git/blobs/{sha}")).await?;
        if blob.encoding != "base64" {
            bail!(
                "GitHub sent blob {sha} as `{}` instead of base64",
                blob.encoding
            );
        }
        let content = blob
            .content
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        base64::engine::general_purpose::STANDARD
            .decode(content)
            .with_context(|| format!("GitHub sent blob {sha} with invalid base64 content"))
    }

    fn require_token(&self) -> Result<()> {
        if self.token.is_none() {
            bail!("GITHUB_TOKEN or GH_TOKEN is required for this command");
        }
        Ok(())
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = self.url(path);
        let response = checked(self.get_response(&url).await?, &url).await?;
        json_response(response, &url).await
    }

    async fn get_optional<T: DeserializeOwned>(&self, path: &str) -> Result<Option<T>> {
        let url = self.url(path);
        let response = self.get_response(&url).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let response = checked(response, &url).await?;
        Ok(Some(json_response(response, &url).await?))
    }

    async fn get_response(&self, url: &str) -> Result<reqwest::Response> {
        let mut attempt = 0;
        loop {
            let (answer, got) = match self.request(Method::GET, url).send().await {
                Ok(response) if !retryable_status(response.status()) => return Ok(response),
                Ok(response) => {
                    let asked = retry_after(response.headers());
                    (Answer::Busy(asked), Ok(response))
                }
                Err(error) => (Answer::Unreachable, Err(error)),
            };
            // The core waits only while another attempt follows, so the loop ends within the policy's attempts.
            match GITHUB_READS.after(attempt, answer) {
                Next::Stop => return got.map_err(Into::into),
                Next::Retry(wait) => {
                    drop(got);
                    tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
                    attempt += 1;
                }
            }
        }
    }

    async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.send_json(Method::POST, path, Some(body)).await
    }

    async fn patch<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.send_json(Method::PATCH, path, Some(body)).await
    }

    async fn post_empty<B: Serialize + ?Sized>(&self, path: &str, body: &B) -> Result<()> {
        let _: serde_json::Value = self.send_json(Method::POST, path, Some(body)).await?;
        Ok(())
    }

    async fn patch_empty<B: Serialize + ?Sized>(&self, path: &str, body: &B) -> Result<()> {
        let _: serde_json::Value = self.send_json(Method::PATCH, path, Some(body)).await?;
        Ok(())
    }

    async fn send_json<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T> {
        let url = self.url(path);
        let mut request = self.request(method, &url);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = checked(request.send().await?, &url).await?;
        json_response(response, &url).await
    }

    fn request(&self, method: Method, url: &str) -> reqwest::RequestBuilder {
        let request = self
            .client
            .request(method, url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION);
        match &self.token {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }

    /// The API URL of `path` below the repository, or of the repository itself for an empty path.
    ///
    /// GitHub answers the repository URL with a trailing slash with 404.
    fn url(&self, path: &str) -> String {
        let repository = format!(
            "{}/repos/{}/{}",
            self.api_url, self.repository.owner, self.repository.name
        );
        match path.trim_start_matches('/') {
            "" => repository,
            path => format!("{repository}/{path}"),
        }
    }
}

fn validate_github_url(raw: &str) -> Result<()> {
    let url = reqwest::Url::parse(raw).context("invalid GitHub API URL")?;
    if url.host_str().is_none() || url.cannot_be_a_base() {
        bail!("GitHub API URL must be an absolute hierarchical URL");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("GitHub API URL must not contain a query or fragment");
    }
    let loopback = url_is_http_loopback(&url);
    if url.scheme() != "https" && !loopback {
        bail!("GitHub API URLs must use HTTPS (HTTP is test-only on loopback)");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("GitHub API URLs must not contain credentials");
    }
    Ok(())
}

fn validate_release_asset_identity(name: &str, media_type: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_ASSET_NAME_LEN
        || name == "."
        || name == ".."
        || name.contains(['/', '\\', '\n', '\r', '\0'])
    {
        bail!("GitHub Release asset name is unsafe");
    }
    if media_type.is_empty()
        || media_type.len() > MAX_MEDIA_TYPE_LEN
        || !media_type.contains('/')
        || !media_type
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
    {
        bail!("GitHub Release asset media type is invalid");
    }
    Ok(())
}

fn validate_release_upload_url(
    raw: &str,
    api_url: &str,
    repository: &GitHubRepository,
    release_id: u64,
) -> Result<reqwest::Url> {
    let raw = raw
        .strip_suffix("{?name,label}")
        .context("GitHub Release upload URL has an unexpected template")?;
    let url = reqwest::Url::parse(raw).context("invalid GitHub Release upload URL")?;
    validate_github_url(url.as_str())?;
    let api = reqwest::Url::parse(api_url).context("invalid configured GitHub API URL")?;
    let same_origin = url.scheme() == api.scheme()
        && url.host_str() == api.host_str()
        && url.port_or_known_default() == api.port_or_known_default();
    let github_upload_origin = api.scheme() == "https"
        && api.host_str() == Some("api.github.com")
        && url.scheme() == "https"
        && url.host_str() == Some("uploads.github.com")
        && url.port_or_known_default() == Some(HTTPS_PORT);
    if !same_origin && !github_upload_origin {
        bail!("GitHub Release upload URL has an untrusted origin");
    }
    let expected_path = format!(
        "/repos/{}/{}/releases/{release_id}/assets",
        repository.owner, repository.name
    );
    if url.path() != expected_path {
        bail!("GitHub Release upload URL does not match the sealed repository and release");
    }
    Ok(url)
}

async fn checked(response: reqwest::Response, url: &str) -> Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = match read_limited(response, MAX_GITHUB_ERROR_BYTES).await {
        Ok(bytes) => crate::secrets::redact(&String::from_utf8_lossy(&bytes)),
        Err(_) => "[response omitted: size limit exceeded]".into(),
    };
    bail!("GitHub request to {url} failed with {status}: {body}")
}

async fn json_response<T: DeserializeOwned>(response: reqwest::Response, url: &str) -> Result<T> {
    let bytes = read_limited(response, MAX_GITHUB_JSON_BYTES)
        .await
        .with_context(|| format!("GitHub response from {url} exceeded its size limit"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid GitHub response from {url}"))
}

async fn read_limited(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        bail!("response size limit exceeded");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            bail!("response size limit exceeded");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// The seconds that a busy response's `Retry-After` header asks the read to wait, when it names them in digits.
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| release_glz_core::delay_seconds(value.as_bytes()))
}

fn retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

/// The change entry of a commit that no merged pull request describes.
fn commit_change(commit: &Commit) -> ChangeEntry {
    ChangeEntry {
        category: default_category(&commit.subject),
        title: commit.subject.clone(),
        pull_request: None,
        author: Some(commit.author_name.clone()),
        url: None,
        labels: vec![],
    }
}

/// The digest that a Release PR commit and its marker record for the files the commit writes.
///
/// A domain tag starts the input, and a length precedes every path and every content, so two different file sets never hash the same bytes.
pub fn files_digest(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut digest = Sha256::new();
    digest.update(release_glz_core::FILES_DOMAIN);
    for (path, contents) in files {
        release_glz_core::frame_file(path.as_bytes(), contents, |part| digest.update(part));
    }
    crate::hex::lower(&digest.finalize())
}

/// Text from a commit or a package interface, made unable to open an HTML comment or tag.
fn inert_text(text: &str) -> String {
    let mut inert = Vec::with_capacity(text.len());
    release_glz_core::write_inert(text.as_bytes(), |part| inert.extend_from_slice(part));
    // The core splits the text only at `<`, so the bytes stay UTF-8.
    String::from_utf8_lossy(&inert).into_owned()
}

fn pull_body(plan: &ReleasePlan, marker: &ManagedMarker) -> Result<String> {
    let mut output = format!(
        "This rolling Release PR prepares `{}` **{}**.\n\n### Release decision\n\n",
        plan.package, plan.version
    );
    for reason in &plan.reasons {
        output.push_str(&format!(
            "- **{}**: {}\n",
            bump_name(reason.bump),
            inert_text(&reason.summary)
        ));
    }
    let breaking: Vec<_> = plan
        .api
        .changes
        .iter()
        .filter(|change| change.breaking)
        .collect();
    if !breaking.is_empty() {
        output.push_str("\n### Breaking API changes\n\n");
        for change in breaking {
            output.push_str(&format!("- {}\n", inert_text(&change.summary)));
        }
    }
    output.push_str(
        "\nMerging this PR approves the semantic `intent_digest`. Publication still requires separate protected Environment approval of the sealed `candidate_digest`.\n\n",
    );
    output.push_str(&format_marker(marker));
    if parse_marker(&output).as_ref() != Some(marker) {
        bail!("the rendered Release PR body does not carry exactly its own marker");
    }
    Ok(output)
}

fn format_marker(marker: &ManagedMarker) -> String {
    let intent = marker.intent_digest.as_deref().unwrap_or(PENDING_INTENT);
    let mut bytes = Vec::new();
    release_glz_core::write_marker(
        [
            marker.package.as_bytes(),
            marker.branch.as_bytes(),
            marker.head.as_bytes(),
            marker.digest.as_bytes(),
            marker.version.as_bytes(),
            intent.as_bytes(),
        ],
        |part| bytes.extend_from_slice(part),
    );
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Byte offset of the one marker that ends a body, if the body has exactly one there.
///
/// Trailing whitespace counts for nothing, so the core searches the trimmed body.
fn trailing_marker_start(body: &str) -> Option<usize> {
    release_glz_core::marker_start(body.trim_end().as_bytes())
}

fn parse_marker(body: &str) -> Option<ManagedMarker> {
    let start = trailing_marker_start(body)? + MARKER_PREFIX.len();
    let fields = body.trim_end()[start..].strip_suffix(MARKER_SUFFIX)?;
    let values = release_glz_core::marker_values(fields.split_whitespace().map(str::as_bytes))?;
    let [package, branch, head, digest, version, intent] =
        values.map(|value| std::str::from_utf8(value).ok());
    let (package, branch, head, digest, version, intent) =
        (package?, branch?, head?, digest?, version?, intent?);
    let valid = crate::config::validate_package_name(package).is_ok()
        && !branch.is_empty()
        && valid_object_id(head)
        && valid_sha256(digest)
        && version.parse::<Version>().is_ok()
        && (intent == PENDING_INTENT || valid_sha256(intent));
    valid.then(|| ManagedMarker {
        package: package.to_owned(),
        branch: branch.to_owned(),
        head: head.to_owned(),
        digest: digest.to_owned(),
        version: version.to_owned(),
        intent_digest: (intent != PENDING_INTENT).then(|| intent.to_owned()),
    })
}

/// Parse the managed Release PR marker without exposing its internal fields.
///
/// This entry point also gives fuzzing and callers a bounded, side-effect-free way to exercise the exact parser used by the GitHub adapter.
pub fn is_managed_release_pr(body: &str) -> bool {
    parse_marker(body).is_some()
}

fn parse_candidate_digest(body: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let digest = line.trim().strip_prefix("release-glz-candidate-digest: ")?;
        valid_sha256(digest).then(|| digest.to_owned())
    })
}

fn replace_managed_marker(body: &str, marker: &ManagedMarker) -> Result<String> {
    let start = trailing_marker_start(body)
        .context("managed Release PR body does not end in exactly one marker")?;
    let output = format!("{}{}", &body[..start], format_marker(marker));
    if parse_marker(&output).as_ref() != Some(marker) {
        bail!("the updated Release PR body does not carry exactly its own marker");
    }
    Ok(output)
}

fn valid_sha256(value: &str) -> bool {
    release_glz_core::is_sha256_hex(value.as_bytes())
}

fn valid_object_id(value: &str) -> bool {
    release_glz_core::is_object_id(value.as_bytes())
}

fn encode_segment(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(&mut output, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ApiChange, ApiChangeKind, ApiDiff, ApiStatus, Baseline, BaselineSource, Bump,
        ReleaseReason, ReleaseState,
    };
    fn marker(intent_digest: Option<String>) -> ManagedMarker {
        ManagedMarker {
            package: "widget".into(),
            branch: "release-glz/widget".into(),
            head: "b".repeat(40),
            digest: "c".repeat(64),
            version: "2.0.0".into(),
            intent_digest,
        }
    }

    /// A `Retry-After` header names a wait only in digits, so a sign or a date leaves the read's default wait.
    #[test]
    fn a_busy_read_waits_only_as_long_as_digits_ask() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert_eq!(retry_after(&headers), None);
        for (value, asked) in [
            ("5", Some(5)),
            ("0", Some(0)),
            ("+5", None),
            ("-5", None),
            ("Wed, 21 Oct 2015 07:28:00 GMT", None),
        ] {
            headers.insert(RETRY_AFTER, value.parse().unwrap());
            assert_eq!(retry_after(&headers), asked, "{value}");
        }
    }

    #[test]
    fn managed_marker_round_trips() {
        for intent in [None, Some("1".repeat(64))] {
            let marker = marker(intent);
            assert_eq!(parse_marker(&format_marker(&marker)), Some(marker));
        }
        // Bodies that earlier releases wrote carry this exact text, so the format can't drift unnoticed.
        assert_eq!(
            format_marker(&marker(None)),
            format!(
                "<!-- release-glz:managed package=widget branch=release-glz/widget head={} digest={} version=2.0.0 intent=pending -->",
                "b".repeat(40),
                "c".repeat(64)
            )
        );
    }

    #[test]
    fn replacing_the_marker_keeps_the_body_and_its_single_marker() {
        let body = format!("Release notes\n\n{}\n", format_marker(&marker(None)));
        let bound = marker(Some("1".repeat(64)));
        let replaced = replace_managed_marker(&body, &bound).unwrap();
        assert!(replaced.starts_with("Release notes\n\n"));
        assert_eq!(parse_marker(&replaced), Some(bound));
        assert!(replace_managed_marker("no marker", &marker(None)).is_err());
    }

    #[test]
    fn tag_and_branch_names_are_safe_url_segments() {
        assert_eq!(encode_segment("package/v1.0.0"), "package%2Fv1.0.0");
    }

    #[test]
    fn release_pr_explains_that_merge_approves_intent_not_publication_bytes() {
        let plan = ReleasePlan {
            schema: ReleasePlan::SCHEMA.into(),
            state: ReleaseState::Planned,
            package: "widget".into(),
            manifest_path: "gleam.toml".into(),
            published_version: Some(Version::new(1, 0, 0)),
            manifest_version: Version::new(2, 0, 0),
            version: Version::new(2, 0, 0),
            bump: Bump::Major,
            release_required: true,
            artifacts_changed: true,
            prerelease: None,
            tag: "v2.0.0".into(),
            baseline: Baseline {
                version: Some(Version::new(1, 0, 0)),
                git_ref: Some("v1.0.0".into()),
                sha: Some("a".repeat(40)),
                source: BaselineSource::Tag,
                retired: false,
            },
            reasons: vec![ReleaseReason {
                kind: crate::model::ReasonKind::ApiBreaking,
                bump: Bump::Major,
                summary: "removed widget.old".into(),
            }],
            api: ApiDiff {
                status: ApiStatus::Changed,
                impact: Bump::Major,
                changes: vec![ApiChange {
                    kind: ApiChangeKind::Removed,
                    path: "widget::function old".into(),
                    breaking: true,
                    summary: "removed widget.old".into(),
                }],
            },
            changes: vec![],
            warnings: vec![],
            required_approvals: vec![],
            stages: vec![],
            pr_url: None,
            release_pr_head: None,
            hex_url: None,
            github_release_url: None,
        };
        let body = pull_body(&plan, &marker(None)).unwrap();
        assert!(body.contains("Breaking API changes"));
        assert!(body.contains("intent_digest"));
        assert!(body.contains("Environment"));
        assert!(!body.contains("approval to publish to Hex"));
        assert_eq!(body.matches("removed widget.old").count(), 2);

        let injected = format_marker(&marker(Some("e".repeat(64))));
        let mut hostile = plan.clone();
        hostile.reasons[0].summary = format!("feat: {injected}");
        hostile.api.changes[0].summary = injected;
        let body = pull_body(&hostile, &marker(None)).unwrap();
        assert_eq!(parse_marker(&body), Some(marker(None)));
        assert_eq!(body.matches(MARKER_PREFIX).count(), 1);
        // The commit text stays in the body, with each `<` written as `&lt;`.
        assert!(body.contains("feat: &lt;!-- release-glz:managed package="));
        assert_eq!(body.matches("&lt;!-- release-glz:managed ").count(), 2);
    }
}
