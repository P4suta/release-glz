use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use base64::Engine;
use chrono::Utc;
use reqwest::{
    Method, StatusCode,
    header::{CONTENT_TYPE, RETRY_AFTER},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

use crate::changelog::default_category;
use crate::config::url_is_http_loopback;
use crate::git::Commit;
use crate::model::{ChangeEntry, ReleasePlan};

const MAX_GITHUB_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_GITHUB_ERROR_BYTES: usize = 64 * 1024;
const GITHUB_GET_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubRepository {
    pub owner: String,
    pub name: String,
}

impl GitHubRepository {
    pub fn parse(value: &str) -> Result<Self> {
        let (owner, name) = value
            .split_once('/')
            .context("GitHub repository must be `owner/name`")?;
        let owner_valid = (1..=39).contains(&owner.len())
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
        let name_valid = (1..=100).contains(&name.len())
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

    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

#[derive(Clone)]
pub struct GitHubClient {
    client: reqwest::Client,
    token: Option<String>,
    api_url: String,
    graphql_url: String,
    pub repository: GitHubRepository,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PullRequest {
    pub number: u64,
    pub title: String,
    pub body: Option<String>,
    pub html_url: String,
    pub merge_commit_sha: Option<String>,
    pub merged_at: Option<String>,
    pub user: User,
    #[serde(default)]
    pub labels: Vec<Label>,
    pub head: PullHead,
}

#[derive(Debug, Clone, Deserialize)]
pub struct User {
    pub login: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Label {
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PullHead {
    #[serde(rename = "ref")]
    pub branch: String,
    pub sha: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubRelease {
    pub id: u64,
    pub html_url: String,
    pub tag_name: String,
    pub target_commitish: String,
    pub candidate_digest: Option<String>,
    pub draft: bool,
    pub upload_url: String,
    pub assets: Vec<GitHubReleaseAsset>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubReleaseAsset {
    pub id: u64,
    pub name: String,
    pub state: String,
    pub media_type: String,
    pub size: u64,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GitHubEnvironmentAudit {
    pub private_repository: bool,
    pub plan: Option<String>,
    pub default_branch: String,
    pub default_branch_protected: bool,
    pub required_reviewers: usize,
    pub prevent_self_review: bool,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedActionsArtifact {
    id: u64,
    sha256: String,
    run_id: String,
    source_sha: String,
}

impl VerifiedActionsArtifact {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn source_sha(&self) -> &str {
        &self.source_sha
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubTagState {
    pub target_sha: String,
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
                .filter(|digest| {
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                })
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
struct GitCommitResponse {
    message: String,
    verification: CommitVerification,
}

#[derive(Debug, Clone, Deserialize)]
struct CommitVerification {
    verified: bool,
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
    pub fn new(
        repository: GitHubRepository,
        api_url: String,
        graphql_url: String,
        token: Option<String>,
    ) -> Result<Self> {
        validate_github_url(&api_url)?;
        validate_github_url(&graphql_url)?;
        Ok(Self {
            client: reqwest::Client::builder()
                .user_agent(concat!("release-glz/", env!("CARGO_PKG_VERSION")))
                .connect_timeout(std::time::Duration::from_secs(10))
                .timeout(std::time::Duration::from_secs(60))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            token,
            api_url: api_url.trim_end_matches('/').to_owned(),
            graphql_url,
            repository,
        })
    }

    pub fn from_environment(repository: GitHubRepository) -> Self {
        let token = std::env::var("GITHUB_TOKEN")
            .or_else(|_| std::env::var("GH_TOKEN"))
            .ok();
        let api_url =
            std::env::var("GITHUB_API_URL").unwrap_or_else(|_| "https://api.github.com".into());
        let graphql_url = std::env::var("GITHUB_GRAPHQL_URL")
            .unwrap_or_else(|_| "https://api.github.com/graphql".into());
        Self::new(repository, api_url, graphql_url, token)
            .expect("valid GitHub API environment URLs")
    }

    pub async fn changes_for_commits(&self, commits: &[Commit]) -> Result<Vec<ChangeEntry>> {
        let mut seen = BTreeSet::new();
        let mut output = Vec::new();
        for commit in commits {
            let path = format!("commits/{}/pulls", commit.sha);
            let pulls: Vec<PullRequest> = self.get(&path).await.unwrap_or_default();
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
                output.push(ChangeEntry {
                    category: default_category(&commit.subject),
                    title: commit.subject.clone(),
                    pull_request: None,
                    author: Some(commit.author_name.clone()),
                    url: None,
                    labels: vec![],
                });
            }
        }
        Ok(output)
    }

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

    pub async fn verify_actions_artifact(
        &self,
        artifact_id: u64,
        expected_sha256: &str,
        expected_run_id: &str,
        expected_source_sha: &str,
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
            || artifact.name != format!("release-glz-candidate-{expected_run_id}")
            || artifact.size_in_bytes == 0
            || artifact.size_in_bytes > 1024 * 1024 * 1024
            || artifact.digest != format!("sha256:{expected_sha256}")
            || artifact.workflow_run.id != expected_run_number
            || artifact.workflow_run.head_sha != expected_source_sha
        {
            bail!(
                "GitHub Actions Candidate artifact does not match its sealed run, source, and digest"
            );
        }
        Ok(VerifiedActionsArtifact {
            id: artifact.id,
            sha256: expected_sha256.to_owned(),
            run_id: expected_run_id.to_owned(),
            source_sha: expected_source_sha.to_owned(),
        })
    }

    pub async fn upsert_release_pr(
        &self,
        plan: &ReleasePlan,
        base: &str,
        branch_prefix: &str,
        files: &BTreeMap<String, Vec<u8>>,
    ) -> Result<String> {
        self.require_token()?;
        let digest = files_digest(files);
        let pulls: Vec<PullRequest> = self.get("pulls?state=open&per_page=100").await?;
        let mut managed = pulls.into_iter().find(|pull| {
            pull.body
                .as_deref()
                .and_then(parse_marker)
                .is_some_and(|marker| marker.package == plan.package)
        });

        if let Some(pull) = managed.as_ref()
            && let Some(marker) = pull.body.as_deref().and_then(parse_marker)
        {
            let actual = self.ref_sha(&marker.branch).await?;
            if actual.as_deref() != Some(&marker.head) {
                let generated_digest = match actual.as_deref() {
                    Some(actual) => self.generated_commit_digest(actual).await?,
                    None => None,
                };
                if generated_digest.as_deref() == Some(&digest) {
                    // The verified commit succeeded but updating the PR body
                    // failed. Repair the marker without creating another commit.
                    let actual = actual.expect("digest requires a commit");
                    let body = pull_body(
                        plan,
                        &ManagedMarker {
                            package: plan.package.clone(),
                            branch: marker.branch,
                            head: actual,
                            digest: digest.clone(),
                            version: plan.version.to_string(),
                            intent_digest: marker.intent_digest,
                        },
                    );
                    let updated: PullRequest = self
                        .patch(
                            &format!("pulls/{}", pull.number),
                            &serde_json::json!({
                                "title": format!("chore(release): {} {}", plan.package, plan.version),
                                "body": body
                            }),
                        )
                        .await?;
                    return Ok(updated.html_url);
                } else if generated_digest.is_none() {
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
            } else if marker.digest == digest && marker.version == plan.version.to_string() {
                return Ok(pull.html_url.clone());
            }
        }

        let branch = if let Some(pull) = managed.as_ref() {
            pull.head.branch.clone()
        } else {
            let desired = format!("{branch_prefix}{}", plan.package);
            if self.ref_sha(&desired).await?.is_some() {
                format!("{desired}-{}", Utc::now().timestamp())
            } else {
                desired
            }
        };

        let parent = if let Some(sha) = self.ref_sha(&branch).await? {
            sha
        } else {
            let base_sha = self
                .ref_sha(base)
                .await?
                .with_context(|| format!("GitHub branch `{base}` does not exist"))?;
            self.create_ref(&branch, &base_sha).await?;
            base_sha
        };
        let head = self.create_commit(&branch, &parent, plan, files).await?;
        let body = pull_body(
            plan,
            &ManagedMarker {
                package: plan.package.clone(),
                branch: branch.clone(),
                head,
                digest,
                version: plan.version.to_string(),
                intent_digest: None,
            },
        );
        let title = format!("chore(release): {} {}", plan.package, plan.version);

        if let Some(pull) = managed {
            let updated: PullRequest = self
                .patch(
                    &format!("pulls/{}", pull.number),
                    &serde_json::json!({"title": title, "body": body}),
                )
                .await?;
            Ok(updated.html_url)
        } else {
            let created: PullRequest = self
                .post(
                    "pulls",
                    &serde_json::json!({
                        "title": title,
                        "head": branch,
                        "base": base,
                        "body": body,
                        "maintainer_can_modify": false
                    }),
                )
                .await?;
            Ok(created.html_url)
        }
    }

    pub async fn close_managed_release_pr(
        &self,
        package: &str,
        branch_prefix: &str,
    ) -> Result<bool> {
        self.require_token()?;
        let pulls: Vec<PullRequest> = self.get("pulls?state=open&per_page=100").await?;
        for pull in pulls {
            let Some(marker) = pull.body.as_deref().and_then(parse_marker) else {
                continue;
            };
            if marker.package != package
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
            self.patch_empty(
                &format!("pulls/{}", pull.number),
                &serde_json::json!({"state": "closed"}),
            )
            .await?;
            self.delete_empty(&format!(
                "git/refs/heads/{}",
                encode_segment(&marker.branch)
            ))
            .await?;
            return Ok(true);
        }
        Ok(false)
    }

    pub async fn merged_release_pr_for_head(
        &self,
        sha: &str,
        package: &str,
        version: &str,
        branch_prefix: &str,
        intent_digest: &str,
    ) -> Result<Option<PullRequest>> {
        let pulls: Vec<PullRequest> = self.get(&format!("commits/{sha}/pulls")).await?;
        for pull in pulls {
            let Some(marker) = pull.body.as_deref().and_then(parse_marker) else {
                continue;
            };
            let structurally_valid = pull.merged_at.is_some()
                && pull.merge_commit_sha.as_deref() == Some(sha)
                && marker.package == package
                && marker.version == version
                && marker.branch == pull.head.branch
                && marker.head == pull.head.sha
                && pull.head.branch.starts_with(branch_prefix)
                && marker.intent_digest.as_deref() == Some(intent_digest);
            if !structurally_valid {
                continue;
            }
            let verified_digest = self.generated_commit_digest(&pull.head.sha).await?;
            if verified_digest.as_deref() == Some(marker.digest.as_str()) {
                return Ok(Some(pull));
            }
        }
        Ok(None)
    }

    pub async fn bind_release_pr_intent(
        &self,
        head_sha: &str,
        package: &str,
        version: &str,
        branch_prefix: &str,
        intent_digest: &str,
    ) -> Result<String> {
        self.require_token()?;
        if !valid_sha256(intent_digest) {
            bail!("Candidate intent digest is not a lowercase SHA-256 digest");
        }
        let pulls: Vec<PullRequest> = self.get("pulls?state=open&per_page=100").await?;
        for pull in pulls {
            let Some(mut marker) = pull.body.as_deref().and_then(parse_marker) else {
                continue;
            };
            let structurally_valid = marker.package == package
                && marker.version == version
                && marker.branch == pull.head.branch
                && marker.head == pull.head.sha
                && marker.head == head_sha
                && pull.head.branch.starts_with(branch_prefix)
                && pull.merged_at.is_none()
                && pull.merge_commit_sha.is_none();
            if !structurally_valid {
                continue;
            }
            if self.generated_commit_digest(head_sha).await?.as_deref()
                != Some(marker.digest.as_str())
            {
                bail!("managed Release PR head is not the server-verified generated commit");
            }
            if let Some(existing) = &marker.intent_digest {
                if existing == intent_digest {
                    return Ok(pull.html_url);
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
            let updated: PullRequest = self
                .patch(
                    &format!("pulls/{}", pull.number),
                    &serde_json::json!({"body": body}),
                )
                .await?;
            return Ok(updated.html_url);
        }
        bail!("no matching open verified managed Release PR exists for this Candidate")
    }

    pub async fn release_for_tag(&self, tag: &str) -> Result<Option<String>> {
        Ok(self
            .release_details_for_tag(tag)
            .await?
            .map(|release| release.html_url))
    }

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

    pub async fn release_details_for_tag(&self, tag: &str) -> Result<Option<GitHubRelease>> {
        Ok(self
            .get_optional::<ReleaseResponse>(&format!("releases/tags/{}", encode_segment(tag)))
            .await?
            .map(Into::into))
    }

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
        let expected_sha256 = format!("{:x}", Sha256::digest(bytes));
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

    pub async fn create_release(
        &self,
        tag: &str,
        sha: &str,
        body: &str,
        prerelease: bool,
    ) -> Result<String> {
        self.require_token()?;
        let release: ReleaseResponse = self
            .post(
                "releases",
                &serde_json::json!({
                    "tag_name": tag,
                    "target_commitish": sha,
                    "name": tag,
                    "body": body,
                    "draft": false,
                    "prerelease": prerelease,
                    "generate_release_notes": false
                }),
            )
            .await?;
        Ok(release.html_url)
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
        struct GraphResponse {
            data: Option<GraphData>,
            #[serde(default)]
            errors: Vec<GraphError>,
        }
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
        #[derive(Deserialize)]
        struct GraphError {
            message: String,
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
        let response = self
            .request(Method::POST, &self.graphql_url)
            .json(&body)
            .send()
            .await?;
        let status = response.status();
        let response: GraphResponse = json_response(response, &self.graphql_url)
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
            bail!("GitHub could not create verified release commit: {errors}");
        }
        Ok(response
            .data
            .context("GitHub GraphQL response had no data")?
            .create_commit_on_branch
            .commit
            .oid)
    }

    async fn generated_commit_digest(&self, sha: &str) -> Result<Option<String>> {
        let commit: GitCommitResponse = self.get(&format!("git/commits/{sha}")).await?;
        if !commit.verification.verified {
            return Ok(None);
        }
        Ok(commit.message.lines().find_map(|line| {
            line.strip_prefix("release-glz-digest: ")
                .filter(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                .map(str::to_owned)
        }))
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
        for attempt in 0..GITHUB_GET_ATTEMPTS {
            let response = self.request(Method::GET, url).send().await?;
            if !retryable_status(response.status()) || attempt + 1 == GITHUB_GET_ATTEMPTS {
                return Ok(response);
            }
            let delay = response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(1_u64 << attempt)
                .min(30);
            drop(response);
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        }
        unreachable!("GitHub GET retry loop always returns")
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

    async fn delete_empty(&self, path: &str) -> Result<()> {
        let url = self.url(path);
        checked(self.request(Method::DELETE, &url).send().await?, &url).await?;
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
            .header("X-GitHub-Api-Version", "2026-03-10");
        match &self.token {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/repos/{}/{}/{}",
            self.api_url,
            self.repository.owner,
            self.repository.name,
            path.trim_start_matches('/')
        )
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
        || name.len() > 256
        || name == "."
        || name == ".."
        || name.contains(['/', '\\', '\n', '\r', '\0'])
    {
        bail!("GitHub Release asset name is unsafe");
    }
    if media_type.is_empty()
        || media_type.len() > 128
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
        && url.port_or_known_default() == Some(443);
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

fn files_digest(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut digest = Sha256::new();
    for (path, contents) in files {
        digest.update(path.as_bytes());
        digest.update([0]);
        digest.update(contents);
    }
    format!("{:x}", digest.finalize())
}

fn pull_body(plan: &ReleasePlan, marker: &ManagedMarker) -> String {
    let mut output = format!(
        "This rolling Release PR prepares `{}` **{}**.\n\n### Release decision\n\n",
        plan.package, plan.version
    );
    for reason in &plan.reasons {
        output.push_str(&format!("- **{}**: {}\n", reason.bump, reason.summary));
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
            output.push_str(&format!("- {}\n", change.summary));
        }
    }
    output.push_str(
        "\nMerging this PR approves the semantic `intent_digest`. Publication still requires separate protected Environment approval of the sealed `candidate_digest`.\n\n",
    );
    output.push_str(&format_marker(marker));
    output
}

fn format_marker(marker: &ManagedMarker) -> String {
    format!(
        "<!-- release-glz:managed package={} branch={} head={} digest={} version={} intent={} -->",
        marker.package,
        marker.branch,
        marker.head,
        marker.digest,
        marker.version,
        marker.intent_digest.as_deref().unwrap_or("pending")
    )
}

fn parse_marker(body: &str) -> Option<ManagedMarker> {
    let start = body.find("<!-- release-glz:managed ")? + "<!-- release-glz:managed ".len();
    let end = body[start..].find(" -->")? + start;
    let values: BTreeMap<_, _> = body[start..end]
        .split_whitespace()
        .filter_map(|part| part.split_once('='))
        .collect();
    Some(ManagedMarker {
        package: (*values.get("package")?).to_owned(),
        branch: (*values.get("branch")?).to_owned(),
        head: (*values.get("head")?).to_owned(),
        digest: (*values.get("digest")?).to_owned(),
        version: (*values.get("version")?).to_owned(),
        intent_digest: values
            .get("intent")
            .copied()
            .filter(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
            .map(str::to_owned),
    })
}

/// Parse the managed Release PR marker without exposing its internal fields.
///
/// This entry point also gives fuzzing and callers a bounded, side-effect-free
/// way to exercise the exact parser used by the GitHub adapter.
pub fn is_managed_release_pr(body: &str) -> bool {
    parse_marker(body).is_some()
}

fn parse_candidate_digest(body: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let digest = line.trim().strip_prefix("release-glz-candidate-digest: ")?;
        (digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
        .then(|| digest.to_owned())
    })
}

fn replace_managed_marker(body: &str, marker: &ManagedMarker) -> Result<String> {
    let start = body
        .find("<!-- release-glz:managed ")
        .context("managed Release PR marker is missing")?;
    let end = body[start..]
        .find(" -->")
        .map(|offset| start + offset + " -->".len())
        .context("managed Release PR marker is incomplete")?;
    let mut output = body.to_owned();
    output.replace_range(start..end, &format_marker(marker));
    Ok(output)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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
    use semver::Version;

    #[test]
    fn managed_marker_round_trips() {
        let marker = ManagedMarker {
            package: "one".into(),
            branch: "release-glz/one".into(),
            head: "abc".into(),
            digest: "def".into(),
            version: "1.2.3".into(),
            intent_digest: Some("1".repeat(64)),
        };
        assert_eq!(parse_marker(&format_marker(&marker)), Some(marker));
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
            intent_digest: None,
            pr_url: None,
            hex_url: None,
            github_release_url: None,
        };
        let body = pull_body(
            &plan,
            &ManagedMarker {
                package: "widget".into(),
                branch: "release-glz/widget".into(),
                head: "b".repeat(40),
                digest: "c".repeat(64),
                version: "2.0.0".into(),
                intent_digest: None,
            },
        );
        assert!(body.contains("Breaking API changes"));
        assert!(body.contains("intent_digest"));
        assert!(body.contains("Environment"));
        assert!(!body.contains("approval to publish to Hex"));
    }
}
