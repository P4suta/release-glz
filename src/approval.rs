//! The approval a publication runs under, gathered from what GitHub verified.
//!
//! The publishing job's environment names the objects to check, and each value in the evidence comes from the answer to one of those checks.

use anyhow::{Context, Result};

use crate::authorization::{GithubOidcVerifier, OidcExpectation};
use crate::candidate::CandidateManifest;
use crate::forge::{CandidateRun, GitHubClient};
use crate::reconciler::ApprovalEvidence;
use crate::workflow::WORKFLOW_PATH;

/// What the publishing job's environment names for its approval.
///
/// None of these values approves anything by itself, because [`verify_approval`] checks each object they name with GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// Where the runner mints this job's OIDC token.
    pub oidc_request_url: String,
    /// The bearer token for that request.
    pub oidc_request_token: String,
    /// The publishing run.
    pub run_id: String,
    /// The Actions artifact that holds the Candidate.
    pub artifact_id: u64,
    /// Digest of that artifact, with or without its `sha256:` prefix.
    pub artifact_digest: String,
    /// The run that uploaded the artifact.
    pub artifact_run_id: String,
    /// Candidate digest that the dispatcher of a manual release named, or that the preparing job of a push sealed.
    pub approved_candidate_digest: Option<String>,
    /// Source commit that a manual release names.
    pub manual_source_sha: Option<String>,
    /// Reason that a manual release gives.
    pub manual_reason: Option<String>,
}

impl ApprovalRequest {
    /// The request that the generated publish job passes through its environment.
    pub fn from_environment() -> Result<Self> {
        Self::from_variables(|name| std::env::var(name).ok())
    }

    /// The request that `variable` describes, using the names of the generated publish job.
    pub fn from_variables(variable: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let required = |name: &str, purpose: &str| {
            variable(name).with_context(|| format!("release approval requires {purpose}"))
        };
        Ok(Self {
            oidc_request_url: required(
                "ACTIONS_ID_TOKEN_REQUEST_URL",
                "GitHub Actions OIDC request URL",
            )?,
            oidc_request_token: required(
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                "GitHub Actions OIDC request token",
            )?,
            run_id: required("GITHUB_RUN_ID", "the GitHub Actions run ID")?,
            artifact_id: required(
                "RELEASE_GLZ_ACTIONS_ARTIFACT_ID",
                "the immutable Actions artifact ID",
            )?
            .parse()
            .context("release approval Actions artifact ID is invalid")?,
            artifact_digest: required(
                "RELEASE_GLZ_ACTIONS_ARTIFACT_DIGEST",
                "the Actions artifact digest",
            )?,
            artifact_run_id: required(
                "RELEASE_GLZ_ACTIONS_RUN_ID",
                "the Candidate-generating Actions run ID",
            )?,
            approved_candidate_digest: variable("RELEASE_GLZ_APPROVED_CANDIDATE_DIGEST"),
            manual_source_sha: variable("RELEASE_GLZ_MANUAL_SOURCE_SHA"),
            manual_reason: variable("RELEASE_GLZ_MANUAL_REASON"),
        })
    }
}

/// Check every object that `request` names, and return the approval evidence that those checks found.
///
/// The OIDC token proves the repository, workflow, Environment, event, and commit of the publishing run.
/// The Actions artifact check proves which run uploaded the Candidate.
/// For a push, the intent digest is the one that the merged Release PR's marker recorded, as GitHub returns that pull request for the source commit.
/// A manual release has no Release PR, so its intent digest is the verified Candidate's own.
pub async fn verify_approval(
    manifest: &CandidateManifest,
    request: &ApprovalRequest,
    oidc: &GithubOidcVerifier,
    github: &GitHubClient,
    now_unix_seconds: i64,
) -> Result<ApprovalEvidence> {
    let expected = OidcExpectation {
        repository: manifest.github_repository.clone(),
        environment: manifest.approval.environment.clone(),
        workflow_path: WORKFLOW_PATH.into(),
        source_sha: manifest.source.commit_sha.clone(),
        run_id: Some(request.run_id.clone()),
    };
    let github_oidc = oidc
        .verify_actions_token(
            &request.oidc_request_url,
            &request.oidc_request_token,
            &expected,
            now_unix_seconds,
        )
        .await
        .context("release approval OIDC verification failed")?;
    let candidate_run = CandidateRun::for_event(
        github_oidc.event_name(),
        github_oidc.run_id(),
        &request.artifact_run_id,
    )?;
    let artifact_digest = request
        .artifact_digest
        .strip_prefix("sha256:")
        .unwrap_or(&request.artifact_digest);
    github
        .verify_actions_artifact(
            request.artifact_id,
            artifact_digest,
            &request.artifact_run_id,
            &manifest.source.commit_sha,
            candidate_run,
        )
        .await
        .context("release approval Actions artifact verification failed")?;
    let approved_intent_digest = match github_oidc.event_name() {
        "push" => {
            github
                .merged_release_pr(
                    &manifest.source.commit_sha,
                    &manifest.package,
                    &manifest.version.to_string(),
                    &manifest.release_branch_prefix,
                )
                .await?
                .context(
                    "release approval requires a server-verified merged managed Release PR for this Candidate",
                )?
                .intent_digest
        }
        "workflow_dispatch" => Some(manifest.intent_digest.clone()),
        _ => None,
    };
    Ok(ApprovalEvidence {
        approved_intent_digest,
        environment_candidate_digest: request.approved_candidate_digest.clone(),
        source_sha: request.manual_source_sha.clone(),
        manual_reason: request.manual_reason.clone(),
        github_oidc: Some(github_oidc),
    })
}
