//! Each value in the approval evidence comes from a check that GitHub answered, never from the publishing job's own outputs.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use release_glz::approval::{ApprovalRequest, verify_approval};
use release_glz::authorization::{GithubOidcClaims, GithubOidcVerifier, OidcAudience};
use release_glz::candidate::{
    CandidateArtifacts, CandidateManifest, CandidateSource, RegistryIdentity, SealedArtifact,
};
use release_glz::config::{ApprovalConfig, AuthKind, OutputConfig, RegistryProvider};
use release_glz::forge::{GitHubClient, GitHubRepository, files_digest};
use release_glz::model::ReleaseState;
use release_glz::reconciler::{ApprovalEvidence, ExternalReleaseState, ReleaseIntent, reconcile};
use release_glz_test_support::oidc;
use semver::Version;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const NOW: i64 = 1_800_000_000;
const REPOSITORY: &str = "owner/widget";
const RUN: u64 = 42;
const EARLIER_RUN: u64 = 41;
const ARTIFACT: u64 = 7;

fn source_sha() -> String {
    "a".repeat(40)
}

fn release_pr_head() -> String {
    "c".repeat(40)
}

fn candidate_intent() -> String {
    "1".repeat(64)
}

fn candidate_digest() -> String {
    "2".repeat(64)
}

fn artifact_digest() -> String {
    "3".repeat(64)
}

#[tokio::test]
async fn a_push_release_takes_its_intent_from_the_merged_release_pr() {
    let intent_digest = candidate_intent();
    let github = FakeGithub::start(Event::Push, ReleasePr::Merged(Some(&intent_digest))).await;
    let evidence = github.verify(push_variables(&github)).await.unwrap();

    assert_eq!(evidence.approved_intent_digest, Some(candidate_intent()));
    assert_ne!(approved_state(&evidence), ReleaseState::AwaitingApproval);
    assert!(github.requests().contains(&format!(
        "/repos/{REPOSITORY}/commits/{}/pulls",
        source_sha()
    )));
}

#[tokio::test]
async fn a_job_value_that_disagrees_with_the_merged_release_pr_never_approves_a_push() {
    let merged_intent = "e".repeat(64);
    let github = FakeGithub::start(Event::Push, ReleasePr::Merged(Some(&merged_intent))).await;
    let mut variables = push_variables(&github);
    // The generated workflow used to pass these from the job's own outputs, and they agree with the Candidate.
    variables.insert(
        "RELEASE_GLZ_APPROVED_INTENT_DIGEST".into(),
        candidate_intent(),
    );
    variables.insert("RELEASE_GLZ_ENVIRONMENT".into(), "release".into());
    let evidence = github.verify(variables).await.unwrap();

    assert_eq!(evidence.approved_intent_digest, Some(merged_intent));
    let plan = reconcile(&intent(), &ExternalReleaseState::default(), &evidence).unwrap();
    assert_eq!(plan.state, ReleaseState::AwaitingApproval);
    assert!(plan.effects.is_empty());
}

#[tokio::test]
async fn a_merged_release_pr_without_a_bound_intent_never_approves_a_push() {
    let github = FakeGithub::start(Event::Push, ReleasePr::Merged(None)).await;
    let evidence = github.verify(push_variables(&github)).await.unwrap();

    assert_eq!(evidence.approved_intent_digest, None);
    assert_eq!(approved_state(&evidence), ReleaseState::AwaitingApproval);
}

#[tokio::test]
async fn a_push_without_a_merged_release_pr_has_no_approval() {
    let github = FakeGithub::start(Event::Push, ReleasePr::Absent).await;
    let error = github.verify(push_variables(&github)).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("merged managed Release PR"),
        "{error:#}"
    );
}

#[tokio::test]
async fn the_environment_of_an_approval_is_the_one_github_signed() {
    let intent_digest = candidate_intent();
    let github = FakeGithub::start(Event::Push, ReleasePr::Merged(Some(&intent_digest))).await;
    let mut variables = push_variables(&github);
    variables.insert("RELEASE_GLZ_ENVIRONMENT".into(), "staging".into());
    let evidence = github.verify(variables).await.unwrap();

    assert_eq!(
        evidence.github_oidc.as_ref().unwrap().environment(),
        "release"
    );
    assert_ne!(approved_state(&evidence), ReleaseState::AwaitingApproval);

    let staging = FakeGithub::start_with(
        Event::Push,
        ReleasePr::Merged(Some(&intent_digest)),
        "staging",
    )
    .await;
    let error = staging.verify(push_variables(&staging)).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("OIDC verification failed"),
        "{error:#}"
    );
}

#[tokio::test]
async fn a_manual_release_takes_its_intent_from_the_verified_candidate() {
    let github = FakeGithub::start(Event::WorkflowDispatch, ReleasePr::Absent).await;
    let mut variables = base_variables(&github, EARLIER_RUN);
    variables.insert(
        "RELEASE_GLZ_APPROVED_CANDIDATE_DIGEST".into(),
        candidate_digest(),
    );
    variables.insert("RELEASE_GLZ_MANUAL_SOURCE_SHA".into(), source_sha());
    variables.insert(
        "RELEASE_GLZ_MANUAL_REASON".into(),
        "Emergency release after incident review".into(),
    );
    let evidence = github.verify(variables).await.unwrap();

    assert_eq!(evidence.approved_intent_digest, Some(candidate_intent()));
    assert_ne!(approved_state(&evidence), ReleaseState::AwaitingApproval);
    assert!(
        !github
            .requests()
            .iter()
            .any(|path| path.ends_with("/pulls")),
        "a manual release has no Release PR to look up"
    );
}

#[test]
fn a_request_names_every_object_that_approval_checks() {
    let variables = BTreeMap::from([
        ("ACTIONS_ID_TOKEN_REQUEST_URL".to_owned(), "url".to_owned()),
        (
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN".to_owned(),
            "token".to_owned(),
        ),
        ("GITHUB_RUN_ID".to_owned(), RUN.to_string()),
        (
            "RELEASE_GLZ_ACTIONS_ARTIFACT_ID".to_owned(),
            ARTIFACT.to_string(),
        ),
        (
            "RELEASE_GLZ_ACTIONS_ARTIFACT_DIGEST".to_owned(),
            format!("sha256:{}", artifact_digest()),
        ),
        ("RELEASE_GLZ_ACTIONS_RUN_ID".to_owned(), RUN.to_string()),
    ]);
    let request = ApprovalRequest::from_variables(lookup(&variables)).unwrap();
    assert_eq!(request.artifact_id, ARTIFACT);
    assert_eq!(request.approved_candidate_digest, None);
    assert_eq!(request.manual_source_sha, None);
    assert_eq!(request.manual_reason, None);

    for (name, message) in [
        ("ACTIONS_ID_TOKEN_REQUEST_URL", "OIDC request URL"),
        ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "OIDC request token"),
        ("GITHUB_RUN_ID", "GitHub Actions run ID"),
        (
            "RELEASE_GLZ_ACTIONS_ARTIFACT_ID",
            "immutable Actions artifact ID",
        ),
        (
            "RELEASE_GLZ_ACTIONS_ARTIFACT_DIGEST",
            "Actions artifact digest",
        ),
        (
            "RELEASE_GLZ_ACTIONS_RUN_ID",
            "Candidate-generating Actions run ID",
        ),
    ] {
        let mut missing = variables.clone();
        missing.remove(name);
        let error = ApprovalRequest::from_variables(lookup(&missing)).unwrap_err();
        assert!(error.to_string().contains(message), "{name}: {error}");
    }
    let mut invalid = variables;
    invalid.insert("RELEASE_GLZ_ACTIONS_ARTIFACT_ID".into(), "seven".into());
    let error = ApprovalRequest::from_variables(lookup(&invalid)).unwrap_err();
    assert!(
        error.to_string().contains("artifact ID is invalid"),
        "{error}"
    );
}

fn lookup(variables: &BTreeMap<String, String>) -> impl Fn(&str) -> Option<String> + '_ {
    |name| variables.get(name).cloned()
}

/// The state that reconciling the empty world under `evidence` reports.
fn approved_state(evidence: &ApprovalEvidence) -> ReleaseState {
    reconcile(&intent(), &ExternalReleaseState::default(), evidence)
        .unwrap()
        .state
}

/// The variables of a publish job that a push started, which consumes the Candidate its own run prepared.
fn push_variables(github: &FakeGithub) -> BTreeMap<String, String> {
    let mut variables = base_variables(github, RUN);
    variables.insert(
        "RELEASE_GLZ_APPROVED_CANDIDATE_DIGEST".into(),
        candidate_digest(),
    );
    variables
}

fn base_variables(github: &FakeGithub, artifact_run: u64) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "ACTIONS_ID_TOKEN_REQUEST_URL".to_owned(),
            format!("{}/token", github.base_url()),
        ),
        (
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN".to_owned(),
            "runner-secret".to_owned(),
        ),
        ("GITHUB_RUN_ID".to_owned(), RUN.to_string()),
        (
            "RELEASE_GLZ_ACTIONS_ARTIFACT_ID".to_owned(),
            ARTIFACT.to_string(),
        ),
        (
            "RELEASE_GLZ_ACTIONS_ARTIFACT_DIGEST".to_owned(),
            format!("sha256:{}", artifact_digest()),
        ),
        (
            "RELEASE_GLZ_ACTIONS_RUN_ID".to_owned(),
            artifact_run.to_string(),
        ),
    ])
}

fn manifest() -> CandidateManifest {
    let artifact = |path: &str, digit: char| SealedArtifact {
        path: path.into(),
        sha256: digit.to_string().repeat(64),
        semantic_sha256: digit.to_string().repeat(64),
        size: 1,
    };
    CandidateManifest {
        schema: "candidate/v1".into(),
        package: "widget".into(),
        version: Version::new(1, 2, 3),
        tag: "v1.2.3".into(),
        source: CandidateSource {
            commit_sha: source_sha(),
            manifest_path: "gleam.toml".into(),
        },
        compiler: Version::new(1, 18, 1),
        registry: RegistryIdentity {
            provider: RegistryProvider::HexPm,
            repository: None,
            api_url: "https://hex.pm/api".into(),
            repository_url: "https://repo.hex.pm".into(),
            docs_url: "https://repo.hex.pm/docs".into(),
            credential_env: "HEXPM_API_KEY".into(),
            auth: AuthKind::HexToken,
            allow_http_loopback: false,
        },
        private: false,
        github_repository: REPOSITORY.into(),
        release_branch_prefix: "release-glz/".into(),
        release_notes: "notes".into(),
        approval: ApprovalConfig::default(),
        outputs: OutputConfig::default(),
        artifacts: CandidateArtifacts {
            package: artifact("artifacts/package.tar", '5'),
            docs: None,
            package_interface: artifact("artifacts/package-interface.json", '6'),
        },
        verify_hook_definitions: vec![],
        sidecar_hook_definitions: vec![],
        hook_evidence: vec![],
        sidecars: vec![],
        notify_hooks: vec![],
        notify_hook_definitions: vec![],
        intent_digest: candidate_intent(),
        candidate_digest: candidate_digest(),
    }
}

/// The intent the reconciler derives from [`manifest`].
fn intent() -> ReleaseIntent {
    let manifest = manifest();
    ReleaseIntent {
        package: manifest.package,
        version: manifest.version,
        source_sha: manifest.source.commit_sha,
        tag: manifest.tag,
        intent_digest: manifest.intent_digest,
        candidate_digest: manifest.candidate_digest,
        approval_environment: manifest.approval.environment,
        manual_refs: manifest.approval.manual_refs,
        github_repository: manifest.github_repository,
        workflow_path: ".github/workflows/release-glz.yml".into(),
        github_release: manifest.outputs.github_release,
        package_sha256: manifest.artifacts.package.sha256,
        docs_sha256: None,
        release_assets: vec![],
        notify_hooks: vec![],
    }
}

/// The event that started the publishing run.
#[derive(Clone, Copy)]
enum Event {
    Push,
    WorkflowDispatch,
}

/// What GitHub lists as the pull requests of the source commit.
#[derive(Clone, Copy)]
enum ReleasePr<'a> {
    /// The managed Release PR that merged as the source commit, and the intent its marker recorded.
    Merged(Option<&'a str>),
    /// No pull request.
    Absent,
}

/// The files that the Release PR commit for widget 1.2.3 wrote.
fn release_files() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        (
            "CHANGELOG.md".into(),
            b"# Changelog\n\n## [1.2.3]\n\n- Add the widget API.\n".to_vec(),
        ),
        (
            "gleam.toml".into(),
            b"name = \"widget\"\nversion = \"1.2.3\"\n".to_vec(),
        ),
    ])
}

/// GitHub's OIDC issuer, the runner's token endpoint, and the repository API on one loopback origin.
///
/// It answers each path from a fixed table, so the order of the requests doesn't matter.
struct FakeGithub {
    address: std::net::SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
}

impl FakeGithub {
    async fn start(event: Event, release_pr: ReleasePr<'_>) -> Self {
        Self::start_with(event, release_pr, "release").await
    }

    /// A server whose OIDC token names `environment`.
    async fn start_with(event: Event, release_pr: ReleasePr<'_>, environment: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let routes = routes(address, event, release_pr, environment);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                }
                let request = String::from_utf8_lossy(&request).into_owned();
                let target = request.split_whitespace().nth(1).unwrap_or_default();
                let path = target.split('?').next().unwrap_or_default().to_owned();
                let response = match routes.get(&path) {
                    Some(body) => format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    ),
                    None => {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_owned()
                    }
                };
                captured.lock().unwrap().push(path);
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Self { address, requests }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// The paths requested so far.
    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    /// The evidence that approval gathers for the job that `variables` describe.
    async fn verify(
        &self,
        variables: BTreeMap<String, String>,
    ) -> anyhow::Result<ApprovalEvidence> {
        let request = ApprovalRequest::from_variables(lookup(&variables))?;
        let verifier = GithubOidcVerifier::new(&format!("{}/discovery", self.base_url()), true)?;
        let github = GitHubClient::new(
            GitHubRepository::parse(REPOSITORY)?,
            self.base_url(),
            format!("{}/graphql", self.base_url()),
            Some("token".into()),
        )?;
        verify_approval(&manifest(), &request, &verifier, &github, NOW).await
    }
}

fn routes(
    address: std::net::SocketAddr,
    event: Event,
    release_pr: ReleasePr<'_>,
    environment: &str,
) -> BTreeMap<String, String> {
    let api = format!("/repos/{REPOSITORY}");
    let (artifact_run, status, conclusion) = match event {
        Event::Push => (RUN, "in_progress", None),
        Event::WorkflowDispatch => (EARLIER_RUN, "completed", Some("success")),
    };
    let files = release_files();
    let pulls = match release_pr {
        ReleasePr::Merged(intent) => serde_json::json!([merged_release_pr(intent, &files)]),
        ReleasePr::Absent => serde_json::json!([]),
    };
    let mut routes = BTreeMap::from([
        (
            "/token".to_owned(),
            serde_json::json!({"value": oidc::sign_rs256(&claims(event, environment))}).to_string(),
        ),
        (
            "/discovery".to_owned(),
            serde_json::json!({
                "issuer": "https://token.actions.githubusercontent.com",
                "jwks_uri": format!("http://{address}/jwks")
            })
            .to_string(),
        ),
        (
            "/jwks".to_owned(),
            serde_json::json!({"keys": [{
                "kty": "RSA",
                "kid": oidc::KEY_ID,
                "alg": "RS256",
                "use": "sig",
                "n": oidc::MODULUS,
                "e": oidc::EXPONENT
            }]})
            .to_string(),
        ),
        (
            format!("{api}/actions/artifacts/{ARTIFACT}"),
            serde_json::json!({
                "id": ARTIFACT,
                "name": format!("release-glz-candidate-{artifact_run}"),
                "size_in_bytes": 100,
                "expired": false,
                "digest": format!("sha256:{}", artifact_digest()),
                "workflow_run": {"id": artifact_run, "head_sha": source_sha()}
            })
            .to_string(),
        ),
        (
            format!("{api}/actions/runs/{artifact_run}"),
            serde_json::json!({
                "id": artifact_run,
                "path": ".github/workflows/release-glz.yml",
                "head_sha": source_sha(),
                "status": status,
                "conclusion": conclusion,
                "repository": {"full_name": REPOSITORY}
            })
            .to_string(),
        ),
        (
            format!("{api}/commits/{}/pulls", source_sha()),
            pulls.to_string(),
        ),
        (
            format!("{api}/commits/{}", release_pr_head()),
            serde_json::json!({
                "commit": {
                    "message": format!(
                        "chore(release): widget 1.2.3\n\nrelease-glz-digest: {}",
                        files_digest(&files)
                    ),
                    "verification": {"verified": true}
                },
                "parents": [{"sha": "0".repeat(40)}],
                "files": files
                    .keys()
                    .enumerate()
                    .map(|(index, path)| serde_json::json!({
                        "filename": path,
                        "status": "modified",
                        "sha": blob_id(index)
                    }))
                    .collect::<Vec<_>>()
            })
            .to_string(),
        ),
    ]);
    for (index, contents) in files.values().enumerate() {
        routes.insert(
            format!("{api}/git/blobs/{}", blob_id(index)),
            serde_json::json!({
                "content": base64::engine::general_purpose::STANDARD.encode(contents),
                "encoding": "base64",
                "size": contents.len()
            })
            .to_string(),
        );
    }
    routes
}

/// A distinct blob id for the file at `index` of the Release PR commit.
fn blob_id(index: usize) -> String {
    format!("{:040x}", index + 1)
}

/// The managed Release PR that merged as the source commit, whose marker records `intent` when its intent was bound and `pending` otherwise.
fn merged_release_pr(intent: Option<&str>, files: &BTreeMap<String, Vec<u8>>) -> serde_json::Value {
    let marker_intent = intent.unwrap_or("pending");
    serde_json::json!({
        "number": 7,
        "title": "chore(release): widget 1.2.3",
        "body": format!(
            "Release body\n\n<!-- release-glz:managed package=widget branch=release-glz/widget head={} digest={} version=1.2.3 intent={marker_intent} -->",
            release_pr_head(),
            files_digest(files)
        ),
        "html_url": "https://github.test/owner/widget/pull/7",
        "merge_commit_sha": source_sha(),
        "merged_at": "2026-01-01T00:00:00Z",
        "user": {"login": "release-glz"},
        "labels": [],
        "head": {
            "ref": "release-glz/widget",
            "sha": release_pr_head(),
            "repo": {"full_name": REPOSITORY, "default_branch": "main"}
        },
        "base": {
            "ref": "main",
            "repo": {"full_name": REPOSITORY, "default_branch": "main"}
        }
    })
}

fn claims(event: Event, environment: &str) -> GithubOidcClaims {
    GithubOidcClaims {
        issuer: "https://token.actions.githubusercontent.com".into(),
        audience: OidcAudience::One("release-glz".into()),
        subject: format!("repo:{REPOSITORY}:environment:{environment}"),
        repository: REPOSITORY.into(),
        environment: Some(environment.into()),
        workflow_ref: format!("{REPOSITORY}/.github/workflows/release-glz.yml@refs/heads/main"),
        git_ref: "refs/heads/main".into(),
        source_sha: source_sha(),
        run_id: RUN.to_string(),
        run_attempt: "1".into(),
        event_name: match event {
            Event::Push => "push",
            Event::WorkflowDispatch => "workflow_dispatch",
        }
        .into(),
        issued_at: NOW - 1,
        not_before: Some(NOW - 1),
        expires_at: NOW + 60,
    }
}
