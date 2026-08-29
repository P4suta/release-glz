use std::collections::BTreeMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use flate2::{Compression, write::GzEncoder};
use release_glz::authorization::{
    GithubOidcClaims, OidcAudience, OidcExpectation, validate_github_claims,
};
use release_glz::candidate::{
    Candidate, CandidateInput, CandidateSource, HookEvidence, HookKind, RegistryIdentity,
};
use release_glz::config::{AuthKind, HookConfig, OutputConfig, RegistryConfig, RegistryProvider};
use release_glz::forge::{GitHubClient, GitHubRepository};
use release_glz::git::GitRepo;
use release_glz::hooks::SidecarArtifact;
use release_glz::model::ReleaseState;
use release_glz::reconciler::{ApprovalEvidence, ReconcileEffect};
use release_glz::registry::HexRegistry;
use release_glz::release::{CandidateReleaseRunner, LiveReleaseTarget, ReleaseExecutionOptions};
use semver::Version;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

#[tokio::test]
async fn live_reconciler_recovers_ambiguous_publish_and_second_run_is_a_no_op() {
    let registry = FakeRegistry::start().await;
    let github = FakeGitHub::start().await;
    let fixture = live_fixture(&registry.base_url());

    let registry_config = RegistryConfig {
        provider: RegistryProvider::HexCompatible,
        repository: None,
        api_url: format!("{}/api", registry.base_url()),
        repository_url: format!("{}/repo", registry.base_url()),
        docs_url: format!("{}/repo/docs", registry.base_url()),
        credential_env: "TEST_REGISTRY_TOKEN".into(),
        auth: AuthKind::Bearer,
        allow_http_loopback: true,
    };
    let registry_adapter =
        HexRegistry::from_config(&registry_config, Some("registry-secret")).unwrap();
    let github_adapter = GitHubClient::new(
        GitHubRepository::parse("owner/widget").unwrap(),
        github.base_url(),
        format!("{}/graphql", github.base_url()),
        Some("github-secret".into()),
    )
    .unwrap();
    let repo = GitRepo::discover(&fixture.repository).unwrap();
    let target = LiveReleaseTarget::with_adapters(
        fixture.manifest.clone(),
        repo,
        registry_adapter,
        github_adapter,
    )
    .unwrap();
    let runner = CandidateReleaseRunner::new(target);

    let first = runner
        .run(
            &fixture.candidate,
            &approved(&fixture.manifest),
            ReleaseExecutionOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(first.state, ReleaseState::Released);
    assert_eq!(
        first.applied,
        vec![
            ReconcileEffect::PrepareAnnotatedTag,
            ReconcileEffect::PrepareGithubDraft,
            ReconcileEffect::PublishPackage,
            ReconcileEffect::PublishDocs,
            ReconcileEffect::UploadGithubAsset {
                name: "sbom.cdx.json".into(),
                sha256: fixture.manifest.sidecars[0].sha256.clone(),
            },
            ReconcileEffect::FinalizeGithubRelease,
        ]
    );
    assert!(first.remaining.is_empty());

    let mutation_count = github.mutation_count();
    let second = runner
        .run(
            &fixture.candidate,
            &approved(&fixture.manifest),
            ReleaseExecutionOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(second.state, ReleaseState::Released);
    assert!(second.applied.is_empty());
    assert!(second.remaining.is_empty());
    assert_eq!(github.mutation_count(), mutation_count);

    let registry_state = registry.state();
    assert_eq!(
        registry_state.package.as_deref(),
        Some(fixture.package.as_slice())
    );
    assert_eq!(
        registry_state.docs.as_deref(),
        Some(fixture.docs.as_slice())
    );
    assert_eq!(registry_state.package_posts, 1);
    assert_eq!(registry_state.docs_posts, 1);
    assert!(registry_state.requests.iter().all(|request| {
        request.headers.get("authorization").map(String::as_str) == Some("Bearer registry-secret")
    }));

    let github_state = github.state();
    assert_eq!(
        github_state.tag_target.as_deref(),
        Some(fixture.manifest.source.commit_sha.as_str())
    );
    assert_eq!(
        github_state.release_target.as_deref(),
        Some(fixture.manifest.source.commit_sha.as_str())
    );
    assert_eq!(
        github_state.candidate_digest.as_deref(),
        Some(fixture.manifest.candidate_digest.as_str())
    );
    assert!(!github_state.draft);
    assert_eq!(
        github_state.asset.as_deref(),
        Some(fixture.sidecar.as_slice())
    );
    assert!(github_state.requests.iter().all(|request| {
        request.headers.get("authorization").map(String::as_str) == Some("Bearer github-secret")
    }));
    assert!(github_state.requests.iter().all(|request| {
        !request.path.contains("clobber")
            && !String::from_utf8_lossy(&request.body).contains("replace")
    }));

    registry.stop();
    github.stop();
}

struct LiveFixture {
    _temp: tempfile::TempDir,
    repository: std::path::PathBuf,
    candidate: std::path::PathBuf,
    manifest: release_glz::candidate::CandidateManifest,
    package: Vec<u8>,
    docs: Vec<u8>,
    sidecar: Vec<u8>,
}

fn live_fixture(registry_base: &str) -> LiveFixture {
    let temp = tempfile::tempdir().unwrap();
    let repository = temp.path().join("repo");
    std::fs::create_dir_all(repository.join("src")).unwrap();
    std::fs::write(
        repository.join("gleam.toml"),
        "name = \"widget\"\nversion = \"1.2.3\"\n",
    )
    .unwrap();
    std::fs::write(
        repository.join("src/widget.gleam"),
        "pub fn widget() -> Int { 1 }\n",
    )
    .unwrap();
    git(&repository, &["init", "--initial-branch=main"]);
    git(&repository, &["config", "core.hooksPath", ".git/no-hooks"]);
    git(
        &repository,
        &["config", "user.email", "fixture@example.test"],
    );
    git(&repository, &["config", "user.name", "Fixture"]);
    git(&repository, &["config", "commit.gpgsign", "false"]);
    git(&repository, &["config", "tag.gpgsign", "false"]);
    git(&repository, &["add", "."]);
    git(&repository, &["commit", "-m", "feat: live fixture"]);
    let source_sha = git_output(&repository, &["rev-parse", "HEAD"]);

    let package = hex_package();
    let docs = tar_gz(&[("index.html", b"sealed docs")]);
    let sidecar = br#"{"bomFormat":"CycloneDX","serialNumber":"sealed"}"#.to_vec();
    let candidate = temp.path().join("candidate");
    let manifest = Candidate::seal(
        &candidate,
        CandidateInput {
            package: "widget".into(),
            version: Version::new(1, 2, 3),
            tag: "v1.2.3".into(),
            source: CandidateSource {
                commit_sha: source_sha,
                manifest_path: "gleam.toml".into(),
            },
            compiler: Version::new(1, 18, 1),
            registry: RegistryIdentity {
                provider: RegistryProvider::HexCompatible,
                repository: None,
                api_url: format!("{registry_base}/api"),
                repository_url: format!("{registry_base}/repo"),
                docs_url: format!("{registry_base}/repo/docs"),
                credential_env: "TEST_REGISTRY_TOKEN".into(),
                auth: AuthKind::Bearer,
                allow_http_loopback: true,
            },
            private: true,
            github_repository: "owner/widget".into(),
            release_branch_prefix: "release-glz/".into(),
            release_notes: "Sealed release notes.".into(),
            approval: release_glz::config::ApprovalConfig::default(),
            outputs: OutputConfig {
                sbom: false,
                provenance: false,
                allow_private_evidence_upload: true,
                ..OutputConfig::default()
            },
            package_tarball: package.clone(),
            docs_tarball: Some(docs.clone()),
            package_interface: br#"{"modules":{}}"#.to_vec(),
            verify_hook_definitions: vec![],
            sidecar_hook_definitions: vec![HookConfig {
                id: "sbom".into(),
                argv: vec!["sidecar-tool".into()],
                timeout_seconds: 10,
                required: true,
                env: vec![],
            }],
            hook_evidence: vec![HookEvidence {
                schema: "hook/v1".into(),
                id: "sbom".into(),
                kind: HookKind::Sidecar,
                required: true,
                success: true,
                output_sha256: "9".repeat(64),
            }],
            sidecars: vec![SidecarArtifact {
                hook_id: "sbom".into(),
                name: "sbom.cdx.json".into(),
                media_type: "application/vnd.cyclonedx+json".into(),
                bytes: sidecar.clone(),
                public: true,
            }],
            notify_hooks: vec![],
            notify_hook_definitions: vec![],
        },
    )
    .unwrap();
    LiveFixture {
        _temp: temp,
        repository,
        candidate,
        manifest,
        package,
        docs,
        sidecar,
    }
}

fn approved(manifest: &release_glz::candidate::CandidateManifest) -> ApprovalEvidence {
    let now = 1_800_000_000;
    let github_oidc = validate_github_claims(
        GithubOidcClaims {
            issuer: "https://token.actions.githubusercontent.com".into(),
            audience: OidcAudience::One("release-glz".into()),
            subject: format!(
                "repo:{}:environment:{}",
                manifest.github_repository, manifest.approval.environment
            ),
            repository: manifest.github_repository.clone(),
            environment: Some(manifest.approval.environment.clone()),
            workflow_ref: format!(
                "{}/.github/workflows/release-glz.yml@refs/heads/main",
                manifest.github_repository
            ),
            git_ref: "refs/heads/main".into(),
            source_sha: manifest.source.commit_sha.clone(),
            run_id: "42".into(),
            run_attempt: "1".into(),
            event_name: "push".into(),
            issued_at: now - 1,
            not_before: Some(now - 1),
            expires_at: now + 60,
        },
        &OidcExpectation {
            repository: manifest.github_repository.clone(),
            environment: manifest.approval.environment.clone(),
            workflow_path: ".github/workflows/release-glz.yml".into(),
            source_sha: manifest.source.commit_sha.clone(),
            run_id: Some("42".into()),
        },
        now,
    )
    .unwrap();
    ApprovalEvidence {
        release_pr_intent_digest: Some(manifest.intent_digest.clone()),
        environment_candidate_digest: Some(manifest.candidate_digest.clone()),
        environment: Some(manifest.approval.environment.clone()),
        github_oidc: Some(github_oidc),
        ..ApprovalEvidence::default()
    }
}

#[derive(Clone, Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct HttpResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(status: u16, value: serde_json::Value) -> Self {
        Self {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(&value).unwrap(),
        }
    }

    fn bytes(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: "application/octet-stream",
            body,
        }
    }
}

async fn read_request(stream: &mut TcpStream) -> HttpRequest {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    let header_end = loop {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0, "client disconnected before request headers");
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let header_text = String::from_utf8_lossy(&bytes[..header_end]);
    let mut lines = header_text.lines();
    let mut request_line = lines.next().unwrap().split_whitespace();
    let method = request_line.next().unwrap().to_owned();
    let path = request_line.next().unwrap().to_owned();
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or_default();
    while bytes.len() < header_end + content_length {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0, "client disconnected before request body");
        bytes.extend_from_slice(&buffer[..read]);
    }
    HttpRequest {
        method,
        path,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    }
}

async fn write_response(stream: &mut TcpStream, response: HttpResponse) {
    let reason = match response.status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        404 => "Not Found",
        _ => "Response",
    };
    let headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        reason,
        response.content_type,
        response.body.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(&response.body).await.unwrap();
}

#[derive(Clone, Debug, Default)]
struct RegistryState {
    package: Option<Vec<u8>>,
    docs: Option<Vec<u8>>,
    package_posts: usize,
    docs_posts: usize,
    requests: Vec<HttpRequest>,
}

struct FakeRegistry {
    address: std::net::SocketAddr,
    state: Arc<Mutex<RegistryState>>,
    task: JoinHandle<()>,
}

impl FakeRegistry {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(RegistryState::default()));
        let shared = Arc::clone(&state);
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                let (response, disconnect) = registry_response(&shared, &request);
                if !disconnect {
                    write_response(&mut stream, response).await;
                }
            }
        });
        Self {
            address,
            state,
            task,
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn state(&self) -> RegistryState {
        self.state.lock().unwrap().clone()
    }

    fn stop(self) {
        self.task.abort();
    }
}

fn registry_response(
    shared: &Arc<Mutex<RegistryState>>,
    request: &HttpRequest,
) -> (HttpResponse, bool) {
    let mut state = shared.lock().unwrap();
    state.requests.push(request.clone());
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/api/publish") => {
            state.package_posts += 1;
            state.package = Some(request.body.clone());
            // The server committed the bytes but the client never saw a response.
            (HttpResponse::bytes(201, vec![]), true)
        }
        ("POST", "/api/packages/widget/releases/1.2.3/docs") => {
            state.docs_posts += 1;
            state.docs = Some(request.body.clone());
            (HttpResponse::json(201, serde_json::json!({})), false)
        }
        ("GET", "/api/packages/widget") => {
            let releases = state.package.as_ref().map_or_else(Vec::new, |_| {
                vec![serde_json::json!({
                    "version": "1.2.3",
                    "has_docs": state.docs.is_some()
                })]
            });
            (
                HttpResponse::json(
                    200,
                    serde_json::json!({"releases": releases, "retirements": {}}),
                ),
                false,
            )
        }
        ("GET", "/api/packages/widget/releases/1.2.3") => match &state.package {
            Some(package) => (
                HttpResponse::json(
                    200,
                    serde_json::json!({
                        "version": "1.2.3",
                        "checksum": format!("{:x}", Sha256::digest(package)),
                        "has_docs": state.docs.is_some()
                    }),
                ),
                false,
            ),
            None => (HttpResponse::bytes(404, vec![]), false),
        },
        ("GET", "/repo/docs/widget-1.2.3.tar.gz") => match &state.docs {
            Some(docs) => (HttpResponse::bytes(200, docs.clone()), false),
            None => (HttpResponse::bytes(404, vec![]), false),
        },
        _ => panic!("unexpected registry request: {request:?}"),
    }
}

#[derive(Clone, Debug, Default)]
struct GitHubState {
    pending_tag_target: Option<String>,
    tag_target: Option<String>,
    release_target: Option<String>,
    candidate_digest: Option<String>,
    draft: bool,
    asset: Option<Vec<u8>>,
    asset_name: Option<String>,
    asset_media_type: Option<String>,
    requests: Vec<HttpRequest>,
}

struct FakeGitHub {
    address: std::net::SocketAddr,
    state: Arc<Mutex<GitHubState>>,
    task: JoinHandle<()>,
}

impl FakeGitHub {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(GitHubState::default()));
        let shared = Arc::clone(&state);
        let base_url = format!("http://{address}");
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                let response = github_response(&shared, &request, &base_url);
                write_response(&mut stream, response).await;
            }
        });
        Self {
            address,
            state,
            task,
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn state(&self) -> GitHubState {
        self.state.lock().unwrap().clone()
    }

    fn mutation_count(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|request| request.method != "GET")
            .count()
    }

    fn stop(self) {
        self.task.abort();
    }
}

fn github_response(
    shared: &Arc<Mutex<GitHubState>>,
    request: &HttpRequest,
    base_url: &str,
) -> HttpResponse {
    let mut state = shared.lock().unwrap();
    state.requests.push(request.clone());
    let path = request.path.split('?').next().unwrap();
    match (request.method.as_str(), path) {
        ("GET", "/repos/owner/widget/git/ref/tags/v1.2.3") => match &state.tag_target {
            Some(_) => HttpResponse::json(
                200,
                serde_json::json!({
                    "ref": "refs/tags/v1.2.3",
                    "object": {"type": "tag", "sha": "tag-object"}
                }),
            ),
            None => HttpResponse::bytes(404, vec![]),
        },
        ("GET", "/repos/owner/widget/git/tags/tag-object") => HttpResponse::json(
            200,
            serde_json::json!({
                "sha": "tag-object",
                "tag": "v1.2.3",
                "object": {"type": "commit", "sha": state.tag_target}
            }),
        ),
        ("POST", "/repos/owner/widget/git/tags") => {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let target = body["object"].as_str().unwrap().to_owned();
            state.pending_tag_target = Some(target.clone());
            HttpResponse::json(
                201,
                serde_json::json!({
                    "sha": "tag-object",
                    "tag": "v1.2.3",
                    "object": {"type": "commit", "sha": target}
                }),
            )
        }
        ("POST", "/repos/owner/widget/git/refs") => {
            state.tag_target = state.pending_tag_target.take();
            HttpResponse::json(
                201,
                serde_json::json!({
                    "ref": "refs/tags/v1.2.3",
                    "object": {"type": "tag", "sha": "tag-object"}
                }),
            )
        }
        ("GET", "/repos/owner/widget/releases/tags/v1.2.3") => match &state.release_target {
            Some(_) => release_response(&state, base_url),
            None => HttpResponse::bytes(404, vec![]),
        },
        ("POST", "/repos/owner/widget/releases") => {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            state.release_target = Some(body["target_commitish"].as_str().unwrap().to_owned());
            state.draft = true;
            state.candidate_digest = body["body"]
                .as_str()
                .and_then(|body| body.split("release-glz-candidate-digest: ").nth(1))
                .map(str::trim)
                .map(str::to_owned);
            release_response(&state, base_url)
        }
        ("POST", "/repos/owner/widget/releases/42/assets") => {
            state.asset = Some(request.body.clone());
            state.asset_name = request.path.split("name=").nth(1).map(str::to_owned);
            state.asset_media_type = request.headers.get("content-type").cloned();
            let digest = format!("{:x}", Sha256::digest(&request.body));
            HttpResponse::json(
                201,
                serde_json::json!({
                    "id": 77,
                    "name": state.asset_name,
                    "state": "uploaded",
                    "content_type": state.asset_media_type,
                    "size": request.body.len(),
                    "digest": format!("sha256:{digest}")
                }),
            )
        }
        ("PATCH", "/repos/owner/widget/releases/42") => {
            state.draft = false;
            release_response(&state, base_url)
        }
        _ => panic!("unexpected GitHub request: {request:?}"),
    }
}

fn release_response(state: &GitHubState, base_url: &str) -> HttpResponse {
    let assets = match (&state.asset, &state.asset_name, &state.asset_media_type) {
        (Some(bytes), Some(name), Some(media_type)) => vec![serde_json::json!({
            "id": 77,
            "name": name,
            "state": "uploaded",
            "content_type": media_type,
            "size": bytes.len(),
            "digest": format!("sha256:{:x}", Sha256::digest(bytes))
        })],
        _ => vec![],
    };
    HttpResponse::json(
        if state.draft { 201 } else { 200 },
        serde_json::json!({
            "id": 42,
            "html_url": "https://github.test/owner/widget/releases/42",
            "tag_name": "v1.2.3",
            "target_commitish": state.release_target,
            "body": format!(
                "release-glz-candidate-digest: {}",
                state.candidate_digest.as_deref().unwrap_or_default()
            ),
            "draft": state.draft,
            "upload_url": format!(
                "{base_url}/repos/owner/widget/releases/42/assets{{?name,label}}"
            ),
            "assets": assets
        }),
    )
}

fn git(directory: &std::path::Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_output(directory: &std::path::Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn hex_package() -> Vec<u8> {
    let contents = tar_gz(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]);
    let version = b"3";
    let metadata = b"metadata";
    let mut digest = Sha256::new();
    digest.update(version);
    digest.update(metadata);
    digest.update(&contents);
    let checksum = format!("{:X}", digest.finalize());
    tar(&[
        ("VERSION", version),
        ("metadata.config", metadata),
        ("contents.tar.gz", &contents),
        ("CHECKSUM", checksum.as_bytes()),
    ])
}

fn tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (path, contents) in files {
        append(&mut archive, path, contents);
    }
    archive.into_inner().unwrap().finish().unwrap()
}

fn tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut archive = tar::Builder::new(&mut bytes);
        for (path, contents) in files {
            append(&mut archive, path, contents);
        }
        archive.finish().unwrap();
    }
    bytes
}

fn append<W: std::io::Write>(archive: &mut tar::Builder<W>, path: &str, contents: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(contents.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    archive.append_data(&mut header, path, contents).unwrap();
}
