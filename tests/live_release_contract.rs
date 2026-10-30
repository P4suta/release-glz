use std::collections::BTreeMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use flate2::{Compression, write::GzEncoder};
use release_glz::approval::{ApprovalRequest, verify_approval};
use release_glz::authorization::{
    GithubOidcClaims, GithubOidcVerifier, JwkSet, OidcAudience, OidcExpectation, RsaJwk,
    VerifiedGithubOidc, verify_github_oidc_token,
};
use release_glz::candidate::{
    Candidate, CandidateInput, CandidateSource, HookEvidence, HookKind, RegistryIdentity,
};
use release_glz::config::{AuthKind, HookConfig, OutputConfig, RegistryConfig, RegistryProvider};
use release_glz::forge::{GitHubClient, GitHubRepository, files_digest};
use release_glz::git::GitRepo;
use release_glz::hooks::SidecarArtifact;
use release_glz::model::ReleaseState;
use release_glz::reconciler::{ApprovalEvidence, ReconcileEffect};
use release_glz::registry::HexRegistry;
use release_glz::release::{CandidateReleaseRunner, LiveReleaseTarget};
use release_glz_test_support::oidc;
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
    let runner = live_runner(&fixture, &registry, &github);

    let first = runner
        .run(&fixture.candidate, &approved(&fixture.manifest))
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
                hook_id: "sbom".into(),
                name: "sbom.cdx.json".into(),
                sha256: fixture.manifest.sidecars[0].sha256.clone(),
            },
            ReconcileEffect::FinalizeGithubRelease,
        ]
    );
    assert!(first.remaining.is_empty());

    let mutation_count = github.mutation_count();
    let second = runner
        .run(&fixture.candidate, &approved(&fixture.manifest))
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
        github_state
            .assets
            .iter()
            .map(|asset| (asset.name.clone(), asset.bytes.clone()))
            .collect::<BTreeMap<_, _>>(),
        fixture.assets
    );
    assert!(
        github_state
            .assets
            .iter()
            .all(|asset| asset.state == "uploaded")
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

/// A failed upload that leaves an unfinished asset stops the run, and the next run deletes only that asset on the draft, uploads the sealed bytes, and finalizes the Release.
#[tokio::test]
async fn a_resumed_run_completes_an_asset_that_a_failed_upload_left_unfinished() {
    let registry = FakeRegistry::start().await;
    let github = FakeGitHub::start().await;
    let fixture = live_fixture_with(
        &registry.base_url(),
        &[
            ("sbom.cdx.json", "application/vnd.cyclonedx+json"),
            ("widget.intoto.jsonl", "application/vnd.in-toto+json"),
        ],
    );
    github.leave_unfinished("widget.intoto.jsonl");
    let runner = live_runner(&fixture, &registry, &github);

    let error = runner
        .run(&fixture.candidate, &approved(&fixture.manifest))
        .await
        .unwrap_err();
    assert_eq!(error.state(), ReleaseState::PartiallyReleased, "{error}");
    assert_eq!(
        error.failure_class(),
        release_glz::failure::FailureClass::PartialRelease
    );
    assert!(error.to_string().contains("failed with 502"), "{error}");
    let stopped = github.state();
    assert!(stopped.deletions.is_empty());
    assert!(stopped.draft);
    let sbom = github.asset("sbom.cdx.json");
    let unfinished = github.asset("widget.intoto.jsonl");
    assert_eq!(sbom.state, "uploaded");
    assert_eq!(unfinished.state, "starter");

    let report = runner
        .run(&fixture.candidate, &approved(&fixture.manifest))
        .await
        .unwrap();
    assert_eq!(report.state, ReleaseState::Released);
    let sealed = fixture
        .manifest
        .sidecars
        .iter()
        .find(|sidecar| sidecar.name == "widget.intoto.jsonl")
        .unwrap();
    assert_eq!(
        report.applied,
        vec![
            ReconcileEffect::UploadGithubAsset {
                hook_id: "sbom".into(),
                name: "widget.intoto.jsonl".into(),
                sha256: sealed.sha256.clone(),
            },
            ReconcileEffect::FinalizeGithubRelease,
        ]
    );
    assert!(report.remaining.is_empty());

    let finished = github.state();
    let deletes = finished
        .requests
        .iter()
        .enumerate()
        .filter(|(_, request)| request.method == "DELETE")
        .collect::<Vec<_>>();
    assert_eq!(deletes.len(), 1, "{deletes:?}");
    let (position, delete) = deletes[0];
    assert_eq!(
        delete.path,
        format!("/repos/owner/widget/releases/assets/{}", unfinished.id)
    );
    let reread = &finished.requests[position - 1];
    assert_eq!(reread.method, "GET");
    assert!(
        reread.path.starts_with("/repos/owner/widget/releases?"),
        "the Release must be read again right before the delete, not {}",
        reread.path
    );
    assert_eq!(finished.deletions.len(), 1);
    assert_eq!(finished.deletions[0].id, unfinished.id);
    assert_eq!(finished.deletions[0].state, "starter");
    assert!(finished.deletions[0].draft);

    assert!(!finished.draft);
    let kept = github.asset("sbom.cdx.json");
    assert_eq!(kept.id, sbom.id);
    assert_eq!(kept.state, "uploaded");
    let completed = github.asset("widget.intoto.jsonl");
    assert_ne!(completed.id, unfinished.id);
    assert_eq!(completed.state, "uploaded");
    assert_eq!(
        Some(&completed.bytes),
        fixture.assets.get("widget.intoto.jsonl")
    );
    assert_eq!(registry.state().package_posts, 1);
    assert_eq!(registry.state().docs_posts, 1);
    registry.stop();
    github.stop();
}

/// An unfinished asset on the published Release stops the release as a conflict that says what a person has to do, and the run changes nothing.
#[tokio::test]
async fn an_unfinished_asset_on_a_published_release_is_left_to_a_person() {
    let registry = FakeRegistry::start().await;
    let github = FakeGitHub::start().await;
    let fixture = live_fixture(&registry.base_url());
    github.hold_release_with_unfinished_asset(&fixture.manifest, false, "sbom.cdx.json");

    let error = live_runner(&fixture, &registry, &github)
        .run(&fixture.candidate, &approved(&fixture.manifest))
        .await
        .unwrap_err();
    assert_eq!(error.state(), ReleaseState::Conflict, "{error}");
    assert_eq!(
        error.failure_class(),
        release_glz::failure::FailureClass::ImmutableStateConflict
    );
    let message = error.to_string();
    assert!(message.contains("published Release"), "{message}");
    assert!(
        message.contains("upload `sidecars/sbom/sbom.cdx.json` from the Candidate"),
        "{message}"
    );
    assert_eq!(github.mutation_count(), 0);
    assert_eq!(github.asset("sbom.cdx.json").state, "starter");
    assert_eq!(registry.state().package_posts, 0);
    registry.stop();
    github.stop();
}

/// An unfinished asset that the Candidate doesn't seal stops the release as a conflict, and the run deletes nothing.
#[tokio::test]
async fn an_unfinished_asset_outside_the_candidate_is_left_to_a_person() {
    let registry = FakeRegistry::start().await;
    let github = FakeGitHub::start().await;
    let fixture = live_fixture(&registry.base_url());
    github.hold_release_with_unfinished_asset(&fixture.manifest, true, "stray.json");

    let error = live_runner(&fixture, &registry, &github)
        .run(&fixture.candidate, &approved(&fixture.manifest))
        .await
        .unwrap_err();
    assert_eq!(error.state(), ReleaseState::Conflict, "{error}");
    assert_eq!(
        error.failure_class(),
        release_glz::failure::FailureClass::ImmutableStateConflict
    );
    let message = error.to_string();
    assert!(
        message.contains("`stray.json` is unfinished, and the Candidate doesn't seal it"),
        "{message}"
    );
    assert_eq!(github.mutation_count(), 0);
    assert_eq!(registry.state().package_posts, 0);
    registry.stop();
    github.stop();
}

/// GitHub keeps the name of every asset that a Candidate seals, so an upload never comes back under another name.
///
/// GitHub keeps some names that the Candidate refuses, so the check runs one way only.
#[test]
fn every_asset_name_that_a_candidate_seals_keeps_its_name_on_github() {
    let temp = tempfile::tempdir().unwrap();
    let mut sealed = 0;
    let characters = (0..=0x7f_u8).map(char::from).chain(['é', '€', '日']);
    for (index, character) in characters.enumerate() {
        let names = [
            format!("{character}x.json"),
            format!("x{character}x.json"),
            format!("x.json{character}"),
        ];
        for (position, name) in names.iter().enumerate() {
            let input = candidate_input(
                "http://127.0.0.1:9",
                "a".repeat(40),
                &[(name.as_str(), "application/json")],
                hex_package(),
                tar_gz(&[("index.html", b"sealed docs")]),
            );
            let directory = temp.path().join(format!("{index}-{position}"));
            if Candidate::seal(&directory, input).is_ok() {
                sealed += 1;
                assert_eq!(github_asset_name(name), *name, "GitHub renames {name:?}");
            }
        }
    }
    assert!(sealed > 0, "no name sealed at all");
}

/// Two drafts with the tag leave the run unable to tell which one the Candidate owns, so it stops before any effect.
#[tokio::test]
async fn two_drafts_with_the_tag_stop_the_release_in_a_conflict() {
    let registry = FakeRegistry::start().await;
    let github = FakeGitHub::start().await;
    let fixture = live_fixture(&registry.base_url());
    github.duplicate_the_draft();

    let error = live_runner(&fixture, &registry, &github)
        .run(&fixture.candidate, &approved(&fixture.manifest))
        .await
        .unwrap_err();
    assert_eq!(error.state(), ReleaseState::Conflict);
    assert_eq!(
        error.failure_class(),
        release_glz::failure::FailureClass::ImmutableStateConflict
    );
    assert!(
        error.to_string().contains("2 GitHub Releases have the tag"),
        "{error}"
    );
    assert_eq!(github.mutation_count(), 0);
    assert_eq!(registry.state().package_posts, 0);
}

/// Evidence that `verify_approval` gathered from GitHub publishes the whole release, as no hand-built evidence can show.
#[tokio::test]
async fn evidence_from_verification_publishes_the_whole_release() {
    let registry = FakeRegistry::start().await;
    let github = FakeGitHub::start().await;
    let fixture = live_fixture(&registry.base_url());
    github.answer_approval(&fixture.manifest, &fixture.manifest.intent_digest);

    let evidence = verify(&fixture.manifest, &github).await.unwrap();
    let report = live_runner(&fixture, &registry, &github)
        .run(&fixture.candidate, &evidence)
        .await
        .unwrap();

    assert_eq!(report.state, ReleaseState::Released);
    assert_eq!(report.applied.len(), 6, "{:?}", report.applied);
    assert!(report.remaining.is_empty());
    assert_eq!(registry.state().package_posts, 1);
    assert_eq!(registry.state().docs_posts, 1);
    assert!(!github.state().draft);
    registry.stop();
    github.stop();
}

/// When the merged Release PR recorded another intent, the evidence that verification gathers publishes nothing.
#[tokio::test]
async fn evidence_for_another_intent_publishes_nothing() {
    let registry = FakeRegistry::start().await;
    let github = FakeGitHub::start().await;
    let fixture = live_fixture(&registry.base_url());
    github.answer_approval(&fixture.manifest, &"e".repeat(64));

    let evidence = verify(&fixture.manifest, &github).await.unwrap();
    let report = live_runner(&fixture, &registry, &github)
        .run(&fixture.candidate, &evidence)
        .await
        .unwrap();

    assert_eq!(report.state, ReleaseState::AwaitingApproval);
    assert!(report.applied.is_empty());
    assert_eq!(github.mutation_count(), 0);
    assert_eq!(registry.state().package_posts, 0);
    assert_eq!(registry.state().docs_posts, 0);
    registry.stop();
    github.stop();
}

/// A runner that publishes the fixture's Candidate to the fake registry and GitHub.
fn live_runner(
    fixture: &LiveFixture,
    registry: &FakeRegistry,
    github: &FakeGitHub,
) -> CandidateReleaseRunner<LiveReleaseTarget> {
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
    let repo = GitRepo::discover(&fixture.repository).unwrap();
    let target = LiveReleaseTarget::with_adapters(
        fixture.manifest.clone(),
        repo,
        registry_adapter,
        github_client(github),
    )
    .unwrap();
    CandidateReleaseRunner::new(target)
}

fn github_client(github: &FakeGitHub) -> GitHubClient {
    GitHubClient::new(
        GitHubRepository::parse("owner/widget").unwrap(),
        github.base_url(),
        format!("{}/graphql", github.base_url()),
        Some("github-secret".into()),
    )
    .unwrap()
}

/// The evidence that `verify_approval` gathers for the publish job of the push run that prepared the fixture's Candidate.
async fn verify(
    manifest: &release_glz::candidate::CandidateManifest,
    github: &FakeGitHub,
) -> anyhow::Result<ApprovalEvidence> {
    let request = ApprovalRequest {
        oidc_request_url: format!("{}/token", github.base_url()),
        oidc_request_token: "runner-secret".into(),
        run_id: RUN.to_string(),
        artifact_id: ARTIFACT,
        artifact_digest: format!("sha256:{}", artifact_digest()),
        artifact_run_id: RUN.to_string(),
        approved_candidate_digest: Some(manifest.candidate_digest.clone()),
        manual_source_sha: None,
        manual_reason: None,
    };
    let verifier = GithubOidcVerifier::new(&format!("{}/discovery", github.base_url()), true)?;
    verify_approval(manifest, &request, &verifier, &github_client(github), NOW).await
}

const NOW: i64 = 1_800_000_000;
const RUN: u64 = 42;
const ARTIFACT: u64 = 7;

fn artifact_digest() -> String {
    "3".repeat(64)
}

/// The head of the merged Release PR, which release-glz generated.
fn release_pr_head() -> String {
    "c".repeat(40)
}

/// The files that the Release PR commit wrote.
fn release_pr_files() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([(
        "CHANGELOG.md".to_owned(),
        b"# Changelog\n\n## [1.2.3]\n".to_vec(),
    )])
}

struct LiveFixture {
    _temp: tempfile::TempDir,
    repository: std::path::PathBuf,
    candidate: std::path::PathBuf,
    manifest: release_glz::candidate::CandidateManifest,
    package: Vec<u8>,
    docs: Vec<u8>,
    /// The sealed bytes of each GitHub Release asset, by name.
    assets: BTreeMap<String, Vec<u8>>,
}

fn live_fixture(registry_base: &str) -> LiveFixture {
    live_fixture_with(
        registry_base,
        &[("sbom.cdx.json", "application/vnd.cyclonedx+json")],
    )
}

/// A Candidate whose `sbom` hook produced one public asset for each name and media type in `assets`.
fn live_fixture_with(registry_base: &str, assets: &[(&str, &str)]) -> LiveFixture {
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
    let candidate = temp.path().join("candidate");
    let manifest = Candidate::seal(
        &candidate,
        candidate_input(
            registry_base,
            source_sha,
            assets,
            package.clone(),
            docs.clone(),
        ),
    )
    .unwrap();
    LiveFixture {
        _temp: temp,
        repository,
        candidate,
        manifest,
        package,
        docs,
        assets: assets
            .iter()
            .map(|(name, _)| ((*name).to_owned(), asset_bytes(name)))
            .collect(),
    }
}

/// The bytes that the `sbom` hook produced for the asset `name`.
fn asset_bytes(name: &str) -> Vec<u8> {
    format!(r#"{{"bomFormat":"CycloneDX","serialNumber":"{name}"}}"#).into_bytes()
}

/// The input of a widget 1.2.3 Candidate at `source_sha` whose `sbom` hook produced one public asset for each name and media type in `assets`.
fn candidate_input(
    registry_base: &str,
    source_sha: String,
    assets: &[(&str, &str)],
    package: Vec<u8>,
    docs: Vec<u8>,
) -> CandidateInput {
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
        package_tarball: package,
        docs_tarball: Some(docs),
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
        sidecars: assets
            .iter()
            .map(|(name, media_type)| SidecarArtifact {
                hook_id: "sbom".into(),
                name: (*name).to_owned(),
                media_type: (*media_type).to_owned(),
                bytes: asset_bytes(name),
                public: true,
            })
            .collect(),
        notify_hooks: vec![],
        notify_hook_definitions: vec![],
    }
}

/// The identity in `claims`, signed and then verified, since no other path yields a verified identity.
fn signed_identity(
    claims: GithubOidcClaims,
    expected: &OidcExpectation,
    now: i64,
) -> anyhow::Result<VerifiedGithubOidc> {
    let key = RsaJwk {
        key_type: "RSA".into(),
        key_id: Some(oidc::KEY_ID.into()),
        algorithm: Some("RS256".into()),
        usage: Some("sig".into()),
        modulus: oidc::MODULUS.into(),
        exponent: oidc::EXPONENT.into(),
    };
    verify_github_oidc_token(
        &oidc::sign_rs256(&claims),
        &JwkSet { keys: vec![key] },
        expected,
        now,
    )
}

fn approved(manifest: &release_glz::candidate::CandidateManifest) -> ApprovalEvidence {
    let now = 1_800_000_000;
    let github_oidc = signed_identity(
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
        approved_intent_digest: Some(manifest.intent_digest.clone()),
        environment_candidate_digest: Some(manifest.candidate_digest.clone()),
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
                        "checksum": release_glz::hex::lower(&Sha256::digest(package)),
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
    /// The Release's assets, in upload order.
    assets: Vec<FakeAsset>,
    /// The id that the next asset gets.
    next_asset_id: u64,
    /// The name whose next upload GitHub stores unfinished before it answers 502.
    unfinished_upload: Option<String>,
    /// Every asset that a DELETE removed, with the state of the Release at that moment.
    deletions: Vec<Deletion>,
    approval: Option<ApprovalAnswers>,
    requests: Vec<HttpRequest>,
    /// Whether the release list holds a second draft with the tag.
    duplicate_draft: bool,
}

/// One asset of the fake Release.
#[derive(Clone, Debug)]
struct FakeAsset {
    id: u64,
    name: String,
    /// `uploaded`, or `starter` for an upload that never finished.
    state: &'static str,
    media_type: String,
    bytes: Vec<u8>,
}

/// An asset that a DELETE removed.
#[derive(Clone, Debug)]
struct Deletion {
    id: u64,
    /// The asset's state when the DELETE removed it.
    state: &'static str,
    /// Whether the Release was a draft when the DELETE removed the asset.
    draft: bool,
}

/// What GitHub answers to the checks that approve a push release.
#[derive(Clone, Debug)]
struct ApprovalAnswers {
    /// The signed OIDC token of the publish job.
    token: String,
    /// The commit the release publishes, which the Release PR merged as.
    source_sha: String,
    /// The intent that the merged Release PR's marker recorded.
    intent: String,
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
        let state = Arc::new(Mutex::new(GitHubState {
            next_asset_id: 77,
            ..GitHubState::default()
        }));
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

    /// Hold a second draft with the release's tag, as an earlier run or another tool may have left one.
    fn duplicate_the_draft(&self) {
        let mut state = self.state.lock().unwrap();
        state.release_target = Some("a".repeat(40));
        state.draft = true;
        state.duplicate_draft = true;
    }

    /// Store the next upload of `name` unfinished and answer it with 502, as GitHub can when an upload breaks off.
    fn leave_unfinished(&self, name: &str) {
        self.state.lock().unwrap().unfinished_upload = Some(name.to_owned());
    }

    /// Hold the Release of the Candidate of `manifest`, a draft when `draft` holds, with an unfinished asset `name`.
    fn hold_release_with_unfinished_asset(
        &self,
        manifest: &release_glz::candidate::CandidateManifest,
        draft: bool,
        name: &str,
    ) {
        let mut state = self.state.lock().unwrap();
        state.release_target = Some(manifest.source.commit_sha.clone());
        state.candidate_digest = Some(manifest.candidate_digest.clone());
        state.draft = draft;
        let id = state.next_asset_id;
        state.next_asset_id += 1;
        state.assets.push(FakeAsset {
            id,
            name: name.to_owned(),
            state: "starter",
            media_type: "application/json".into(),
            bytes: b"{\"partial".to_vec(),
        });
    }

    fn asset(&self, name: &str) -> FakeAsset {
        self.state()
            .assets
            .into_iter()
            .find(|asset| asset.name == name)
            .unwrap_or_else(|| panic!("the fake Release has no asset `{name}`"))
    }

    /// Answer the approval checks of the push run that prepared the Candidate of `manifest`, with a merged Release PR that recorded `intent`.
    fn answer_approval(&self, manifest: &release_glz::candidate::CandidateManifest, intent: &str) {
        let claims = GithubOidcClaims {
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
            run_id: RUN.to_string(),
            run_attempt: "1".into(),
            event_name: "push".into(),
            issued_at: NOW - 1,
            not_before: Some(NOW - 1),
            expires_at: NOW + 60,
        };
        self.state.lock().unwrap().approval = Some(ApprovalAnswers {
            token: oidc::sign_rs256(&claims),
            source_sha: manifest.source.commit_sha.clone(),
            intent: intent.to_owned(),
        });
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
    if request.method == "GET"
        && let Some(approval) = &state.approval
        && let Some(response) = approval_response(approval, path, base_url)
    {
        return response;
    }
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
        // GitHub answers the tag endpoint only with a published Release, and lists drafts only to a token that can write.
        ("GET", "/repos/owner/widget/releases/tags/v1.2.3") => match &state.release_target {
            Some(_) if !state.draft => release_response(&state, base_url),
            _ => HttpResponse::bytes(404, vec![]),
        },
        ("GET", "/repos/owner/widget/releases") => {
            let mut releases = state
                .release_target
                .iter()
                .map(|_| release_json(&state, base_url))
                .collect::<Vec<_>>();
            if state.duplicate_draft {
                let mut second = release_json(&state, base_url);
                second["id"] = serde_json::json!(43);
                releases.push(second);
            }
            HttpResponse::json(200, serde_json::Value::Array(releases))
        }
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
            let name = github_asset_name(request.path.split("name=").nth(1).unwrap_or_default());
            // GitHub refuses a second asset with a name while the first one still holds it.
            if state.assets.iter().any(|asset| asset.name == name) {
                return HttpResponse::json(
                    422,
                    serde_json::json!({
                        "message": "Validation Failed",
                        "errors": [{"resource": "ReleaseAsset", "code": "already_exists", "field": "name"}]
                    }),
                );
            }
            let unfinished = state.unfinished_upload.as_deref() == Some(name.as_str());
            let asset = FakeAsset {
                id: state.next_asset_id,
                name,
                state: if unfinished { "starter" } else { "uploaded" },
                media_type: request
                    .headers
                    .get("content-type")
                    .cloned()
                    .unwrap_or_default(),
                bytes: request.body.clone(),
            };
            state.next_asset_id += 1;
            let answer = asset_json(&asset);
            state.assets.push(asset);
            if unfinished {
                state.unfinished_upload = None;
                return HttpResponse::json(502, serde_json::json!({"message": "Server Error"}));
            }
            HttpResponse::json(201, answer)
        }
        ("DELETE", path) if path.starts_with("/repos/owner/widget/releases/assets/") => {
            let id = path
                .rsplit('/')
                .next()
                .and_then(|id| id.parse::<u64>().ok());
            match state.assets.iter().position(|asset| Some(asset.id) == id) {
                Some(index) => {
                    let removed = state.assets.remove(index);
                    let draft = state.draft;
                    state.deletions.push(Deletion {
                        id: removed.id,
                        state: removed.state,
                        draft,
                    });
                    HttpResponse::bytes(204, vec![])
                }
                None => HttpResponse::json(404, serde_json::json!({"message": "Not Found"})),
            }
        }
        ("PATCH", "/repos/owner/widget/releases/42") => {
            state.draft = false;
            release_response(&state, base_url)
        }
        _ => panic!("unexpected GitHub request: {request:?}"),
    }
}

/// The name that the fake GitHub gives an asset uploaded as `requested`.
///
/// GitHub documents only that it renames a name with special characters or a leading or trailing `.`, so this models that rule.
/// It replaces every character outside ASCII letters, digits, `.`, `-`, and `_` with `.`, drops a trailing `.`, and puts `default` before a leading `.`.
fn github_asset_name(requested: &str) -> String {
    let replaced = requested
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '.'
            }
        })
        .collect::<String>();
    let trimmed = replaced.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.starts_with('.') {
        format!("default{trimmed}")
    } else {
        trimmed.to_owned()
    }
}

/// How GitHub lists `asset`, with a digest only once its upload finished, so an observation can't rely on the digest of an unfinished one.
fn asset_json(asset: &FakeAsset) -> serde_json::Value {
    let mut value = serde_json::json!({
        "id": asset.id,
        "name": asset.name,
        "state": asset.state,
        "content_type": asset.media_type,
        "size": asset.bytes.len()
    });
    if asset.state == "uploaded" {
        value["digest"] = serde_json::json!(format!(
            "sha256:{}",
            release_glz::hex::lower(&Sha256::digest(&asset.bytes))
        ));
    }
    value
}

/// GitHub's answer to one approval check, or `None` for a path that no approval check reads.
fn approval_response(
    approval: &ApprovalAnswers,
    path: &str,
    base_url: &str,
) -> Option<HttpResponse> {
    let files = release_pr_files();
    let digest = files_digest(&files);
    let head = release_pr_head();
    let value = match path {
        "/token" => serde_json::json!({"value": approval.token}),
        "/discovery" => serde_json::json!({
            "issuer": "https://token.actions.githubusercontent.com",
            "jwks_uri": format!("{base_url}/jwks")
        }),
        "/jwks" => serde_json::json!({"keys": [{
            "kty": "RSA",
            "kid": oidc::KEY_ID,
            "alg": "RS256",
            "use": "sig",
            "n": oidc::MODULUS,
            "e": oidc::EXPONENT
        }]}),
        "/repos/owner/widget/actions/artifacts/7" => serde_json::json!({
            "id": ARTIFACT,
            "name": format!("release-glz-candidate-{RUN}"),
            "size_in_bytes": 100,
            "expired": false,
            "digest": format!("sha256:{}", artifact_digest()),
            "workflow_run": {"id": RUN, "head_sha": approval.source_sha}
        }),
        "/repos/owner/widget/actions/runs/42" => serde_json::json!({
            "id": RUN,
            "path": ".github/workflows/release-glz.yml",
            "head_sha": approval.source_sha,
            "status": "in_progress",
            "conclusion": null,
            "repository": {"full_name": "owner/widget"}
        }),
        "/repos/owner/widget/git/blobs/0000000000000000000000000000000000000001" => {
            serde_json::json!({
                "content": base64::engine::general_purpose::STANDARD.encode(&files["CHANGELOG.md"]),
                "encoding": "base64",
                "size": files["CHANGELOG.md"].len()
            })
        }
        _ if path == format!("/repos/owner/widget/commits/{}/pulls", approval.source_sha) => {
            serde_json::json!([{
                "number": 7,
                "title": "chore(release): widget 1.2.3",
                "body": format!(
                    "<!-- release-glz:managed package=widget branch=release-glz/widget head={head} digest={digest} version=1.2.3 intent={} -->",
                    approval.intent
                ),
                "html_url": "https://github.test/owner/widget/pull/7",
                "merge_commit_sha": approval.source_sha,
                "merged_at": "2026-01-01T00:00:00Z",
                "user": {"login": "release-glz"},
                "labels": [],
                "head": {
                    "ref": "release-glz/widget",
                    "sha": head,
                    "repo": {"full_name": "owner/widget", "default_branch": "main"}
                },
                "base": {
                    "ref": "main",
                    "repo": {"full_name": "owner/widget", "default_branch": "main"}
                }
            }])
        }
        _ if path == format!("/repos/owner/widget/commits/{head}") => serde_json::json!({
            "commit": {
                "message": format!("chore(release): widget 1.2.3\n\nrelease-glz-digest: {digest}"),
                "verification": {"verified": true}
            },
            "parents": [{"sha": "0".repeat(40)}],
            "files": [{
                "filename": "CHANGELOG.md",
                "status": "modified",
                "sha": "0000000000000000000000000000000000000001"
            }]
        }),
        _ => return None,
    };
    Some(HttpResponse::json(200, value))
}

fn release_response(state: &GitHubState, base_url: &str) -> HttpResponse {
    HttpResponse::json(
        if state.draft { 201 } else { 200 },
        release_json(state, base_url),
    )
}

fn release_json(state: &GitHubState, base_url: &str) -> serde_json::Value {
    let assets = state.assets.iter().map(asset_json).collect::<Vec<_>>();
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
    })
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
    let checksum = release_glz::hex::upper(&digest.finalize());
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
