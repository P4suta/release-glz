use std::io::Write;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use anyhow::{Result, bail};
use async_trait::async_trait;
use flate2::{Compression, write::GzEncoder};
use release_glz::authorization::{
    GithubOidcClaims, OidcAudience, OidcExpectation, validate_github_claims,
};
use release_glz::candidate::{
    Candidate, CandidateInput, CandidateSource, HookEvidence, HookKind, RegistryIdentity,
};
use release_glz::config::{HookConfig, RegistryProvider};
use release_glz::hooks::SidecarArtifact;
use release_glz::model::ReleaseState;
use release_glz::reconciler::{
    ApprovalEvidence, ExternalReleaseState, NotifyObservation, ObservedArtifact,
    ObservedGithubRelease, ObservedTag, ReconcileEffect, ReleaseIntent,
};
use release_glz::release::{
    CandidateReleaseRunner, ReleaseExecutionOptions, ReleasePayload, ReleaseTarget,
};
use semver::Version;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn crash_after_docs_resumes_without_republishing_candidate_bytes() {
    let fixture = candidate_fixture();
    let target = FakeTarget::default();
    target.fail_once(ReconcileEffect::FinalizeGithubRelease, false);
    let runner = CandidateReleaseRunner::new(target.clone());
    let error = runner
        .run(
            &fixture.directory,
            &approved(&fixture.manifest),
            ReleaseExecutionOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.state(), ReleaseState::PartiallyReleased);

    let report = runner
        .run(
            &fixture.directory,
            &approved(&fixture.manifest),
            ReleaseExecutionOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(report.state, ReleaseState::Released);
    let applied = target.applied();
    assert_eq!(
        applied
            .iter()
            .filter(|effect| **effect == ReconcileEffect::PublishPackage)
            .count(),
        1
    );
    assert_eq!(
        applied
            .iter()
            .filter(|effect| **effect == ReconcileEffect::PublishDocs)
            .count(),
        1
    );
    assert_eq!(target.package_payloads(), vec![fixture.package]);
    assert_eq!(
        target.asset_payloads(),
        vec![("sbom.cdx.json".into(), br#"{"bom":"sealed"}"#.to_vec())]
    );
}

#[tokio::test]
async fn unknown_publish_response_is_reobserved_before_any_retry() {
    let fixture = candidate_fixture();
    let target = FakeTarget::default();
    target.fail_once(ReconcileEffect::PublishPackage, true);
    let report = CandidateReleaseRunner::new(target.clone())
        .run(
            &fixture.directory,
            &approved(&fixture.manifest),
            ReleaseExecutionOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(report.state, ReleaseState::Released);
    assert_eq!(
        target
            .applied()
            .iter()
            .filter(|effect| **effect == ReconcileEffect::PublishPackage)
            .count(),
        1
    );
}

#[tokio::test]
async fn dry_run_reports_every_effect_without_applying_any() {
    let fixture = candidate_fixture();
    let target = FakeTarget::default();
    let report = CandidateReleaseRunner::new(target.clone())
        .run(
            &fixture.directory,
            &approved(&fixture.manifest),
            ReleaseExecutionOptions { dry_run: true },
        )
        .await
        .unwrap();
    assert_eq!(report.state, ReleaseState::CandidateReady);
    assert_eq!(report.remaining.len(), 7);
    assert!(target.applied().is_empty());
}

#[tokio::test]
async fn optional_notify_is_attempted_once_but_failure_does_not_make_release_partial() {
    let fixture = candidate_fixture_with_notify(false);
    let target = FakeTarget::default();
    let effect = ReconcileEffect::Notify {
        hook_id: "announce".into(),
        idempotency_key: release_glz::reconciler::notification_key(
            &fixture.manifest.candidate_digest,
            "announce",
        ),
        required: false,
    };
    target.fail_once(effect.clone(), false);

    let report = CandidateReleaseRunner::new(target.clone())
        .run(
            &fixture.directory,
            &approved(&fixture.manifest),
            ReleaseExecutionOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(report.state, ReleaseState::Released);
    assert_eq!(
        target
            .attempts()
            .iter()
            .filter(|attempt| **attempt == effect)
            .count(),
        1
    );
}

#[tokio::test]
async fn public_release_asset_bytes_are_bound_to_their_sidecar_hook_and_name() {
    let fixture = candidate_fixture_with_options(true, true);
    let target = FakeTarget::default();

    let report = CandidateReleaseRunner::new(target.clone())
        .run(
            &fixture.directory,
            &approved(&fixture.manifest),
            ReleaseExecutionOptions::default(),
        )
        .await
        .unwrap();

    assert_eq!(report.state, ReleaseState::Released);
    assert_eq!(
        target.asset_payloads(),
        vec![("sbom.cdx.json".into(), br#"{"bom":"sealed"}"#.to_vec())]
    );
}

#[tokio::test]
async fn missing_approval_is_reported_without_applying_a_single_effect() {
    let fixture = candidate_fixture();
    let target = FakeTarget::default();
    let report = CandidateReleaseRunner::new(target.clone())
        .run(
            &fixture.directory,
            &ApprovalEvidence::default(),
            ReleaseExecutionOptions::default(),
        )
        .await
        .unwrap();
    assert_eq!(report.state, ReleaseState::AwaitingApproval);
    assert!(report.remaining.is_empty());
    assert!(report.applied.is_empty());
    assert!(target.attempts().is_empty());
}

#[tokio::test]
async fn an_invalid_candidate_and_an_existing_checksum_conflict_keep_their_exact_states() {
    let fixture = candidate_fixture();
    std::fs::write(fixture.directory.join("artifacts/package.tar"), b"tampered").unwrap();
    let error = CandidateReleaseRunner::new(FakeTarget::default())
        .run(
            &fixture.directory,
            &approved(&fixture.manifest),
            ReleaseExecutionOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.state(), ReleaseState::Blocked);
    assert!(error.to_string().contains("release blocked"));
    assert!(error.to_string().contains("checksum"));

    let fixture = candidate_fixture();
    let target = FakeTarget::default();
    target.inner.lock().unwrap().state.package = Some(ObservedArtifact {
        sha256: "0".repeat(64),
    });
    let error = CandidateReleaseRunner::new(target.clone())
        .run(
            &fixture.directory,
            &approved(&fixture.manifest),
            ReleaseExecutionOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.state(), ReleaseState::Conflict);
    assert!(error.to_string().contains("immutable state conflict"));
    assert!(target.attempts().is_empty());
}

#[tokio::test]
async fn a_required_notification_failure_is_partial_and_is_never_rolled_back() {
    let fixture = candidate_fixture_with_notify(true);
    let target = FakeTarget::default();
    let effect = ReconcileEffect::Notify {
        hook_id: "announce".into(),
        idempotency_key: release_glz::reconciler::notification_key(
            &fixture.manifest.candidate_digest,
            "announce",
        ),
        required: true,
    };
    target.fail_once(effect.clone(), false);
    let error = CandidateReleaseRunner::new(target.clone())
        .run(
            &fixture.directory,
            &approved(&fixture.manifest),
            ReleaseExecutionOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.state(), ReleaseState::PartiallyReleased);
    assert!(error.to_string().contains("partial release"));
    assert_eq!(target.attempts().last(), Some(&effect));
    assert!(target.inner.lock().unwrap().state.package.is_some());
}

#[tokio::test]
async fn an_observation_failure_after_an_ambiguous_effect_preserves_the_pre_effect_state() {
    let fixture = candidate_fixture();
    let target = ObserveFailsAfterApply {
        observations: AtomicUsize::new(0),
    };
    let error = CandidateReleaseRunner::new(target)
        .run(
            &fixture.directory,
            &approved(&fixture.manifest),
            ReleaseExecutionOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.state(), ReleaseState::CandidateReady);
    assert!(error.to_string().contains("release failed"));
    assert!(error.to_string().contains("observation unavailable"));
}

#[tokio::test]
async fn a_target_that_never_records_success_hits_the_fixed_convergence_limit() {
    let fixture = candidate_fixture();
    let attempts = Arc::new(AtomicUsize::new(0));
    let target = NonConvergingTarget {
        attempts: Arc::clone(&attempts),
    };
    let error = CandidateReleaseRunner::new(target)
        .run(
            &fixture.directory,
            &approved(&fixture.manifest),
            ReleaseExecutionOptions::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(attempts.load(Ordering::SeqCst), 128);
    assert_eq!(error.state(), ReleaseState::Blocked);
    assert!(error.to_string().contains("did not converge"));
}

struct ObserveFailsAfterApply {
    observations: AtomicUsize,
}

#[async_trait]
impl ReleaseTarget for ObserveFailsAfterApply {
    async fn observe(&self, _intent: &ReleaseIntent) -> Result<ExternalReleaseState> {
        if self.observations.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(ExternalReleaseState::default())
        } else {
            bail!("observation unavailable")
        }
    }

    async fn apply(
        &self,
        _effect: &ReconcileEffect,
        _intent: &ReleaseIntent,
        _payload: ReleasePayload<'_>,
    ) -> Result<()> {
        bail!("ambiguous apply failure")
    }
}

struct NonConvergingTarget {
    attempts: Arc<AtomicUsize>,
}

#[async_trait]
impl ReleaseTarget for NonConvergingTarget {
    async fn observe(&self, _intent: &ReleaseIntent) -> Result<ExternalReleaseState> {
        Ok(ExternalReleaseState::default())
    }

    async fn apply(
        &self,
        _effect: &ReconcileEffect,
        _intent: &ReleaseIntent,
        _payload: ReleasePayload<'_>,
    ) -> Result<()> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Clone, Default)]
struct FakeTarget {
    inner: Arc<Mutex<FakeInner>>,
}

#[derive(Default)]
struct FakeInner {
    state: ExternalReleaseState,
    attempts: Vec<ReconcileEffect>,
    applied: Vec<ReconcileEffect>,
    package_payloads: Vec<Vec<u8>>,
    asset_payloads: Vec<(String, Vec<u8>)>,
    fail: Option<(ReconcileEffect, bool)>,
}

impl FakeTarget {
    fn fail_once(&self, effect: ReconcileEffect, apply_before_error: bool) {
        self.inner.lock().unwrap().fail = Some((effect, apply_before_error));
    }

    fn applied(&self) -> Vec<ReconcileEffect> {
        self.inner.lock().unwrap().applied.clone()
    }

    fn attempts(&self) -> Vec<ReconcileEffect> {
        self.inner.lock().unwrap().attempts.clone()
    }

    fn package_payloads(&self) -> Vec<Vec<u8>> {
        self.inner.lock().unwrap().package_payloads.clone()
    }

    fn asset_payloads(&self) -> Vec<(String, Vec<u8>)> {
        self.inner.lock().unwrap().asset_payloads.clone()
    }
}

#[async_trait]
impl ReleaseTarget for FakeTarget {
    async fn observe(&self, _intent: &ReleaseIntent) -> Result<ExternalReleaseState> {
        Ok(self.inner.lock().unwrap().state.clone())
    }

    async fn apply(
        &self,
        effect: &ReconcileEffect,
        intent: &ReleaseIntent,
        payload: ReleasePayload<'_>,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.attempts.push(effect.clone());
        let failure = if inner
            .fail
            .as_ref()
            .is_some_and(|(expected, _)| expected == effect)
        {
            inner.fail.take()
        } else {
            None
        };
        if failure.as_ref().is_some_and(|(_, apply)| !apply) {
            bail!("injected crash");
        }
        inner.applied.push(effect.clone());
        match effect {
            ReconcileEffect::PrepareAnnotatedTag => {
                inner.state.tag = Some(ObservedTag {
                    target_sha: intent.source_sha.clone(),
                    annotated: true,
                });
            }
            ReconcileEffect::PrepareGithubDraft => {
                inner.state.github_release = Some(ObservedGithubRelease {
                    target_sha: intent.source_sha.clone(),
                    candidate_digest: intent.candidate_digest.clone(),
                    draft: true,
                });
            }
            ReconcileEffect::PublishPackage => {
                inner.package_payloads.push(payload.package.to_vec());
                inner.state.package = Some(ObservedArtifact {
                    sha256: intent.package_sha256.clone(),
                });
            }
            ReconcileEffect::PublishDocs => {
                assert_eq!(payload.docs.unwrap(), fixture_docs().as_slice());
                inner.state.docs = Some(ObservedArtifact {
                    sha256: intent.docs_sha256.clone().unwrap(),
                });
            }
            ReconcileEffect::UploadGithubAsset {
                hook_id,
                name,
                sha256,
            } => {
                let asset = payload
                    .release_assets
                    .iter()
                    .find(|asset| asset.hook_id == hook_id.as_str() && asset.name == name.as_str())
                    .unwrap();
                assert_eq!(format!("{:x}", Sha256::digest(asset.bytes)), *sha256);
                inner
                    .asset_payloads
                    .push((name.clone(), asset.bytes.to_vec()));
                inner.state.release_assets.insert(
                    name.clone(),
                    ObservedArtifact {
                        sha256: sha256.clone(),
                    },
                );
            }
            ReconcileEffect::FinalizeGithubRelease => {
                inner.state.github_release.as_mut().unwrap().draft = false;
            }
            ReconcileEffect::Notify {
                hook_id,
                idempotency_key,
                ..
            } => {
                inner.state.notifications.insert(
                    hook_id.clone(),
                    NotifyObservation {
                        idempotency_key: idempotency_key.clone(),
                        complete: true,
                    },
                );
            }
        }
        if failure.is_some() {
            bail!("ambiguous injected response");
        }
        Ok(())
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    directory: std::path::PathBuf,
    manifest: release_glz::candidate::CandidateManifest,
    package: Vec<u8>,
}

fn candidate_fixture() -> Fixture {
    candidate_fixture_with_notify(true)
}

fn candidate_fixture_with_notify(notify_required: bool) -> Fixture {
    candidate_fixture_with_options(notify_required, false)
}

fn candidate_fixture_with_options(notify_required: bool, duplicate_private_asset: bool) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("candidate");
    let package = hex_package();
    let mut sidecar_hook_definitions = Vec::new();
    let mut hook_evidence = Vec::new();
    let mut sidecars = Vec::new();
    if duplicate_private_asset {
        sidecar_hook_definitions.push(HookConfig {
            id: "private-evidence".into(),
            argv: vec!["/bin/true".into()],
            timeout_seconds: 10,
            required: true,
            env: vec![],
        });
        hook_evidence.push(HookEvidence {
            schema: "hook/v1".into(),
            id: "private-evidence".into(),
            kind: HookKind::Sidecar,
            required: true,
            success: true,
            output_sha256: "8".repeat(64),
        });
        sidecars.push(SidecarArtifact {
            hook_id: "private-evidence".into(),
            name: "sbom.cdx.json".into(),
            media_type: "application/vnd.cyclonedx+json".into(),
            bytes: br#"{"bom":"private"}"#.to_vec(),
            public: false,
        });
    }
    sidecar_hook_definitions.push(HookConfig {
        id: "sbom".into(),
        argv: vec!["/bin/true".into()],
        timeout_seconds: 10,
        required: true,
        env: vec![],
    });
    hook_evidence.push(HookEvidence {
        schema: "hook/v1".into(),
        id: "sbom".into(),
        kind: HookKind::Sidecar,
        required: true,
        success: true,
        output_sha256: "9".repeat(64),
    });
    sidecars.push(SidecarArtifact {
        hook_id: "sbom".into(),
        name: "sbom.cdx.json".into(),
        media_type: "application/vnd.cyclonedx+json".into(),
        bytes: br#"{"bom":"sealed"}"#.to_vec(),
        public: true,
    });
    let manifest = Candidate::seal(
        &directory,
        CandidateInput {
            package: "widget".into(),
            version: Version::new(1, 2, 3),
            tag: "v1.2.3".into(),
            source: CandidateSource {
                commit_sha: "a".repeat(40),
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
                auth: release_glz::config::AuthKind::HexToken,
                allow_http_loopback: false,
            },
            private: false,
            github_repository: "owner/widget".into(),
            release_branch_prefix: "release-glz/".into(),
            release_notes: "Widget release notes.".into(),
            approval: release_glz::config::ApprovalConfig::default(),
            outputs: release_glz::config::OutputConfig {
                sbom: false,
                provenance: false,
                ..release_glz::config::OutputConfig::default()
            },
            package_tarball: package.clone(),
            docs_tarball: Some(fixture_docs()),
            package_interface: br#"{"modules":{}}"#.to_vec(),
            verify_hook_definitions: vec![],
            sidecar_hook_definitions,
            hook_evidence,
            sidecars,
            notify_hooks: vec!["announce".into()],
            notify_hook_definitions: vec![release_glz::config::HookConfig {
                id: "announce".into(),
                argv: vec!["/bin/true".into()],
                timeout_seconds: 10,
                required: notify_required,
                env: vec![],
            }],
        },
    )
    .unwrap();
    Fixture {
        _temp: temp,
        directory,
        manifest,
        package,
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
        environment: Some("release".into()),
        source_sha: None,
        manual_reason: None,
        github_oidc: Some(github_oidc),
    }
}

fn fixture_docs() -> Vec<u8> {
    tar_gz(&[("index.html", b"docs")])
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

fn append<W: Write>(archive: &mut tar::Builder<W>, path: &str, contents: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(contents.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive.append_data(&mut header, path, contents).unwrap();
}
