use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use release_glz::config::HookConfig;
use release_glz::failure::{RefusalReason, refusal_reason};
use release_glz::hooks::{HookContext, HookRunner};
use release_glz_test_support::fake_tool::{self, Action, Behavior, Condition, Rule, Stream};
use semver::Version;

/// Seconds a hook that exits by itself may run, which leave a loaded machine time to start it.
const FINISHES: u64 = 30;

/// Seconds a hook that leaves a child holding its pipes may run, which leave it time to start that child before the timeout.
const STARTS_ITS_CHILD: u64 = 10;

/// A successful `hook/v1` answer with empty evidence.
const OK: &str = r#"{"schema":"hook/v1","success":true,"summary":"ok","evidence":{}}"#;

/// A successful `hook/v1` answer from a hook that changed the snapshot.
const BAD: &str = r#"{"schema":"hook/v1","success":true,"summary":"bad","evidence":{}}"#;

#[tokio::test]
async fn verify_hook_uses_json_stdio_and_records_v1_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "pub fn main() { Nil }\n").unwrap();
    let hook = fake_tool::install(
        tools.path(),
        "verify",
        &Behavior {
            rules: vec![Rule {
                when: vec![Condition::InputContains(r#""schema":"hook/v1""#.into())],
                actions: vec![Action::Stdout(
                    r#"{"schema":"hook/v1","success":true,"summary":"verified","evidence":{"policy":"ok"}}"#
                        .into(),
                )],
            }],
        },
    );
    let evidence = HookRunner::default()
        .run_verify(
            &[HookConfig {
                id: "policy".into(),
                argv: vec![hook.to_string_lossy().into_owned()],
                timeout_seconds: FINISHES,
                required: true,
                env: vec![],
            }],
            temp.path(),
            &context(),
        )
        .await
        .unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].schema, "hook/v1");
    assert_eq!(evidence[0].id, "policy");
    assert!(evidence[0].success);
    assert_eq!(evidence[0].output_sha256.len(), 64);
}

#[tokio::test]
async fn a_later_verify_hook_cannot_mutate_the_snapshot_either() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let quiet = printing(tools.path(), "quiet", OK);
    let mutator = mutating(tools.path(), "late-mutate", BAD);
    let error = HookRunner::default()
        .run_verify(
            &[
                required("quiet", &quiet, FINISHES),
                required("mutator", &mutator, FINISHES),
            ],
            temp.path(),
            &context(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::HookSnapshotModified)
    );
    assert!(error.to_string().contains("modified the source snapshot"));
}

#[tokio::test]
async fn a_later_sidecar_hook_cannot_mutate_the_snapshot_either() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let quiet = printing(tools.path(), "quiet-sidecar", OK);
    let mutator = mutating(tools.path(), "late-mutate-sidecar", BAD);
    let error = HookRunner::default()
        .run_sidecars(
            &[
                required("quiet", &quiet, FINISHES),
                required("mutator", &mutator, FINISHES),
            ],
            temp.path(),
            &context(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::HookSnapshotModified)
    );
    assert!(error.to_string().contains("modified the source snapshot"));
}

#[tokio::test]
async fn verify_hook_cannot_mutate_the_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let hook = mutating(tools.path(), "mutate", BAD);
    let error = HookRunner::default()
        .run_verify(
            &[required("mutator", &hook, FINISHES)],
            temp.path(),
            &context(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::HookSnapshotModified)
    );
    assert!(error.to_string().contains("modified the source snapshot"));
}

#[tokio::test]
async fn required_hook_timeout_is_bounded_and_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let hook = fake_tool::install(
        tools.path(),
        "slow",
        &Behavior::always(vec![Action::Sleep(60)]),
    );
    let started = Instant::now();
    let error = HookRunner::default()
        .run_verify(&[required("slow", &hook, 1)], temp.path(), &context())
        .await
        .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(30));
    assert_eq!(refusal_reason(&error), Some(RefusalReason::HookTimedOut));
    assert!(error.to_string().contains("timed out"));
}

/// The hook leads a process group on Unix and runs in a job object on Windows, and either way the timeout ends the child it left behind.
#[tokio::test]
async fn hook_timeout_ends_the_whole_process_tree_that_holds_its_pipes() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let pid_file = tools.path().join("grandchild.pid");
    let lingering = fake_tool::install(
        tools.path(),
        "lingering",
        &Behavior::always(vec![Action::Sleep(60)]),
    );
    let hook = fake_tool::install(
        tools.path(),
        "inherited-pipe",
        &Behavior::always(vec![
            Action::SpawnHoldingPipes {
                program: lingering,
                pid_file: pid_file.clone(),
            },
            Action::Stdout(
                r#"{"schema":"hook/v1","success":true,"summary":"direct child exited","evidence":{}}"#
                    .into(),
            ),
        ]),
    );
    let started = Instant::now();
    let error = HookRunner::default()
        .run_verify(
            &[required("inherited-pipe", &hook, STARTS_ITS_CHILD)],
            temp.path(),
            &context(),
        )
        .await
        .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(60));
    assert_eq!(refusal_reason(&error), Some(RefusalReason::HookTimedOut));
    let error = error.to_string();
    assert!(error.contains("timed out"), "{error}");

    let grandchild =
        fs::read_to_string(&pid_file).expect("the hook started its child before the timeout");
    let deadline = Instant::now() + Duration::from_secs(30);
    while process_is_alive(&grandchild) {
        assert!(
            Instant::now() < deadline,
            "grandchild {grandchild} outlived the timed-out hook"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Whether a process still runs, checked without an external `kill` program.
#[cfg(unix)]
fn process_is_alive(pid: &str) -> bool {
    let pid = rustix::process::Pid::from_raw(pid.parse().unwrap()).unwrap();
    if rustix::process::test_kill_process(pid).is_err() {
        return false;
    }
    // A killed process stays a zombie until its new parent reaps it, and a container's first process may never do that.
    #[cfg(target_os = "linux")]
    if let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", pid.as_raw_nonzero())) {
        return stat
            .rsplit_once(')')
            .and_then(|(_, fields)| fields.split_whitespace().next())
            != Some("Z");
    }
    true
}

/// Whether a process still runs, as the task list reports it.
#[cfg(windows)]
fn process_is_alive(pid: &str) -> bool {
    let tasklist = PathBuf::from(std::env::var_os("SystemRoot").expect("Windows sets SystemRoot"))
        .join("System32")
        .join("tasklist.exe");
    let output = std::process::Command::new(tasklist)
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8_lossy(&output.stdout).contains(&format!("\"{pid}\""))
}

#[tokio::test]
async fn optional_notify_execution_errors_are_observed_as_incomplete() {
    let temp = tempfile::tempdir().unwrap();
    let hook = temp.path().join("missing-optional-notify");
    assert!(
        !HookRunner::default()
            .observe_notify(
                &optional("notify", &hook, FINISHES),
                temp.path(),
                &context()
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn undeclared_environment_is_not_forwarded() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let record = tools.path().join("environment.json");
    let hook = fake_tool::install(
        tools.path(),
        "env",
        &Behavior::always(vec![
            Action::RecordEnvironment(record.clone()),
            Action::Stdout(OK.into()),
        ]),
    );
    assert!(
        std::env::var_os("PATH").is_some(),
        "the runner's own environment holds PATH"
    );
    HookRunner::default()
        .run_verify(&[required("env", &hook, FINISHES)], temp.path(), &context())
        .await
        .unwrap();
    let recorded: BTreeMap<String, String> =
        serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
    assert!(recorded.is_empty(), "{recorded:?}");
}

#[tokio::test]
async fn protected_authorization_environment_is_rejected_at_the_runner_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let hook = printing(tools.path(), "protected-env", OK);
    let mut configured = required("protected-env", &hook, FINISHES);
    configured.env = vec!["GITHUB_TOKEN".into()];
    let error = HookRunner::default()
        .run_verify(&[configured], temp.path(), &context())
        .await
        .unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::HookEnvProtected)
    );
    let error = error.to_string();
    assert!(error.contains("may not receive"), "{error}");
}

#[tokio::test]
async fn notify_hooks_have_separate_idempotent_observe_and_apply_phases() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    let observe = || Condition::InputContains(r#""phase":"observe""#.into());
    let observed = |complete: bool| {
        Action::Stdout(format!(
            r#"{{"schema":"hook/v1","success":true,"summary":"observed","evidence":{{"complete":{complete}}}}}"#
        ))
    };
    let hook = fake_tool::install(
        tools.path(),
        "notify",
        &Behavior {
            rules: vec![
                Rule {
                    when: vec![observe(), Condition::FileExists("delivered".into())],
                    actions: vec![observed(true)],
                },
                Rule {
                    when: vec![observe()],
                    actions: vec![observed(false)],
                },
                Rule {
                    when: vec![Condition::InputContains(r#""phase":"apply""#.into())],
                    actions: vec![
                        Action::Write {
                            path: "delivered".into(),
                            contents: "delivered".into(),
                        },
                        Action::Stdout(
                            r#"{"schema":"hook/v1","success":true,"summary":"notified","evidence":{}}"#
                                .into(),
                        ),
                    ],
                },
            ],
        },
    );
    let hook = required("announce", &hook, FINISHES);
    let mut context = context();
    context.candidate_digest = Some("c".repeat(64));
    context.idempotency_key = Some("k".repeat(64));
    let runner = HookRunner::default();

    assert!(
        !runner
            .observe_notify(&hook, temp.path(), &context)
            .await
            .unwrap()
    );
    runner
        .apply_notify(&hook, temp.path(), &context)
        .await
        .unwrap();
    assert!(
        runner
            .observe_notify(&hook, temp.path(), &context)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn sidecar_hooks_return_bounded_artifacts_without_mutating_the_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let hook = fake_tool::install(
        tools.path(),
        "sidecar",
        &Behavior {
            rules: vec![Rule {
                when: vec![Condition::InputContains(r#""phase":"sidecar""#.into())],
                actions: vec![Action::Stdout(
                    r#"{"schema":"hook/v1","success":true,"summary":"sbom","evidence":{"artifacts":[{"name":"sbom.cdx.json","media_type":"application/vnd.cyclonedx+json","content_base64":"eyJib20iOiJvayJ9","public":true}]}}"#
                        .into(),
                )],
            }],
        },
    );
    let result = HookRunner::default()
        .run_sidecars(
            &[required("sbom", &hook, FINISHES)],
            temp.path(),
            &context(),
        )
        .await
        .unwrap();
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(
        result.evidence[0].kind,
        release_glz::candidate::HookKind::Sidecar
    );
    assert_eq!(result.artifacts.len(), 1);
    assert_eq!(result.artifacts[0].hook_id, "sbom");
    assert_eq!(result.artifacts[0].name, "sbom.cdx.json");
    assert_eq!(result.artifacts[0].bytes, br#"{"bom":"ok"}"#);
    assert!(result.artifacts[0].public);
    assert_eq!(
        fs::read_to_string(temp.path().join("source.gleam")).unwrap(),
        "before"
    );
}

#[tokio::test]
async fn sidecar_asset_names_must_be_publishable_basenames() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let hook = printing(
        tools.path(),
        "nested-sidecar",
        r#"{"schema":"hook/v1","success":true,"summary":"nested","evidence":{"artifacts":[{"name":"nested/evidence.json","media_type":"application/json","content_base64":"e30="}]}}"#,
    );

    let error = HookRunner::default()
        .run_sidecars(
            &[required("evidence", &hook, FINISHES)],
            temp.path(),
            &context(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::SidecarNameUnsafe)
    );
    let error = error.to_string();
    assert!(error.contains("safe asset name"), "{error}");
}

#[tokio::test]
async fn sidecar_protocol_rejects_unknown_evidence_and_artifact_fields() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let cases = [
        (
            "evidence-field",
            r#"{"schema":"hook/v1","success":true,"summary":"extra","evidence":{"artifacts":[],"unexpected":true}}"#,
        ),
        (
            "artifact-field",
            r#"{"schema":"hook/v1","success":true,"summary":"extra","evidence":{"artifacts":[{"name":"evidence.json","media_type":"application/json","content_base64":"e30=","unexpected":true}]}}"#,
        ),
    ];

    for (name, output) in cases {
        let hook = printing(tools.path(), name, output);
        let error = HookRunner::default()
            .run_sidecars(
                &[required("evidence", &hook, FINISHES)],
                temp.path(),
                &context(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::SidecarArtifactsInvalid),
            "{name}"
        );
        let error = error.to_string();
        assert!(error.contains("invalid artifacts"), "{name}: {error}");
    }
}

#[tokio::test]
async fn verify_failures_preserve_required_and_optional_policy() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let reported = printing(
        tools.path(),
        "reported-failure",
        r#"{"schema":"hook/v1","success":false,"summary":"denied","evidence":{}}"#,
    );
    let invalid = printing(tools.path(), "invalid-json", "not-json");
    let nonzero = fake_tool::install(
        tools.path(),
        "nonzero",
        &Behavior::always(vec![Action::Exit(17)]),
    );
    let runner = HookRunner::default();

    for (name, hook, reason, expected) in [
        (
            "reported",
            &reported,
            RefusalReason::HookReportedFailure,
            "reported failure",
        ),
        (
            "invalid",
            &invalid,
            RefusalReason::HookOutputInvalid,
            "invalid JSON",
        ),
        (
            "nonzero",
            &nonzero,
            RefusalReason::HookReportedFailure,
            "reported failure",
        ),
    ] {
        let error = runner
            .run_verify(&[required(name, hook, FINISHES)], temp.path(), &context())
            .await
            .unwrap_err();
        assert_eq!(refusal_reason(&error), Some(reason), "{name}");
        let error = error.to_string();
        assert!(error.contains(expected), "{name}: {error}");

        let evidence = runner
            .run_verify(&[optional(name, hook, FINISHES)], temp.path(), &context())
            .await
            .unwrap();
        assert_eq!(evidence.len(), 1, "{name}");
        assert!(!evidence[0].required, "{name}");
        assert!(!evidence[0].success, "{name}");
        assert_eq!(evidence[0].output_sha256.len(), 64, "{name}");
    }
}

#[tokio::test]
async fn hook_output_protocol_is_strict_at_every_field() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let cases = [
        ("invalid", "not-json", "invalid JSON"),
        (
            "schema",
            r#"{"schema":"hook/v2","success":true,"summary":"ok","evidence":{}}"#,
            "unsupported schema",
        ),
        (
            "summary",
            r#"{"schema":"hook/v1","success":true,"summary":"  ","evidence":{}}"#,
            "empty summary",
        ),
        (
            "evidence",
            r#"{"schema":"hook/v1","success":true,"summary":"ok","evidence":[]}"#,
            "evidence must be a JSON object",
        ),
        (
            "unknown",
            r#"{"schema":"hook/v1","success":true,"summary":"ok","evidence":{},"unexpected":true}"#,
            "invalid JSON",
        ),
        (
            "positional.sh",
            r#"["hook/v1",true,"ok",{}]"#,
            "output must be a JSON object",
        ),
    ];
    let runner = HookRunner::default();
    for (name, output, expected) in cases {
        // A hook that lost its argument would match no rule and fail with a nonzero exit instead of its output.
        let hook = fake_tool::install(
            tools.path(),
            name,
            &Behavior {
                rules: vec![Rule {
                    when: vec![Condition::ArgumentsStartWith(vec![
                        "--case".into(),
                        name.into(),
                    ])],
                    actions: vec![Action::Stdout(output.into())],
                }],
            },
        );
        let hook = HookConfig {
            id: "protocol".into(),
            argv: vec![
                hook.to_string_lossy().into_owned(),
                "--case".into(),
                name.into(),
            ],
            timeout_seconds: FINISHES,
            required: true,
            env: vec![],
        };
        let error = runner
            .run_verify(&[hook], temp.path(), &context())
            .await
            .unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::HookOutputInvalid),
            "{name}"
        );
        let error = error.to_string();
        assert!(error.contains(expected), "{name}: {error}");
    }

    let empty_argv = HookConfig {
        id: "empty".into(),
        argv: vec![],
        timeout_seconds: FINISHES,
        required: true,
        env: vec![],
    };
    let error = runner
        .run_verify(&[empty_argv], temp.path(), &context())
        .await
        .unwrap_err();
    assert_eq!(refusal_reason(&error), Some(RefusalReason::HookArgvInvalid));
    let error = error.to_string();
    assert!(error.contains("non-empty NUL-free argv"), "{error}");
}

#[tokio::test]
async fn declared_environment_reaches_a_hook_over_a_nested_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::create_dir_all(temp.path().join("nested/deeper")).unwrap();
    fs::write(temp.path().join("nested/deeper/source.gleam"), "before").unwrap();
    let hook = declared_environment_hook(tools.path());
    let mut configured = required("declared", &hook, FINISHES);
    configured.env = vec!["CARGO_MANIFEST_DIR".into()];
    HookRunner::default()
        .run_verify(&[configured], temp.path(), &context())
        .await
        .unwrap();
}

/// A symbolic link in the snapshot is refused, and only Unix creates one without a privilege.
#[cfg(unix)]
#[tokio::test]
async fn a_symbolic_link_in_the_snapshot_is_refused_as_a_non_regular_entry() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::create_dir_all(temp.path().join("nested/deeper")).unwrap();
    fs::write(temp.path().join("nested/deeper/source.gleam"), "before").unwrap();
    let hook = declared_environment_hook(tools.path());
    std::os::unix::fs::symlink(
        "nested/deeper/source.gleam",
        temp.path().join("source-link"),
    )
    .unwrap();
    let error = HookRunner::default()
        .run_verify(
            &[required("declared", &hook, FINISHES)],
            temp.path(),
            &context(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::HookSnapshotEntryNotRegular)
    );
    let error = error.to_string();
    assert!(error.contains("non-regular entry"), "{error}");
}

/// A hook that succeeds only when `CARGO_MANIFEST_DIR` reaches it.
fn declared_environment_hook(tools: &Path) -> PathBuf {
    fake_tool::install(
        tools,
        "declared-env",
        &Behavior {
            rules: vec![Rule {
                when: vec![Condition::EnvironmentHas("CARGO_MANIFEST_DIR".into())],
                actions: vec![Action::Stdout(
                    r#"{"schema":"hook/v1","success":true,"summary":"declared","evidence":{}}"#
                        .into(),
                )],
            }],
        },
    )
}

#[tokio::test]
async fn stdout_and_stderr_are_streamed_but_strictly_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let stdout = fake_tool::install(
        tools.path(),
        "large-stdout",
        &Behavior::always(vec![Action::Zeros {
            stream: Stream::Stdout,
            count: 1_048_577,
        }]),
    );
    let stderr = fake_tool::install(
        tools.path(),
        "large-stderr",
        &Behavior::always(vec![
            Action::Zeros {
                stream: Stream::Stderr,
                count: 262_145,
            },
            Action::Stdout(OK.into()),
        ]),
    );
    let runner = HookRunner::default();
    for (name, hook) in [("stdout", stdout), ("stderr", stderr)] {
        let error = runner
            .run_verify(&[required(name, &hook, FINISHES)], temp.path(), &context())
            .await
            .unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::HookOutputLimitExceeded),
            "{name}"
        );
        let error = error.to_string();
        assert!(error.contains("output limit"), "{name}: {error}");
    }
}

#[tokio::test]
async fn sidecar_failures_preserve_policy_and_snapshot_immutability() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let reported = printing(
        tools.path(),
        "sidecar-reported",
        r#"{"schema":"hook/v1","success":false,"summary":"none","evidence":{}}"#,
    );
    let invalid = printing(tools.path(), "sidecar-invalid", "invalid");
    let mutating = mutating(
        tools.path(),
        "sidecar-mutating",
        r#"{"schema":"hook/v1","success":true,"summary":"bad","evidence":{"artifacts":[]}}"#,
    );
    let runner = HookRunner::default();

    let error = runner
        .run_sidecars(
            &[required("reported", &reported, FINISHES)],
            temp.path(),
            &context(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::HookReportedFailure)
    );
    let error = error.to_string();
    assert!(error.contains("reported failure"), "{error}");
    let result = runner
        .run_sidecars(
            &[optional("reported", &reported, FINISHES)],
            temp.path(),
            &context(),
        )
        .await
        .unwrap();
    assert!(!result.evidence[0].success);
    assert!(result.artifacts.is_empty());

    let result = runner
        .run_sidecars(
            &[optional("invalid", &invalid, FINISHES)],
            temp.path(),
            &context(),
        )
        .await
        .unwrap();
    assert!(!result.evidence[0].success);

    let error = runner
        .run_sidecars(
            &[required("mutating", &mutating, FINISHES)],
            temp.path(),
            &context(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::HookSnapshotModified)
    );
    let error = error.to_string();
    assert!(error.contains("modified the source snapshot"), "{error}");
}

#[tokio::test]
async fn sidecar_artifact_protocol_rejects_every_unsafe_shape() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let cases = [
        (
            "shape",
            r#"{"artifacts":"not-an-array"}"#,
            RefusalReason::SidecarArtifactsInvalid,
            "invalid artifacts",
        ),
        (
            "name",
            r#"{"artifacts":[{"name":"../escape","media_type":"application/json","content_base64":"e30="}]}"#,
            RefusalReason::SidecarNameUnsafe,
            "safe asset name",
        ),
        (
            "parent-name",
            r#"{"artifacts":[{"name":"..","media_type":"application/json","content_base64":"e30="}]}"#,
            RefusalReason::SidecarNameUnsafe,
            "safe asset name",
        ),
        (
            "media",
            r#"{"artifacts":[{"name":"evidence.json","media_type":"json","content_base64":"e30="}]}"#,
            RefusalReason::SidecarMediaTypeInvalid,
            "media type",
        ),
        (
            "control-media",
            r#"{"artifacts":[{"name":"evidence.json","media_type":"application/\u007f","content_base64":"e30="}]}"#,
            RefusalReason::SidecarMediaTypeInvalid,
            "media type",
        ),
        (
            "long-media",
            r#"{"artifacts":[{"name":"evidence.json","media_type":"application/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","content_base64":"e30="}]}"#,
            RefusalReason::SidecarMediaTypeInvalid,
            "media type",
        ),
        (
            "base64",
            r#"{"artifacts":[{"name":"evidence.json","media_type":"application/json","content_base64":"%%%"}]}"#,
            RefusalReason::SidecarArtifactsInvalid,
            "valid base64",
        ),
        (
            "duplicate",
            r#"{"artifacts":[{"name":"evidence.json","media_type":"application/json","content_base64":"e30="},{"name":"evidence.json","media_type":"application/json","content_base64":"e30="}]}"#,
            RefusalReason::SidecarArtifactsInvalid,
            "duplicate artifact",
        ),
        (
            "positional.sh",
            r#"{"artifacts":[["evidence.json","application/json","e30=",true]]}"#,
            RefusalReason::SidecarArtifactsInvalid,
            "artifact must be a JSON object",
        ),
    ];
    let runner = HookRunner::default();
    for (name, evidence, reason, expected) in cases {
        let output = format!(
            "{{\"schema\":\"hook/v1\",\"success\":true,\"summary\":\"case\",\"evidence\":{evidence}}}"
        );
        let hook = printing(tools.path(), name, &output);
        let error = runner
            .run_sidecars(
                &[required("evidence", &hook, FINISHES)],
                temp.path(),
                &context(),
            )
            .await
            .unwrap_err();
        assert_eq!(refusal_reason(&error), Some(reason), "{name}");
        let error = error.to_string();
        assert!(error.contains(expected), "{name}: {error}");
    }

    let artifacts = (0..65)
        .map(|index| {
            serde_json::json!({
                "name": format!("evidence-{index}.json"),
                "media_type": "application/json",
                "content_base64": "e30="
            })
        })
        .collect::<Vec<_>>();
    let output = serde_json::json!({
        "schema": "hook/v1",
        "success": true,
        "summary": "too many",
        "evidence": {"artifacts": artifacts}
    })
    .to_string();
    let hook = printing(tools.path(), "count", &output);
    let error = runner
        .run_sidecars(
            &[required("evidence", &hook, FINISHES)],
            temp.path(),
            &context(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::SidecarArtifactsLimitExceeded)
    );
    let error = error.to_string();
    assert!(error.contains("count limit"), "{error}");
}

#[tokio::test]
async fn notify_failure_and_observation_shapes_are_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let tools = tempfile::tempdir().unwrap();
    let failed = printing(
        tools.path(),
        "notify-failed",
        r#"{"schema":"hook/v1","success":false,"summary":"failed","evidence":{}}"#,
    );
    let missing = printing(
        tools.path(),
        "notify-missing",
        r#"{"schema":"hook/v1","success":true,"summary":"missing","evidence":{}}"#,
    );
    let wrong = printing(
        tools.path(),
        "notify-wrong",
        r#"{"schema":"hook/v1","success":true,"summary":"wrong","evidence":{"complete":"yes"}}"#,
    );
    let runner = HookRunner::default();

    let error = runner
        .observe_notify(
            &required("notify", &failed, FINISHES),
            temp.path(),
            &context(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::HookObservationFailed)
    );
    let error = error.to_string();
    assert!(error.contains("could not observe"), "{error}");
    assert!(
        !runner
            .observe_notify(
                &optional("notify", &failed, FINISHES),
                temp.path(),
                &context()
            )
            .await
            .unwrap()
    );
    let error = runner
        .apply_notify(
            &optional("notify", &failed, FINISHES),
            temp.path(),
            &context(),
        )
        .await
        .unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::HookReportedFailure)
    );
    let error = error.to_string();
    assert!(error.contains("apply failure"), "{error}");

    for hook in [missing, wrong] {
        let error = runner
            .observe_notify(
                &required("notify", &hook, FINISHES),
                temp.path(),
                &context(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::HookOutputInvalid)
        );
        let error = error.to_string();
        assert!(error.contains("boolean `complete`"), "{error}");
    }
}

fn context() -> HookContext {
    HookContext {
        package: "widget".into(),
        version: Version::new(1, 2, 3),
        source_sha: "a".repeat(40),
        intent_digest: None,
        candidate_digest: None,
        idempotency_key: None,
    }
}

fn required(id: &str, path: &Path, timeout_seconds: u64) -> HookConfig {
    HookConfig {
        id: id.into(),
        argv: vec![path.to_string_lossy().into_owned()],
        timeout_seconds,
        required: true,
        env: vec![],
    }
}

fn optional(id: &str, path: &Path, timeout_seconds: u64) -> HookConfig {
    HookConfig {
        required: false,
        ..required(id, path, timeout_seconds)
    }
}

/// Install a hook in `tools` that prints `output`.
fn printing(tools: &Path, name: &str, output: &str) -> PathBuf {
    fake_tool::install(
        tools,
        name,
        &Behavior::always(vec![Action::Stdout(output.into())]),
    )
}

/// Install a hook in `tools` that overwrites `source.gleam` in its working directory, the snapshot, and then prints `output`.
fn mutating(tools: &Path, name: &str, output: &str) -> PathBuf {
    fake_tool::install(
        tools,
        name,
        &Behavior::always(vec![
            Action::Write {
                path: "source.gleam".into(),
                contents: "changed".into(),
            },
            Action::Stdout(output.into()),
        ]),
    )
}
