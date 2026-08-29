#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use release_glz::config::HookConfig;
use release_glz::hooks::{HookContext, HookRunner};
use semver::Version;

#[tokio::test]
async fn verify_hook_uses_json_stdio_and_records_v1_evidence() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "pub fn main() { Nil }\n").unwrap();
    let hook = script(
        temp.path(),
        "verify.sh",
        r#"input=$(cat)
case "$input" in *\"schema\":\"hook/v1\"*) ;; *) exit 9 ;; esac
printf '%s' '{"schema":"hook/v1","success":true,"summary":"verified","evidence":{"policy":"ok"}}'
"#,
    );
    let evidence = HookRunner::default()
        .run_verify(
            &[HookConfig {
                id: "policy".into(),
                argv: vec![hook.to_string_lossy().into_owned()],
                timeout_seconds: 5,
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
async fn verify_hook_cannot_mutate_the_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let hook = script(
        temp.path(),
        "mutate.sh",
        "printf changed > source.gleam\nprintf '%s' '{\"schema\":\"hook/v1\",\"success\":true,\"summary\":\"bad\",\"evidence\":{}}'\n",
    );
    let error = HookRunner::default()
        .run_verify(&[required("mutator", &hook, 5)], temp.path(), &context())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("modified the source snapshot"));
}

#[tokio::test]
async fn required_hook_timeout_is_bounded_and_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let hook = script(temp.path(), "slow.sh", "sleep 5\n");
    let started = Instant::now();
    let error = HookRunner::default()
        .run_verify(&[required("slow", &hook, 1)], temp.path(), &context())
        .await
        .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(error.to_string().contains("timed out"));
}

#[tokio::test]
async fn undeclared_environment_is_not_forwarded() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let hook = script(
        temp.path(),
        "env.sh",
        "/usr/bin/env | /bin/grep -q '^HOME=' && exit 8 || true\nprintf '%s' '{\"schema\":\"hook/v1\",\"success\":true,\"summary\":\"clean\",\"evidence\":{}}'\n",
    );
    HookRunner::default()
        .run_verify(&[required("env", &hook, 5)], temp.path(), &context())
        .await
        .unwrap();
}

#[tokio::test]
async fn notify_hooks_have_separate_idempotent_observe_and_apply_phases() {
    let temp = tempfile::tempdir().unwrap();
    let hook = script(
        temp.path(),
        "notify.sh",
        r#"input=$(cat)
case "$input" in
  *'"phase":"observe"'*)
    if test -f delivered; then complete=true; else complete=false; fi
    printf '{"schema":"hook/v1","success":true,"summary":"observed","evidence":{"complete":%s}}' "$complete"
    ;;
  *'"phase":"apply"'*)
    printf delivered > delivered
    printf '%s' '{"schema":"hook/v1","success":true,"summary":"notified","evidence":{}}'
    ;;
  *) exit 9 ;;
esac
"#,
    );
    let hook = required("announce", &hook, 5);
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
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let hook = script(
        temp.path(),
        "sidecar.sh",
        r#"input=$(cat)
case "$input" in *'"phase":"sidecar"'*) ;; *) exit 9 ;; esac
printf '%s' '{"schema":"hook/v1","success":true,"summary":"sbom","evidence":{"artifacts":[{"name":"sbom.cdx.json","media_type":"application/vnd.cyclonedx+json","content_base64":"eyJib20iOiJvayJ9","public":true}]}}'
"#,
    );
    let result = HookRunner::default()
        .run_sidecars(&[required("sbom", &hook, 5)], temp.path(), &context())
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
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let hook = script(
        temp.path(),
        "nested-sidecar.sh",
        r#"printf '%s' '{"schema":"hook/v1","success":true,"summary":"nested","evidence":{"artifacts":[{"name":"nested/evidence.json","media_type":"application/json","content_base64":"e30="}]}}'
"#,
    );

    let error = HookRunner::default()
        .run_sidecars(&[required("evidence", &hook, 5)], temp.path(), &context())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("safe asset name"), "{error}");
}

#[tokio::test]
async fn sidecar_protocol_rejects_unknown_evidence_and_artifact_fields() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let cases = [
        (
            "evidence-field.sh",
            r#"{"schema":"hook/v1","success":true,"summary":"extra","evidence":{"artifacts":[],"unexpected":true}}"#,
        ),
        (
            "artifact-field.sh",
            r#"{"schema":"hook/v1","success":true,"summary":"extra","evidence":{"artifacts":[{"name":"evidence.json","media_type":"application/json","content_base64":"e30=","unexpected":true}]}}"#,
        ),
    ];

    for (name, output) in cases {
        let hook = script(temp.path(), name, &format!("printf '%s' '{output}'\n"));
        let error = HookRunner::default()
            .run_sidecars(&[required("evidence", &hook, 5)], temp.path(), &context())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid artifacts"), "{name}: {error}");
    }
}

#[tokio::test]
async fn verify_failures_preserve_required_and_optional_policy() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let reported = script(
        temp.path(),
        "reported-failure.sh",
        r#"printf '%s' '{"schema":"hook/v1","success":false,"summary":"denied","evidence":{}}'
"#,
    );
    let invalid = script(temp.path(), "invalid-json.sh", "printf '%s' 'not-json'\n");
    let nonzero = script(temp.path(), "nonzero.sh", "exit 17\n");
    let runner = HookRunner::default();

    for (name, hook, expected) in [
        ("reported", &reported, "reported failure"),
        ("invalid", &invalid, "invalid JSON"),
        ("nonzero", &nonzero, "reported failure"),
    ] {
        let error = runner
            .run_verify(&[required(name, hook, 5)], temp.path(), &context())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{name}: {error}");

        let evidence = runner
            .run_verify(&[optional(name, hook, 5)], temp.path(), &context())
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
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let cases = [
        ("invalid.sh", "not-json", "invalid JSON"),
        (
            "schema.sh",
            r#"{"schema":"hook/v2","success":true,"summary":"ok","evidence":{}}"#,
            "unsupported schema",
        ),
        (
            "summary.sh",
            r#"{"schema":"hook/v1","success":true,"summary":"  ","evidence":{}}"#,
            "empty summary",
        ),
        (
            "evidence.sh",
            r#"{"schema":"hook/v1","success":true,"summary":"ok","evidence":[]}"#,
            "evidence must be a JSON object",
        ),
        (
            "unknown.sh",
            r#"{"schema":"hook/v1","success":true,"summary":"ok","evidence":{},"unexpected":true}"#,
            "invalid JSON",
        ),
    ];
    let runner = HookRunner::default();
    for (name, output, expected) in cases {
        let hook = script(temp.path(), name, &format!("printf '%s' '{output}'\n"));
        let error = runner
            .run_verify(&[required("protocol", &hook, 5)], temp.path(), &context())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{name}: {error}");
    }

    let empty_argv = HookConfig {
        id: "empty".into(),
        argv: vec![],
        timeout_seconds: 5,
        required: true,
        env: vec![],
    };
    let error = runner
        .run_verify(&[empty_argv], temp.path(), &context())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("argv unexpectedly empty"), "{error}");
}

#[tokio::test]
async fn declared_environment_nested_snapshots_and_non_regular_entries_are_handled_exactly() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir_all(temp.path().join("nested/deeper")).unwrap();
    fs::write(temp.path().join("nested/deeper/source.gleam"), "before").unwrap();
    let hook = script(
        temp.path(),
        "declared-env.sh",
        r#"test -n "${CARGO_MANIFEST_DIR-}"
printf '%s' '{"schema":"hook/v1","success":true,"summary":"declared","evidence":{}}'
"#,
    );
    let mut configured = required("declared", &hook, 5);
    configured.env = vec!["CARGO_MANIFEST_DIR".into()];
    HookRunner::default()
        .run_verify(&[configured], temp.path(), &context())
        .await
        .unwrap();

    std::os::unix::fs::symlink(
        "nested/deeper/source.gleam",
        temp.path().join("source-link"),
    )
    .unwrap();
    let error = HookRunner::default()
        .run_verify(&[required("declared", &hook, 5)], temp.path(), &context())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("non-regular entry"), "{error}");
}

#[tokio::test]
async fn stdout_and_stderr_are_streamed_but_strictly_bounded() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let stdout = script(
        temp.path(),
        "large-stdout.sh",
        "dd if=/dev/zero bs=1048577 count=1 2>/dev/null\n",
    );
    let stderr = script(
        temp.path(),
        "large-stderr.sh",
        "dd if=/dev/zero bs=262145 count=1 >&2 2>/dev/null\nprintf '%s' '{\"schema\":\"hook/v1\",\"success\":true,\"summary\":\"ok\",\"evidence\":{}}'\n",
    );
    let runner = HookRunner::default();
    for (name, hook) in [("stdout", stdout), ("stderr", stderr)] {
        let error = runner
            .run_verify(&[required(name, &hook, 5)], temp.path(), &context())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("output limit"), "{name}: {error}");
    }
}

#[tokio::test]
async fn sidecar_failures_preserve_policy_and_snapshot_immutability() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let reported = script(
        temp.path(),
        "sidecar-reported.sh",
        r#"printf '%s' '{"schema":"hook/v1","success":false,"summary":"none","evidence":{}}'
"#,
    );
    let invalid = script(temp.path(), "sidecar-invalid.sh", "printf invalid\n");
    let mutating = script(
        temp.path(),
        "sidecar-mutating.sh",
        "printf changed > source.gleam\nprintf '%s' '{\"schema\":\"hook/v1\",\"success\":true,\"summary\":\"bad\",\"evidence\":{\"artifacts\":[]}}'\n",
    );
    let runner = HookRunner::default();

    let error = runner
        .run_sidecars(
            &[required("reported", &reported, 5)],
            temp.path(),
            &context(),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("reported failure"), "{error}");
    let result = runner
        .run_sidecars(
            &[optional("reported", &reported, 5)],
            temp.path(),
            &context(),
        )
        .await
        .unwrap();
    assert!(!result.evidence[0].success);
    assert!(result.artifacts.is_empty());

    let result = runner
        .run_sidecars(&[optional("invalid", &invalid, 5)], temp.path(), &context())
        .await
        .unwrap();
    assert!(!result.evidence[0].success);

    let error = runner
        .run_sidecars(
            &[required("mutating", &mutating, 5)],
            temp.path(),
            &context(),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("modified the source snapshot"), "{error}");
}

#[tokio::test]
async fn sidecar_artifact_protocol_rejects_every_unsafe_shape() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("source.gleam"), "before").unwrap();
    let cases = [
        (
            "shape.sh",
            r#"{"artifacts":"not-an-array"}"#,
            "invalid artifacts",
        ),
        (
            "name.sh",
            r#"{"artifacts":[{"name":"../escape","media_type":"application/json","content_base64":"e30="}]}"#,
            "safe asset name",
        ),
        (
            "media.sh",
            r#"{"artifacts":[{"name":"evidence.json","media_type":"json","content_base64":"e30="}]}"#,
            "media type",
        ),
        (
            "base64.sh",
            r#"{"artifacts":[{"name":"evidence.json","media_type":"application/json","content_base64":"%%%"}]}"#,
            "valid base64",
        ),
        (
            "duplicate.sh",
            r#"{"artifacts":[{"name":"evidence.json","media_type":"application/json","content_base64":"e30="},{"name":"evidence.json","media_type":"application/json","content_base64":"e30="}]}"#,
            "duplicate artifact",
        ),
    ];
    let runner = HookRunner::default();
    for (name, evidence, expected) in cases {
        let output = format!(
            "{{\"schema\":\"hook/v1\",\"success\":true,\"summary\":\"case\",\"evidence\":{evidence}}}"
        );
        let hook = script(temp.path(), name, &format!("printf '%s' '{output}'\n"));
        let error = runner
            .run_sidecars(&[required("evidence", &hook, 5)], temp.path(), &context())
            .await
            .unwrap_err()
            .to_string();
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
    let hook = script(
        temp.path(),
        "count.sh",
        &format!("printf '%s' '{output}'\n"),
    );
    let error = runner
        .run_sidecars(&[required("evidence", &hook, 5)], temp.path(), &context())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("count limit"), "{error}");
}

#[tokio::test]
async fn notify_failure_and_observation_shapes_are_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let failed = script(
        temp.path(),
        "notify-failed.sh",
        r#"printf '%s' '{"schema":"hook/v1","success":false,"summary":"failed","evidence":{}}'
"#,
    );
    let missing = script(
        temp.path(),
        "notify-missing.sh",
        r#"printf '%s' '{"schema":"hook/v1","success":true,"summary":"missing","evidence":{}}'
"#,
    );
    let wrong = script(
        temp.path(),
        "notify-wrong.sh",
        r#"printf '%s' '{"schema":"hook/v1","success":true,"summary":"wrong","evidence":{"complete":"yes"}}'
"#,
    );
    let runner = HookRunner::default();

    let error = runner
        .observe_notify(&required("notify", &failed, 5), temp.path(), &context())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("could not observe"), "{error}");
    assert!(
        !runner
            .observe_notify(&optional("notify", &failed, 5), temp.path(), &context())
            .await
            .unwrap()
    );
    let error = runner
        .apply_notify(&optional("notify", &failed, 5), temp.path(), &context())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("apply failure"), "{error}");

    for hook in [missing, wrong] {
        let error = runner
            .observe_notify(&required("notify", &hook, 5), temp.path(), &context())
            .await
            .unwrap_err()
            .to_string();
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

fn required(id: &str, path: &std::path::Path, timeout_seconds: u64) -> HookConfig {
    HookConfig {
        id: id.into(),
        argv: vec![path.to_string_lossy().into_owned()],
        timeout_seconds,
        required: true,
        env: vec![],
    }
}

fn optional(id: &str, path: &std::path::Path, timeout_seconds: u64) -> HookConfig {
    HookConfig {
        required: false,
        ..required(id, path, timeout_seconds)
    }
}

fn script(directory: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = directory.join(name);
    fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}")).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}
