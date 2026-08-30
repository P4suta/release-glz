use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_release-glz"))
}

#[test]
fn v1_cli_exposes_every_public_command() {
    let output = binary().arg("--help").output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for command in [
        "plan",
        "rehearse",
        "verify",
        "release",
        "status",
        "doctor",
        "release-pr",
        "update",
        "prerelease",
        "set-version",
        "init",
        "migrate",
        "completion",
    ] {
        assert!(help.contains(command), "missing `{command}` in:\n{help}");
    }
}

#[test]
fn candidate_commands_require_explicit_candidate_paths_and_full_refs() {
    let rehearse = binary().args(["rehearse", "--help"]).output().unwrap();
    let rehearse = String::from_utf8(rehearse.stdout).unwrap();
    assert!(rehearse.contains("--ref"));
    assert!(rehearse.contains("--out"));

    for command in ["verify", "release", "release-pr"] {
        let output = binary().args([command, "--help"]).output().unwrap();
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("--candidate"), "{command}: {help}");
    }
}

#[test]
fn usage_errors_have_the_stable_exit_code_two() {
    let output = binary().arg("not-a-command").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn json_usage_errors_are_machine_readable_and_keep_the_requested_command() {
    let output = binary()
        .args(["--output", "json", "release", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "command/v2");
    assert_eq!(value["ok"], false);
    assert_eq!(value["command"], "release");
    assert_eq!(value["diagnostics"][0]["code"], "usage_or_config");
    assert_eq!(value["result"], serde_json::Value::Null);
}

#[test]
fn equals_form_json_output_also_preserves_the_usage_error_envelope() {
    let output = binary()
        .args(["--output=json", "release", "--dry-run"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "command/v2");
    assert_eq!(value["command"], "release");
}

#[test]
fn completion_supports_all_documented_shells() {
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let output = binary().args(["completion", shell]).output().unwrap();
        assert!(
            output.status.success(),
            "{shell}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty(), "{shell}");
        let source = String::from_utf8(output.stdout).unwrap();
        for generated_from_cli in ["candidate-build", "action-sha", "allow-version-zero"] {
            assert!(
                source.contains(generated_from_cli),
                "{shell} completion omitted {generated_from_cli}"
            );
        }
    }
}

#[test]
fn json_output_uses_the_command_envelope_v2() {
    let output = binary()
        .args(["--output", "json", "completion", "bash"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "command/v2");
    assert_eq!(value["ok"], true);
    assert_eq!(value["command"], "completion");
    assert!(
        value["result"]["source"]
            .as_str()
            .unwrap()
            .contains("complete")
    );
    assert!(value["diagnostics"].is_array());
    assert!(value["next_actions"].is_array());
}

#[test]
fn json_configuration_failures_use_envelope_v2_and_exit_two() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = temp.path().join("gleam.toml");
    std::fs::write(&manifest, "name = 42\nversion = \"1.0.0\"\n").unwrap();
    let output = binary()
        .args([
            "--manifest-path",
            manifest.to_str().unwrap(),
            "--output",
            "json",
            "doctor",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "command/v2");
    assert_eq!(value["ok"], false);
    assert_eq!(value["command"], "doctor");
    assert_eq!(value["diagnostics"][0]["level"], "error");
    assert_eq!(value["result"], serde_json::Value::Null);
}
