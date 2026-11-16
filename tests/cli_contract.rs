use std::process::Command;

use release_glz_test_support::schema::assert_published_envelope;
use release_glz_test_support::{git, init_repository, isolated_command};

fn binary() -> Command {
    isolated_command(env!("CARGO_BIN_EXE_release-glz"))
}

#[test]
fn the_cli_exposes_exactly_the_public_commands() {
    let output = binary().arg("--help").output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    let commands: Vec<_> = help
        .lines()
        .skip_while(|line| *line != "Commands:")
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert_eq!(
        commands,
        [
            "plan",
            "rehearse",
            "verify",
            "release-pr",
            "release",
            "status",
            "doctor",
            "init",
            "set-version",
            "prerelease",
            "completion",
            "help",
        ],
        "{help}"
    );
}

#[test]
fn the_rolling_release_pr_has_one_command_name() {
    let output = binary().args(["update", "--help"]).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("unrecognized subcommand 'update'"),
        "{stderr}"
    );
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
    assert_published_envelope(&value);
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
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let output = binary()
            .args(["--output", "json", "completion", shell])
            .output()
            .unwrap();
        assert!(output.status.success(), "{shell}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_published_envelope(&value);
        assert_eq!(value["schema"], "command/v2");
        assert_eq!(value["ok"], true);
        assert_eq!(value["command"], "completion");
        assert_eq!(value["result"]["schema"], "completion/v1");
        assert_eq!(value["result"]["shell"], shell);
        assert!(
            value["result"]["source"]
                .as_str()
                .unwrap()
                .contains("candidate-build"),
            "{shell}"
        );
    }
}

/// A committed package whose manifest has no `[tools.release-glz]` table, and the commit that holds it.
fn unconfigured_package() -> (tempfile::TempDir, std::path::PathBuf, String) {
    let temp = tempfile::tempdir().unwrap();
    let manifest = temp.path().join("gleam.toml");
    std::fs::write(&manifest, "name = \"widget\"\nversion = \"1.0.0\"\n").unwrap();
    init_repository(temp.path());
    for setting in [
        ["core.hooksPath", ".git/no-hooks"],
        ["user.email", "fixture@example.test"],
        ["user.name", "Fixture"],
        ["commit.gpgsign", "false"],
    ] {
        git(temp.path(), &["config", setting[0], setting[1]]);
    }
    git(temp.path(), &["add", "gleam.toml"]);
    git(temp.path(), &["commit", "--quiet", "-m", "feat: widget"]);
    let sha = git(temp.path(), &["rev-parse", "HEAD"]).trim().to_owned();
    (temp, manifest, sha)
}

#[test]
fn commands_that_read_the_release_configuration_refuse_a_manifest_without_it() {
    let (temp, manifest, sha) = unconfigured_package();
    let candidate = temp.path().join("candidate");
    let candidate = candidate.to_str().unwrap();
    for command in [
        vec!["plan"],
        vec!["release-pr", "--dry-run"],
        vec!["status"],
        vec!["set-version", "2.0.0", "--dry-run"],
        vec!["prerelease", "rc", "--dry-run"],
        vec!["rehearse", "--ref", &sha, "--out", candidate],
    ] {
        let output = binary()
            .current_dir(temp.path())
            .args([
                "--manifest-path",
                manifest.to_str().unwrap(),
                "--output",
                "json",
            ])
            .args(&command)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{command:?}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_published_envelope(&value);
        assert_eq!(value["command"], command[0]);
        assert_eq!(value["ok"], false);
        assert_eq!(value["diagnostics"][0]["code"], "usage_or_config");
        let message = value["diagnostics"][0]["message"].as_str().unwrap();
        assert!(
            message.contains("[tools.release-glz]") && message.contains("release-glz init"),
            "{command:?}: {message}"
        );
        assert!(!temp.path().join("candidate").exists(), "{command:?}");
    }
    assert_eq!(
        std::fs::read_to_string(&manifest).unwrap(),
        "name = \"widget\"\nversion = \"1.0.0\"\n"
    );
}

#[test]
fn doctor_reports_a_manifest_without_release_configuration_and_points_to_init() {
    let (temp, manifest, _) = unconfigured_package();
    let output = binary()
        .current_dir(temp.path())
        .args([
            "--manifest-path",
            manifest.to_str().unwrap(),
            "--output",
            "json",
            "doctor",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_published_envelope(&value);
    assert_eq!(value["ok"], false);
    assert_eq!(value["result"]["state"], "blocked");
    assert_eq!(
        value["result"]["required_compiler"],
        serde_json::Value::Null
    );
    let diagnostics = value["result"]["diagnostics"].as_array().unwrap();
    assert_eq!(
        diagnostics
            .iter()
            .map(|diagnostic| diagnostic["code"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["config_missing"],
        "{value}"
    );
    assert_eq!(diagnostics[0]["level"], "error");
    let actions = value["result"]["next_actions"].as_array().unwrap();
    assert_eq!(actions.len(), 1, "{value}");
    assert_eq!(actions[0]["argv"], serde_json::json!([]));
    assert!(
        actions[0]["description"]
            .as_str()
            .unwrap()
            .contains("release-glz init"),
        "{value}"
    );
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
    assert_published_envelope(&value);
    assert_eq!(value["schema"], "command/v2");
    assert_eq!(value["ok"], false);
    assert_eq!(value["command"], "doctor");
    assert_eq!(value["diagnostics"][0]["level"], "error");
    assert_eq!(value["result"], serde_json::Value::Null);
}
