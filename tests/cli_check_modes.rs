use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_release-glz"))
}

const ACTION_SHA: &str = "abcdef0123456789abcdef0123456789abcdef01";

#[test]
fn init_check_is_non_mutating_and_fails_when_the_managed_workflow_is_stale() {
    let temp = tempfile::tempdir().unwrap();
    Command::new("git")
        .args(["init", "--initial-branch=main"])
        .current_dir(temp.path())
        .output()
        .unwrap();
    std::fs::write(temp.path().join("gleam.toml"), schema_two_manifest()).unwrap();

    let output = binary()
        .current_dir(temp.path())
        .args([
            "--output",
            "json",
            "init",
            "--check",
            "--action-sha",
            ACTION_SHA,
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(
        !temp
            .path()
            .join(".github/workflows/release-glz.yml")
            .exists()
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["result"]["changed"], true);
    assert_eq!(envelope["result"]["written"], false);
    assert_eq!(envelope["diagnostics"][0]["code"], "managed_file_outdated");
    assert_eq!(
        envelope["next_actions"][0]["command"],
        format!("release-glz init --update --action-sha {ACTION_SHA}")
    );
}

#[test]
fn migrate_check_is_non_mutating_and_fails_when_schema_two_is_required() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = temp.path().join("gleam.toml");
    let gleam = fake_gleam(temp.path(), "1.17.2");
    let legacy = "name = \"widget\"\nversion = \"1.0.0\"\n";
    std::fs::write(&manifest, legacy).unwrap();

    let output = binary()
        .current_dir(temp.path())
        .env("RELEASE_GLZ_GLEAM", &gleam)
        .args(["--output", "json", "migrate", "--check"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(std::fs::read_to_string(&manifest).unwrap(), legacy);
    assert!(!temp.path().join(".release-glz/legacy-gleam.toml").exists());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["result"]["changed"], true);
    assert_eq!(envelope["result"]["written"], false);
    assert_eq!(envelope["diagnostics"][0]["code"], "migration_required");
    assert_eq!(
        envelope["next_actions"][0]["command"],
        "release-glz migrate --update"
    );
}

#[test]
fn init_diff_update_and_check_form_a_non_destructive_managed_file_lifecycle() {
    let temp = tempfile::tempdir().unwrap();
    Command::new("git")
        .args(["init", "--initial-branch=main"])
        .current_dir(temp.path())
        .output()
        .unwrap();
    std::fs::write(temp.path().join("gleam.toml"), schema_two_manifest()).unwrap();
    let workflow = temp.path().join(".github/workflows/release-glz.yml");

    let diff = binary()
        .current_dir(temp.path())
        .args(["init", "--diff", "--action-sha", ACTION_SHA])
        .output()
        .unwrap();
    assert!(diff.status.success());
    let diff_text = String::from_utf8(diff.stdout).unwrap();
    assert!(diff_text.contains("+++ .github/workflows/release-glz.yml"));
    assert!(diff_text.contains("name: release-glz"));
    assert!(!workflow.exists());

    let unsupported_global_dry_run = binary()
        .current_dir(temp.path())
        .args(["--output", "json", "--dry-run", "init", "--update"])
        .output()
        .unwrap();
    assert_eq!(unsupported_global_dry_run.status.code(), Some(2));
    assert!(!workflow.exists());

    let update = binary()
        .current_dir(temp.path())
        .args([
            "--output",
            "json",
            "init",
            "--update",
            "--action-sha",
            ACTION_SHA,
        ])
        .output()
        .unwrap();
    assert!(
        update.status.success(),
        "{}",
        String::from_utf8_lossy(&update.stderr)
    );
    let update: serde_json::Value = serde_json::from_slice(&update.stdout).unwrap();
    assert_eq!(update["result"]["changed"], true);
    assert_eq!(update["result"]["written"], true);
    assert!(workflow.exists());

    let check = binary()
        .current_dir(temp.path())
        .args([
            "--output",
            "json",
            "init",
            "--check",
            "--action-sha",
            ACTION_SHA,
        ])
        .output()
        .unwrap();
    assert!(check.status.success());
    let check: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(check["ok"], true);
    assert_eq!(check["result"]["changed"], false);
    assert_eq!(check["result"]["written"], false);

    let conflicting = binary()
        .current_dir(temp.path())
        .args([
            "--output",
            "json",
            "init",
            "--check",
            "--diff",
            "--action-sha",
            ACTION_SHA,
        ])
        .output()
        .unwrap();
    assert_eq!(conflicting.status.code(), Some(2));
    let conflicting: serde_json::Value = serde_json::from_slice(&conflicting.stdout).unwrap();
    assert_eq!(conflicting["diagnostics"][0]["code"], "usage_or_config");
}

#[test]
fn migrate_diff_dry_run_update_and_check_preserve_the_legacy_source() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = temp.path().join("gleam.toml");
    let gleam = fake_gleam(temp.path(), "1.17.2");
    let legacy = r#"name = "widget"
version = "0.4.2"
description = "legacy fixture"
licences = ["MIT"]

[repository]
type = "github"
user = "acme"
repo = "widget"

[tools.release-glz]
allow_version_zero = true
"#;
    std::fs::write(&manifest, legacy).unwrap();

    let diff = binary()
        .current_dir(temp.path())
        .env("RELEASE_GLZ_GLEAM", &gleam)
        .args(["migrate", "--diff"])
        .output()
        .unwrap();
    assert!(diff.status.success());
    let diff = String::from_utf8(diff.stdout).unwrap();
    assert!(diff.contains("+++ gleam.toml (schema 2)"));
    assert!(diff.contains("schema = 2"));
    assert_eq!(std::fs::read_to_string(&manifest).unwrap(), legacy);

    let unsupported_global_dry_run = binary()
        .current_dir(temp.path())
        .env("RELEASE_GLZ_GLEAM", &gleam)
        .args(["--output", "json", "--dry-run", "migrate", "--update"])
        .output()
        .unwrap();
    assert_eq!(unsupported_global_dry_run.status.code(), Some(2));
    assert_eq!(std::fs::read_to_string(&manifest).unwrap(), legacy);

    let update = binary()
        .current_dir(temp.path())
        .env("RELEASE_GLZ_GLEAM", &gleam)
        .args(["--output", "json", "migrate", "--update"])
        .output()
        .unwrap();
    assert!(
        update.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&update.stdout),
        String::from_utf8_lossy(&update.stderr)
    );
    let update: serde_json::Value = serde_json::from_slice(&update.stdout).unwrap();
    assert_eq!(update["result"]["changed"], true);
    assert_eq!(update["result"]["written"], true);
    let migrated = std::fs::read_to_string(&manifest).unwrap();
    assert!(migrated.contains("schema = 2"));
    assert!(migrated.contains("compiler = \"1.17.2\""));
    assert!(migrated.contains("allow_version_zero = true"));
    assert_eq!(
        std::fs::read_to_string(temp.path().join(".release-glz/legacy-gleam.toml")).unwrap(),
        legacy
    );

    let check = binary()
        .current_dir(temp.path())
        .env("RELEASE_GLZ_GLEAM", &gleam)
        .args(["--output", "json", "migrate", "--check"])
        .output()
        .unwrap();
    assert!(check.status.success());
    let check: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(check["ok"], true);
    assert_eq!(check["result"]["changed"], false);

    let conflicting = binary()
        .current_dir(temp.path())
        .env("RELEASE_GLZ_GLEAM", &gleam)
        .args(["--output", "json", "migrate", "--diff", "--update"])
        .output()
        .unwrap();
    assert_eq!(conflicting.status.code(), Some(2));
    let conflicting: serde_json::Value = serde_json::from_slice(&conflicting.stdout).unwrap();
    assert_eq!(conflicting["diagnostics"][0]["code"], "usage_or_config");
}

fn fake_gleam(directory: &std::path::Path, version: &str) -> std::path::PathBuf {
    #[cfg(unix)]
    {
        let executable = directory.join("fake-gleam");
        std::fs::write(
            &executable,
            format!("#!/bin/sh\nprintf '%s\\n' 'gleam {version}'\n"),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();
        executable
    }
    #[cfg(windows)]
    {
        let executable = directory.join("fake-gleam.cmd");
        std::fs::write(
            &executable,
            format!("@echo off\r\necho gleam {version}\r\n"),
        )
        .unwrap();
        executable
    }
}

fn schema_two_manifest() -> &'static str {
    r#"name = "widget"
version = "1.0.0"

[repository]
type = "github"
user = "acme"
repo = "widget"

[tools.release-glz]
schema = 2
compiler = "1.12.3"

[tools.release-glz.registry]
provider = "hexpm"
api_url = "https://hex.pm/api"
repository_url = "https://repo.hex.pm"
docs_url = "https://repo.hex.pm/docs"
credential_env = "HEXPM_API_KEY"
auth = "hex-token"

[tools.release-glz.approval]
normal = "release-pr-and-environment"
manual = "environment"
environment = "release"
separation = "solo"
manual_refs = ["refs/heads/main"]

[tools.release-glz.outputs]
docs = true
github_release = true
sbom = true
provenance = true
signature = false
allow_private_evidence_upload = false

[tools.release-glz.changelog]
path = "CHANGELOG.md"
managed_block = true
notes_dir = ".release-glz/notes"
"#
}
