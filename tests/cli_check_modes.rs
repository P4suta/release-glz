use std::process::Command;

use release_glz_test_support::schema::assert_published_envelope;
use release_glz_test_support::{init_repository, isolated_command};

fn binary() -> Command {
    isolated_command(env!("CARGO_BIN_EXE_release-glz"))
}

const ACTION_SHA: &str = "abcdef0123456789abcdef0123456789abcdef01";

#[test]
fn init_check_is_non_mutating_and_fails_when_the_managed_workflow_is_stale() {
    let temp = tempfile::tempdir().unwrap();
    init_repository(temp.path());
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
    assert_published_envelope(&envelope);
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
fn init_diff_update_and_check_form_a_non_destructive_managed_file_lifecycle() {
    let temp = tempfile::tempdir().unwrap();
    init_repository(temp.path());
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
    assert!(diff_text.contains("@@ "));
    assert!(diff_text.contains("name: release-glz"));
    assert!(!workflow.exists());

    let json_diff = binary()
        .current_dir(temp.path())
        .args([
            "--output",
            "json",
            "init",
            "--diff",
            "--action-sha",
            ACTION_SHA,
        ])
        .output()
        .unwrap();
    assert!(json_diff.status.success());
    let json_diff: serde_json::Value = serde_json::from_slice(&json_diff.stdout).unwrap();
    assert_published_envelope(&json_diff);
    assert_eq!(
        json_diff["result"]["manifest_diff"],
        serde_json::Value::Null
    );
    assert!(
        json_diff["result"]["workflow_diff"]
            .as_str()
            .unwrap()
            .contains("@@ ")
    );

    let unsupported_global_dry_run = binary()
        .current_dir(temp.path())
        .args(["--output", "json", "--dry-run", "init", "--update"])
        .output()
        .unwrap();
    assert_eq!(unsupported_global_dry_run.status.code(), Some(2));
    assert_published_envelope(&serde_json::from_slice(&unsupported_global_dry_run.stdout).unwrap());
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
    assert_published_envelope(&update);
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
    assert_published_envelope(&check);
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
    assert_published_envelope(&conflicting);
    assert_eq!(conflicting["diagnostics"][0]["code"], "usage_or_config");
}

#[test]
fn init_refuses_a_release_table_that_sets_another_schema_and_leaves_it_alone() {
    let temp = tempfile::tempdir().unwrap();
    init_repository(temp.path());
    let manifest = temp.path().join("gleam.toml");
    let source = schema_two_manifest().replace("schema = 2", "schema = 1");
    std::fs::write(&manifest, &source).unwrap();

    let output = binary()
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
    assert_eq!(output.status.code(), Some(2));
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_published_envelope(&envelope);
    assert_eq!(envelope["diagnostics"][0]["code"], "usage_or_config");
    let message = envelope["diagnostics"][0]["message"].as_str().unwrap();
    assert!(
        message.contains("`[tools.release-glz]` requires `schema = 2`, but it sets `schema = 1`"),
        "{message}"
    );
    assert_eq!(std::fs::read_to_string(&manifest).unwrap(), source);
    assert!(
        !temp
            .path()
            .join(".github/workflows/release-glz.yml")
            .exists()
    );
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
