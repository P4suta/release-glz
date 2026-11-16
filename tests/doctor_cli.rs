use std::ffi::OsString;
use std::path::Path;

use release_glz::workflow::{self, WorkflowMode, WorkflowSettings};
use release_glz_test_support::fake_tool::{self, Action, Behavior, Condition, Rule};
use release_glz_test_support::http::{FakeServer, Request, Response};
use release_glz_test_support::schema::assert_published_envelope;
use release_glz_test_support::{fs, git, init_repository, isolated_command};

#[test]
fn doctor_cli_collects_local_and_github_checks_into_the_command_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let mut registry = fake_github(&[""]);
    fs::write(
        temp.path().join("gleam.toml"),
        manifest(&registry.base_url()),
    );
    init_repository(temp.path());
    workflow::sync(
        temp.path(),
        &WorkflowSettings {
            default_branch: "main".into(),
            manifest_path: "gleam.toml".into(),
            compiler: "1.12.3".into(),
            environment: "release".into(),
            registry_credential_env: "TEST_HEX_TOKEN".into(),
            release_branch_prefix: "release-glz/".into(),
            action_sha: "abcdef0123456789abcdef0123456789abcdef01".into(),
        },
        WorkflowMode::Update,
    )
    .unwrap();

    let gleam = fake_gleam(temp.path(), &Behavior::reporting_version("1.12.3"));

    let mut server = fake_github(&[
        r#"{"private":true,"default_branch":"main","plan":{"name":"enterprise"}}"#,
        r#"{"protection_rules":[{"type":"required_reviewers","prevent_self_review":true,"reviewers":[{"type":"User","reviewer":{"login":"reviewer"}}]}],"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false}}"#,
        r#"{"name":"main","protected":true}"#,
    ]);

    let output = isolated_command(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .args(["--output", "json", "doctor", "--online"])
        .env("PATH", &gleam)
        .env("TEST_HEX_TOKEN", "not-a-real-token")
        .env("GITHUB_TOKEN", "not-a-real-token")
        .env_remove("GH_TOKEN")
        .env("GITHUB_REPOSITORY", "acme/widget")
        .env("GITHUB_API_URL", server.base_url())
        .env(
            "GITHUB_GRAPHQL_URL",
            format!("{}/graphql", server.base_url()),
        )
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env("NO_PROXY", "")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let request_count = server.finish().len();
    let registry_requests: Vec<String> = registry.finish().iter().map(Request::text).collect();
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_published_envelope(&envelope);
    assert_eq!(envelope["schema"], "command/v1");
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["result"]["schema"], "doctor/v1");
    assert_eq!(envelope["result"]["state"], "up_to_date");
    assert_eq!(envelope["result"]["installed_compiler"], "1.12.3");
    assert_eq!(envelope["result"]["diagnostics"], serde_json::json!([]));
    assert_eq!(request_count, 3);
    assert!(
        (1..=3).contains(&registry_requests.len()),
        "unexpected bounded GET count: {registry_requests:?}"
    );
    for request in registry_requests {
        assert!(request.starts_with("GET /api/auth?domain=api&resource=write HTTP/1.1"));
        assert!(request.contains("authorization: not-a-real-token"));
    }
}

#[test]
fn doctor_defaults_to_local_checks_without_contacting_registry_or_github() {
    let temp = tempfile::tempdir().unwrap();
    let mut registry = fake_github(&[]);
    fs::write(
        temp.path().join("gleam.toml"),
        manifest(&registry.base_url()),
    );
    init_repository(temp.path());
    workflow::sync(
        temp.path(),
        &WorkflowSettings {
            default_branch: "main".into(),
            manifest_path: "gleam.toml".into(),
            compiler: "1.12.3".into(),
            environment: "release".into(),
            registry_credential_env: "TEST_HEX_TOKEN".into(),
            release_branch_prefix: "release-glz/".into(),
            action_sha: "abcdef0123456789abcdef0123456789abcdef01".into(),
        },
        WorkflowMode::Update,
    )
    .unwrap();
    let gleam = fake_gleam(temp.path(), &Behavior::reporting_version("1.12.3"));
    let mut github = fake_github(&[]);

    let output = isolated_command(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .args(["--output", "json", "doctor"])
        .env("PATH", &gleam)
        .env("TEST_HEX_TOKEN", "must-not-be-sent")
        .env("GITHUB_TOKEN", "must-not-be-sent")
        .env("GITHUB_REPOSITORY", "acme/widget")
        .env("GITHUB_API_URL", github.base_url())
        .env(
            "GITHUB_GRAPHQL_URL",
            format!("{}/graphql", github.base_url()),
        )
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(registry.finish().len(), 0);
    assert_eq!(github.finish().len(), 0);
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_published_envelope(&envelope);
    assert_eq!(envelope["result"]["state"], "up_to_date");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "");
}

/// A check that observes nothing still blocks the report, and stderr names why it observed nothing.
#[test]
fn doctor_names_why_a_check_observed_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let mut registry = fake_github(&[]);
    fs::write(
        temp.path().join("gleam.toml"),
        manifest(&registry.base_url()),
    );
    init_repository(temp.path());
    let gleam = fake_gleam(temp.path(), &Behavior::reporting_version("1.12.3"));

    let output = isolated_command(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .args(["--output", "json", "doctor"])
        .env("PATH", &gleam)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(registry.finish().len(), 0);
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_published_envelope(&envelope);
    assert_eq!(envelope["diagnostics"][0]["code"], "workflow_outdated");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.starts_with(
            "release-glz: doctor could not observe the managed release workflow: managed release workflow is missing: failed to read `"
        ),
        "{stderr}"
    );
}

#[test]
fn candidate_build_reports_the_original_isolated_failure_without_claiming_credential_cause() {
    let temp = tempfile::tempdir().unwrap();
    let mut registry = fake_github(&[]);
    fs::write(
        temp.path().join("gleam.toml"),
        manifest(&registry.base_url()),
    );
    fs::create_dir(temp.path().join("src"));
    fs::write(
        temp.path().join("src/widget.gleam"),
        "pub fn value() -> Int { 1 }\n",
    );
    init_repository(temp.path());
    git(temp.path(), &["add", "."]);
    git(temp.path(), &["commit", "-m", "initial"]);

    // A build that still saw the registry credential would match no rule and fail without the injected message.
    let gleam = fake_gleam(
        temp.path(),
        &Behavior {
            rules: vec![
                Rule {
                    when: vec![Condition::ArgumentsStartWith(vec!["--version".into()])],
                    actions: vec![Action::Stdout("gleam 1.12.3\n".into())],
                },
                Rule {
                    when: vec![Condition::EnvironmentLacks("TEST_HEX_TOKEN".into())],
                    actions: vec![
                        Action::Stderr("injected compiler failure\n".into()),
                        Action::Exit(9),
                    ],
                },
            ],
        },
    );

    let output = isolated_command(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .args(["--output", "json", "doctor", "--candidate-build"])
        .env("PATH", &gleam)
        .env("TEST_HEX_TOKEN", "must-not-reach-the-build")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    registry.finish();
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_published_envelope(&envelope);
    let diagnostic = envelope["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["code"] == "candidate_build_failed")
        .expect("candidate build failure diagnostic");
    assert!(
        diagnostic["detail"]
            .as_str()
            .unwrap()
            .contains("injected compiler failure")
    );
    assert!(
        envelope["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .all(|diagnostic| diagnostic["code"] != "candidate_build_credentials_required"),
        "{}",
        envelope["diagnostics"]
    );
}

#[test]
fn doctor_cli_uses_policy_exit_and_unsuccessful_envelope_when_blocked() {
    let temp = tempfile::tempdir().unwrap();
    let mut registry = fake_github(&[""]);
    fs::write(
        temp.path().join("gleam.toml"),
        manifest(&registry.base_url()),
    );
    init_repository(temp.path());
    workflow::sync(
        temp.path(),
        &WorkflowSettings {
            default_branch: "main".into(),
            manifest_path: "gleam.toml".into(),
            compiler: "1.12.3".into(),
            environment: "release".into(),
            registry_credential_env: "TEST_HEX_TOKEN".into(),
            release_branch_prefix: "release-glz/".into(),
            action_sha: "abcdef0123456789abcdef0123456789abcdef01".into(),
        },
        WorkflowMode::Update,
    )
    .unwrap();

    let gleam = fake_gleam(temp.path(), &Behavior::reporting_version("9.9.9"));
    let mut server = fake_github(&[
        r#"{"private":true,"default_branch":"main","plan":{"name":"enterprise"}}"#,
        r#"{"protection_rules":[{"type":"required_reviewers","prevent_self_review":true,"reviewers":[{"type":"User","reviewer":{"login":"reviewer"}}]}],"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false}}"#,
        r#"{"name":"main","protected":true}"#,
    ]);

    let output = isolated_command(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .args(["--output", "json", "doctor", "--online"])
        .env("PATH", &gleam)
        .env("TEST_HEX_TOKEN", "not-a-real-token")
        .env("GITHUB_TOKEN", "not-a-real-token")
        .env_remove("GH_TOKEN")
        .env("GITHUB_REPOSITORY", "acme/widget")
        .env("GITHUB_API_URL", server.base_url())
        .env(
            "GITHUB_GRAPHQL_URL",
            format!("{}/graphql", server.base_url()),
        )
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    server.finish();
    registry.finish();
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_published_envelope(&envelope);
    assert_eq!(envelope["schema"], "command/v1");
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["result"]["state"], "blocked");
    assert_eq!(envelope["diagnostics"][0]["code"], "compiler_mismatch");
    assert_eq!(
        envelope["next_actions"][0]["command"],
        "install Gleam 1.12.3"
    );
}

/// Install a compiler stand-in that plays `behavior`, and return a `PATH` that finds it first.
fn fake_gleam(root: &Path, behavior: &Behavior) -> OsString {
    fake_tool::gleam_on_path(&root.join("fake-compiler"), behavior)
}

fn manifest(registry_base: &str) -> String {
    r#"name = "widget"
version = "1.2.3"

[repository]
type = "github"
user = "acme"
repo = "widget"

[tools.release-glz]
schema = 2
compiler = "1.12.3"

[tools.release-glz.registry]
provider = "hexpm"
api_url = "REGISTRY_BASE/api"
repository_url = "REGISTRY_BASE/repo"
docs_url = "REGISTRY_BASE/repo/docs"
credential_env = "TEST_HEX_TOKEN"
auth = "hex-token"

[tools.release-glz.approval]
normal = "release-pr-and-environment"
manual = "environment"
environment = "release"
separation = "strict"
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
    .replace("REGISTRY_BASE", registry_base)
}

/// A server that answers its requests in order with `bodies`, each as a JSON 200 response.
fn fake_github(bodies: &[&str]) -> FakeServer {
    let server = FakeServer::start();
    server.script(bodies.iter().map(|body| {
        Response::new(200)
            .header("Content-Type", "application/json")
            .body(*body)
    }));
    server
}
