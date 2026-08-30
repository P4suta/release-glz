#![cfg(unix)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use release_glz::workflow::{self, WorkflowMode, WorkflowSettings};

#[test]
fn doctor_cli_collects_local_and_github_checks_into_envelope_v2() {
    let temp = tempfile::tempdir().unwrap();
    let registry = FakeGitHub::start(vec![""]);
    std::fs::write(
        temp.path().join("gleam.toml"),
        manifest(&registry.base_url()),
    )
    .unwrap();
    Command::new("git")
        .args(["init", "--initial-branch=main"])
        .current_dir(temp.path())
        .output()
        .unwrap();
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

    let gleam = temp.path().join("fake-gleam");
    std::fs::write(&gleam, "#!/bin/sh\nprintf '%s\\n' 'gleam 1.12.3'\n").unwrap();
    let mut permissions = std::fs::metadata(&gleam).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&gleam, permissions).unwrap();

    let server = FakeGitHub::start(vec![
        r#"{"private":true,"default_branch":"main","plan":{"name":"enterprise"}}"#,
        r#"{"protection_rules":[{"type":"required_reviewers","prevent_self_review":true,"reviewers":[{"type":"User","reviewer":{"login":"reviewer"}}]}],"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false}}"#,
        r#"{"name":"main","protected":true}"#,
    ]);

    let output = Command::new(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .args(["--output", "json", "doctor", "--online"])
        .env("RELEASE_GLZ_GLEAM", &gleam)
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
    let request_count = server.request_count();
    let registry_requests = registry.requests();
    server.stop();
    registry.stop();

    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["schema"], "command/v2");
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
    let registry = FakeGitHub::start(vec![]);
    std::fs::write(
        temp.path().join("gleam.toml"),
        manifest(&registry.base_url()),
    )
    .unwrap();
    Command::new("git")
        .args(["init", "--initial-branch=main"])
        .current_dir(temp.path())
        .output()
        .unwrap();
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
    let gleam = temp.path().join("fake-gleam");
    std::fs::write(&gleam, "#!/bin/sh\nprintf '%s\\n' 'gleam 1.12.3'\n").unwrap();
    let mut permissions = std::fs::metadata(&gleam).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&gleam, permissions).unwrap();
    let github = FakeGitHub::start(vec![]);

    let output = Command::new(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .args(["--output", "json", "doctor"])
        .env("RELEASE_GLZ_GLEAM", &gleam)
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
    assert_eq!(registry.request_count(), 0);
    assert_eq!(github.request_count(), 0);
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["result"]["state"], "up_to_date");
    registry.stop();
    github.stop();
}

#[test]
fn candidate_build_reports_the_original_isolated_failure_without_claiming_credential_cause() {
    let temp = tempfile::tempdir().unwrap();
    let registry = FakeGitHub::start(vec![]);
    std::fs::write(
        temp.path().join("gleam.toml"),
        manifest(&registry.base_url()),
    )
    .unwrap();
    std::fs::create_dir(temp.path().join("src")).unwrap();
    std::fs::write(
        temp.path().join("src/widget.gleam"),
        "pub fn value() -> Int { 1 }\n",
    )
    .unwrap();
    for args in [
        vec!["init", "--initial-branch=main"],
        vec!["config", "user.email", "release-glz@example.test"],
        vec!["config", "user.name", "release-glz test"],
        vec!["add", "."],
        vec!["commit", "-m", "initial"],
    ] {
        assert!(
            Command::new("git")
                .args(args)
                .current_dir(temp.path())
                .output()
                .unwrap()
                .status
                .success()
        );
    }

    let gleam = temp.path().join("failing-gleam");
    std::fs::write(
        &gleam,
        "#!/bin/sh\nset -eu\nif [ \"${1:-}\" = --version ]; then printf '%s\\n' 'gleam 1.12.3'; exit 0; fi\ntest -z \"${TEST_HEX_TOKEN-}\"\nprintf '%s\\n' 'injected compiler failure' >&2\nexit 9\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&gleam).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&gleam, permissions).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .args(["--output", "json", "doctor", "--candidate-build"])
        .env("RELEASE_GLZ_GLEAM", &gleam)
        .env("TEST_HEX_TOKEN", "must-not-reach-the-build")
        .output()
        .unwrap();
    registry.stop();

    assert_eq!(output.status.code(), Some(3));
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
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
    assert_ne!(diagnostic["code"], "candidate_build_credentials_required");
}

#[test]
fn doctor_cli_uses_policy_exit_and_unsuccessful_envelope_when_blocked() {
    let temp = tempfile::tempdir().unwrap();
    let registry = FakeGitHub::start(vec![""]);
    std::fs::write(
        temp.path().join("gleam.toml"),
        manifest(&registry.base_url()),
    )
    .unwrap();
    Command::new("git")
        .args(["init", "--initial-branch=main"])
        .current_dir(temp.path())
        .output()
        .unwrap();
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

    let gleam = temp.path().join("wrong-gleam");
    std::fs::write(&gleam, "#!/bin/sh\nprintf '%s\\n' 'gleam 9.9.9'\n").unwrap();
    let mut permissions = std::fs::metadata(&gleam).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&gleam, permissions).unwrap();
    let server = FakeGitHub::start(vec![
        r#"{"private":true,"default_branch":"main","plan":{"name":"enterprise"}}"#,
        r#"{"protection_rules":[{"type":"required_reviewers","prevent_self_review":true,"reviewers":[{"type":"User","reviewer":{"login":"reviewer"}}]}],"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false}}"#,
        r#"{"name":"main","protected":true}"#,
    ]);

    let output = Command::new(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .args(["--output", "json", "doctor", "--online"])
        .env("RELEASE_GLZ_GLEAM", &gleam)
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
    server.stop();
    registry.stop();

    assert_eq!(output.status.code(), Some(3));
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["schema"], "command/v2");
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["result"]["state"], "blocked");
    assert_eq!(envelope["diagnostics"][0]["code"], "compiler_mismatch");
    assert_eq!(
        envelope["next_actions"][0]["command"],
        "install Gleam 1.12.3"
    );
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
allow_http_loopback = true

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

struct FakeGitHub {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<std::sync::Mutex<Vec<String>>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl FakeGitHub {
    fn start(responses: Vec<&'static str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let thread_stop = Arc::clone(&stop);
        let thread_requests = Arc::clone(&requests);
        let thread = thread::spawn(move || {
            let mut responses = responses.into_iter();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !thread_stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut request = Vec::new();
                        let mut buffer = [0_u8; 4096];
                        loop {
                            let count = stream.read(&mut buffer).unwrap_or(0);
                            request.extend_from_slice(&buffer[..count]);
                            if count == 0 || request.windows(4).any(|window| window == b"\r\n\r\n")
                            {
                                break;
                            }
                        }
                        thread_requests
                            .lock()
                            .unwrap()
                            .push(String::from_utf8_lossy(&request).into_owned());
                        let body = responses
                            .next()
                            .unwrap_or(r#"{"message":"unexpected request"}"#);
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                        .unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            address,
            stop,
            requests,
            thread: Some(thread),
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}
