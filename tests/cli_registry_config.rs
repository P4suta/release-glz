#![cfg(unix)]

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::mpsc;
use std::thread;

use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256};

#[test]
fn sealed_candidate_cli_lifecycle_reuses_one_candidate_without_rebuilding() {
    let temp = tempfile::tempdir().unwrap();
    let (registry_listener, registry_url) = bound_listener();
    let (github_listener, github_url) = bound_listener();
    let manifest = manifest(&registry_url).replace("docs = true", "docs = false");
    let readme = b"# Widget\n";
    let source = b"pub fn widget() -> Int { 1 }\n";
    std::fs::create_dir(temp.path().join("src")).unwrap();
    std::fs::write(temp.path().join("gleam.toml"), &manifest).unwrap();
    std::fs::write(temp.path().join("README.md"), readme).unwrap();
    std::fs::write(temp.path().join("src/widget.gleam"), source).unwrap();
    git(temp.path(), &["init", "--initial-branch=main"]);
    git(temp.path(), &["config", "core.hooksPath", ".git/no-hooks"]);
    git(
        temp.path(),
        &["config", "user.email", "fixture@example.test"],
    );
    git(temp.path(), &["config", "user.name", "Fixture"]);
    git(temp.path(), &["config", "commit.gpgsign", "false"]);
    git(temp.path(), &["config", "tag.gpgsign", "false"]);
    git(temp.path(), &["add", "."]);
    git(temp.path(), &["commit", "-m", "feat: initial package"]);
    let source_sha = git_output(temp.path(), &["rev-parse", "HEAD"]);

    let package = hex_package_with_files(&[
        ("gleam.toml", manifest.as_bytes()),
        ("README.md", readme),
        ("src/widget.gleam", source),
    ]);
    let package_path = temp.path().join("fixture.tar");
    std::fs::write(&package_path, &package).unwrap();
    let interface_path = temp.path().join("interface.json");
    std::fs::write(&interface_path, br#"{"modules":{}}"#).unwrap();
    let gleam = fake_gleam(temp.path());
    let candidate = temp.path().join("candidate");

    // These uncommitted bytes must never become the Candidate source.
    std::fs::write(
        temp.path().join("src/widget.gleam"),
        "pub fn dirty() -> Int { 999 }\n",
    )
    .unwrap();

    let rehearse = candidate_command(temp.path(), &gleam, &package_path, &interface_path)
        .args([
            "--output",
            "json",
            "rehearse",
            "--ref",
            &source_sha,
            "--out",
            candidate.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success(&rehearse, "rehearse");
    let rehearsed = json(&rehearse);
    assert_eq!(rehearsed["schema"], "command/v2");
    assert_eq!(rehearsed["result"]["schema"], "candidate/v1");
    assert_eq!(rehearsed["result"]["source"]["commit_sha"], source_sha);
    let candidate_digest = rehearsed["result"]["candidate_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    let sealed_package = std::fs::read(candidate.join("artifacts/package.tar")).unwrap();

    let verify = candidate_command(temp.path(), &gleam, &package_path, &interface_path)
        .args([
            "--output",
            "json",
            "verify",
            "--candidate",
            candidate.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success(&verify, "verify");
    let verified = json(&verify);
    assert_eq!(verified["result"]["state"], "candidate_ready");
    assert_eq!(
        verified["result"]["candidate"]["candidate_digest"],
        candidate_digest
    );

    let status = candidate_command(temp.path(), &gleam, &package_path, &interface_path)
        .args([
            "--output",
            "json",
            "status",
            "--candidate",
            candidate.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success(&status, "status");
    let status = json(&status);
    assert_eq!(status["result"]["state"], "candidate_ready");
    assert_eq!(status["result"]["candidate_digest"], candidate_digest);

    let (registry_requests, registry_server) =
        serve_recording(registry_listener, vec![http_response(404, b"")]);
    let (github_requests, github_server) = serve_recording(
        github_listener,
        vec![http_response(404, b""), http_response(404, b"")],
    );
    let release = candidate_command(temp.path(), &gleam, &package_path, &interface_path)
        .args([
            "--output",
            "json",
            "--dry-run",
            "release",
            "--candidate",
            candidate.to_str().unwrap(),
        ])
        .env("GITHUB_API_URL", &github_url)
        .env("GITHUB_GRAPHQL_URL", format!("{github_url}/graphql"))
        .output()
        .unwrap();
    registry_server.join().unwrap();
    github_server.join().unwrap();
    assert_success(&release, "release --dry-run");
    let release = json(&release);
    assert_eq!(release["result"]["state"], "candidate_ready");
    assert_eq!(release["result"]["candidate_digest"], candidate_digest);
    assert_eq!(release["result"]["applied"], serde_json::json!([]));
    assert_eq!(
        release["result"]["remaining"],
        serde_json::json!([
            {"kind": "prepare_annotated_tag"},
            {"kind": "prepare_github_draft"},
            {"kind": "publish_package"},
            {"kind": "finalize_github_release"}
        ])
    );
    assert_eq!(
        std::fs::read(candidate.join("artifacts/package.tar")).unwrap(),
        sealed_package
    );
    assert_eq!(registry_requests.try_iter().count(), 1);
    assert_eq!(github_requests.try_iter().count(), 2);
}

#[test]
fn a_version_below_the_automatic_minimum_is_a_policy_exit_not_an_internal_failure() {
    let temp = tempfile::tempdir().unwrap();
    let (registry_url, _request, server) = not_found_server();
    let manifest = manifest(&registry_url).replace("docs = true", "docs = false");
    std::fs::create_dir(temp.path().join("src")).unwrap();
    std::fs::write(temp.path().join("gleam.toml"), &manifest).unwrap();
    std::fs::write(temp.path().join("README.md"), "# Widget\n").unwrap();
    std::fs::write(
        temp.path().join("src/widget.gleam"),
        "pub fn widget() -> Int { 1 }\n",
    )
    .unwrap();
    git(temp.path(), &["init", "--initial-branch=main"]);
    git(temp.path(), &["config", "core.hooksPath", ".git/no-hooks"]);
    git(
        temp.path(),
        &["config", "user.email", "fixture@example.test"],
    );
    git(temp.path(), &["config", "user.name", "Fixture"]);
    git(temp.path(), &["config", "commit.gpgsign", "false"]);
    git(temp.path(), &["config", "tag.gpgsign", "false"]);
    git(temp.path(), &["add", "."]);
    git(temp.path(), &["commit", "-m", "feat: initial package"]);

    let package_path = temp.path().join("fixture.tar");
    std::fs::write(&package_path, hex_package()).unwrap();
    let interface_path = temp.path().join("interface.json");
    std::fs::write(&interface_path, br#"{"modules":{}}"#).unwrap();
    let gleam = fake_gleam(temp.path());
    let before = std::fs::read(temp.path().join("gleam.toml")).unwrap();

    let output = candidate_command(temp.path(), &gleam, &package_path, &interface_path)
        .args(["--output", "json", "set-version", "0.9.0"])
        .output()
        .unwrap();
    server.join().unwrap();

    assert_eq!(
        output.status.code(),
        Some(3),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope = json(&output);
    assert_eq!(envelope["schema"], "command/v2");
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["diagnostics"][0]["code"], "policy_or_approval");
    assert_eq!(
        std::fs::read(temp.path().join("gleam.toml")).unwrap(),
        before
    );
}

#[test]
fn set_version_dry_run_and_apply_only_raise_the_manifest_version() {
    let temp = tempfile::tempdir().unwrap();
    let (listener, registry_url) = bound_listener();
    let (package, interface, gleam) = initialize_initial_package(temp.path(), &registry_url);
    let (_requests, server) = serve_recording(
        listener,
        vec![http_response(404, b""), http_response(404, b"")],
    );
    let before = std::fs::read_to_string(temp.path().join("gleam.toml")).unwrap();

    let dry_run = candidate_command(temp.path(), &gleam, &package, &interface)
        .args(["--output", "json", "--dry-run", "set-version", "2.0.0"])
        .output()
        .unwrap();
    assert_success(&dry_run, "set-version --dry-run");
    let dry_run = json(&dry_run);
    assert_eq!(dry_run["result"]["version"], "2.0.0");
    assert_eq!(dry_run["result"]["manifest_version"], "2.0.0");
    assert_eq!(
        std::fs::read_to_string(temp.path().join("gleam.toml")).unwrap(),
        before
    );

    let apply = candidate_command(temp.path(), &gleam, &package, &interface)
        .args(["--output", "json", "set-version", "2.0.0"])
        .output()
        .unwrap();
    server.join().unwrap();
    assert_success(&apply, "set-version");
    let apply = json(&apply);
    assert_eq!(apply["result"]["version"], "2.0.0");
    let written = std::fs::read_to_string(temp.path().join("gleam.toml")).unwrap();
    assert!(written.contains("version = \"2.0.0\""));
    assert!(written.contains("description = \"fixture\""));
    assert!(written.contains("credential_env = \"TEST_REGISTRY_TOKEN\""));
}

#[test]
fn prerelease_command_starts_the_alpha_train_and_persists_channel_and_version() {
    let temp = tempfile::tempdir().unwrap();
    let (listener, registry_url) = bound_listener();
    let (package, interface, gleam) = initialize_initial_package(temp.path(), &registry_url);
    let (_requests, server) = serve_recording(listener, vec![http_response(404, b"")]);

    let output = candidate_command(temp.path(), &gleam, &package, &interface)
        .args(["--output", "json", "prerelease", "alpha"])
        .output()
        .unwrap();
    server.join().unwrap();
    assert_success(&output, "prerelease alpha");
    let output = json(&output);
    assert_eq!(output["result"]["version"], "1.0.0-alpha.1");
    assert_eq!(output["result"]["prerelease"], "alpha");
    let written = std::fs::read_to_string(temp.path().join("gleam.toml")).unwrap();
    assert!(written.contains("version = \"1.0.0-alpha.1\""));
    assert!(written.contains("prerelease = \"alpha\""));
}

#[test]
fn plan_uses_the_strict_manifest_registry_adapter_and_private_read_credential() {
    let temp = tempfile::tempdir().unwrap();
    let (registry_url, request, server) = not_found_server();
    std::fs::create_dir(temp.path().join("src")).unwrap();
    std::fs::write(temp.path().join("gleam.toml"), manifest(&registry_url)).unwrap();
    std::fs::write(temp.path().join("README.md"), "# Widget\n").unwrap();
    std::fs::write(
        temp.path().join("src/widget.gleam"),
        "pub fn widget() -> Int { 1 }\n",
    )
    .unwrap();
    git(temp.path(), &["init", "--initial-branch=main"]);
    git(
        temp.path(),
        &["config", "user.email", "fixture@example.test"],
    );
    git(temp.path(), &["config", "user.name", "Fixture"]);
    git(temp.path(), &["config", "commit.gpgsign", "false"]);
    git(temp.path(), &["config", "tag.gpgsign", "false"]);
    git(temp.path(), &["add", "."]);
    git(temp.path(), &["commit", "-m", "feat: initial package"]);

    let package = temp.path().join("fixture.tar");
    std::fs::write(&package, hex_package()).unwrap();
    let interface = temp.path().join("interface.json");
    std::fs::write(&interface, br#"{"modules":{}}"#).unwrap();
    let gleam = temp.path().join("fake-gleam");
    std::fs::write(
        &gleam,
        "#!/bin/sh\nset -eu\nif [ \"${1:-}\" = \"--version\" ]; then printf '%s\\n' 'gleam 1.12.3'; exit 0; fi\nif [ \"${1:-}\" = \"export\" ] && [ \"${2:-}\" = \"hex-tarball\" ]; then mkdir -p build; cp \"$TEST_HEX_TAR\" build/widget-1.0.0.tar; exit 0; fi\nif [ \"${1:-}\" = \"export\" ] && [ \"${2:-}\" = \"package-interface\" ]; then cp \"$TEST_INTERFACE\" \"$4\"; exit 0; fi\nexit 64\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&gleam).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&gleam, permissions).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .args(["--output", "json", "plan"])
        .env("RELEASE_GLZ_GLEAM", &gleam)
        .env("TEST_HEX_TAR", &package)
        .env("TEST_INTERFACE", &interface)
        .env("TEST_REGISTRY_TOKEN", "private-read-value")
        .env("RELEASE_GLZ_HEX_API_URL", "http://127.0.0.1:9")
        .env("RELEASE_GLZ_HEX_REPOSITORY_URL", "http://127.0.0.1:9")
        .env("RELEASE_GLZ_HEX_DOCS_URL", "http://127.0.0.1:9")
        .output()
        .unwrap();

    let observed = request
        .recv_timeout(std::time::Duration::from_secs(3))
        .unwrap_or_else(|_| "no request reached the configured registry".into());
    server.join().unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(observed.starts_with("get /api/packages/widget http/1.1"));
    assert!(observed.contains("authorization: bearer private-read-value"));
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["result"]["state"], "planned");
    assert_eq!(envelope["result"]["release_required"], true);
}

#[test]
fn update_closes_a_stale_verified_managed_pr_when_no_release_is_required() {
    let temp = tempfile::tempdir().unwrap();
    let (registry_listener, registry_url) = bound_listener();
    let manifest = manifest(&registry_url);
    let readme = b"# Widget\n";
    let source = b"pub fn widget() -> Int { 1 }\n";
    std::fs::create_dir(temp.path().join("src")).unwrap();
    std::fs::write(temp.path().join("gleam.toml"), &manifest).unwrap();
    std::fs::write(temp.path().join("README.md"), readme).unwrap();
    std::fs::write(temp.path().join("src/widget.gleam"), source).unwrap();
    git(temp.path(), &["init", "--initial-branch=main"]);
    git(
        temp.path(),
        &["config", "user.email", "fixture@example.test"],
    );
    git(temp.path(), &["config", "user.name", "Fixture"]);
    git(temp.path(), &["config", "commit.gpgsign", "false"]);
    git(temp.path(), &["config", "tag.gpgsign", "false"]);
    git(temp.path(), &["add", "."]);
    git(temp.path(), &["commit", "-m", "feat: published package"]);
    git(temp.path(), &["tag", "v1.0.0"]);
    let head = git_output(temp.path(), &["rev-parse", "HEAD"]);

    let package = hex_package_with_files(&[
        ("gleam.toml", manifest.as_bytes()),
        ("README.md", readme),
        ("src/widget.gleam", source),
    ]);
    let interface_bytes = br#"{"modules":{}}"#;
    let docs = tar_gz(&[("package-interface.json", interface_bytes)]);
    let registry_responses = vec![
        http_response(
            200,
            br#"{"releases":[{"version":"1.0.0","has_docs":true}],"retirements":{}}"#,
        ),
        http_response(200, &package),
        http_response(200, &docs),
    ];
    let (registry_requests, registry_server) =
        serve_recording(registry_listener, registry_responses);

    let package_path = temp.path().join("fixture.tar");
    std::fs::write(&package_path, &package).unwrap();
    let interface_path = temp.path().join("interface.json");
    std::fs::write(&interface_path, interface_bytes).unwrap();
    let gleam = fake_gleam(temp.path());

    let (github_listener, github_url) = bound_listener();
    let digest = "d".repeat(64);
    let pull = format!(
        r#"[{{"number":7,"title":"chore(release): widget 1.0.0","body":"<!-- release-glz:managed package=widget branch=release-glz/widget head={head} digest={digest} version=1.0.0 -->","html_url":"https://github.test/acme/widget/pull/7","merge_commit_sha":null,"merged_at":null,"user":{{"login":"bot"}},"labels":[],"head":{{"ref":"release-glz/widget","sha":"{head}"}}}}]"#,
    );
    let github_responses = vec![
        http_response(200, pull.as_bytes()),
        http_response(200, format!(r#"{{"object":{{"sha":"{head}"}}}}"#).as_bytes()),
        http_response(
            200,
            format!(
                "{{\"message\":\"Generated by release-glz.\\n\\nrelease-glz-digest: {digest}\",\"verification\":{{\"verified\":true}}}}"
            )
            .as_bytes(),
        ),
        http_response(200, b"{}"),
        http_response(204, b""),
    ];
    let (github_requests, github_server) = serve_recording(github_listener, github_responses);

    let output = Command::new(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .args(["--output", "json", "update"])
        .env("RELEASE_GLZ_GLEAM", &gleam)
        .env("TEST_HEX_TAR", &package_path)
        .env("TEST_INTERFACE", &interface_path)
        .env("TEST_REGISTRY_TOKEN", "private-read-value")
        .env("GITHUB_TOKEN", "github-value")
        .env_remove("GH_TOKEN")
        .env("GITHUB_REPOSITORY", "acme/widget")
        .env("GITHUB_API_URL", &github_url)
        .env("GITHUB_GRAPHQL_URL", format!("{github_url}/graphql"))
        .output()
        .unwrap();

    registry_server.join().unwrap();
    github_server.join().unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let registry_requests: Vec<_> = registry_requests.try_iter().collect();
    assert_eq!(registry_requests.len(), 3);
    let github_requests: Vec<_> = github_requests.try_iter().collect();
    assert_eq!(github_requests.len(), 5, "{github_requests:#?}");
    assert!(
        github_requests[0].starts_with("GET /repos/acme/widget/pulls?state=open&per_page=100 ")
    );
    assert!(github_requests[3].starts_with("PATCH /repos/acme/widget/pulls/7 "));
    assert!(github_requests[3].contains("\"state\":\"closed\""));
    assert!(
        github_requests[4]
            .starts_with("DELETE /repos/acme/widget/git/refs/heads/release-glz%2Fwidget ")
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["result"]["state"], "up_to_date");
}

#[test]
fn top_level_diagnostics_redact_the_configured_registry_credential() {
    let temp = tempfile::tempdir().unwrap();
    let secret = "custom-registry-value-that-must-never-escape";
    let source = manifest("https://registry.example.test")
        .replace("TEST_REGISTRY_TOKEN", "CUSTOM_REGISTRY_CREDENTIAL");
    std::fs::write(temp.path().join("gleam.toml"), source).unwrap();
    let gleam = temp.path().join("failing-gleam");
    std::fs::write(
        &gleam,
        format!("#!/bin/sh\nprintf '%s' '{secret}' >&2\nexit 9\n"),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&gleam).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&gleam, permissions).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .env("RELEASE_GLZ_GLEAM", &gleam)
        .env("CUSTOM_REGISTRY_CREDENTIAL", secret)
        .args(["--output", "json", "plan"])
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains(secret), "{combined}");
    assert!(combined.contains("[REDACTED]"), "{combined}");
}

fn manifest(base: &str) -> String {
    r#"name = "widget"
version = "1.0.0"
description = "fixture"
licences = ["MIT"]

[repository]
type = "github"
user = "acme"
repo = "widget"

[tools.release-glz]
schema = 2
compiler = "1.12.3"

[tools.release-glz.registry]
provider = "hex-compatible"
api_url = "__BASE__/api"
repository_url = "__BASE__/repo"
docs_url = "__BASE__/repo/docs"
credential_env = "TEST_REGISTRY_TOKEN"
auth = "bearer"
allow_http_loopback = true

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
    .replace("__BASE__", base)
}

fn not_found_server() -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return;
                    }
                    thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => panic!("registry accept failed: {error}"),
            }
        };
        let request = read_http_request(&mut stream);
        sender.send(request.to_ascii_lowercase()).unwrap();
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    (format!("http://{address}"), receiver, handle)
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn http_response(status: u16, body: &[u8]) -> HttpResponse {
    HttpResponse {
        status,
        body: body.to_vec(),
    }
}

fn bound_listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    (listener, base)
}

#[test]
fn http_request_reader_normalizes_an_inherited_nonblocking_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let client = thread::spawn(move || {
        let mut stream = TcpStream::connect(address).unwrap();
        thread::sleep(std::time::Duration::from_millis(25));
        stream
            .write_all(b"POST /fixture HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}")
            .unwrap();
    });
    let (mut stream, _) = listener.accept().unwrap();
    stream.set_nonblocking(true).unwrap();

    let request = read_http_request(&mut stream);

    client.join().unwrap();
    assert_eq!(
        request,
        "POST /fixture HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}"
    );
}

fn serve_recording(
    listener: TcpListener,
    responses: Vec<HttpResponse>,
) -> (mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut responses = VecDeque::from(responses);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while let Some(response) = responses.pop_front() {
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if std::time::Instant::now() >= deadline {
                            return;
                        }
                        thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(error) => panic!("server accept failed: {error}"),
                }
            };
            let request = read_http_request(&mut stream);
            sender.send(request).unwrap();
            let reason = match response.status {
                200 => "OK",
                204 => "No Content",
                404 => "Not Found",
                _ => "Response",
            };
            write!(
                stream,
                "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.status,
                reason,
                response.body.len()
            )
            .unwrap();
            stream.write_all(&response.body).unwrap();
        }
    });
    (receiver, handle)
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let count = stream.read(&mut buffer).unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
        .unwrap_or(0);
    while bytes.len() < header_end + length {
        let count = stream.read(&mut buffer).unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&buffer[..count]);
    }
    String::from_utf8_lossy(&bytes[..header_end + length]).into_owned()
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

fn initialize_initial_package(
    directory: &std::path::Path,
    registry_url: &str,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let manifest = manifest(registry_url).replace("docs = true", "docs = false");
    std::fs::create_dir(directory.join("src")).unwrap();
    std::fs::write(directory.join("gleam.toml"), manifest).unwrap();
    std::fs::write(directory.join("README.md"), "# Widget\n").unwrap();
    std::fs::write(
        directory.join("src/widget.gleam"),
        "pub fn widget() -> Int { 1 }\n",
    )
    .unwrap();
    git(directory, &["init", "--initial-branch=main"]);
    git(directory, &["config", "core.hooksPath", ".git/no-hooks"]);
    git(directory, &["config", "user.email", "fixture@example.test"]);
    git(directory, &["config", "user.name", "Fixture"]);
    git(directory, &["config", "commit.gpgsign", "false"]);
    git(directory, &["config", "tag.gpgsign", "false"]);
    git(directory, &["add", "."]);
    git(directory, &["commit", "-m", "feat: initial package"]);

    let package = directory.join("fixture.tar");
    std::fs::write(&package, hex_package()).unwrap();
    let interface = directory.join("interface.json");
    std::fs::write(&interface, br#"{"modules":{}}"#).unwrap();
    let gleam = fake_gleam(directory);
    (package, interface, gleam)
}

fn candidate_command(
    directory: &std::path::Path,
    gleam: &std::path::Path,
    package: &std::path::Path,
    interface: &std::path::Path,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_release-glz"));
    command
        .current_dir(directory)
        .env("RELEASE_GLZ_GLEAM", gleam)
        .env("TEST_HEX_TAR", package)
        .env("TEST_INTERFACE", interface)
        .env("TEST_REGISTRY_TOKEN", "private-read-value")
        .env_remove("GITHUB_TOKEN")
        .env_remove("GH_TOKEN");
    command
}

fn assert_success(output: &std::process::Output, action: &str) {
    assert!(
        output.status.success(),
        "{action}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn json(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

fn fake_gleam(directory: &std::path::Path) -> std::path::PathBuf {
    let gleam = directory.join("fake-gleam");
    std::fs::write(
        &gleam,
        "#!/bin/sh\nset -eu\nif [ \"${1:-}\" = \"--version\" ]; then printf '%s\\n' 'gleam 1.12.3'; exit 0; fi\nif [ \"${1:-}\" = \"export\" ] && [ \"${2:-}\" = \"hex-tarball\" ]; then mkdir -p build; cp \"$TEST_HEX_TAR\" build/widget-1.0.0.tar; exit 0; fi\nif [ \"${1:-}\" = \"export\" ] && [ \"${2:-}\" = \"package-interface\" ]; then cp \"$TEST_INTERFACE\" \"$4\"; exit 0; fi\nexit 64\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&gleam).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&gleam, permissions).unwrap();
    gleam
}

fn hex_package() -> Vec<u8> {
    let contents = tar_gz(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.0.0\"\n")]);
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

fn hex_package_with_files(files: &[(&str, &[u8])]) -> Vec<u8> {
    let contents = tar_gz(files);
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
    header.set_mtime(0);
    header.set_cksum();
    archive.append_data(&mut header, path, contents).unwrap();
}
