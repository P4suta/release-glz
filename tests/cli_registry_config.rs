#![cfg(unix)]

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::mpsc;
use std::thread;

use base64::Engine as _;
use flate2::{Compression, write::GzEncoder};
use release_glz_test_support::isolated_command;
use sha2::{Digest, Sha256};

#[test]
fn sealed_candidate_cli_lifecycle_reuses_one_candidate_without_rebuilding() {
    let temp = tempfile::tempdir().unwrap();
    let (registry_listener, registry_url) = bound_listener();
    let (github_listener, github_url) = bound_listener();
    let gleam = initialize_initial_package(temp.path(), &registry_url);
    let source_sha = git_output(temp.path(), &["rev-parse", "HEAD"]);
    let candidate = temp.path().join("candidate");

    // These uncommitted bytes must never become the Candidate source.
    std::fs::write(
        temp.path().join("src/widget.gleam"),
        "pub fn dirty() -> Int { 999 }\n",
    )
    .unwrap();

    let rehearse = candidate_command(temp.path(), &gleam)
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

    let verify = candidate_command(temp.path(), &gleam)
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

    let status = candidate_command(temp.path(), &gleam)
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
    let release = candidate_command(temp.path(), &gleam)
        .args([
            "--output",
            "json",
            "release",
            "--dry-run",
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

    let output = candidate_command(temp.path(), &gleam)
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
    let gleam = initialize_initial_package(temp.path(), &registry_url);
    let (_requests, server) = serve_recording(
        listener,
        vec![http_response(404, b""), http_response(404, b"")],
    );
    let before = std::fs::read_to_string(temp.path().join("gleam.toml")).unwrap();

    let dry_run = candidate_command(temp.path(), &gleam)
        .args(["--output", "json", "set-version", "2.0.0", "--dry-run"])
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

    let apply = candidate_command(temp.path(), &gleam)
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
    let gleam = initialize_initial_package(temp.path(), &registry_url);
    let (_requests, server) = serve_recording(listener, vec![http_response(404, b"")]);

    let output = candidate_command(temp.path(), &gleam)
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
    let gleam = fake_gleam(temp.path());

    let output = isolated_command(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .args(["--output", "json", "plan"])
        .env("RELEASE_GLZ_GLEAM", &gleam)
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
fn release_pr_closes_a_stale_verified_managed_pr_when_no_release_is_required() {
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
        r#"[{{"number":7,"title":"chore(release): widget 1.0.0","body":"<!-- release-glz:managed package=widget branch=release-glz/widget head={head} digest={digest} version=1.0.0 intent=pending -->","html_url":"https://github.test/acme/widget/pull/7","merge_commit_sha":null,"merged_at":null,"user":{{"login":"bot"}},"labels":[],"head":{{"ref":"release-glz/widget","sha":"{head}","repo":{{"full_name":"acme/widget","default_branch":"main"}}}},"base":{{"ref":"main","repo":{{"full_name":"acme/widget","default_branch":"main"}}}}}}]"#,
    );
    let github_responses = vec![
        http_response(200, REPOSITORY.as_bytes()),
        http_response(200, format!(r#"{{"object":{{"sha":"{head}"}}}}"#).as_bytes()),
        http_response(200, pull.as_bytes()),
        http_response(200, format!(r#"{{"object":{{"sha":"{head}"}}}}"#).as_bytes()),
        http_response(
            200,
            format!(
                "{{\"message\":\"Generated by release-glz.\\n\\nrelease-glz-digest: {digest}\",\"verification\":{{\"verified\":true}},\"parents\":[{{\"sha\":\"{head}\"}}]}}"
            )
            .as_bytes(),
        ),
        http_response(200, b"{}"),
        http_response(204, b""),
    ];
    let (github_requests, github_server) = serve_recording(github_listener, github_responses);

    let output = isolated_command(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .args(["--output", "json", "release-pr"])
        .env("RELEASE_GLZ_GLEAM", &gleam)
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
    assert_eq!(github_requests.len(), 7, "{github_requests:#?}");
    assert!(github_requests[0].starts_with("GET /repos/acme/widget "));
    assert!(github_requests[1].starts_with("GET /repos/acme/widget/git/ref/heads/main "));
    assert!(
        github_requests[2].starts_with("GET /repos/acme/widget/pulls?state=open&per_page=100 ")
    );
    assert!(github_requests[5].starts_with("PATCH /repos/acme/widget/pulls/7 "));
    assert!(github_requests[5].contains("\"state\":\"closed\""));
    assert!(
        github_requests[6]
            .starts_with("DELETE /repos/acme/widget/git/refs/heads/release-glz%2Fwidget ")
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["result"]["state"], "up_to_date");
}

#[test]
fn a_handed_off_plan_writes_the_release_pr_without_the_compiler() {
    let temp = tempfile::tempdir().unwrap();
    let (registry_listener, registry_url) = bound_listener();
    let gleam = initialize_initial_package(temp.path(), &registry_url);
    let source_sha = git_output(temp.path(), &["rev-parse", "HEAD"]);
    let (_registry_requests, registry_server) =
        serve_recording(registry_listener, vec![http_response(404, b"")]);
    let plan_path = temp.path().join("plan.json");

    let planned = candidate_command(temp.path(), &gleam)
        .args(["--output", "json", "plan", "--out"])
        .arg(&plan_path)
        .output()
        .unwrap();
    registry_server.join().unwrap();
    assert_success(&planned, "plan --out");
    let plan_bytes = std::fs::read(&plan_path).unwrap();
    let handed_off: serde_json::Value = serde_json::from_slice(&plan_bytes).unwrap();
    assert_eq!(json(&planned)["result"], handed_off);
    assert_eq!(handed_off["release_required"], true);
    assert_eq!(handed_off["release_pr_head"], serde_json::Value::Null);
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/release-plan.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&handed_off)
    );

    // The registry has stopped listening, so only the compiler stand-in could still answer.
    let (refusing, compiler_runs) = refusing_gleam(temp.path());
    let replanned = candidate_command(temp.path(), &refusing)
        .args(["--output", "json", "plan", "--out"])
        .arg(&plan_path)
        .output()
        .unwrap();
    assert_eq!(replanned.status.code(), Some(2), "{replanned:?}");
    assert!(
        !compiler_runs.exists(),
        "plan --out started planning before it refused the existing file"
    );
    assert_eq!(std::fs::read(&plan_path).unwrap(), plan_bytes);

    let (github_listener, github_url) = bound_listener();
    let release_pr_head = "b".repeat(40);
    let graph = format!(
        r#"{{"data":{{"createCommitOnBranch":{{"commit":{{"oid":"{release_pr_head}"}}}}}},"errors":[]}}"#
    );
    let created = format!(
        r#"{{"number":9,"title":"chore(release): widget 1.0.0","body":"managed","html_url":"https://github.test/acme/widget/pull/9","merge_commit_sha":null,"merged_at":null,"user":{{"login":"bot"}},"labels":[],"head":{{"ref":"release-glz/widget","sha":"{release_pr_head}"}}}}"#
    );
    let (github_requests, github_server) = serve_recording(
        github_listener,
        vec![
            http_response(200, REPOSITORY.as_bytes()),
            http_response(
                200,
                format!(r#"{{"object":{{"sha":"{source_sha}"}}}}"#).as_bytes(),
            ),
            http_response(200, b"[]"),
            http_response(200, b"[]"),
            http_response(200, b"[]"),
            http_response(404, b"{}"),
            http_response(201, b"{}"),
            http_response(200, graph.as_bytes()),
            http_response(201, created.as_bytes()),
        ],
    );

    let written = release_pr_from_plan(temp.path(), &plan_path, &refusing, &github_url)
        .output()
        .unwrap();
    github_server.join().unwrap();
    assert_success(&written, "release-pr --plan");
    assert!(
        !compiler_runs.exists(),
        "release-pr --plan ran the compiler: {}",
        std::fs::read_to_string(&compiler_runs).unwrap()
    );
    let result = &json(&written)["result"];
    assert_eq!(result["pr_url"], "https://github.test/acme/widget/pull/9");
    assert_eq!(result["release_pr_head"], release_pr_head.as_str());
    assert!(jsonschema::validator_for(&schema).unwrap().is_valid(result));

    let github_requests: Vec<_> = github_requests.try_iter().collect();
    assert_eq!(github_requests.len(), 9, "{github_requests:#?}");
    assert!(github_requests[0].starts_with("GET /repos/acme/widget "));
    assert!(github_requests[1].starts_with("GET /repos/acme/widget/git/ref/heads/main "));
    for lookup in &github_requests[2..4] {
        assert!(lookup.starts_with(&format!(
            "GET /repos/acme/widget/commits/{source_sha}/pulls "
        )));
    }
    assert!(github_requests[6].starts_with("POST /repos/acme/widget/git/refs "));
    assert!(github_requests[6].contains(&format!("\"sha\":\"{source_sha}\"")));
    assert!(github_requests[7].starts_with("POST /graphql "));
    let commit = request_json(&github_requests[7]);
    let input = &commit["variables"]["input"];
    assert_eq!(input["expectedHeadOid"], source_sha.as_str());
    let files: std::collections::BTreeMap<_, _> = input["fileChanges"]["additions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|addition| {
            let contents = base64::engine::general_purpose::STANDARD
                .decode(addition["contents"].as_str().unwrap())
                .unwrap();
            (
                addition["path"].as_str().unwrap().to_owned(),
                String::from_utf8(contents).unwrap(),
            )
        })
        .collect();
    assert_eq!(
        files.keys().collect::<Vec<_>>(),
        ["CHANGELOG.md", "gleam.toml"]
    );
    assert!(files["gleam.toml"].contains("version = \"1.0.0\""));
    assert!(files["CHANGELOG.md"].contains("initial package"));
    assert!(github_requests[8].starts_with("POST /repos/acme/widget/pulls "));
    assert!(
        request_json(&github_requests[8])["body"]
            .as_str()
            .unwrap()
            .contains(&format!("head={release_pr_head}"))
    );

    // Once the default branch moves past this checkout, the same plan writes and closes nothing.
    let (github_listener, github_url) = bound_listener();
    let newer_tip = "f".repeat(40);
    let (github_requests, github_server) = serve_recording(
        github_listener,
        vec![
            http_response(200, REPOSITORY.as_bytes()),
            http_response(
                200,
                format!(r#"{{"object":{{"sha":"{newer_tip}"}}}}"#).as_bytes(),
            ),
        ],
    );
    let superseded = release_pr_from_plan(temp.path(), &plan_path, &refusing, &github_url)
        .output()
        .unwrap();
    github_server.join().unwrap();
    assert_success(&superseded, "release-pr --plan behind the tip");
    let envelope = json(&superseded);
    assert_eq!(
        envelope["result"]["release_pr_head"],
        serde_json::Value::Null
    );
    assert_eq!(envelope["result"]["pr_url"], serde_json::Value::Null);
    assert_eq!(envelope["diagnostics"][0]["code"], "release_pr_superseded");
    assert_eq!(github_requests.try_iter().count(), 2);
}

#[test]
fn release_pr_at_the_merge_of_its_release_pr_writes_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let (registry_listener, registry_url) = bound_listener();
    let gleam = initialize_initial_package(temp.path(), &registry_url);
    let merge_commit = git_output(temp.path(), &["rev-parse", "HEAD"]);
    let (_registry_requests, registry_server) =
        serve_recording(registry_listener, vec![http_response(404, b"")]);
    let plan_path = temp.path().join("plan.json");
    let planned = candidate_command(temp.path(), &gleam)
        .args(["--output", "json", "plan", "--out"])
        .arg(&plan_path)
        .output()
        .unwrap();
    registry_server.join().unwrap();
    assert_success(&planned, "plan --out");

    let release_head = "e".repeat(40);
    let digest = "d".repeat(64);
    let merged = format!(
        r#"[{{"number":7,"title":"chore(release): widget 1.0.0","body":"<!-- release-glz:managed package=widget branch=release-glz/widget head={release_head} digest={digest} version=1.0.0 intent={} -->","html_url":"https://github.test/acme/widget/pull/7","merge_commit_sha":"{merge_commit}","merged_at":"2026-01-01T00:00:00Z","user":{{"login":"bot"}},"labels":[],"head":{{"ref":"release-glz/widget","sha":"{release_head}","repo":{{"full_name":"acme/widget","default_branch":"main"}}}},"base":{{"ref":"main","repo":{{"full_name":"acme/widget","default_branch":"main"}}}}}}]"#,
        "1".repeat(64)
    );
    let generated = format!(
        "{{\"message\":\"Generated by release-glz.\\n\\nrelease-glz-digest: {digest}\",\"verification\":{{\"verified\":true}},\"parents\":[{{\"sha\":\"{}\"}}]}}",
        "0".repeat(40)
    );
    let (github_listener, github_url) = bound_listener();
    let (github_requests, github_server) = serve_recording(
        github_listener,
        vec![
            http_response(200, REPOSITORY.as_bytes()),
            http_response(
                200,
                format!(r#"{{"object":{{"sha":"{merge_commit}"}}}}"#).as_bytes(),
            ),
            http_response(200, merged.as_bytes()),
            http_response(200, generated.as_bytes()),
        ],
    );
    let (refusing, _compiler_runs) = refusing_gleam(temp.path());

    let output = release_pr_from_plan(temp.path(), &plan_path, &refusing, &github_url)
        .output()
        .unwrap();
    github_server.join().unwrap();

    assert_success(&output, "release-pr --plan at the merge commit");
    let envelope = json(&output);
    assert_eq!(envelope["diagnostics"][0]["code"], "release_pr_merged");
    assert_eq!(
        envelope["result"]["pr_url"],
        "https://github.test/acme/widget/pull/7"
    );
    assert_eq!(
        envelope["result"]["release_pr_head"],
        serde_json::Value::Null
    );
    let github_requests: Vec<_> = github_requests.try_iter().collect();
    assert_eq!(github_requests.len(), 4, "{github_requests:#?}");
    assert!(
        github_requests
            .iter()
            .all(|request| request.starts_with("GET "))
    );
    assert!(github_requests[2].starts_with(&format!(
        "GET /repos/acme/widget/commits/{merge_commit}/pulls "
    )));
}

#[test]
fn a_handed_off_plan_that_does_not_describe_the_checkout_is_refused_before_any_request() {
    let temp = tempfile::tempdir().unwrap();
    let (registry_listener, registry_url) = bound_listener();
    let gleam = initialize_initial_package(temp.path(), &registry_url);
    let first = git_output(temp.path(), &["rev-parse", "HEAD"]);
    let (_registry_requests, registry_server) =
        serve_recording(registry_listener, vec![http_response(404, b"")]);
    let plan_path = temp.path().join("plan.json");
    let planned = candidate_command(temp.path(), &gleam)
        .args(["--output", "json", "plan", "--out"])
        .arg(&plan_path)
        .output()
        .unwrap();
    registry_server.join().unwrap();
    assert_success(&planned, "plan --out");
    let plan: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&plan_path).unwrap()).unwrap();
    git(temp.path(), &["switch", "--quiet", "--create", "side"]);
    git(
        temp.path(),
        &["commit", "--quiet", "--allow-empty", "-m", "chore: side"],
    );
    let side = git_output(temp.path(), &["rev-parse", "HEAD"]);
    git(temp.path(), &["switch", "--quiet", "main"]);
    git(
        temp.path(),
        &["commit", "--quiet", "--allow-empty", "-m", "fix: second"],
    );
    let second = git_output(temp.path(), &["rev-parse", "HEAD"]);
    let (refusing, compiler_runs) = refusing_gleam(temp.path());

    let mut accepted = plan.clone();
    accepted["baseline"]["sha"] = first.clone().into();
    let accepted_path = temp.path().join("accepted.json");
    std::fs::write(&accepted_path, serde_json::to_vec(&accepted).unwrap()).unwrap();
    let (github_listener, github_url) = bound_listener();
    let (github_requests, github_server) =
        serve_recording(github_listener, vec![http_response(200, b"[]")]);
    let dry_run = release_pr_from_plan(temp.path(), &accepted_path, &refusing, &github_url)
        .arg("--dry-run")
        .output()
        .unwrap();
    github_server.join().unwrap();
    assert_success(&dry_run, "release-pr --plan --dry-run");
    let github_requests: Vec<_> = github_requests.try_iter().collect();
    assert_eq!(github_requests.len(), 1, "{github_requests:#?}");
    assert!(
        github_requests[0].starts_with(&format!("GET /repos/acme/widget/commits/{second}/pulls "))
    );
    assert_eq!(
        json(&dry_run)["result"]["changes"][0]["title"],
        "fix: second"
    );

    let edit = |change: &dyn Fn(&mut serde_json::Value)| {
        let mut edited = plan.clone();
        change(&mut edited);
        serde_json::to_vec(&edited).unwrap()
    };
    let mut oversized = serde_json::to_vec(&plan).unwrap();
    oversized.resize(
        usize::try_from(release_glz::handoff::MAX_PLAN_BYTES).unwrap() + 1,
        b' ',
    );
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "another package",
            edit(&|plan| plan["package"] = "gadget".into()),
        ),
        (
            "another manifest version",
            edit(&|plan| plan["manifest_version"] = "1.0.1".into()),
        ),
        (
            "a baseline off the checked-out history",
            edit(&|plan| plan["baseline"]["sha"] = side.clone().into()),
        ),
        (
            "a symbolic baseline",
            edit(&|plan| plan["baseline"]["sha"] = "HEAD".into()),
        ),
        (
            "an abbreviated baseline",
            edit(&|plan| plan["baseline"]["sha"] = first[..7].into()),
        ),
        (
            "another schema",
            edit(&|plan| plan["schema"] = "plan/v1".into()),
        ),
        (
            "an unknown field",
            edit(&|plan| plan["unknown"] = true.into()),
        ),
        (
            "an unknown nested field",
            edit(&|plan| plan["baseline"]["unknown"] = true.into()),
        ),
        (
            "a Release PR already written",
            edit(&|plan| plan["release_pr_head"] = "c".repeat(40).into()),
        ),
        (
            "a Release PR page already named",
            edit(&|plan| plan["pr_url"] = "https://github.test/acme/widget/pull/1".into()),
        ),
        ("bytes that are not JSON", b"plan".to_vec()),
        ("a file above the size limit", oversized),
    ];
    let (silent_listener, silent_url) = bound_listener();
    for (case, bytes) in cases {
        let path = temp.path().join("refused.json");
        std::fs::write(&path, bytes).unwrap();
        let refused = release_pr_from_plan(temp.path(), &path, &refusing, &silent_url)
            .output()
            .unwrap();
        assert_eq!(refused.status.code(), Some(2), "{case}: {refused:?}");
        assert_eq!(
            json(&refused)["diagnostics"][0]["code"],
            "usage_or_config",
            "{case}"
        );
        assert!(
            matches!(silent_listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "{case}: release-pr contacted GitHub"
        );
    }
    assert!(
        !compiler_runs.exists(),
        "release-pr --plan ran the compiler"
    );

    let both = release_pr_from_plan(temp.path(), &plan_path, &refusing, &silent_url)
        .arg("--candidate")
        .arg(temp.path().join("candidate"))
        .output()
        .unwrap();
    assert_eq!(both.status.code(), Some(2), "{both:?}");
    assert!(
        json(&both)["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("cannot be used with")
    );
}

#[test]
fn a_candidate_whose_head_the_release_pr_left_binds_nothing_and_succeeds() {
    let temp = tempfile::tempdir().unwrap();
    let (_registry_listener, registry_url) = bound_listener();
    let gleam = initialize_initial_package(temp.path(), &registry_url);
    let source_sha = git_output(temp.path(), &["rev-parse", "HEAD"]);
    let candidate = temp.path().join("candidate");
    let rehearse = candidate_command(temp.path(), &gleam)
        .args([
            "--output",
            "json",
            "rehearse",
            "--ref",
            &source_sha,
            "--out",
        ])
        .arg(&candidate)
        .output()
        .unwrap();
    assert_success(&rehearse, "rehearse");

    let (github_listener, github_url) = bound_listener();
    let moved_head = "e".repeat(40);
    let moved = format!(
        r#"[{{"number":7,"title":"chore(release): widget 1.0.0","body":"<!-- release-glz:managed package=widget branch=release-glz/widget head={moved_head} digest={} version=1.0.0 intent=pending -->","html_url":"https://github.test/acme/widget/pull/7","merge_commit_sha":null,"merged_at":null,"user":{{"login":"bot"}},"labels":[],"head":{{"ref":"release-glz/widget","sha":"{moved_head}","repo":{{"full_name":"acme/widget","default_branch":"main"}}}},"base":{{"ref":"main","repo":{{"full_name":"acme/widget","default_branch":"main"}}}}}}]"#,
        "d".repeat(64)
    );
    let (github_requests, github_server) = serve_recording(
        github_listener,
        vec![
            http_response(200, b"[]"),
            http_response(200, moved.as_bytes()),
        ],
    );
    let (refusing, compiler_runs) = refusing_gleam(temp.path());

    let bound = isolated_command(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .args(["--output", "json", "release-pr", "--candidate"])
        .arg(&candidate)
        .env("RELEASE_GLZ_GLEAM", &refusing)
        .env("GITHUB_TOKEN", "github-value")
        .env("GITHUB_API_URL", &github_url)
        .env("GITHUB_GRAPHQL_URL", format!("{github_url}/graphql"))
        .output()
        .unwrap();
    github_server.join().unwrap();

    assert_success(&bound, "release-pr --candidate");
    let result = &json(&bound)["result"];
    assert_eq!(result["schema"], "release-pr-intent/v1");
    assert_eq!(result["intent_binding"], "superseded");
    assert_eq!(result["state"], "planned");
    assert_eq!(result["pr_url"], serde_json::Value::Null);
    let github_requests: Vec<_> = github_requests.try_iter().collect();
    assert_eq!(github_requests.len(), 2, "{github_requests:#?}");
    assert!(github_requests[0].starts_with(&format!(
        "GET /repos/acme/widget/commits/{source_sha}/pulls "
    )));
    assert!(
        github_requests[1].starts_with("GET /repos/acme/widget/pulls?state=open&per_page=100 ")
    );
    assert!(
        !compiler_runs.exists(),
        "release-pr --candidate ran the compiler"
    );
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

    let output = isolated_command(env!("CARGO_BIN_EXE_release-glz"))
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

/// The GitHub repository of the fixture package, whose default branch is `main`.
const REPOSITORY: &str = r#"{"node_id":"R_widget","default_branch":"main","private":false}"#;

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

/// Commit an unpublished package and return the compiler stand-in that exports its fixtures.
fn initialize_initial_package(
    directory: &std::path::Path,
    registry_url: &str,
) -> std::path::PathBuf {
    let manifest = manifest(registry_url).replace("docs = true", "docs = false");
    let readme = b"# Widget\n";
    let source = b"pub fn widget() -> Int { 1 }\n";
    std::fs::create_dir(directory.join("src")).unwrap();
    std::fs::write(directory.join("gleam.toml"), &manifest).unwrap();
    std::fs::write(directory.join("README.md"), readme).unwrap();
    std::fs::write(directory.join("src/widget.gleam"), source).unwrap();
    git(directory, &["init", "--initial-branch=main"]);
    git(directory, &["config", "core.hooksPath", ".git/no-hooks"]);
    git(directory, &["config", "user.email", "fixture@example.test"]);
    git(directory, &["config", "user.name", "Fixture"]);
    git(directory, &["config", "commit.gpgsign", "false"]);
    git(directory, &["config", "tag.gpgsign", "false"]);
    git(directory, &["add", "."]);
    git(directory, &["commit", "-m", "feat: initial package"]);

    let package = hex_package_with_files(&[
        ("gleam.toml", manifest.as_bytes()),
        ("README.md", readme),
        ("src/widget.gleam", source),
    ]);
    std::fs::write(directory.join("fixture.tar"), package).unwrap();
    std::fs::write(directory.join("interface.json"), br#"{"modules":{}}"#).unwrap();
    fake_gleam(directory)
}

fn candidate_command(directory: &std::path::Path, gleam: &std::path::Path) -> Command {
    let mut command = isolated_command(env!("CARGO_BIN_EXE_release-glz"));
    command
        .current_dir(directory)
        .env("RELEASE_GLZ_GLEAM", gleam)
        .env("TEST_REGISTRY_TOKEN", "private-read-value")
        .env_remove("GITHUB_TOKEN")
        .env_remove("GH_TOKEN");
    command
}

/// `release-pr --plan` with a GitHub token, and with no registry credential because writing the Release PR never reads the registry.
fn release_pr_from_plan(
    directory: &std::path::Path,
    plan: &std::path::Path,
    gleam: &std::path::Path,
    github_url: &str,
) -> Command {
    let mut command = isolated_command(env!("CARGO_BIN_EXE_release-glz"));
    command
        .current_dir(directory)
        .args(["--output", "json", "release-pr", "--plan"])
        .arg(plan)
        .env("RELEASE_GLZ_GLEAM", gleam)
        .env("GITHUB_TOKEN", "github-value")
        .env("GITHUB_REPOSITORY", "acme/widget")
        .env("GITHUB_API_URL", github_url)
        .env("GITHUB_GRAPHQL_URL", format!("{github_url}/graphql"));
    command
}

/// A compiler stand-in that records every run in the returned file and then fails.
fn refusing_gleam(directory: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let gleam = directory.join("refusing-gleam");
    let runs = directory.join("refusing-gleam.log");
    std::fs::write(
        &gleam,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexit 97\n",
            runs.display()
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&gleam).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&gleam, permissions).unwrap();
    (gleam, runs)
}

fn request_json(request: &str) -> serde_json::Value {
    let (_, body) = request.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(body).unwrap()
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

/// A compiler stand-in that exports `fixture.tar` and `interface.json` from its own directory.
///
/// The paths are part of the script, because the compiler inherits no test variables.
fn fake_gleam(directory: &std::path::Path) -> std::path::PathBuf {
    let gleam = directory.join("fake-gleam");
    let package = directory.join("fixture.tar");
    let interface = directory.join("interface.json");
    std::fs::write(
        &gleam,
        format!(
            "#!/bin/sh\nset -eu\nif [ \"${{1:-}}\" = \"--version\" ]; then printf '%s\\n' 'gleam 1.12.3'; exit 0; fi\nif [ \"${{1:-}}\" = \"export\" ] && [ \"${{2:-}}\" = \"hex-tarball\" ]; then mkdir -p build; cp '{}' build/widget-1.0.0.tar; exit 0; fi\nif [ \"${{1:-}}\" = \"export\" ] && [ \"${{2:-}}\" = \"package-interface\" ]; then cp '{}' \"$4\"; exit 0; fi\nexit 64\n",
            package.display(),
            interface.display()
        ),
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
    let checksum = release_glz::hex::upper(&digest.finalize());
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
    let checksum = release_glz::hex::upper(&digest.finalize());
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
