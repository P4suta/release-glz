use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use release_glz::forge::{
    CandidateRun, DefaultBranch, GitHubClient, GitHubRelease, GitHubReleaseAsset, GitHubRepository,
    IntentBinding, MAX_ATTRIBUTED_COMMITS, files_digest,
};
use release_glz::git::Commit;
use release_glz::model::{ApiDiff, Baseline, BaselineSource, Bump, ReleasePlan, ReleaseState};
use semver::Version;
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn github_repository_identity_cannot_change_api_paths_or_origins() {
    for valid in ["P4suta/release-glz", "Owner123/release_glz.rs", "a/b"] {
        assert_eq!(GitHubRepository::parse(valid).unwrap().full_name(), valid);
    }

    for invalid in [
        "owner/repo?token=secret",
        "owner/repo#fragment",
        "owner/%2e%2e",
        "owner/repo/extra",
        " owner/repo",
        "owner/repo ",
        "-owner/repo",
        "owner-/repo",
        "owner/.",
        "owner/..",
        "owner/répo",
        "/repo",
        "owner/",
    ] {
        let error = GitHubRepository::parse(invalid).unwrap_err().to_string();
        assert!(
            error.contains("owner/name"),
            "unexpected error for {invalid}: {error}"
        );
        assert!(!error.contains("secret"));
    }

    assert!(GitHubRepository::parse(&format!("{}/repo", "a".repeat(40))).is_err());
    assert!(GitHubRepository::parse(&format!("owner/{}", "a".repeat(101))).is_err());
}

#[test]
fn github_api_base_urls_are_absolute_hierarchical_and_query_free() {
    let repository = GitHubRepository::parse("o/r").unwrap();
    for invalid in [
        "https://api.github.com?credential=secret",
        "https://api.github.com/graphql#fragment",
    ] {
        let error = GitHubClient::new(
            repository.clone(),
            invalid.into(),
            "https://api.github.com/graphql".into(),
            Some("token".into()),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("query or fragment"), "{invalid}: {error}");
    }
}

#[tokio::test]
async fn github_release_is_observed_as_immutable_candidate_state_and_finalized_by_id() {
    let responses = vec![
        response(
            200,
            r#"[{"id":41,"html_url":"https://github.test/o/r/releases/41","tag_name":"v1.2.2","target_commitish":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","draft":false},{"id":42,"html_url":"https://github.test/o/r/releases/42","tag_name":"v1.2.3","target_commitish":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","body":"release-glz-candidate-digest: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","draft":true}]"#,
        ),
        response(
            200,
            r#"{"id":42,"html_url":"https://github.test/o/r/releases/42","tag_name":"v1.2.3","target_commitish":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","body":"release-glz-candidate-digest: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","draft":false}"#,
        ),
    ];
    let server = FakeServer::start(responses).await;
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        server.base_url(),
        format!("{}/graphql", server.base_url()),
        Some("token".into()),
    )
    .unwrap();

    let release = client
        .release_details_for_tag("v1.2.3")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(release.id, 42);
    assert_eq!(
        release.candidate_digest.as_deref(),
        Some("d".repeat(64).as_str())
    );
    assert!(release.draft);
    let finalized = client.finalize_release(release.id).await.unwrap();
    assert!(!finalized.draft);

    let requests = server.requests();
    // The tag endpoint hides drafts, so the lookup reads the release list.
    assert!(requests[0].starts_with("GET /repos/o/r/releases?per_page=100&page=1 "));
    assert!(requests[1].starts_with("PATCH /repos/o/r/releases/42 "));
    assert!(requests[1].contains("\"draft\":false"));
}

#[tokio::test]
async fn draft_creation_binds_target_and_candidate_digest() {
    let server = FakeServer::start(vec![response(
        201,
        r#"{"id":9,"html_url":"https://github.test/o/r/releases/9","tag_name":"v2.0.0","target_commitish":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","body":"release-glz-candidate-digest: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","draft":true}"#,
    )])
    .await;
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        server.base_url(),
        format!("{}/graphql", server.base_url()),
        Some("token".into()),
    )
    .unwrap();
    let created = client
        .create_draft_release("v2.0.0", &"b".repeat(40), "notes", &"c".repeat(64), false)
        .await
        .unwrap();
    assert!(created.draft);
    let request = &server.requests()[0];
    assert!(request.starts_with("POST /repos/o/r/releases "));
    assert!(request.contains("\"draft\":true"));
    assert!(request.contains("release-glz-candidate-digest"));
}

#[tokio::test]
async fn release_asset_upload_is_content_addressed_and_never_uses_clobber() {
    let bytes = br#"{"bomFormat":"CycloneDX"}"#;
    let digest = release_glz::hex::lower(&sha2::Sha256::digest(bytes));
    let response_body = format!(
        r#"{{"id":77,"name":"sbom.cdx.json","state":"uploaded","content_type":"application/vnd.cyclonedx+json","size":{},"digest":"sha256:{digest}"}}"#,
        bytes.len()
    );
    let server = FakeServer::start(vec![response(201, &response_body)]).await;
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        server.base_url(),
        format!("{}/graphql", server.base_url()),
        Some("token".into()),
    )
    .unwrap();
    let release = GitHubRelease {
        id: 42,
        html_url: "https://github.test/o/r/releases/42".into(),
        tag_name: "v1.2.3".into(),
        target_commitish: "a".repeat(40),
        candidate_digest: Some("d".repeat(64)),
        draft: true,
        upload_url: format!(
            "{}/repos/o/r/releases/42/assets{{?name,label}}",
            server.base_url()
        ),
        assets: vec![],
    };

    let uploaded = client
        .upload_release_asset(
            &release,
            "sbom.cdx.json",
            "application/vnd.cyclonedx+json",
            bytes,
        )
        .await
        .unwrap();
    assert_eq!(uploaded.sha256.as_deref(), Some(digest.as_str()));
    let request = &server.requests()[0];
    assert!(request.starts_with("POST /repos/o/r/releases/42/assets?name=sbom.cdx.json "));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("content-type: application/vnd.cyclonedx+json")
    );
    assert!(request.ends_with(std::str::from_utf8(bytes).unwrap()));
    assert!(!request.contains("clobber"));
}

#[tokio::test]
async fn annotated_tag_is_observed_by_peeling_the_github_tag_object() {
    let server = FakeServer::start(vec![
        response(
            200,
            r#"{"ref":"refs/tags/v1.2.3","object":{"type":"tag","sha":"tag-object"}}"#,
        ),
        response(
            200,
            r#"{"tag":"v1.2.3","object":{"type":"commit","sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#,
        ),
    ])
    .await;
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        server.base_url(),
        format!("{}/graphql", server.base_url()),
        Some("token".into()),
    )
    .unwrap();

    let tag = client.tag_state("v1.2.3").await.unwrap().unwrap();
    assert!(tag.annotated);
    assert_eq!(tag.target_sha, "a".repeat(40));
    let requests = server.requests();
    assert!(requests[0].starts_with("GET /repos/o/r/git/ref/tags/v1.2.3 "));
    assert!(requests[1].starts_with("GET /repos/o/r/git/tags/tag-object "));
}

#[tokio::test]
async fn annotated_tag_creation_uses_git_data_api_without_remote_credentials() {
    let server = FakeServer::start(vec![
        response(
            201,
            r#"{"sha":"tag-object","object":{"type":"commit","sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}"#,
        ),
        response(
            201,
            r#"{"ref":"refs/tags/v2.0.0","object":{"type":"tag","sha":"tag-object"}}"#,
        ),
    ])
    .await;
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        server.base_url(),
        format!("{}/graphql", server.base_url()),
        Some("token".into()),
    )
    .unwrap();

    client
        .create_annotated_tag("v2.0.0", &"b".repeat(40), "Release widget 2.0.0")
        .await
        .unwrap();
    let requests = server.requests();
    assert!(requests[0].starts_with("POST /repos/o/r/git/tags "));
    assert!(requests[0].contains("\"type\":\"commit\""));
    assert!(requests[1].starts_with("POST /repos/o/r/git/refs "));
    assert!(requests[1].contains("\"ref\":\"refs/tags/v2.0.0\""));
}

#[tokio::test]
async fn merged_release_pr_evidence_is_bound_to_the_candidate_merge_commit() {
    let head = "c".repeat(40);
    let merged = "a".repeat(40);
    let pull = |merge_sha: &str, intent: &str| {
        format!(
            r#"[{{"number":7,"title":"chore(release): widget 1.2.3","body":"<!-- release-glz:managed package=widget branch=release-glz/widget head={head} digest={} version=1.2.3 intent={intent} -->","html_url":"https://github.test/o/r/pull/7","merge_commit_sha":"{merge_sha}","merged_at":"2026-01-01T00:00:00Z","user":{{"login":"bot"}},"labels":[],"head":{{"ref":"release-glz/widget","sha":"{head}","repo":{{"full_name":"o/r","default_branch":"main"}}}},"base":{{"ref":"main","repo":{{"full_name":"o/r","default_branch":"main"}}}}}}]"#,
            files_digest(&release_files()),
        )
    };
    let mut responses = vec![response(200, &pull(&merged, &"1".repeat(64)))];
    responses.extend(generated_commit_on(&release_files(), &"0".repeat(40)));
    responses.push(response(200, &pull(&merged, &"e".repeat(64))));
    responses.extend(generated_commit_on(&release_files(), &"0".repeat(40)));
    responses.push(response(200, &pull(&"b".repeat(40), &"1".repeat(64))));
    let server = FakeServer::start(responses).await;
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        server.base_url(),
        format!("{}/graphql", server.base_url()),
        Some("token".into()),
    )
    .unwrap();
    let lookup = || client.merged_release_pr(&merged, "widget", "1.2.3", "release-glz/");

    let found = lookup().await.unwrap().unwrap();
    assert_eq!(found.html_url, "https://github.test/o/r/pull/7");
    assert_eq!(found.intent_digest, Some("1".repeat(64)));
    assert_eq!(
        lookup().await.unwrap().unwrap().intent_digest,
        Some("e".repeat(64)),
        "the lookup reports the intent that the merge approved, and the caller compares it"
    );
    assert!(
        lookup().await.unwrap().is_none(),
        "a pull request that merged as another commit"
    );
}

/// A managed Release PR whose head and base live in `o/r` unless a test overrides them.
fn managed_pull(head: &str, merge_sha: Option<&str>, intent: &str) -> serde_json::Value {
    serde_json::json!({
        "number": 7,
        "title": "chore(release): widget 1.2.3",
        "body": format!(
            "Release body\n\n<!-- release-glz:managed package=widget branch=release-glz/widget head={head} digest={} version=1.2.3 intent={intent} -->",
            files_digest(&release_files())
        ),
        "html_url": "https://github.test/o/r/pull/7",
        "merge_commit_sha": merge_sha,
        "merged_at": merge_sha.map(|_| "2026-01-01T00:00:00Z"),
        "user": {"login": "bot"},
        "labels": [],
        "head": {
            "ref": "release-glz/widget",
            "sha": head,
            "repo": {"full_name": "o/r", "default_branch": "main"}
        },
        "base": {
            "ref": "main",
            "repo": {"full_name": "o/r", "default_branch": "main"}
        }
    })
}

/// The responses that show `files` as a server-verified commit on `parent` that records their digest, in the order the client reads them.
fn generated_commit_on(files: &BTreeMap<String, Vec<u8>>, parent: &str) -> Vec<Vec<u8>> {
    recorded_commit_on(files, &files_digest(files), parent)
}

/// The responses for a server-verified commit on `parent` that modified `files` and whose message records `digest`, then one blob response for each file.
fn recorded_commit_on(
    files: &BTreeMap<String, Vec<u8>>,
    digest: &str,
    parent: &str,
) -> Vec<Vec<u8>> {
    let changed = files
        .keys()
        .enumerate()
        .map(|(index, path)| {
            serde_json::json!({"filename": path, "status": "modified", "sha": blob_id(index)})
        })
        .collect();
    let mut responses = vec![response(
        200,
        &commit_value(digest, &[parent], true, changed).to_string(),
    )];
    responses.extend(
        files
            .values()
            .map(|contents| response(200, &blob_value(contents).to_string())),
    );
    responses
}

/// The `commits/{sha}` response for a commit whose message records `digest`.
fn commit_value(
    digest: &str,
    parents: &[&str],
    verified: bool,
    files: Vec<serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "commit": {
            "message": format!("chore(release): widget 1.2.3\n\nGenerated by release-glz.\n\nrelease-glz-digest: {digest}"),
            "verification": {"verified": verified}
        },
        "parents": parents
            .iter()
            .map(|sha| serde_json::json!({"sha": sha}))
            .collect::<Vec<_>>(),
        "files": files
    })
}

/// A blob response whose base64 content GitHub breaks into lines of 60 characters.
fn blob_value(contents: &[u8]) -> serde_json::Value {
    let encoded = base64::engine::general_purpose::STANDARD.encode(contents);
    let lines = encoded
        .as_bytes()
        .chunks(60)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect::<Vec<_>>();
    serde_json::json!({
        "content": format!("{}\n", lines.join("\n")),
        "encoding": "base64",
        "size": contents.len()
    })
}

/// A distinct blob id for the file at `index` of a commit.
fn blob_id(index: usize) -> String {
    format!("{:040x}", index + 1)
}

/// The `main` branch of the test repository at `tip`.
fn default_branch(tip: &str) -> DefaultBranch {
    DefaultBranch {
        name: "main".into(),
        tip: tip.into(),
        repository_id: "R_repository".into(),
    }
}

#[tokio::test]
async fn a_merged_release_pr_counts_only_from_this_repository_into_its_default_branch() {
    let head = "c".repeat(40);
    let merged = "a".repeat(40);
    let intent = "1".repeat(64);
    let valid = managed_pull(&head, Some(&merged), &intent);
    let mut fork = valid.clone();
    fork["head"]["repo"]["full_name"] = "fork/r".into();
    let mut deleted_fork = valid.clone();
    deleted_fork["head"]["repo"] = serde_json::Value::Null;
    let mut other_base = valid.clone();
    other_base["base"]["ref"] = "develop".into();
    let list = |pull: &serde_json::Value| response(200, &serde_json::json!([pull]).to_string());
    let merge_commit = commit_value(
        &files_digest(&release_files()),
        &[&"0".repeat(40), &"1".repeat(40)],
        true,
        vec![],
    );
    let mut responses = vec![
        list(&fork),
        list(&deleted_fork),
        list(&other_base),
        list(&valid),
        response(200, &merge_commit.to_string()),
        list(&valid),
    ];
    responses.extend(generated_commit_on(&release_files(), &"0".repeat(40)));
    let server = FakeServer::start(responses).await;
    let client = test_client(&server, Some("token"));
    let lookup = || client.merged_release_pr(&merged, "widget", "1.2.3", "release-glz/");

    for refused in ["fork", "deleted fork", "other base", "merge commit head"] {
        assert!(lookup().await.unwrap().is_none(), "{refused}");
    }
    assert!(lookup().await.unwrap().is_some());
    assert_eq!(server.requests().len(), 9);
}

#[tokio::test]
async fn only_the_merged_release_pr_for_the_planned_version_marks_a_commit_as_pending() {
    let head = "c".repeat(40);
    let merged = "a".repeat(40);
    let valid = managed_pull(&head, Some(&merged), &"1".repeat(64));
    let mut other_version = valid.clone();
    other_version["body"] = valid["body"]
        .as_str()
        .unwrap()
        .replace("version=1.2.3", "version=1.2.2")
        .into();
    let mut fork = valid.clone();
    fork["head"]["repo"]["full_name"] = "fork/r".into();
    let mut unbound = valid.clone();
    unbound["body"] = valid["body"]
        .as_str()
        .unwrap()
        .replace(&format!("intent={}", "1".repeat(64)), "intent=pending")
        .into();
    let list = |pull: &serde_json::Value| response(200, &serde_json::json!([pull]).to_string());
    let mut responses = vec![list(&other_version), list(&fork), list(&unbound)];
    responses.extend(generated_commit_on(&release_files(), &"0".repeat(40)));
    let server = FakeServer::start(responses).await;
    let client = test_client(&server, Some("token"));
    let lookup = || client.merged_release_pr(&merged, "widget", "1.2.3", "release-glz/");

    assert!(lookup().await.unwrap().is_none(), "another version");
    assert!(lookup().await.unwrap().is_none(), "a fork");
    let pending = lookup().await.unwrap().unwrap();
    assert_eq!(
        pending.html_url, "https://github.test/o/r/pull/7",
        "a merged Release PR without a bound intent still marks its version as pending"
    );
    assert_eq!(pending.intent_digest, None);
    assert_eq!(server.requests().len(), 6);
}

#[tokio::test]
async fn intent_never_binds_to_a_release_pr_from_a_fork() {
    let head = "c".repeat(40);
    let mut fork = managed_pull(&head, None, "pending");
    fork["head"]["repo"]["full_name"] = "fork/r".into();
    let server =
        FakeServer::start(vec![response(200, &serde_json::json!([fork]).to_string())]).await;
    let client = test_client(&server, Some("token"));

    let binding = client
        .bind_release_pr_intent(&head, "widget", "1.2.3", "release-glz/", &"1".repeat(64))
        .await
        .unwrap();
    assert_eq!(binding, IntentBinding::Superseded);
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn a_candidate_whose_head_the_release_pr_left_binds_nothing() {
    let candidate_head = "c".repeat(40);
    let moved = managed_pull(&"e".repeat(40), None, "pending");
    let server =
        FakeServer::start(vec![response(200, &serde_json::json!([moved]).to_string())]).await;
    let client = test_client(&server, Some("token"));

    let binding = client
        .bind_release_pr_intent(
            &candidate_head,
            "widget",
            "1.2.3",
            "release-glz/",
            &"1".repeat(64),
        )
        .await
        .unwrap();

    assert_eq!(binding, IntentBinding::Superseded);
    let requests = server.requests();
    assert_eq!(requests.len(), 1, "{requests:#?}");
    assert!(requests[0].starts_with("GET /repos/o/r/pulls?state=open&per_page=100 "));
}

#[tokio::test]
async fn a_release_pr_at_the_candidate_head_must_describe_the_candidate_release() {
    let head = "c".repeat(40);
    let consistent = managed_pull(&head, None, "pending");
    let marker_field = |field: &str, value: &str| {
        let mut pull = consistent.clone();
        let body = pull["body"].as_str().unwrap().to_owned();
        let current = body
            .split(' ')
            .find(|token| token.starts_with(&format!("{field}=")))
            .unwrap()
            .to_owned();
        pull["body"] = body.replace(&current, &format!("{field}={value}")).into();
        pull
    };
    for (case, pull) in [
        ("another version", marker_field("version", "1.2.4")),
        ("another marker head", marker_field("head", &"e".repeat(40))),
        (
            "another branch",
            marker_field("branch", "release-glz/gadget"),
        ),
    ] {
        let server =
            FakeServer::start(vec![response(200, &serde_json::json!([pull]).to_string())]).await;
        let client = test_client(&server, Some("token"));
        let error = client
            .bind_release_pr_intent(&head, "widget", "1.2.3", "release-glz/", &"1".repeat(64))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("describes another release"),
            "{case}: {error:#}"
        );
        assert_eq!(server.requests().len(), 1, "{case}");
    }
}

#[tokio::test]
async fn an_intent_binds_only_to_a_verified_head_that_carries_no_other_intent() {
    let head = "c".repeat(40);
    let intent = "1".repeat(64);
    let unverified = commit_value(
        &files_digest(&release_files()),
        &[&"0".repeat(40)],
        false,
        vec![],
    )
    .to_string();
    let list = |intent: &str| {
        response(
            200,
            &serde_json::json!([managed_pull(&head, None, intent)]).to_string(),
        )
    };
    let mut responses = vec![
        list("pending"),
        response(200, &unverified),
        list(&"2".repeat(64)),
    ];
    responses.extend(generated_commit_on(&release_files(), &"0".repeat(40)));
    responses.push(list(&intent));
    responses.extend(generated_commit_on(&release_files(), &"0".repeat(40)));
    let server = FakeServer::start(responses).await;
    let client = test_client(&server, Some("token"));
    let bind = || client.bind_release_pr_intent(&head, "widget", "1.2.3", "release-glz/", &intent);

    let error = bind().await.unwrap_err();
    assert!(
        error.to_string().contains("not the server-verified"),
        "{error:#}"
    );
    let error = bind().await.unwrap_err();
    assert!(
        error.to_string().contains("different Candidate intent"),
        "{error:#}"
    );
    assert_eq!(
        bind().await.unwrap(),
        IntentBinding::Bound {
            url: "https://github.test/o/r/pull/7".into()
        }
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 10, "{requests:#?}");
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
}

#[tokio::test]
async fn a_binding_writes_nothing_over_a_release_pr_that_changed_after_it_was_read() {
    let head = "c".repeat(40);
    let intent = "1".repeat(64);
    let listed = managed_pull(&head, None, "pending");
    let moved = managed_pull(&"e".repeat(40), None, "pending");
    let mut edited = listed.clone();
    edited["body"] = format!(
        "Rewritten by a newer run.\n\n{}",
        listed["body"].as_str().unwrap()
    )
    .into();
    for (case, current) in [("a newer head", moved), ("a newer body", edited)] {
        let mut responses = vec![response(200, &serde_json::json!([listed]).to_string())];
        responses.extend(generated_commit_on(&release_files(), &"0".repeat(40)));
        responses.push(response(200, &current.to_string()));
        let server = FakeServer::start(responses).await;
        let result = test_client(&server, Some("token"))
            .bind_release_pr_intent(&head, "widget", "1.2.3", "release-glz/", &intent)
            .await;
        match case {
            "a newer head" => assert_eq!(result.unwrap(), IntentBinding::Superseded),
            _ => {
                let error = result.unwrap_err().to_string();
                assert!(error.contains("changed while"), "{case}: {error}");
            }
        }
        let requests = server.requests();
        assert_eq!(requests.len(), 5, "{case}: {requests:#?}");
        assert!(requests[4].starts_with("GET /repos/o/r/pulls/7 "), "{case}");
        assert!(
            requests.iter().all(|request| request.starts_with("GET ")),
            "{case}"
        );
    }
}

#[test]
fn a_managed_body_carries_exactly_one_complete_marker_at_its_end() {
    let marker = format!(
        "<!-- release-glz:managed package=widget branch=release-glz/widget head={} digest={} version=1.2.3 intent=pending -->",
        "c".repeat(40),
        "d".repeat(64)
    );
    assert!(release_glz::forge::is_managed_release_pr(&format!(
        "Release body\n\n{marker}\n"
    )));
    for (case, body) in [
        ("text after the marker", format!("{marker}\nmore text")),
        ("two markers", format!("{marker}\n{marker}")),
        (
            "an earlier partial marker",
            format!("<!-- release-glz:managed package=evil -->\n{marker}"),
        ),
        ("a short head", marker.replace(&"c".repeat(40), "cccc")),
        (
            "an uppercase digest",
            marker.replace(&"d".repeat(64), &"D".repeat(64)),
        ),
        ("a missing intent", marker.replace(" intent=pending", "")),
        (
            "a repeated key",
            marker.replace(" intent=pending", " intent=pending intent=pending"),
        ),
        (
            "an unknown key",
            marker.replace(" intent=pending", " intent=pending extra=1"),
        ),
        (
            "an invalid version",
            marker.replace("version=1.2.3", "version=1.2"),
        ),
        (
            "an invalid package",
            marker.replace("package=widget", "package=Widget"),
        ),
    ] {
        assert!(!release_glz::forge::is_managed_release_pr(&body), "{case}");
    }
}

#[tokio::test]
async fn candidate_intent_binds_only_to_the_verified_managed_pr_head() {
    let head = "c".repeat(40);
    let files_digest = files_digest(&release_files());
    let intent_digest = "1".repeat(64);
    let pending = format!(
        r#"[{{"number":7,"title":"chore(release): widget 1.2.3","body":"Release body\n\n<!-- release-glz:managed package=widget branch=release-glz/widget head={head} digest={files_digest} version=1.2.3 intent=pending -->","html_url":"https://github.test/o/r/pull/7","merge_commit_sha":null,"merged_at":null,"user":{{"login":"bot"}},"labels":[],"head":{{"ref":"release-glz/widget","sha":"{head}","repo":{{"full_name":"o/r","default_branch":"main"}}}},"base":{{"ref":"main","repo":{{"full_name":"o/r","default_branch":"main"}}}}}}]"#,
    );
    let current = pending.trim_start_matches('[').trim_end_matches(']');
    let bound = current.replace("intent=pending", &format!("intent={intent_digest}"));
    let mut responses = vec![response(200, &pending)];
    responses.extend(generated_commit_on(&release_files(), &"0".repeat(40)));
    responses.push(response(200, current));
    responses.push(response(200, &bound));
    let server = FakeServer::start(responses).await;
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        server.base_url(),
        format!("{}/graphql", server.base_url()),
        Some("token".into()),
    )
    .unwrap();

    let binding = client
        .bind_release_pr_intent(&head, "widget", "1.2.3", "release-glz/", &intent_digest)
        .await
        .unwrap();
    assert_eq!(
        binding,
        IntentBinding::Bound {
            url: "https://github.test/o/r/pull/7".into()
        }
    );
    let requests = server.requests();
    assert!(requests[0].starts_with("GET /repos/o/r/pulls?state=open&per_page=100 "));
    assert!(requests[1].starts_with(&format!("GET /repos/o/r/commits/{head} ")));
    assert!(requests[2].starts_with(&format!("GET /repos/o/r/git/blobs/{} ", blob_id(0))));
    assert!(requests[3].starts_with(&format!("GET /repos/o/r/git/blobs/{} ", blob_id(1))));
    assert!(requests[4].starts_with("GET /repos/o/r/pulls/7 "));
    assert!(requests[5].starts_with("PATCH /repos/o/r/pulls/7 "));
    assert!(requests[5].contains(&format!("intent={intent_digest}")));
}

#[tokio::test]
async fn managed_release_pr_searches_every_bounded_open_pr_page() {
    let head = "c".repeat(40);
    let files_digest = files_digest(&release_files());
    let intent_digest = "1".repeat(64);
    let first_page: Vec<_> = (1..=100)
        .map(|number| pull_value(number, "ordinary pull request", "feature", "a"))
        .collect();
    let body = managed_body(
        "widget",
        "release-glz/widget",
        &head,
        &files_digest,
        "1.2.3",
        "pending",
    );
    let bound_body = managed_body(
        "widget",
        "release-glz/widget",
        &head,
        &files_digest,
        "1.2.3",
        &intent_digest,
    );
    let mut responses = vec![
        response(200, &serde_json::to_string(&first_page).unwrap()),
        response(
            200,
            &serde_json::json!([pull_value(101, &body, "release-glz/widget", &head)]).to_string(),
        ),
    ];
    responses.extend(generated_commit_on(&release_files(), &"0".repeat(40)));
    responses.push(response(
        200,
        &pull_value(101, &body, "release-glz/widget", &head).to_string(),
    ));
    responses.push(response(
        200,
        &pull_value(101, &bound_body, "release-glz/widget", &head).to_string(),
    ));
    let server = FakeServer::start(responses).await;
    let client = test_client(&server, Some("token"));

    let binding = client
        .bind_release_pr_intent(&head, "widget", "1.2.3", "release-glz/", &intent_digest)
        .await
        .unwrap();

    assert_eq!(
        binding,
        IntentBinding::Bound {
            url: "https://github.test/o/r/pull/101".into()
        }
    );
    let requests = server.requests();
    assert!(requests[0].starts_with("GET /repos/o/r/pulls?state=open&per_page=100 "));
    assert!(requests[1].starts_with("GET /repos/o/r/pulls?state=open&per_page=100&page=2 "));
    assert!(requests[5].starts_with("GET /repos/o/r/pulls/101 "));
    assert!(requests[6].starts_with("PATCH /repos/o/r/pulls/101 "));
}

#[tokio::test]
async fn rolling_release_pr_is_created_from_a_server_side_verified_commit() {
    let base_sha = "a".repeat(40);
    let head_sha = "b".repeat(40);
    let pull = format!(
        r#"{{"number":7,"title":"chore(release): widget 1.2.3","body":"managed","html_url":"https://github.test/o/r/pull/7","merge_commit_sha":null,"merged_at":null,"user":{{"login":"release-glz"}},"labels":[],"head":{{"ref":"release-glz/widget","sha":"{head_sha}"}}}}"#,
    );
    let graph = format!(
        r#"{{"data":{{"createCommitOnBranch":{{"commit":{{"oid":"{head_sha}"}}}}}},"errors":[]}}"#
    );
    let server = FakeServer::start(vec![
        response(200, "[]"),
        response(404, "{}"),
        response(201, "{}"),
        response(200, &graph),
        response(201, &pull),
    ])
    .await;
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        server.base_url(),
        format!("{}/graphql", server.base_url()),
        Some("server-token".into()),
    )
    .unwrap();
    let mut files = BTreeMap::new();
    files.insert("CHANGELOG.md".into(), b"# Changelog\n".to_vec());
    files.insert(
        "gleam.toml".into(),
        b"name = \"widget\"\nversion = \"1.2.3\"\n".to_vec(),
    );

    let update = client
        .upsert_release_pr(
            &release_plan(),
            &default_branch(&base_sha),
            "release-glz/",
            &files,
        )
        .await
        .unwrap();
    assert_eq!(update.url, "https://github.test/o/r/pull/7");
    assert_eq!(update.head, head_sha);

    let requests = server.requests();
    assert_eq!(requests.len(), 5, "{requests:#?}");
    assert!(requests[0].starts_with("GET /repos/o/r/pulls?state=open&per_page=100 "));
    assert!(requests[1].starts_with("GET /repos/o/r/git/ref/heads/release-glz%2Fwidget "));
    assert!(requests[2].starts_with("POST /repos/o/r/git/refs "));
    assert!(requests[2].contains("\"ref\":\"refs/heads/release-glz/widget\""));
    assert!(requests[2].contains(&format!("\"sha\":\"{base_sha}\"")));

    assert!(requests[3].starts_with("POST /graphql "));
    let graph_body = request_json(&requests[3]);
    let input = &graph_body["variables"]["input"];
    assert_eq!(input["branch"]["repositoryNameWithOwner"], "o/r");
    assert_eq!(input["branch"]["branchName"], "release-glz/widget");
    assert_eq!(input["expectedHeadOid"], base_sha);
    let additions = input["fileChanges"]["additions"].as_array().unwrap();
    assert_eq!(additions.len(), 2);
    for addition in additions {
        let path = addition["path"].as_str().unwrap();
        let expected = files.get(path).unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(addition["contents"].as_str().unwrap())
                .unwrap(),
            *expected
        );
    }

    assert!(requests[4].starts_with("POST /repos/o/r/pulls "));
    let pull_body = request_json(&requests[4]);
    assert_eq!(pull_body["head"], "release-glz/widget");
    assert_eq!(pull_body["base"], "main");
    assert_eq!(pull_body["maintainer_can_modify"], false);
    let body = pull_body["body"].as_str().unwrap();
    assert!(body.contains("Merging this PR approves the semantic `intent_digest`"));
    assert!(body.contains("protected Environment approval"));
    assert!(body.contains(&format!("head={head_sha}")));
    assert!(body.contains("intent=pending"));
    assert!(requests.iter().all(|request| {
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer server-token")
    }));
}

#[tokio::test]
async fn rolling_release_pr_is_a_no_op_when_it_already_shows_the_plan_on_the_tip() {
    let files = release_files();
    let digest = release_files_digest(&files);
    let tip = "a".repeat(40);
    let head = "b".repeat(40);
    let body = managed_body(
        "widget",
        "release-glz/widget",
        &head,
        &digest,
        "1.2.3",
        "pending",
    );
    let mut responses = vec![
        response(
            200,
            &serde_json::json!([pull_value(7, &body, "release-glz/widget", &head)]).to_string(),
        ),
        response(200, &format!(r#"{{"object":{{"sha":"{head}"}}}}"#)),
    ];
    responses.extend(generated_commit_on(&files, &tip));
    let server = FakeServer::start(responses).await;
    let client = test_client(&server, Some("token"));

    let update = client
        .upsert_release_pr(
            &release_plan(),
            &default_branch(&tip),
            "release-glz/",
            &files,
        )
        .await
        .unwrap();
    assert_eq!(update.url, "https://github.test/o/r/pull/7");
    assert_eq!(update.head, head);
    let requests = server.requests();
    assert_eq!(requests.len(), 5, "{requests:#?}");
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
}

#[tokio::test]
async fn rolling_release_pr_ignores_pull_requests_that_only_copy_its_marker() {
    let files = release_files();
    let digest = release_files_digest(&files);
    let tip = "a".repeat(40);
    let head = "b".repeat(40);
    let managed = managed_body(
        "widget",
        "release-glz/widget",
        &head,
        &digest,
        "1.2.3",
        "pending",
    );
    let unprefixed = managed_body(
        "widget",
        "notes/widget",
        &"d".repeat(40),
        &digest,
        "1.2.3",
        "pending",
    );
    let other_package = managed_body(
        "gadget",
        "release-glz/gadget",
        &"e".repeat(40),
        &digest,
        "2.0.0",
        "pending",
    );
    let mut responses = vec![
        response(
            200,
            &serde_json::json!([
                pull_value(11, &other_package, "release-glz/gadget", &"e".repeat(40)),
                pull_value(10, &managed, "release-glz/widget-copy", &"f".repeat(40)),
                pull_value(9, &managed, "feature/notes", &"c".repeat(40)),
                pull_value(8, &unprefixed, "notes/widget", &"d".repeat(40)),
                pull_value(7, &managed, "release-glz/widget", &head),
            ])
            .to_string(),
        ),
        response(200, &format!(r#"{{"object":{{"sha":"{head}"}}}}"#)),
    ];
    responses.extend(generated_commit_on(&files, &tip));
    let server = FakeServer::start(responses).await;
    let client = test_client(&server, Some("token"));

    let update = client
        .upsert_release_pr(
            &release_plan(),
            &default_branch(&tip),
            "release-glz/",
            &files,
        )
        .await
        .unwrap();
    assert_eq!(update.url, "https://github.test/o/r/pull/7");
    let requests = server.requests();
    assert_eq!(requests.len(), 5, "{requests:#?}");
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
    assert!(
        requests[1].starts_with("GET /repos/o/r/git/ref/heads/release-glz%2Fwidget "),
        "{}",
        requests[1]
    );
}

#[tokio::test]
async fn rolling_release_pr_is_rebuilt_on_the_tip_when_the_tip_or_the_plan_moved() {
    let files = release_files();
    let digest = release_files_digest(&files);
    let tip = "a".repeat(40);
    let head = "b".repeat(40);
    let rebuilt = "e".repeat(40);
    for (case, committed, parent) in [
        ("a moved default branch", files.clone(), "f".repeat(40)),
        ("a changed plan", earlier_release_files(), tip.clone()),
    ] {
        let body = managed_body(
            "widget",
            "release-glz/widget",
            &head,
            &files_digest(&committed),
            "1.2.3",
            "pending",
        );
        let commit = format!(
            r#"{{"data":{{"createCommitOnBranch":{{"commit":{{"oid":"{rebuilt}"}}}}}},"errors":[]}}"#
        );
        let mut responses = vec![
            response(
                200,
                &serde_json::json!([pull_value(7, &body, "release-glz/widget", &head)]).to_string(),
            ),
            response(200, &format!(r#"{{"object":{{"sha":"{head}"}}}}"#)),
        ];
        responses.extend(generated_commit_on(&committed, &parent));
        responses.push(response(
            200,
            r#"{"data":{"updateRefs":{"clientMutationId":null}},"errors":[]}"#,
        ));
        responses.push(response(200, &commit));
        responses.push(response(
            200,
            &pull_value(7, &body, "release-glz/widget", &rebuilt).to_string(),
        ));
        let server = FakeServer::start(responses).await;
        let client = test_client(&server, Some("token"));

        let update = client
            .upsert_release_pr(
                &release_plan(),
                &default_branch(&tip),
                "release-glz/",
                &files,
            )
            .await
            .unwrap();

        assert_eq!(update.head, rebuilt, "{case}");
        let requests = server.requests();
        assert_eq!(requests.len(), 8, "{case}: {requests:#?}");
        assert!(requests[5].starts_with("POST /graphql "), "{case}");
        let reset = request_json(&requests[5]);
        assert!(
            reset["query"].as_str().unwrap().contains("updateRefs("),
            "{case}"
        );
        assert_eq!(
            reset["variables"]["input"],
            serde_json::json!({
                "repositoryId": "R_repository",
                "refUpdates": [{
                    "name": "refs/heads/release-glz/widget",
                    "beforeOid": head,
                    "afterOid": tip,
                    "force": true
                }]
            }),
            "{case}"
        );
        let commit = request_json(&requests[6]);
        assert_eq!(
            commit["variables"]["input"]["expectedHeadOid"], tip,
            "{case}"
        );
        assert!(
            requests[7].starts_with("PATCH /repos/o/r/pulls/7 "),
            "{case}"
        );
        let patch = request_json(&requests[7]);
        let patched_body = patch["body"].as_str().unwrap();
        assert!(patched_body.contains(&format!("head={rebuilt}")), "{case}");
        assert!(patched_body.contains(&format!("digest={digest}")), "{case}");
    }
}

#[tokio::test]
async fn a_failed_compare_and_swap_leaves_the_release_branch_and_pr_alone() {
    let files = release_files();
    let tip = "a".repeat(40);
    let head = "b".repeat(40);
    let body = managed_body(
        "widget",
        "release-glz/widget",
        &head,
        &files_digest(&earlier_release_files()),
        "1.2.3",
        "pending",
    );
    let mut responses = vec![
        response(
            200,
            &serde_json::json!([pull_value(7, &body, "release-glz/widget", &head)]).to_string(),
        ),
        response(200, &format!(r#"{{"object":{{"sha":"{head}"}}}}"#)),
    ];
    responses.extend(generated_commit_on(&earlier_release_files(), &tip));
    responses.push(response(
        200,
        r#"{"data":null,"errors":[{"message":"Expected branch to point to another commit"}]}"#,
    ));
    let server = FakeServer::start(responses).await;
    let client = test_client(&server, Some("token"));

    let error = client
        .upsert_release_pr(
            &release_plan(),
            &default_branch(&tip),
            "release-glz/",
            &files,
        )
        .await
        .unwrap_err();

    assert!(error.to_string().contains("another commit"), "{error:#}");
    assert_eq!(server.requests().len(), 6);
}

#[tokio::test]
async fn a_repaired_marker_keeps_an_intent_only_for_the_same_head() {
    let files = release_files();
    let tip = "c".repeat(40);
    let actual_head = "b".repeat(40);
    let intent = "1".repeat(64);
    for (case, marker_head, expected_intent) in [
        ("a replaced head", "a".repeat(40), "pending".to_owned()),
        ("the same head", actual_head.clone(), intent.clone()),
    ] {
        let body = managed_body(
            "widget",
            "release-glz/widget",
            &marker_head,
            &"0".repeat(64),
            "1.2.3",
            &intent,
        );
        let mut responses = vec![
            response(
                200,
                &serde_json::json!([pull_value(7, &body, "release-glz/widget", &marker_head)])
                    .to_string(),
            ),
            response(200, &format!(r#"{{"object":{{"sha":"{actual_head}"}}}}"#)),
        ];
        responses.extend(generated_commit_on(&files, &tip));
        responses.push(response(
            200,
            &pull_value(7, &body, "release-glz/widget", &actual_head).to_string(),
        ));
        let server = FakeServer::start(responses).await;
        test_client(&server, Some("token"))
            .upsert_release_pr(
                &release_plan(),
                &default_branch(&tip),
                "release-glz/",
                &files,
            )
            .await
            .unwrap();
        let requests = server.requests();
        assert!(
            requests[5].starts_with("PATCH /repos/o/r/pulls/7 "),
            "{case}"
        );
        let patch = request_json(&requests[5]);
        let body = patch["body"].as_str().unwrap();
        assert!(body.contains(&format!("head={actual_head}")), "{case}");
        assert!(
            body.contains(&format!("intent={expected_intent} ")),
            "{case}: {body}"
        );
    }
}

#[tokio::test]
async fn rolling_release_pr_repairs_a_marker_after_a_verified_commit_race() {
    let files = release_files();
    let digest = release_files_digest(&files);
    let tip = "c".repeat(40);
    let old_head = "a".repeat(40);
    let actual_head = "b".repeat(40);
    let body = managed_body(
        "widget",
        "release-glz/widget",
        &old_head,
        &"0".repeat(64),
        "1.2.3",
        "pending",
    );
    let repaired_body = managed_body(
        "widget",
        "release-glz/widget",
        &actual_head,
        &digest,
        "1.2.3",
        "pending",
    );
    let mut responses = vec![
        response(
            200,
            &serde_json::json!([pull_value(7, &body, "release-glz/widget", &old_head)]).to_string(),
        ),
        response(200, &format!(r#"{{"object":{{"sha":"{actual_head}"}}}}"#)),
    ];
    responses.extend(generated_commit_on(&files, &tip));
    responses.push(response(
        200,
        &pull_value(7, &repaired_body, "release-glz/widget", &actual_head).to_string(),
    ));
    let server = FakeServer::start(responses).await;
    let client = test_client(&server, Some("token"));

    let update = client
        .upsert_release_pr(
            &release_plan(),
            &default_branch(&tip),
            "release-glz/",
            &files,
        )
        .await
        .unwrap();
    assert_eq!(update.url, "https://github.test/o/r/pull/7");
    assert_eq!(update.head, actual_head);
    let requests = server.requests();
    assert_eq!(requests.len(), 6, "{requests:#?}");
    assert!(requests[2].starts_with(&format!("GET /repos/o/r/commits/{actual_head} ")));
    assert!(requests[5].starts_with("PATCH /repos/o/r/pulls/7 "));
    let patch = request_json(&requests[5]);
    assert!(
        patch["body"]
            .as_str()
            .unwrap()
            .contains(&format!("head={actual_head}"))
    );
    assert!(
        patch["body"]
            .as_str()
            .unwrap()
            .contains(&format!("digest={digest}"))
    );
}

#[tokio::test]
async fn human_modified_rolling_branch_is_closed_without_overwrite_and_recreated_separately() {
    let files = release_files();
    let old_head = "a".repeat(40);
    let human_head = "b".repeat(40);
    let base_head = "c".repeat(40);
    let generated_head = "d".repeat(40);
    let body = managed_body(
        "widget",
        "release-glz/widget",
        &old_head,
        &"0".repeat(64),
        "1.2.3",
        "pending",
    );
    let graph = format!(
        r#"{{"data":{{"createCommitOnBranch":{{"commit":{{"oid":"{generated_head}"}}}}}},"errors":[]}}"#
    );
    let created = pull_value(
        8,
        "new managed pull",
        "release-glz/widget-replacement",
        &generated_head,
    )
    .to_string();
    let server = FakeServer::start(vec![
        response(
            200,
            &serde_json::json!([pull_value(7, &body, "release-glz/widget", &old_head)]).to_string(),
        ),
        response(200, &format!(r#"{{"object":{{"sha":"{human_head}"}}}}"#)),
        response(
            200,
            r#"{"commit":{"message":"human commit","verification":{"verified":false}},"parents":[{"sha":"0000000000000000000000000000000000000000"}],"files":[]}"#,
        ),
        response(200, "{}"),
        response(200, "{}"),
        response(200, &format!(r#"{{"object":{{"sha":"{human_head}"}}}}"#)),
        response(201, "{}"),
        response(200, &graph),
        response(201, &created),
    ])
    .await;
    let client = test_client(&server, Some("token"));

    let update = client
        .upsert_release_pr(
            &release_plan(),
            &default_branch(&base_head),
            "release-glz/",
            &files,
        )
        .await
        .unwrap();
    assert_eq!(update.url, "https://github.test/o/r/pull/8");
    assert_eq!(update.head, generated_head);
    let requests = server.requests();
    assert_eq!(requests.len(), 9, "{requests:#?}");
    assert!(requests[3].starts_with("POST /repos/o/r/issues/7/comments "));
    assert!(requests[3].contains("not created by the bot"));
    assert!(requests[4].starts_with("PATCH /repos/o/r/pulls/7 "));
    assert!(requests[4].contains("\"state\":\"closed\""));
    assert!(requests[6].starts_with("POST /repos/o/r/git/refs "));
    assert!(requests[6].contains(&format!("\"sha\":\"{base_head}\"")));
    assert!(!requests[6].contains("\"ref\":\"refs/heads/release-glz/widget\""));
    assert!(requests[7].starts_with("POST /graphql "));
    assert!(!requests[7].contains("updateRefs"));
    assert!(requests[8].starts_with("POST /repos/o/r/pulls "));
    assert!(
        !requests
            .iter()
            .any(|request| request.starts_with("DELETE ") || request.contains("updateRefs"))
    );
}

/// Verified single-parent commits on `parent` that record the digest of [`release_files`] but changed something else, with the responses that reading each one takes.
fn impostor_commits(parent: &str) -> Vec<(&'static str, Vec<Vec<u8>>)> {
    let files = release_files();
    let digest = files_digest(&files);
    let mut amended = files.clone();
    amended.insert(
        "gleam.toml".into(),
        b"name = \"widget\"\nversion = \"9.9.9\"\n".to_vec(),
    );
    let mut extra = files.clone();
    extra.remove("gleam.toml");
    extra.insert("src/extra.gleam".into(), b"pub fn extra() { 1 }\n".to_vec());
    let listed = |entries: Vec<serde_json::Value>| {
        vec![response(
            200,
            &commit_value(&digest, &[parent], true, entries).to_string(),
        )]
    };
    let entry = |path: &str, status: &str, sha: Option<String>| serde_json::json!({"filename": path, "status": status, "sha": sha});
    vec![
        (
            "a modified managed file",
            recorded_commit_on(&amended, &digest, parent),
        ),
        (
            "another file in place of a managed one",
            recorded_commit_on(&extra, &digest, parent),
        ),
        (
            "a deleted file",
            listed(vec![
                entry("CHANGELOG.md", "modified", Some(blob_id(0))),
                entry("gleam.toml", "removed", None),
            ]),
        ),
        (
            "a renamed file",
            listed(vec![entry("gleam.toml", "renamed", Some(blob_id(0)))]),
        ),
        (
            "more files than release-glz writes",
            listed(vec![
                entry("CHANGELOG.md", "modified", Some(blob_id(0))),
                entry("gleam.toml", "modified", Some(blob_id(1))),
                entry("src/extra.gleam", "added", Some(blob_id(2))),
            ]),
        ),
        (
            "a file listed twice",
            listed(vec![
                entry("gleam.toml", "modified", Some(blob_id(0))),
                entry("gleam.toml", "modified", Some(blob_id(1))),
            ]),
        ),
        (
            "a blob id that isn't an object id",
            listed(vec![entry(
                "gleam.toml",
                "modified",
                Some("../../pulls/7".into()),
            )]),
        ),
    ]
}

#[tokio::test]
async fn a_verified_commit_with_the_digest_line_counts_only_when_its_changes_match() {
    let merged = "a".repeat(40);
    let head = "c".repeat(40);
    let pull = managed_pull(&head, Some(&merged), "pending");
    for (case, commit) in impostor_commits(&"0".repeat(40)) {
        let mut responses = vec![response(200, &serde_json::json!([pull]).to_string())];
        let reads = commit.len();
        responses.extend(commit);
        let server = FakeServer::start(responses).await;

        let found = test_client(&server, Some("token"))
            .merged_release_pr(&merged, "widget", "1.2.3", "release-glz/")
            .await
            .unwrap();

        assert!(found.is_none(), "{case}");
        let requests = server.requests();
        assert_eq!(requests.len(), 1 + reads, "{case}: {requests:#?}");
        assert!(
            requests[1].starts_with(&format!("GET /repos/o/r/commits/{head} ")),
            "{case}"
        );
        assert!(
            requests[2..]
                .iter()
                .all(|request| request.starts_with("GET /repos/o/r/git/blobs/")),
            "{case}"
        );
    }
}

#[tokio::test]
async fn an_amended_commit_that_keeps_the_digest_line_is_closed_as_human_work() {
    let files = release_files();
    let tip = "a".repeat(40);
    let amended = "b".repeat(40);
    let generated = "e".repeat(40);
    let body = managed_body(
        "widget",
        "release-glz/widget",
        &amended,
        &files_digest(&files),
        "1.2.3",
        "pending",
    );
    let (_, commit) = impostor_commits(&tip).swap_remove(0);
    let mut responses = vec![
        response(
            200,
            &serde_json::json!([pull_value(7, &body, "release-glz/widget", &amended)]).to_string(),
        ),
        response(200, &format!(r#"{{"object":{{"sha":"{amended}"}}}}"#)),
    ];
    responses.extend(commit);
    responses.extend([
        response(200, "{}"),
        response(200, "{}"),
        response(200, &format!(r#"{{"object":{{"sha":"{amended}"}}}}"#)),
        response(201, "{}"),
        response(
            200,
            &format!(
                r#"{{"data":{{"createCommitOnBranch":{{"commit":{{"oid":"{generated}"}}}}}},"errors":[]}}"#
            ),
        ),
        response(
            201,
            &pull_value(8, "new managed pull", "release-glz/widget-2", &generated).to_string(),
        ),
    ]);
    let server = FakeServer::start(responses).await;

    let update = test_client(&server, Some("token"))
        .upsert_release_pr(
            &release_plan(),
            &default_branch(&tip),
            "release-glz/",
            &files,
        )
        .await
        .unwrap();

    assert_eq!(update.head, generated);
    let requests = server.requests();
    assert_eq!(requests.len(), 11, "{requests:#?}");
    assert!(requests[5].starts_with("POST /repos/o/r/issues/7/comments "));
    assert!(requests[6].starts_with("PATCH /repos/o/r/pulls/7 "));
    assert!(requests[6].contains("\"state\":\"closed\""));
    assert!(
        !requests
            .iter()
            .any(|request| request.contains("updateRefs")),
        "the amended commit stays on its branch"
    );
}

#[tokio::test]
async fn an_amended_commit_neither_binds_an_intent_nor_loses_its_branch() {
    let head = "c".repeat(40);
    let (_, commit) = impostor_commits(&"0".repeat(40)).swap_remove(0);
    let mut responses = vec![response(
        200,
        &serde_json::json!([managed_pull(&head, None, "pending")]).to_string(),
    )];
    responses.extend(commit.clone());
    let server = FakeServer::start(responses).await;
    let error = test_client(&server, Some("token"))
        .bind_release_pr_intent(&head, "widget", "1.2.3", "release-glz/", &"1".repeat(64))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("not the server-verified"),
        "{error:#}"
    );
    assert!(
        server
            .requests()
            .iter()
            .all(|request| request.starts_with("GET "))
    );

    let mut responses = vec![
        response(200, &closable_release_pr(&head)),
        response(200, &format!(r#"{{"object":{{"sha":"{head}"}}}}"#)),
    ];
    responses.extend(commit);
    let server = FakeServer::start(responses).await;
    let closed = test_client(&server, Some("token"))
        .close_managed_release_pr("widget", "release-glz/", &default_branch(&"a".repeat(40)))
        .await
        .unwrap();
    assert!(!closed);
    assert!(
        server
            .requests()
            .iter()
            .all(|request| request.starts_with("GET "))
    );
}

#[tokio::test]
async fn a_blob_that_cannot_be_read_fails_the_check_instead_of_closing_the_release_pr() {
    let files = release_files();
    let tip = "a".repeat(40);
    let head = "b".repeat(40);
    let body = managed_body(
        "widget",
        "release-glz/widget",
        &head,
        &files_digest(&files),
        "1.2.3",
        "pending",
    );
    let mut generated = generated_commit_on(&files, &tip);
    let commit = generated.remove(0);
    for (case, blob) in [
        (
            "a missing blob",
            response(404, r#"{"message":"Not Found"}"#),
        ),
        (
            "an encoding other than base64",
            response(
                200,
                r#"{"content":"Changelog","encoding":"utf-8","size":9}"#,
            ),
        ),
        (
            "content that isn't base64",
            response(
                200,
                r#"{"content":"not base64!","encoding":"base64","size":11}"#,
            ),
        ),
    ] {
        let server = FakeServer::start(vec![
            response(
                200,
                &serde_json::json!([pull_value(7, &body, "release-glz/widget", &head)]).to_string(),
            ),
            response(200, &format!(r#"{{"object":{{"sha":"{head}"}}}}"#)),
            commit.clone(),
            blob,
        ])
        .await;

        let result = test_client(&server, Some("token"))
            .upsert_release_pr(
                &release_plan(),
                &default_branch(&tip),
                "release-glz/",
                &files,
            )
            .await;

        assert!(result.is_err(), "{case}");
        let requests = server.requests();
        assert_eq!(requests.len(), 4, "{case}: {requests:#?}");
        assert!(
            requests.iter().all(|request| request.starts_with("GET ")),
            "{case}"
        );
    }
}

#[tokio::test]
async fn a_release_commit_stays_within_the_bounds_that_recognize_it_on_the_next_run() {
    let mut three = release_files();
    three.insert("src/extra.gleam".into(), b"pub fn extra() { 1 }\n".to_vec());
    let mut oversized = release_files();
    oversized.insert("CHANGELOG.md".into(), vec![b'#'; 2 * 1024 * 1024 + 1]);
    for (case, files, expected) in [
        (
            "no files",
            BTreeMap::new(),
            "a Release PR commit changes 1 to 2 files, not 0",
        ),
        (
            "more files than a check reads",
            three,
            "a Release PR commit changes 1 to 2 files, not 3",
        ),
        (
            "a file over 2 MiB",
            oversized,
            "Release PR file `CHANGELOG.md` exceeds 2 MiB",
        ),
    ] {
        let server = FakeServer::start(vec![]).await;
        let error = test_client(&server, Some("token"))
            .upsert_release_pr(
                &release_plan(),
                &default_branch(&"a".repeat(40)),
                "release-glz/",
                &files,
            )
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), expected, "{case}");
    }
}

/// Bytes a file in a Release PR commit may hold.
const MAX_RELEASE_FILE_BYTES: usize = 2 * 1024 * 1024;

#[tokio::test]
async fn a_release_commit_may_write_a_file_of_exactly_2_mib() {
    let mut files = release_files();
    files.insert("CHANGELOG.md".into(), vec![b'#'; MAX_RELEASE_FILE_BYTES]);
    let head = "b".repeat(40);
    let graph = format!(
        r#"{{"data":{{"createCommitOnBranch":{{"commit":{{"oid":"{head}"}}}}}},"errors":[]}}"#
    );
    let server = FakeServer::start(vec![
        response(200, "[]"),
        response(404, "{}"),
        response(201, "{}"),
        response(200, &graph),
        response(
            201,
            &pull_value(7, "managed", "release-glz/widget", &head).to_string(),
        ),
    ])
    .await;

    let update = test_client(&server, Some("token"))
        .upsert_release_pr(
            &release_plan(),
            &default_branch(&"a".repeat(40)),
            "release-glz/",
            &files,
        )
        .await
        .unwrap();

    assert_eq!(update.head, head);
    assert_eq!(server.requests().len(), 5);
}

#[tokio::test]
async fn a_generated_file_counts_up_to_exactly_2_mib() {
    let merged = "a".repeat(40);
    let head = "c".repeat(40);
    for (case, size, counts) in [
        ("exactly 2 MiB", MAX_RELEASE_FILE_BYTES, true),
        ("one byte over", MAX_RELEASE_FILE_BYTES + 1, false),
    ] {
        let files = BTreeMap::from([("CHANGELOG.md".to_owned(), vec![b'#'; size])]);
        let mut pull = managed_pull(&head, Some(&merged), "pending");
        pull["body"] = pull["body"]
            .as_str()
            .unwrap()
            .replace(&files_digest(&release_files()), &files_digest(&files))
            .into();
        let mut responses = vec![response(200, &serde_json::json!([pull]).to_string())];
        responses.extend(generated_commit_on(&files, &"0".repeat(40)));
        let server = FakeServer::start(responses).await;

        let found = test_client(&server, Some("token"))
            .merged_release_pr(&merged, "widget", "1.2.3", "release-glz/")
            .await
            .unwrap();

        assert_eq!(found.is_some(), counts, "{case}");
        assert_eq!(server.requests().len(), 3, "{case}");
    }
}

#[tokio::test]
async fn a_release_commit_that_writes_one_file_is_recognized_on_the_next_run() {
    let mut files = release_files();
    files.remove("gleam.toml");
    let tip = "a".repeat(40);
    let head = "b".repeat(40);
    let body = managed_body(
        "widget",
        "release-glz/widget",
        &head,
        &files_digest(&files),
        "1.2.3",
        "pending",
    );
    let mut responses = vec![
        response(
            200,
            &serde_json::json!([pull_value(7, &body, "release-glz/widget", &head)]).to_string(),
        ),
        response(200, &format!(r#"{{"object":{{"sha":"{head}"}}}}"#)),
    ];
    responses.extend(generated_commit_on(&files, &tip));
    let server = FakeServer::start(responses).await;

    let update = test_client(&server, Some("token"))
        .upsert_release_pr(
            &release_plan(),
            &default_branch(&tip),
            "release-glz/",
            &files,
        )
        .await
        .unwrap();

    assert_eq!(update.head, head);
    let requests = server.requests();
    assert_eq!(requests.len(), 4, "{requests:#?}");
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
}

#[tokio::test]
async fn commit_changes_prefer_merged_pr_metadata_and_deduplicate_pr_numbers() {
    let merged = serde_json::json!([{
        "number": 7,
        "title": "feat: add public API",
        "body": null,
        "html_url": "https://github.test/o/r/pull/7",
        "merge_commit_sha": "a",
        "merged_at": "2026-01-01T00:00:00Z",
        "user": {"login": "contributor"},
        "labels": [{"name": "feature"}],
        "head": {"ref": "feature", "sha": "a"}
    }])
    .to_string();
    let unmerged = serde_json::json!([{
        "number": 9,
        "title": "open work",
        "body": null,
        "html_url": "https://github.test/o/r/pull/9",
        "merge_commit_sha": null,
        "merged_at": null,
        "user": {"login": "someone"},
        "labels": [],
        "head": {"ref": "open", "sha": "b"}
    }])
    .to_string();
    let server = FakeServer::start(vec![
        response(200, &merged),
        response(200, &merged),
        response(200, &unmerged),
        response(200, "[]"),
    ])
    .await;
    let client = test_client(&server, Some("token"));
    let commits = [
        commit("a", "feat: fallback one"),
        commit("b", "fix: duplicate fallback must not appear"),
        commit("c", "fix: unmerged fallback"),
        commit("d", "docs: no PR fallback"),
    ];

    let changes = client.changes_for_commits(&commits).await.unwrap();
    assert_eq!(changes.len(), 3);
    assert_eq!(changes[0].pull_request, Some(7));
    assert_eq!(changes[0].author.as_deref(), Some("contributor"));
    assert_eq!(changes[0].labels, ["feature"]);
    assert_eq!(changes[1].title, "fix: unmerged fallback");
    assert_eq!(changes[1].pull_request, None);
    assert_eq!(changes[2].title, "docs: no PR fallback");
}

#[tokio::test]
async fn change_attribution_looks_up_at_most_a_fixed_number_of_commits() {
    let commits: Vec<_> = (0..=MAX_ATTRIBUTED_COMMITS)
        .map(|index| commit(&format!("{index:040x}"), &format!("fix: change {index}")))
        .collect();

    let silent = FakeServer::start(vec![]).await;
    let changes = test_client(&silent, Some("token"))
        .changes_for_commits(&commits)
        .await
        .unwrap();
    assert!(silent.requests().is_empty());
    assert_eq!(changes.len(), commits.len());
    assert!(changes.iter().all(|change| change.pull_request.is_none()));
    assert_eq!(changes[0].title, "fix: change 0");

    let at_bound = &commits[..MAX_ATTRIBUTED_COMMITS];
    let server = FakeServer::start(
        (0..MAX_ATTRIBUTED_COMMITS)
            .map(|_| response(200, "[]"))
            .collect(),
    )
    .await;
    let changes = test_client(&server, Some("token"))
        .changes_for_commits(at_bound)
        .await
        .unwrap();
    assert_eq!(server.requests().len(), MAX_ATTRIBUTED_COMMITS);
    assert_eq!(changes.len(), MAX_ATTRIBUTED_COMMITS);
}

#[tokio::test]
async fn a_repository_spelled_differently_from_github_fails_before_any_write() {
    for full_name in ["O/r", "o/R", "other/r"] {
        let server = FakeServer::start(vec![response(
            200,
            &serde_json::json!({
                "node_id": "R_repository",
                "full_name": full_name,
                "default_branch": "main"
            })
            .to_string(),
        )])
        .await;
        let error = test_client(&server, Some("token"))
            .default_branch()
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(&format!("`{full_name}`")), "{error}");
        assert_eq!(server.requests().len(), 1, "{full_name}");
    }
}

#[tokio::test]
async fn commit_change_lookup_errors_are_not_reported_as_commit_fallbacks() {
    let unavailable =
        response_with_headers(503, r#"{"message":"unavailable"}"#, &["Retry-After: 0"]);
    let server =
        FakeServer::start(vec![unavailable.clone(), unavailable.clone(), unavailable]).await;
    let client = test_client(&server, Some("token"));

    let error = client
        .changes_for_commits(&[commit("a", "feat: must not be fabricated")])
        .await
        .unwrap_err()
        .to_string();

    assert!(error.contains("503"), "{error}");
    assert_eq!(server.requests().len(), 3);
}

/// The open managed Release PR at `head` whose marker records the digest of [`release_files`].
fn closable_release_pr(head: &str) -> String {
    format!(
        r#"[{{"number":7,"title":"chore(release): widget 1.2.3","body":"<!-- release-glz:managed package=widget branch=release-glz/widget head={head} digest={} version=1.2.3 intent=pending -->","html_url":"https://github.test/o/r/pull/7","merge_commit_sha":null,"merged_at":null,"user":{{"login":"bot"}},"labels":[],"head":{{"ref":"release-glz/widget","sha":"{head}","repo":{{"full_name":"o/r","default_branch":"main"}}}},"base":{{"ref":"main","repo":{{"full_name":"o/r","default_branch":"main"}}}}}}]"#,
        files_digest(&release_files()),
    )
}

#[tokio::test]
async fn no_release_deletes_only_the_unchanged_verified_branch_and_then_closes_its_pr() {
    let head = "c".repeat(40);
    let mut responses = vec![
        response(200, &closable_release_pr(&head)),
        response(200, &format!(r#"{{"object":{{"sha":"{head}"}}}}"#)),
    ];
    responses.extend(generated_commit_on(&release_files(), &"0".repeat(40)));
    responses.push(response(
        200,
        r#"{"data":{"updateRefs":{"clientMutationId":null}},"errors":[]}"#,
    ));
    responses.push(response(200, "{}"));
    let server = FakeServer::start(responses).await;
    let client = test_client(&server, Some("token"));

    assert!(
        client
            .close_managed_release_pr("widget", "release-glz/", &default_branch(&"a".repeat(40)))
            .await
            .unwrap()
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 7, "{requests:#?}");
    assert!(requests[5].starts_with("POST /graphql "));
    let delete = request_json(&requests[5]);
    assert!(delete["query"].as_str().unwrap().contains("updateRefs("));
    assert_eq!(
        delete["variables"]["input"],
        serde_json::json!({
            "repositoryId": "R_repository",
            "refUpdates": [{
                "name": "refs/heads/release-glz/widget",
                "beforeOid": head,
                "afterOid": "0".repeat(40),
                "force": true
            }]
        })
    );
    assert!(requests[6].starts_with("PATCH /repos/o/r/pulls/7 "));
    assert!(requests[6].contains("\"state\":\"closed\""));
}

#[tokio::test]
async fn no_release_leaves_a_managed_branch_that_moved_before_or_during_the_close() {
    let head = "c".repeat(40);
    let moved = FakeServer::start(vec![
        response(200, &closable_release_pr(&head)),
        response(
            200,
            &format!(r#"{{"object":{{"sha":"{}"}}}}"#, "e".repeat(40)),
        ),
    ])
    .await;
    assert!(
        !test_client(&moved, Some("token"))
            .close_managed_release_pr("widget", "release-glz/", &default_branch(&"a".repeat(40)))
            .await
            .unwrap()
    );
    assert_eq!(moved.requests().len(), 2);

    let mut responses = vec![
        response(200, &closable_release_pr(&head)),
        response(200, &format!(r#"{{"object":{{"sha":"{head}"}}}}"#)),
    ];
    responses.extend(generated_commit_on(&release_files(), &"0".repeat(40)));
    responses.push(response(
        200,
        r#"{"data":null,"errors":[{"message":"Expected branch to point to another commit"}]}"#,
    ));
    let raced = FakeServer::start(responses).await;
    let error = test_client(&raced, Some("token"))
        .close_managed_release_pr("widget", "release-glz/", &default_branch(&"a".repeat(40)))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("delete the Release PR branch"), "{error}");
    let requests = raced.requests();
    assert_eq!(requests.len(), 6, "{requests:#?}");
    assert!(
        requests
            .iter()
            .all(|request| !request.starts_with("PATCH "))
    );
}

#[tokio::test]
async fn doctor_observes_environment_reviewers_plan_and_branch_protection() {
    let server = FakeServer::start(vec![
        response(
            200,
            r#"{"private":true,"default_branch":"main","plan":{"name":"enterprise"}}"#,
        ),
        response(
            200,
            r#"{"protection_rules":[{"type":"required_reviewers","prevent_self_review":true,"reviewers":[{"type":"User","reviewer":{"login":"reviewer"}}]},{"type":"branch_policy"}],"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false}}"#,
        ),
        response(200, r#"{"name":"main","protected":true}"#),
    ])
    .await;
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        server.base_url(),
        format!("{}/graphql", server.base_url()),
        Some("token".into()),
    )
    .unwrap();

    let audit = client.environment_audit("release").await.unwrap();
    assert!(audit.private_repository);
    assert_eq!(audit.plan.as_deref(), Some("enterprise"));
    assert_eq!(audit.default_branch, "main");
    assert!(audit.default_branch_protected);
    assert_eq!(audit.required_reviewers, 1);
    assert!(audit.prevent_self_review);
    assert!(audit.protected_branches_only);
    let requests = server.requests();
    assert!(requests[0].starts_with("GET /repos/o/r "));
    assert!(requests[1].starts_with("GET /repos/o/r/environments/release "));
    assert!(requests[2].starts_with("GET /repos/o/r/branches/main "));
}

#[tokio::test]
async fn actions_artifact_is_bound_to_the_oidc_run_source_and_server_digest() {
    let source = "a".repeat(40);
    let digest = "d".repeat(64);
    let body = format!(
        r#"{{"id":91,"name":"release-glz-candidate-42","size_in_bytes":4096,"expired":false,"digest":"sha256:{digest}","workflow_run":{{"id":42,"head_sha":"{source}"}}}}"#
    );
    let run = actions_run_value(
        42,
        "o/r",
        ".github/workflows/release-glz.yml",
        &source,
        "completed",
        Some("success"),
    );
    let server =
        FakeServer::start(vec![response(200, &body), response(200, &run.to_string())]).await;
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        server.base_url(),
        format!("{}/graphql", server.base_url()),
        Some("token".into()),
    )
    .unwrap();

    let evidence = client
        .verify_actions_artifact(91, &digest, "42", &source, CandidateRun::Completed)
        .await
        .unwrap();
    assert_eq!(evidence.id(), 91);
    assert_eq!(evidence.sha256(), digest);
    assert_eq!(evidence.run_id(), "42");
    assert_eq!(evidence.source_sha(), source);
    assert_eq!(evidence.repository(), "o/r");
    assert_eq!(
        evidence.workflow_path(),
        ".github/workflows/release-glz.yml"
    );
    let requests = server.requests();
    assert!(requests[0].starts_with("GET /repos/o/r/actions/artifacts/91 "));
    assert!(requests[1].starts_with("GET /repos/o/r/actions/runs/42 "));
}

#[tokio::test]
async fn actions_artifact_run_requires_the_managed_successful_repository_source() {
    let source = "a".repeat(40);
    let digest = "d".repeat(64);
    let artifact =
        actions_artifact_value(91, "release-glz-candidate-42", 4096, &digest, 42, &source);
    let invalid_runs = [
        actions_run_value(
            43,
            "o/r",
            ".github/workflows/release-glz.yml",
            &source,
            "completed",
            Some("success"),
        ),
        actions_run_value(
            42,
            "other/r",
            ".github/workflows/release-glz.yml",
            &source,
            "completed",
            Some("success"),
        ),
        actions_run_value(
            42,
            "o/r",
            ".github/workflows/other.yml",
            &source,
            "completed",
            Some("success"),
        ),
        actions_run_value(
            42,
            "o/r",
            ".github/workflows/release-glz.yml",
            &"b".repeat(40),
            "completed",
            Some("success"),
        ),
        actions_run_value(
            42,
            "o/r",
            ".github/workflows/release-glz.yml",
            &source,
            "in_progress",
            None,
        ),
        actions_run_value(
            42,
            "o/r",
            ".github/workflows/release-glz.yml",
            &source,
            "completed",
            Some("failure"),
        ),
    ];
    for invalid in invalid_runs {
        let server = FakeServer::start(vec![
            response(200, &artifact.to_string()),
            response(200, &invalid.to_string()),
        ])
        .await;
        let client = test_client(&server, Some("token"));
        let error = client
            .verify_actions_artifact(91, &digest, "42", &source, CandidateRun::Completed)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("Candidate run does not match"), "{error}");
    }
}

#[tokio::test]
async fn a_candidate_from_the_current_run_requires_that_run_to_be_in_progress() {
    let source = "a".repeat(40);
    let digest = "d".repeat(64);
    let artifact =
        actions_artifact_value(91, "release-glz-candidate-42", 4096, &digest, 42, &source);
    let workflow = ".github/workflows/release-glz.yml";
    let running = actions_run_value(42, "o/r", workflow, &source, "in_progress", None);
    let server = FakeServer::start(vec![
        response(200, &artifact.to_string()),
        response(200, &running.to_string()),
    ])
    .await;
    let evidence = test_client(&server, Some("token"))
        .verify_actions_artifact(91, &digest, "42", &source, CandidateRun::Current)
        .await
        .unwrap();
    assert_eq!(evidence.run_id(), "42");

    let invalid_runs = [
        actions_run_value(42, "o/r", workflow, &source, "completed", Some("success")),
        actions_run_value(42, "o/r", workflow, &source, "queued", None),
        actions_run_value(43, "o/r", workflow, &source, "in_progress", None),
        actions_run_value(42, "other/r", workflow, &source, "in_progress", None),
        actions_run_value(
            42,
            "o/r",
            ".github/workflows/other.yml",
            &source,
            "in_progress",
            None,
        ),
        actions_run_value(42, "o/r", workflow, &"b".repeat(40), "in_progress", None),
    ];
    for invalid in invalid_runs {
        let server = FakeServer::start(vec![
            response(200, &artifact.to_string()),
            response(200, &invalid.to_string()),
        ])
        .await;
        let error = test_client(&server, Some("token"))
            .verify_actions_artifact(91, &digest, "42", &source, CandidateRun::Current)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("Candidate run does not match"), "{error}");
    }
}

#[test]
fn a_push_publishes_only_its_own_candidate_and_a_promotion_only_an_earlier_one() {
    assert_eq!(
        CandidateRun::for_event("push", "42", "42").unwrap(),
        CandidateRun::Current
    );
    assert_eq!(
        CandidateRun::for_event("workflow_dispatch", "43", "42").unwrap(),
        CandidateRun::Completed
    );
    for (event, current, candidate, expected) in [
        ("push", "43", "42", "its own run"),
        (
            "workflow_dispatch",
            "42",
            "42",
            "completed prior prepare run",
        ),
        ("schedule", "42", "41", "push or a manual promotion"),
    ] {
        let error = CandidateRun::for_event(event, current, candidate)
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{event}: {error}");
    }
}

#[tokio::test]
async fn expired_or_mismatched_actions_artifact_is_not_approval_evidence() {
    let source = "a".repeat(40);
    let server = FakeServer::start(vec![response(
        200,
        &format!(
            r#"{{"id":91,"name":"release-glz-candidate-42","size_in_bytes":4096,"expired":true,"digest":"sha256:{}","workflow_run":{{"id":42,"head_sha":"{source}"}}}}"#,
            "d".repeat(64)
        ),
    )])
    .await;
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        server.base_url(),
        format!("{}/graphql", server.base_url()),
        Some("token".into()),
    )
    .unwrap();

    let error = client
        .verify_actions_artifact(91, &"d".repeat(64), "42", &source, CandidateRun::Completed)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("expired"));
}

#[tokio::test]
async fn actions_artifact_validation_checks_every_local_and_server_identity_field() {
    let source = "a".repeat(40);
    let digest = "d".repeat(64);
    let empty_server = FakeServer::start(vec![]).await;
    let without_token = test_client(&empty_server, None);
    let error = without_token
        .verify_actions_artifact(91, &digest, "42", &source, CandidateRun::Completed)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("GITHUB_TOKEN"), "{error}");

    let client = test_client(&empty_server, Some("token"));
    for (id, expected_digest, run_id, expected) in [
        (0, digest.as_str(), "42", "identity is invalid"),
        (91, "not-a-digest", "42", "identity is invalid"),
        (91, digest.as_str(), "not-a-run", "run ID is invalid"),
        (91, digest.as_str(), "042", "run ID is not canonical"),
    ] {
        let error = client
            .verify_actions_artifact(
                id,
                expected_digest,
                run_id,
                &source,
                CandidateRun::Completed,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{id}/{run_id}: {error}");
    }

    let mismatches = [
        actions_artifact_value(92, "release-glz-candidate-42", 4096, &digest, 42, &source),
        actions_artifact_value(91, "other", 4096, &digest, 42, &source),
        actions_artifact_value(91, "release-glz-candidate-42", 0, &digest, 42, &source),
        actions_artifact_value(
            91,
            "release-glz-candidate-42",
            1024 * 1024 * 1024 + 1,
            &digest,
            42,
            &source,
        ),
        actions_artifact_value(
            91,
            "release-glz-candidate-42",
            4096,
            &"e".repeat(64),
            42,
            &source,
        ),
        actions_artifact_value(91, "release-glz-candidate-42", 4096, &digest, 43, &source),
        actions_artifact_value(
            91,
            "release-glz-candidate-42",
            4096,
            &digest,
            42,
            &"b".repeat(40),
        ),
    ];
    let server = FakeServer::start(
        mismatches
            .iter()
            .map(|body| response(200, &body.to_string()))
            .collect(),
    )
    .await;
    let client = test_client(&server, Some("token"));
    for index in 0..mismatches.len() {
        let error = client
            .verify_actions_artifact(91, &digest, "42", &source, CandidateRun::Completed)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match"), "case {index}: {error}");
    }
}

#[tokio::test]
async fn environment_audit_reports_empty_and_unprotected_configurations_exactly() {
    let empty_server = FakeServer::start(vec![]).await;
    let client = test_client(&empty_server, Some("token"));
    let error = client.environment_audit("").await.unwrap_err().to_string();
    assert!(error.contains("must not be empty"), "{error}");

    let missing_default = FakeServer::start(vec![response(
        200,
        r#"{"private":false,"default_branch":"","plan":null}"#,
    )])
    .await;
    let error = test_client(&missing_default, Some("token"))
        .environment_audit("release")
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("no default branch"), "{error}");

    let unprotected = FakeServer::start(vec![
        response(
            200,
            r#"{"private":false,"default_branch":"develop","plan":null}"#,
        ),
        response(
            200,
            r#"{"protection_rules":[{"type":"wait_timer"}],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}"#,
        ),
        response(200, r#"{"name":"develop","protected":false}"#),
    ])
    .await;
    let audit = test_client(&unprotected, Some("token"))
        .environment_audit("release candidate")
        .await
        .unwrap();
    assert!(!audit.private_repository);
    assert!(audit.plan.is_none());
    assert_eq!(audit.required_reviewers, 0);
    assert!(!audit.prevent_self_review);
    assert!(!audit.protected_branches_only);
    assert!(!audit.default_branch_protected);
    assert!(unprotected.requests()[1].contains("environments/release%20candidate"));
}

#[tokio::test]
async fn tag_observation_distinguishes_missing_lightweight_and_invalid_objects() {
    let lightweight_sha = "a".repeat(40);
    let server = FakeServer::start(vec![
        response(404, "{}"),
        response(
            200,
            &format!(
                r#"{{"ref":"refs/tags/v1","object":{{"type":"commit","sha":"{lightweight_sha}"}}}}"#
            ),
        ),
        response(
            200,
            r#"{"ref":"refs/tags/v2","object":{"type":"tag","sha":"tag-object"}}"#,
        ),
        response(
            200,
            r#"{"sha":"tag-object","object":{"type":"tree","sha":"tree-object"}}"#,
        ),
        response(
            200,
            r#"{"ref":"refs/tags/v3","object":{"type":"tree","sha":"tree-object"}}"#,
        ),
    ])
    .await;
    let client = test_client(&server, Some("token"));
    assert!(client.tag_state("missing").await.unwrap().is_none());
    let lightweight = client.tag_state("v1").await.unwrap().unwrap();
    assert!(!lightweight.annotated);
    assert_eq!(lightweight.target_sha, lightweight_sha);
    let error = client.tag_state("v2").await.unwrap_err().to_string();
    assert!(
        error.contains("does not directly target a commit"),
        "{error}"
    );
    let error = client.tag_state("v3").await.unwrap_err().to_string();
    assert!(error.contains("unsupported object type"), "{error}");
}

#[tokio::test]
async fn annotated_tag_creation_rejects_every_unexpected_server_identity() {
    let expected = "a".repeat(40);
    for (name, body) in [
        (
            "empty object",
            serde_json::json!({"sha":"", "object":{"type":"commit", "sha":expected}}),
        ),
        (
            "wrong kind",
            serde_json::json!({"sha":"tag", "object":{"type":"tree", "sha":expected}}),
        ),
        (
            "wrong target",
            serde_json::json!({"sha":"tag", "object":{"type":"commit", "sha":"b".repeat(40)}}),
        ),
    ] {
        let server = FakeServer::start(vec![response(201, &body.to_string())]).await;
        let error = test_client(&server, Some("token"))
            .create_annotated_tag("v1.2.3", &expected, "release")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("unexpected annotated tag"),
            "{name}: {error}"
        );
        assert_eq!(server.requests().len(), 1, "{name}");
    }
}

#[tokio::test]
async fn release_asset_preflight_rejects_unpublishable_identity_and_untrusted_urls() {
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        "https://api.github.com".into(),
        "https://api.github.com/graphql".into(),
        Some("token".into()),
    )
    .unwrap();
    let valid_url = "https://api.github.com/repos/o/r/releases/42/assets{?name,label}";
    let release = upload_release(valid_url, true);

    let mut published = release.clone();
    published.draft = false;
    let error = client
        .upload_release_asset(&published, "evidence.json", "application/json", b"{}")
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("sealed draft"), "{error}");

    for name in [
        "",
        ".",
        "..",
        "nested/evidence.json",
        "bad\\name",
        "bad\nname",
    ] {
        let error = client
            .upload_release_asset(&release, name, "application/json", b"{}")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("name is unsafe"), "{name:?}: {error}");
    }
    let long_name = "x".repeat(257);
    assert!(
        client
            .upload_release_asset(&release, &long_name, "application/json", b"{}")
            .await
            .unwrap_err()
            .to_string()
            .contains("name is unsafe")
    );

    for media_type in [
        "",
        "json",
        "application/with quote\"",
        "application/bad\\type",
    ] {
        let error = client
            .upload_release_asset(&release, "evidence.json", media_type, b"{}")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("media type is invalid"),
            "{media_type:?}: {error}"
        );
    }
    let long_media_type = format!("application/{}", "x".repeat(128));
    assert!(
        client
            .upload_release_asset(&release, "evidence.json", &long_media_type, b"{}")
            .await
            .unwrap_err()
            .to_string()
            .contains("media type is invalid")
    );

    for (url, expected) in [
        (
            "https://api.github.com/repos/o/r/releases/42/assets",
            "unexpected template",
        ),
        (
            "https://api.github.com/repos/o/r/releases/42/assets?unexpected=1{?name,label}",
            "query or fragment",
        ),
        (
            "https://evil.example/repos/o/r/releases/42/assets{?name,label}",
            "untrusted origin",
        ),
        (
            "https://uploads.github.com/wrong{?name,label}",
            "does not match",
        ),
        (
            "https://api.github.com/repos/o/other/releases/42/assets{?name,label}",
            "does not match",
        ),
    ] {
        let error = client
            .upload_release_asset(
                &upload_release(url, true),
                "evidence.json",
                "application/json",
                b"{}",
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{url}: {error}");
    }
}

#[tokio::test]
async fn release_asset_response_must_match_every_uploaded_byte_identity() {
    let bytes = b"sealed evidence";
    let digest = release_glz::hex::lower(&sha2::Sha256::digest(bytes));
    let valid = serde_json::json!({
        "id": 7,
        "name": "evidence.json",
        "state": "uploaded",
        "content_type": "application/json",
        "size": bytes.len(),
        "digest": format!("sha256:{digest}")
    });
    let mut bodies = Vec::new();
    for (field, value) in [
        ("name", serde_json::json!("other.json")),
        ("state", serde_json::json!("new")),
        ("content_type", serde_json::json!("text/plain")),
        ("size", serde_json::json!(bytes.len() + 1)),
        (
            "digest",
            serde_json::json!(format!("sha256:{}", "0".repeat(64))),
        ),
    ] {
        let mut body = valid.clone();
        body[field] = value;
        bodies.push(response(201, &body.to_string()));
    }
    let server = FakeServer::start(bodies).await;
    let client = test_client(&server, Some("token"));
    let release = upload_release(
        &format!(
            "{}/repos/o/r/releases/42/assets{{?name,label}}",
            server.base_url()
        ),
        true,
    );
    for index in 0..5 {
        let error = client
            .upload_release_asset(&release, "evidence.json", "application/json", bytes)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("unexpected immutable identity"),
            "case {index}: {error}"
        );
    }
    assert_eq!(server.requests().len(), 5);
}

/// A delete reaches GitHub only for an unfinished asset of a draft, by that asset's id, and GitHub's empty 204 answer counts as success.
#[tokio::test]
async fn only_an_unfinished_asset_of_a_draft_is_deleted() {
    let asset = |id: u64, name: &str, state: &str| GitHubReleaseAsset {
        id,
        name: name.into(),
        state: state.into(),
        media_type: "application/json".into(),
        size: 2,
        sha256: None,
    };
    let release = |draft: bool, assets: Vec<GitHubReleaseAsset>| GitHubRelease {
        assets,
        ..upload_release(
            "https://api.github.com/repos/o/r/releases/42/assets{?name,label}",
            draft,
        )
    };
    let unfinished = release(true, vec![asset(77, "evidence.json", "starter")]);

    let server = FakeServer::start(vec![
        response(204, ""),
        response(404, r#"{"message":"Not Found"}"#),
    ])
    .await;
    let client = test_client(&server, Some("token"));
    client
        .delete_unfinished_release_asset(&unfinished, "evidence.json")
        .await
        .unwrap();
    let error = client
        .delete_unfinished_release_asset(&unfinished, "evidence.json")
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("404"), "{error}");
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.starts_with("DELETE /repos/o/r/releases/assets/77 ")),
        "{requests:?}"
    );

    let untouched = FakeServer::start(vec![response(204, "")]).await;
    let client = test_client(&untouched, Some("token"));
    for (case, refused, name, expected) in [
        (
            "published",
            release(false, vec![asset(77, "evidence.json", "starter")]),
            "evidence.json",
            "published",
        ),
        (
            "uploaded",
            release(true, vec![asset(77, "evidence.json", "uploaded")]),
            "evidence.json",
            "never deletes an uploaded asset",
        ),
        (
            "missing",
            release(true, vec![asset(77, "evidence.json", "starter")]),
            "other.json",
            "has no asset `other.json`",
        ),
        (
            "duplicate",
            release(
                true,
                vec![
                    asset(77, "evidence.json", "starter"),
                    asset(78, "evidence.json", "starter"),
                ],
            ),
            "evidence.json",
            "duplicate asset",
        ),
        (
            "anonymous",
            release(true, vec![asset(0, "evidence.json", "starter")]),
            "evidence.json",
            "no id",
        ),
    ] {
        let error = client
            .delete_unfinished_release_asset(&refused, name)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{case}: {error}");
    }
    let error = test_client(&untouched, None)
        .delete_unfinished_release_asset(&unfinished, "evidence.json")
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("GITHUB_TOKEN"), "{error}");
    assert!(untouched.requests().is_empty());
}

#[tokio::test]
async fn github_get_retries_retry_after_without_reposting_and_bounds_json_bodies() {
    let server = FakeServer::start(vec![
        response_with_headers(503, r#"{"message":"busy"}"#, &["Retry-After: 0"]),
        response(
            200,
            r#"[{"id":42,"html_url":"https://github.test/o/r/releases/42","tag_name":"v1.2.3","target_commitish":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","draft":true}]"#,
        ),
    ])
    .await;
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        server.base_url(),
        format!("{}/graphql", server.base_url()),
        Some("token".into()),
    )
    .unwrap();
    assert!(
        client
            .release_details_for_tag("v1.2.3")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(server.requests().len(), 2);
    assert!(
        server
            .requests()
            .iter()
            .all(|request| request.starts_with("GET "))
    );

    let oversized = format!(
        r#"[{{"id":42,"html_url":"https://github.test/o/r/releases/42","tag_name":"v1.2.3","target_commitish":"{}","draft":true,"padding":"{}"}}]"#,
        "a".repeat(40),
        "x".repeat(5 * 1024 * 1024)
    );
    let oversized_server = FakeServer::start(vec![response(200, &oversized)]).await;
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        oversized_server.base_url(),
        format!("{}/graphql", oversized_server.base_url()),
        Some("token".into()),
    )
    .unwrap();
    let error = client.release_details_for_tag("v1.2.3").await.unwrap_err();
    assert!(error.to_string().contains("size limit"));
}

/// A GitHub read waits one second and then two after busy responses that name no wait, at most thirty seconds after one that names a wait, and gives up after its third attempt.
#[test]
fn github_reads_double_their_wait_and_stop_after_three_attempts() {
    use release_glz_core::{Answer, GITHUB_READS, Next};
    assert_eq!(
        GITHUB_READS.after(0, Answer::Busy(None)),
        Next::Retry(1_000)
    );
    assert_eq!(
        GITHUB_READS.after(1, Answer::Busy(None)),
        Next::Retry(2_000)
    );
    assert_eq!(
        GITHUB_READS.after(0, Answer::Busy(Some(45))),
        Next::Retry(30_000)
    );
    assert_eq!(GITHUB_READS.after(1, Answer::Unreachable), Next::Retry(200));
    assert_eq!(GITHUB_READS.after(2, Answer::Busy(None)), Next::Stop);
}

/// A GitHub error body of up to 64 KiB reaches the error message, and a longer one is left out.
#[tokio::test]
async fn a_github_error_body_reaches_the_message_up_to_64_kib() {
    for (length, kept) in [(64 * 1024, true), (64 * 1024 + 1, false)] {
        let body = "x".repeat(length);
        let server = FakeServer::start(vec![response(403, &body)]).await;
        let error = test_client(&server, Some("token"))
            .release_details_for_tag("v1.2.3")
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(error.contains(&body), kept, "a body of {length} bytes");
        assert_eq!(
            error.contains("[response omitted: size limit exceeded]"),
            !kept,
            "a body of {length} bytes"
        );
    }
}

#[tokio::test]
async fn github_get_retries_a_transport_failure_without_reposting() {
    let server = FakeServer::start(vec![
        Vec::new(),
        response(
            200,
            r#"[{"id":42,"html_url":"https://github.test/o/r/releases/42","tag_name":"v1.2.3","target_commitish":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","draft":true}]"#,
        ),
    ])
    .await;
    let client = test_client(&server, Some("token"));

    assert!(
        client
            .release_details_for_tag("v1.2.3")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(server.requests().len(), 2);
    assert!(
        server
            .requests()
            .iter()
            .all(|request| request.starts_with("GET "))
    );
}

/// A Release with another tag never matches, a full page leads to the next one, and two Releases with the tag are a conflict.
#[tokio::test]
async fn a_release_lookup_pages_through_the_list_and_refuses_an_ambiguous_tag() {
    let release = |id: u64, tag: &str, draft: bool| {
        serde_json::json!({
            "id": id,
            "html_url": format!("https://github.test/o/r/releases/{id}"),
            "tag_name": tag,
            "target_commitish": "a".repeat(40),
            "draft": draft
        })
    };
    let full_page = serde_json::Value::Array(
        (0..100)
            .map(|index| release(1000 + index, &format!("v0.0.{index}"), false))
            .collect(),
    )
    .to_string();
    let last_page = serde_json::json!([release(42, "v1.2.3", true)]).to_string();
    let server =
        FakeServer::start(vec![response(200, &full_page), response(200, &last_page)]).await;
    let found = test_client(&server, Some("token"))
        .release_details_for_tag("v1.2.3")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.id, 42);
    assert!(found.draft);
    let requests = server.requests();
    assert!(requests[0].starts_with("GET /repos/o/r/releases?per_page=100&page=1 "));
    assert!(requests[1].starts_with("GET /repos/o/r/releases?per_page=100&page=2 "));

    let other_tags = serde_json::json!([release(41, "v1.2.2", false)]).to_string();
    let server = FakeServer::start(vec![response(200, &other_tags)]).await;
    assert!(
        test_client(&server, Some("token"))
            .release_details_for_tag("v1.2.3")
            .await
            .unwrap()
            .is_none()
    );

    let two_drafts =
        serde_json::json!([release(42, "v1.2.3", true), release(43, "v1.2.3", true)]).to_string();
    let server = FakeServer::start(vec![response(200, &two_drafts)]).await;
    let error = test_client(&server, Some("token"))
        .release_details_for_tag("v1.2.3")
        .await
        .unwrap_err();
    assert_eq!(
        release_glz::failure::classify(&error),
        release_glz::failure::FailureClass::ImmutableStateConflict
    );
    assert!(
        error
            .to_string()
            .contains("2 GitHub Releases have the tag `v1.2.3`")
    );
}

fn test_client(server: &FakeServer, token: Option<&str>) -> GitHubClient {
    GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        server.base_url(),
        format!("{}/graphql", server.base_url()),
        token.map(str::to_owned),
    )
    .unwrap()
}

fn actions_artifact_value(
    id: u64,
    name: &str,
    size: u64,
    digest: &str,
    run_id: u64,
    source_sha: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "name": name,
        "size_in_bytes": size,
        "expired": false,
        "digest": format!("sha256:{digest}"),
        "workflow_run": {"id": run_id, "head_sha": source_sha}
    })
}

fn actions_run_value(
    id: u64,
    repository: &str,
    path: &str,
    source_sha: &str,
    status: &str,
    conclusion: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "path": path,
        "head_sha": source_sha,
        "status": status,
        "conclusion": conclusion,
        "repository": {"full_name": repository}
    })
}

fn upload_release(upload_url: &str, draft: bool) -> GitHubRelease {
    GitHubRelease {
        id: 42,
        html_url: "https://github.test/o/r/releases/42".into(),
        tag_name: "v1.2.3".into(),
        target_commitish: "a".repeat(40),
        candidate_digest: Some("d".repeat(64)),
        draft,
        upload_url: upload_url.into(),
        assets: vec![],
    }
}

/// The files a Release PR commit for widget 1.2.3 writes, with a changelog long enough that GitHub breaks its base64 into lines.
fn release_files() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        (
            "CHANGELOG.md".into(),
            b"# Changelog\n\n## [1.2.3]\n\n### Features\n\n- Add the widget API that every gadget calls.\n"
                .to_vec(),
        ),
        (
            "gleam.toml".into(),
            b"name = \"widget\"\nversion = \"1.2.3\"\n".to_vec(),
        ),
    ])
}

/// The files that a Release PR commit for an earlier plan wrote.
fn earlier_release_files() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        (
            "CHANGELOG.md".into(),
            b"# Changelog\n\n## [1.2.2]\n\n### Fixes\n\n- Fix the widget API.\n".to_vec(),
        ),
        (
            "gleam.toml".into(),
            b"name = \"widget\"\nversion = \"1.2.2\"\n".to_vec(),
        ),
    ])
}

fn release_files_digest(files: &BTreeMap<String, Vec<u8>>) -> String {
    files_digest(files)
}

#[test]
fn different_file_sets_never_share_a_files_digest() {
    let separate = BTreeMap::from([
        ("a".to_owned(), b"1".to_vec()),
        ("b".to_owned(), b"2".to_vec()),
    ]);
    let joined = BTreeMap::from([("a".to_owned(), b"1b\x002".to_vec())]);
    assert_ne!(files_digest(&separate), files_digest(&joined));

    let moved = BTreeMap::from([
        ("a".to_owned(), b"".to_vec()),
        ("b".to_owned(), b"12".to_vec()),
    ]);
    let shifted = BTreeMap::from([
        ("a".to_owned(), b"1".to_vec()),
        ("b".to_owned(), b"2".to_vec()),
    ]);
    assert_ne!(files_digest(&moved), files_digest(&shifted));
}

#[test]
fn the_files_digest_format_is_pinned() {
    let files = BTreeMap::from([
        ("CHANGELOG.md".to_owned(), b"## [1.2.3]\n".to_vec()),
        ("gleam.toml".to_owned(), b"version = \"1.2.3\"\n".to_vec()),
    ]);
    assert_eq!(files_digest(&files), PINNED_FILES_DIGEST);
}

/// The files digest of the pinned file set, which changes only when the digest format does.
///
/// `shasum -a 256` over the tag, then each length as eight big-endian bytes before its path or content, gives the same value.
const PINNED_FILES_DIGEST: &str =
    "b5d2ee9e17f61225f18337cd112e36a110b2cacf19a0da50e37b182d080a71c0";

fn managed_body(
    package: &str,
    branch: &str,
    head: &str,
    digest: &str,
    version: &str,
    intent: &str,
) -> String {
    format!(
        "<!-- release-glz:managed package={package} branch={branch} head={head} digest={digest} version={version} intent={intent} -->"
    )
}

fn pull_value(number: u64, body: &str, branch: &str, head: &str) -> serde_json::Value {
    serde_json::json!({
        "number": number,
        "title": "chore(release): widget 1.2.3",
        "body": body,
        "html_url": format!("https://github.test/o/r/pull/{number}"),
        "merge_commit_sha": null,
        "merged_at": null,
        "user": {"login": "release-glz"},
        "labels": [],
        "head": {
            "ref": branch,
            "sha": head,
            "repo": {"full_name": "o/r", "default_branch": "main"}
        },
        "base": {
            "ref": "main",
            "repo": {"full_name": "o/r", "default_branch": "main"}
        }
    })
}

fn commit(sha: &str, subject: &str) -> Commit {
    Commit {
        sha: sha.into(),
        author_name: "Author".into(),
        author_email: "author@example.com".into(),
        subject: subject.into(),
        body: String::new(),
    }
}

struct FakeServer {
    address: std::net::SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
}

impl FakeServer {
    async fn start(responses: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        tokio::spawn(async move {
            let mut responses: VecDeque<_> = responses.into();
            while let Some(response) = responses.pop_front() {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                    if let Some(header_end) =
                        bytes.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        let headers = String::from_utf8_lossy(&bytes[..header_end + 4]);
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length: ")
                                    .and_then(|value| value.parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if bytes.len() >= header_end + 4 + length {
                            break;
                        }
                    }
                }
                captured
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&bytes).into_owned());
                stream.write_all(&response).await.unwrap();
            }
        });
        Self { address, requests }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

fn response(status: u16, body: &str) -> Vec<u8> {
    response_with_headers(status, body, &[])
}

fn response_with_headers(status: u16, body: &str, headers: &[&str]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let extra_headers = if headers.is_empty() {
        String::new()
    } else {
        format!("{}\r\n", headers.join("\r\n"))
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn request_json(request: &str) -> serde_json::Value {
    let (_, body) = request.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(body).unwrap()
}

fn release_plan() -> ReleasePlan {
    ReleasePlan {
        schema: ReleasePlan::SCHEMA.into(),
        state: ReleaseState::Planned,
        package: "widget".into(),
        manifest_path: "gleam.toml".into(),
        published_version: Some(Version::new(1, 1, 0)),
        manifest_version: Version::new(1, 1, 0),
        version: Version::new(1, 2, 3),
        bump: Bump::Minor,
        release_required: true,
        artifacts_changed: true,
        prerelease: None,
        tag: "v1.2.3".into(),
        baseline: Baseline {
            version: Some(Version::new(1, 1, 0)),
            git_ref: Some("v1.1.0".into()),
            sha: Some("a".repeat(40)),
            source: BaselineSource::Tag,
            retired: false,
        },
        reasons: vec![],
        api: ApiDiff::default(),
        changes: vec![],
        warnings: vec![],
        required_approvals: vec![],
        stages: vec![],
        pr_url: None,
        release_pr_head: None,
        hex_url: None,
        github_release_url: None,
    }
}
