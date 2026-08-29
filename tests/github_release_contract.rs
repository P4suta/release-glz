use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use release_glz::forge::{GitHubClient, GitHubRelease, GitHubRepository};
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
            r#"{"id":42,"html_url":"https://github.test/o/r/releases/42","tag_name":"v1.2.3","target_commitish":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","body":"release-glz-candidate-digest: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","draft":true}"#,
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
    assert!(requests[0].starts_with("GET /repos/o/r/releases/tags/v1.2.3 "));
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
    let digest = format!("{:x}", sha2::Sha256::digest(bytes));
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
            r#"[{{"number":7,"title":"chore(release): widget 1.2.3","body":"<!-- release-glz:managed package=widget branch=release-glz/widget head={head} digest={} version=1.2.3 intent={intent} -->","html_url":"https://github.test/o/r/pull/7","merge_commit_sha":"{merge_sha}","merged_at":"2026-01-01T00:00:00Z","user":{{"login":"bot"}},"labels":[],"head":{{"ref":"release-glz/widget","sha":"{head}"}}}}]"#,
            "d".repeat(64),
        )
    };
    let server = FakeServer::start(vec![
        response(200, &pull(&merged, &"1".repeat(64))),
        response(
            200,
            &format!(
                "{{\"message\":\"Generated by release-glz.\\n\\nrelease-glz-digest: {}\",\"verification\":{{\"verified\":true}}}}",
                "d".repeat(64)
            ),
        ),
        response(200, &pull(&merged, &"e".repeat(64))),
        response(200, &pull(&"b".repeat(40), &"1".repeat(64))),
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
            .merged_release_pr_for_head(
                &merged,
                "widget",
                "1.2.3",
                "release-glz/",
                &"1".repeat(64),
            )
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        client
            .merged_release_pr_for_head(
                &merged,
                "widget",
                "1.2.3",
                "release-glz/",
                &"1".repeat(64),
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        client
            .merged_release_pr_for_head(
                &merged,
                "widget",
                "1.2.3",
                "release-glz/",
                &"1".repeat(64),
            )
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn candidate_intent_binds_only_to_the_verified_managed_pr_head() {
    let head = "c".repeat(40);
    let files_digest = "d".repeat(64);
    let intent_digest = "1".repeat(64);
    let pending = format!(
        r#"[{{"number":7,"title":"chore(release): widget 1.2.3","body":"Release body\n\n<!-- release-glz:managed package=widget branch=release-glz/widget head={head} digest={files_digest} version=1.2.3 intent=pending -->","html_url":"https://github.test/o/r/pull/7","merge_commit_sha":null,"merged_at":null,"user":{{"login":"bot"}},"labels":[],"head":{{"ref":"release-glz/widget","sha":"{head}"}}}}]"#,
    );
    let bound = pending
        .trim_start_matches('[')
        .trim_end_matches(']')
        .replace("intent=pending", &format!("intent={intent_digest}"));
    let server = FakeServer::start(vec![
        response(200, &pending),
        response(
            200,
            &format!(
                "{{\"message\":\"Generated by release-glz.\\n\\nrelease-glz-digest: {files_digest}\",\"verification\":{{\"verified\":true}}}}"
            ),
        ),
        response(200, &bound),
    ])
    .await;
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        server.base_url(),
        format!("{}/graphql", server.base_url()),
        Some("token".into()),
    )
    .unwrap();

    let url = client
        .bind_release_pr_intent(&head, "widget", "1.2.3", "release-glz/", &intent_digest)
        .await
        .unwrap();
    assert_eq!(url, "https://github.test/o/r/pull/7");
    let requests = server.requests();
    assert!(requests[0].starts_with("GET /repos/o/r/pulls?state=open&per_page=100 "));
    assert!(requests[1].starts_with(&format!("GET /repos/o/r/git/commits/{head} ")));
    assert!(requests[2].starts_with("PATCH /repos/o/r/pulls/7 "));
    assert!(requests[2].contains(&format!("intent={intent_digest}")));
}

#[tokio::test]
async fn managed_release_pr_searches_every_bounded_open_pr_page() {
    let head = "c".repeat(40);
    let files_digest = "d".repeat(64);
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
    let server = FakeServer::start(vec![
        response(200, &serde_json::to_string(&first_page).unwrap()),
        response(
            200,
            &serde_json::json!([pull_value(101, &body, "release-glz/widget", &head)])
                .to_string(),
        ),
        response(
            200,
            &format!(
                "{{\"message\":\"Generated by release-glz.\\n\\nrelease-glz-digest: {files_digest}\",\"verification\":{{\"verified\":true}}}}"
            ),
        ),
        response(
            200,
            &pull_value(101, &bound_body, "release-glz/widget", &head).to_string(),
        ),
    ])
    .await;
    let client = test_client(&server, Some("token"));

    let url = client
        .bind_release_pr_intent(&head, "widget", "1.2.3", "release-glz/", &intent_digest)
        .await
        .unwrap();

    assert_eq!(url, "https://github.test/o/r/pull/101");
    let requests = server.requests();
    assert!(requests[0].starts_with("GET /repos/o/r/pulls?state=open&per_page=100 "));
    assert!(requests[1].starts_with("GET /repos/o/r/pulls?state=open&per_page=100&page=2 "));
    assert!(requests[3].starts_with("PATCH /repos/o/r/pulls/101 "));
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
        response(404, "{}"),
        response(200, &format!(r#"{{"object":{{"sha":"{base_sha}"}}}}"#)),
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

    let url = client
        .upsert_release_pr(&release_plan(), "main", "release-glz/", &files)
        .await
        .unwrap();
    assert_eq!(url, "https://github.test/o/r/pull/7");

    let requests = server.requests();
    assert_eq!(requests.len(), 7, "{requests:#?}");
    assert!(requests[0].starts_with("GET /repos/o/r/pulls?state=open&per_page=100 "));
    assert!(requests[1].starts_with("GET /repos/o/r/git/ref/heads/release-glz%2Fwidget "));
    assert!(requests[2].starts_with("GET /repos/o/r/git/ref/heads/release-glz%2Fwidget "));
    assert!(requests[3].starts_with("GET /repos/o/r/git/ref/heads/main "));
    assert!(requests[4].starts_with("POST /repos/o/r/git/refs "));
    assert!(requests[4].contains("\"ref\":\"refs/heads/release-glz/widget\""));
    assert!(requests[4].contains(&format!("\"sha\":\"{base_sha}\"")));

    assert!(requests[5].starts_with("POST /graphql "));
    let graph_body = request_json(&requests[5]);
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

    assert!(requests[6].starts_with("POST /repos/o/r/pulls "));
    let pull_body = request_json(&requests[6]);
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
async fn rolling_release_pr_is_a_no_op_when_the_verified_marker_is_current() {
    let files = release_files();
    let digest = release_files_digest(&files);
    let head = "b".repeat(40);
    let body = managed_body(
        "widget",
        "release-glz/widget",
        &head,
        &digest,
        "1.2.3",
        "pending",
    );
    let server = FakeServer::start(vec![
        response(
            200,
            &serde_json::json!([pull_value(7, &body, "release-glz/widget", &head)]).to_string(),
        ),
        response(200, &format!(r#"{{"object":{{"sha":"{head}"}}}}"#)),
    ])
    .await;
    let client = test_client(&server, Some("token"));

    let url = client
        .upsert_release_pr(&release_plan(), "main", "release-glz/", &files)
        .await
        .unwrap();
    assert_eq!(url, "https://github.test/o/r/pull/7");
    let requests = server.requests();
    assert_eq!(requests.len(), 2, "{requests:#?}");
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
}

#[tokio::test]
async fn rolling_release_pr_repairs_a_marker_after_a_verified_commit_race() {
    let files = release_files();
    let digest = release_files_digest(&files);
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
    let server = FakeServer::start(vec![
        response(200, &serde_json::json!([pull_value(7, &body, "release-glz/widget", &old_head)]).to_string()),
        response(
            200,
            &format!(r#"{{"object":{{"sha":"{actual_head}"}}}}"#),
        ),
        response(
            200,
            &format!(
                "{{\"message\":\"Generated by release-glz.\\n\\nrelease-glz-digest: {digest}\",\"verification\":{{\"verified\":true}}}}"
            ),
        ),
        response(
            200,
            &pull_value(7, &repaired_body, "release-glz/widget", &actual_head).to_string(),
        ),
    ])
    .await;
    let client = test_client(&server, Some("token"));

    let url = client
        .upsert_release_pr(&release_plan(), "main", "release-glz/", &files)
        .await
        .unwrap();
    assert_eq!(url, "https://github.test/o/r/pull/7");
    let requests = server.requests();
    assert_eq!(requests.len(), 4, "{requests:#?}");
    assert!(requests[2].starts_with(&format!("GET /repos/o/r/git/commits/{actual_head} ")));
    assert!(requests[3].starts_with("PATCH /repos/o/r/pulls/7 "));
    let patch = request_json(&requests[3]);
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
            r#"{"message":"human commit","verification":{"verified":false}}"#,
        ),
        response(200, "{}"),
        response(200, "{}"),
        response(200, &format!(r#"{{"object":{{"sha":"{human_head}"}}}}"#)),
        response(404, "{}"),
        response(200, &format!(r#"{{"object":{{"sha":"{base_head}"}}}}"#)),
        response(201, "{}"),
        response(200, &graph),
        response(201, &created),
    ])
    .await;
    let client = test_client(&server, Some("token"));

    let url = client
        .upsert_release_pr(&release_plan(), "main", "release-glz/", &files)
        .await
        .unwrap();
    assert_eq!(url, "https://github.test/o/r/pull/8");
    let requests = server.requests();
    assert_eq!(requests.len(), 11, "{requests:#?}");
    assert!(requests[3].starts_with("POST /repos/o/r/issues/7/comments "));
    assert!(requests[3].contains("not created by the bot"));
    assert!(requests[4].starts_with("PATCH /repos/o/r/pulls/7 "));
    assert!(requests[4].contains("\"state\":\"closed\""));
    assert!(requests[8].starts_with("POST /repos/o/r/git/refs "));
    assert!(requests[9].starts_with("POST /graphql "));
    assert!(requests[10].starts_with("POST /repos/o/r/pulls "));
    assert!(
        !requests
            .iter()
            .any(|request| request.starts_with("DELETE "))
    );
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

#[tokio::test]
async fn no_release_closes_and_deletes_only_an_unchanged_verified_managed_branch() {
    let head = "c".repeat(40);
    let digest = "d".repeat(64);
    let pull = format!(
        r#"[{{"number":7,"title":"chore(release): widget 1.2.3","body":"<!-- release-glz:managed package=widget branch=release-glz/widget head={head} digest={digest} version=1.2.3 -->","html_url":"https://github.test/o/r/pull/7","merge_commit_sha":null,"merged_at":null,"user":{{"login":"bot"}},"labels":[],"head":{{"ref":"release-glz/widget","sha":"{head}"}}}}]"#,
    );
    let server = FakeServer::start(vec![
        response(200, &pull),
        response(200, &format!(r#"{{"object":{{"sha":"{head}"}}}}"#)),
        response(
            200,
            &format!(
                "{{\"message\":\"Generated by release-glz.\\n\\nrelease-glz-digest: {digest}\",\"verification\":{{\"verified\":true}}}}"
            ),
        ),
        response(200, "{}"),
        response(204, ""),
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
            .close_managed_release_pr("widget", "release-glz/")
            .await
            .unwrap()
    );
    let requests = server.requests();
    assert!(requests[3].starts_with("PATCH /repos/o/r/pulls/7 "));
    assert!(requests[3].contains("\"state\":\"closed\""));
    assert!(requests[4].starts_with("DELETE /repos/o/r/git/refs/heads/release-glz%2Fwidget "));
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
    assert!(requests[0].starts_with("GET /repos/o/r/ "));
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
    let server = FakeServer::start(vec![response(200, &body)]).await;
    let client = GitHubClient::new(
        GitHubRepository::parse("o/r").unwrap(),
        server.base_url(),
        format!("{}/graphql", server.base_url()),
        Some("token".into()),
    )
    .unwrap();

    let evidence = client
        .verify_actions_artifact(91, &digest, "42", &source)
        .await
        .unwrap();
    assert_eq!(evidence.id(), 91);
    assert_eq!(evidence.sha256(), digest);
    assert_eq!(evidence.run_id(), "42");
    assert_eq!(evidence.source_sha(), source);
    assert!(server.requests()[0].starts_with("GET /repos/o/r/actions/artifacts/91 "));
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
        .verify_actions_artifact(91, &"d".repeat(64), "42", &source)
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
        .verify_actions_artifact(91, &digest, "42", &source)
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
            .verify_actions_artifact(id, expected_digest, run_id, &source)
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
            .verify_actions_artifact(91, &digest, "42", &source)
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
    let digest = format!("{:x}", sha2::Sha256::digest(bytes));
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

#[tokio::test]
async fn github_get_retries_retry_after_without_reposting_and_bounds_json_bodies() {
    let server = FakeServer::start(vec![
        response_with_headers(503, r#"{"message":"busy"}"#, &["Retry-After: 0"]),
        response(
            200,
            r#"{"id":42,"html_url":"https://github.test/o/r/releases/42","tag_name":"v1.2.3","target_commitish":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","draft":true}"#,
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
        r#"{{"id":42,"html_url":"https://github.test/o/r/releases/42","tag_name":"v1.2.3","target_commitish":"{}","draft":true,"padding":"{}"}}"#,
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

fn release_files() -> BTreeMap<String, Vec<u8>> {
    BTreeMap::from([
        ("CHANGELOG.md".into(), b"# Changelog\n".to_vec()),
        (
            "gleam.toml".into(),
            b"name = \"widget\"\nversion = \"1.2.3\"\n".to_vec(),
        ),
    ])
}

fn release_files_digest(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut digest = sha2::Sha256::new();
    for (path, contents) in files {
        digest.update(path.as_bytes());
        digest.update([0]);
        digest.update(contents);
    }
    format!("{:x}", digest.finalize())
}

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
        "head": {"ref": branch, "sha": head}
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
        intent_digest: None,
        pr_url: None,
        hex_url: None,
        github_release_url: None,
    }
}
