use release_glz::config::{AuthKind, RegistryConfig, RegistryProvider};
use release_glz::failure::{RefusalReason, refusal_reason};
use release_glz::registry::{
    HexRegistry, PublishOutcome, Registry, RegistryCredentialAudit, VisibilityPoll,
};
use release_glz_domain::Sha256Digest;
use release_glz_test_support::http::{FakeServer, Reply, Request, Response};
use semver::Version;

#[tokio::test]
async fn custom_registry_authenticates_reads_and_observes_outer_checksum() {
    let (base, mut permission_server) = server(vec![
        response(200, br#"{"releases":[{"version":"1.2.3","has_docs":true}],"retirements":{}}"#),
        response(200, br#"{"version":"1.2.3","checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","has_docs":true}"#),
        response(200, b"package-bytes"),
        response(200, b"docs-bytes"),
    ]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    let version = Version::new(1, 2, 3);
    assert!(registry.package("widget").await.unwrap().is_some());
    let release = registry.release("widget", &version).await.unwrap().unwrap();
    assert_eq!(release.outer_checksum.unwrap().as_str(), "a".repeat(64));
    assert_eq!(
        registry.source_tarball("widget", &version).await.unwrap(),
        b"package-bytes"
    );
    assert_eq!(
        registry
            .docs_tarball("widget", &version)
            .await
            .unwrap()
            .unwrap(),
        b"docs-bytes"
    );

    let requests = permission_server.finish();
    assert_eq!(requests[0].target, "/api/packages/widget");
    assert_eq!(requests[1].target, "/api/packages/widget/releases/1.2.3");
    assert_eq!(requests[2].target, "/repo/tarballs/widget-1.2.3.tar");
    assert_eq!(requests[3].target, "/repo/docs/widget-1.2.3.tar.gz");
    assert!(
        requests
            .iter()
            .all(|request| authorization(request) == Some("Bearer secret"))
    );
}

#[tokio::test]
async fn organization_registry_uses_repos_prefix_and_publishes_exact_bytes() {
    let (base, mut server) = server(vec![
        response(200, b"org-source"),
        response(200, b"org-docs"),
        response(201, b"{}"),
        response(201, b""),
    ]);
    let mut config = custom_config(&base);
    config.provider = RegistryProvider::HexPm;
    config.repository = Some("acme".into());
    // Hex's API root remains global.
    // Repository-scoped API operations add `/repos/REPO`, while `/auth` remains directly under this root.
    config.api_url = format!("{base}/api");
    config.repository_url = format!("{base}/repo/repos/acme");
    config.docs_url = format!("{base}/repo/repos/acme/docs");
    config.auth = AuthKind::HexToken;
    let registry = HexRegistry::from_config(&config, Some("org-token")).unwrap();
    assert_eq!(
        registry
            .source_tarball("widget", &Version::new(1, 2, 3))
            .await
            .unwrap(),
        b"org-source"
    );
    assert_eq!(
        registry
            .docs_tarball("widget", &Version::new(1, 2, 3))
            .await
            .unwrap()
            .unwrap(),
        b"org-docs"
    );
    assert_eq!(
        registry.publish_package(b"sealed-package").await.unwrap(),
        PublishOutcome::Accepted
    );
    assert_eq!(
        registry
            .publish_docs("widget", &Version::new(1, 2, 3), b"sealed-docs")
            .await
            .unwrap(),
        PublishOutcome::Accepted
    );
    let [source, downloaded_docs, package, docs] = server.finish().try_into().unwrap();
    assert_eq!(source.target, "/repo/repos/acme/tarballs/widget-1.2.3.tar");
    assert_eq!(
        downloaded_docs.target,
        "/repo/repos/acme/docs/widget-1.2.3.tar.gz"
    );
    assert_eq!(package.method, "POST");
    assert_eq!(package.target, "/api/repos/acme/publish");
    assert_eq!(package.body, b"sealed-package");
    assert_eq!(
        docs.target,
        "/api/repos/acme/packages/widget/releases/1.2.3/docs"
    );
    assert_eq!(docs.body, b"sealed-docs");
    assert_eq!(authorization(&package), Some("org-token"));
}

#[test]
fn registry_adapter_rejects_every_unsafe_base_url_without_contacting_it() {
    let untrusted = Some(RefusalReason::UrlTransportUntrusted);
    let cases = [
        ("http", "http://example.test/api", untrusted, "HTTPS"),
        (
            "http-to-localhost",
            "http://localhost:9/api",
            untrusted,
            "HTTPS",
        ),
        (
            "http-to-a-public-address",
            "http://192.0.2.1/api",
            untrusted,
            "HTTPS",
        ),
        (
            "http-to-a-mapped-address",
            "http://[::ffff:127.0.0.1]:9/api",
            untrusted,
            "HTTPS",
        ),
        (
            "credentials",
            "https://user:secret@example.test/api",
            Some(RefusalReason::UrlCredentials),
            "credentials",
        ),
        // A URL that doesn't parse is no named refusal, so its exact message identifies it.
        ("relative", "not-a-url", None, "registry.api_url is invalid"),
        (
            "query",
            "https://example.test/api?token=x",
            Some(RefusalReason::UrlQueryOrFragment),
            "query or fragment",
        ),
        (
            "fragment",
            "https://example.test/api#x",
            Some(RefusalReason::UrlQueryOrFragment),
            "query or fragment",
        ),
    ];
    for (name, url, reason, expected) in cases {
        let config = RegistryConfig {
            api_url: url.into(),
            ..RegistryConfig::default()
        };
        let error = HexRegistry::from_config(&config, Some("never-print-me")).unwrap_err();
        assert_eq!(refusal_reason(&error), reason, "{name}");
        let error = error.to_string();
        if reason.is_none() {
            assert_eq!(error, expected, "{name}");
        }
        assert!(error.contains(expected), "{name}: {error}");
        assert!(!error.contains("never-print-me"), "{name}: {error}");
    }
}

#[test]
fn registry_adapter_accepts_http_to_a_numeric_loopback_address_without_any_switch() {
    for base in [
        "http://127.0.0.1:9",
        "http://127.8.9.10:9",
        "http://[::1]:9",
    ] {
        let config = RegistryConfig {
            api_url: format!("{base}/api"),
            repository_url: format!("{base}/repo"),
            docs_url: format!("{base}/repo/docs"),
            ..RegistryConfig::default()
        };
        HexRegistry::from_config(&config, None).unwrap();
    }
}

#[tokio::test]
async fn credential_audit_checks_publish_and_private_repository_permissions_without_mutation() {
    let (base, mut server) = server(vec![response(204, b""), response(204, b"")]);
    let mut config = custom_config(&base);
    config.provider = RegistryProvider::HexPm;
    config.repository = Some("acme".into());
    config.auth = AuthKind::HexToken;
    let registry = HexRegistry::from_config(&config, Some("audit-token")).unwrap();

    assert_eq!(
        registry.audit_credential().await.unwrap(),
        RegistryCredentialAudit::PublishAndReadAllowed
    );

    let [publish, repository] = server.finish().try_into().unwrap();
    assert_eq!(publish.method, "GET");
    assert_eq!(publish.target, "/api/auth?domain=api&resource=write");
    assert_eq!(
        repository.target,
        "/api/auth?domain=repository&resource=acme"
    );
    assert_eq!(authorization(&publish), Some("audit-token"));
    assert_eq!(authorization(&repository), Some("audit-token"));
    assert!(publish.body.is_empty());
    assert!(repository.body.is_empty());
}

#[tokio::test]
async fn credential_audit_distinguishes_missing_invalid_and_insufficient_credentials() {
    let missing = HexRegistry::from_config(&custom_config("http://127.0.0.1:9"), None).unwrap();
    assert_eq!(
        missing.audit_credential().await.unwrap(),
        RegistryCredentialAudit::Missing
    );

    let (invalid_base, mut invalid_server) =
        server(vec![response(401, br#"{"message":"failed to authorize"}"#)]);
    let invalid =
        HexRegistry::from_config(&custom_config(&invalid_base), Some("never-print-me")).unwrap();
    assert_eq!(
        invalid.audit_credential().await.unwrap(),
        RegistryCredentialAudit::Invalid
    );
    assert_eq!(
        invalid_server.finish()[0].target,
        "/api/auth?domain=api&resource=write"
    );

    let (denied_base, mut denied_server) =
        server(vec![response(403, br#"{"message":"permission denied"}"#)]);
    let denied =
        HexRegistry::from_config(&custom_config(&denied_base), Some("also-secret")).unwrap();
    assert_eq!(
        denied.audit_credential().await.unwrap(),
        RegistryCredentialAudit::PublishPermissionDenied
    );
    assert_eq!(
        denied_server.finish()[0].target,
        "/api/auth?domain=api&resource=write"
    );
}

#[tokio::test]
async fn credential_audit_reports_private_read_permission_separately_and_redacts_errors() {
    let (base, mut permission_server) = server(vec![
        response(204, b""),
        response(403, br#"{"message":"contains-super-secret"}"#),
    ]);
    let mut config = custom_config(&base);
    config.repository = Some("acme".into());
    let registry = HexRegistry::from_config(&config, Some("super-secret")).unwrap();

    assert_eq!(
        registry.audit_credential().await.unwrap(),
        RegistryCredentialAudit::RepositoryReadPermissionDenied
    );
    assert_eq!(permission_server.finish().len(), 2);

    let (failure_base, mut failure_server) =
        server(vec![response(400, br#"{"message":"super-secret"}"#)]);
    let failed = HexRegistry::from_config(&custom_config(&failure_base), Some("super-secret"))
        .unwrap()
        .audit_credential()
        .await
        .unwrap_err();
    let message = format!("{failed:#}");
    assert!(!message.contains("super-secret"), "{message}");
    failure_server.finish();
}

#[tokio::test]
async fn ambiguous_publish_is_reported_without_reposting() {
    let (base, mut server) = server(vec![Reply::Close]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    assert_eq!(
        registry.publish_package(b"one-attempt").await.unwrap(),
        PublishOutcome::Unknown
    );
    let requests = server.finish();
    assert_eq!(requests[0].body, b"one-attempt");
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn get_retries_retry_after_but_refuses_cross_origin_redirects() {
    let redirect = Response::new(302).header("Location", "http://example.test/stolen");
    let (base, mut server) = server(vec![
        Response::new(429).header("Retry-After", "0").into(),
        response(200, br#"{"releases":[],"retirements":{}}"#),
        redirect.into(),
    ]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    assert!(registry.package("widget").await.unwrap().is_some());
    let error = registry
        .source_tarball("widget", &Version::new(1, 2, 3))
        .await
        .unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::RegistryRedirectCrossOrigin)
    );
    assert!(error.to_string().contains("cross-origin"));
    let seen = server.finish();
    assert!(
        seen.iter()
            .all(|request| authorization(request) == Some("Bearer secret"))
    );
}

#[tokio::test]
async fn registry_payloads_are_strictly_typed_and_release_checksums_are_exact() {
    let valid_checksum = "A".repeat(64);
    let (base, mut server) = server(vec![
        response(404, b""),
        response(200, b"not-json"),
        response(
            200,
            br#"{"releases":[{"version":"not-semver"}],"retirements":{}}"#,
        ),
        response(200, b"not-json"),
        response(
            200,
            br#"{"version":"not-semver","checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        ),
        response(
            200,
            br#"{"version":"9.9.9","checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        ),
        response(
            200,
            br#"{"version":"1.2.3","checksum":"too-short"}"#,
        ),
        response(
            200,
            format!(
                r#"{{"version":"1.2.3","checksum":"{valid_checksum}","has_docs":true,"retirement":{{"reason":"invalid"}}}}"#
            )
            .as_bytes(),
        ),
        response(
            200,
            br#"{"releases":[{"version":"1.2.3","has_docs":false}],"retirements":{"1.2.3":{"reason":"invalid"}}}"#,
        ),
    ]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    let version = Version::new(1, 2, 3);

    assert!(
        registry
            .release("widget", &version)
            .await
            .unwrap()
            .is_none()
    );
    let refusal = |error: anyhow::Error| (refusal_reason(&error), error.to_string());
    let not_json = registry.package("widget").await.unwrap_err();
    assert!(
        not_json.downcast_ref::<serde_json::Error>().is_some(),
        "{not_json:#}"
    );
    assert_eq!(
        refusal(not_json),
        (
            Some(RefusalReason::RegistryPackageInvalid),
            "invalid registry package response".to_owned()
        )
    );
    let not_semver = registry.package("widget").await.unwrap_err();
    assert!(
        not_semver.downcast_ref::<semver::Error>().is_some(),
        "{not_semver:#}"
    );
    assert_eq!(
        refusal(not_semver),
        (
            Some(RefusalReason::RegistryPackageInvalid),
            "registry returned invalid version `not-semver`".to_owned()
        )
    );
    let not_json = registry.release("widget", &version).await.unwrap_err();
    assert!(
        not_json.downcast_ref::<serde_json::Error>().is_some(),
        "{not_json:#}"
    );
    assert_eq!(
        refusal(not_json),
        (
            Some(RefusalReason::RegistryReleaseInvalid),
            "invalid registry release response".to_owned()
        )
    );
    let not_semver = registry.release("widget", &version).await.unwrap_err();
    assert!(
        not_semver.downcast_ref::<semver::Error>().is_some(),
        "{not_semver:#}"
    );
    assert_eq!(
        refusal(not_semver),
        (
            Some(RefusalReason::RegistryReleaseInvalid),
            "registry release has an invalid version".to_owned()
        )
    );
    assert_eq!(
        refusal(registry.release("widget", &version).await.unwrap_err()),
        (
            Some(RefusalReason::RegistryReleaseInvalid),
            "registry returned release 9.9.9 while observing 1.2.3".to_owned()
        )
    );
    assert_eq!(
        refusal(registry.release("widget", &version).await.unwrap_err()),
        (
            Some(RefusalReason::RegistryReleaseInvalid),
            "registry release checksum is not SHA-256".to_owned()
        )
    );
    let release = registry.release("widget", &version).await.unwrap().unwrap();
    assert_eq!(
        release.outer_checksum.as_ref().map(Sha256Digest::as_str),
        Some("a".repeat(64).as_str())
    );
    assert!(release.has_docs);
    assert!(release.retired);
    let package = registry.package("widget").await.unwrap().unwrap();
    assert!(package.release(&version).unwrap().retired);
    server.finish();
}

#[tokio::test]
async fn every_retryable_publish_status_is_ambiguous_and_permanent_errors_fail() {
    let (base, mut server) = server(vec![
        response(409, b"conflict"),
        response(408, b"timeout"),
        response(429, b"rate limited"),
        response(500, b"server error"),
        response(400, b"invalid"),
    ]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    for status in [409, 408, 429, 500] {
        assert_eq!(
            registry
                .publish_package(status.to_string().as_bytes())
                .await
                .unwrap(),
            PublishOutcome::Unknown,
            "status {status}"
        );
    }
    let error = registry.publish_package(b"invalid").await.unwrap_err();
    assert!(error.to_string().contains("400"));
    let requests = server.finish();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "POST")
            .count(),
        5
    );
}

/// A publish refuses every redirect, so its bytes and its credential reach no URL but the configured one.
#[tokio::test]
async fn each_publish_refuses_each_redirect_and_sends_nothing_to_its_location() {
    let version = Version::new(1, 2, 3);
    for (publication, target) in [
        ("package", "/api/publish"),
        ("docs", "/api/packages/widget/releases/1.2.3/docs"),
    ] {
        for (status, phrase) in [
            (301, "301 Moved Permanently"),
            (302, "302 Found"),
            (307, "307 Temporary Redirect"),
            (308, "308 Permanent Redirect"),
        ] {
            let case = format!("the {publication} publish answered with {status}");
            let mut elsewhere = FakeServer::start();
            let location = format!(
                "http://user:publish-secret@{}/publish-secret?token=publish-secret#publish-secret",
                elsewhere.address()
            );
            let (base, mut server) = server(vec![
                Response::new(status).header("Location", &location).into(),
            ]);
            let registry =
                HexRegistry::from_config(&custom_config(&base), Some("publish-secret")).unwrap();

            let error = match publication {
                "package" => registry.publish_package(b"sealed").await,
                _ => registry.publish_docs("widget", &version, b"sealed").await,
            }
            .unwrap_err();

            assert_eq!(
                (refusal_reason(&error), error.to_string()),
                (
                    Some(RefusalReason::RegistryPublishRedirectRefused),
                    format!(
                        "refusing registry publish redirect {phrase} from {base}{target} to {}",
                        elsewhere.base_url()
                    )
                ),
                "{case}"
            );
            let [publish] = server.finish().try_into().unwrap();
            assert_eq!(
                (
                    publish.method.as_str(),
                    publish.target.as_str(),
                    authorization(&publish),
                    publish.body.as_slice()
                ),
                (
                    "POST",
                    target,
                    Some("Bearer publish-secret"),
                    &b"sealed"[..]
                ),
                "{case}"
            );
            assert_eq!(elsewhere.finish(), [], "{case}");
            assert_eq!(elsewhere.connections(), 0, "{case}");
        }
    }
}

#[tokio::test]
async fn same_origin_redirects_preserve_auth_while_missing_locations_fail_closed() {
    let redirect = |location: Option<&str>| -> Reply {
        match location {
            Some(value) => Response::new(302).header("Location", value),
            None => Response::new(302),
        }
        .into()
    };
    let (base, mut server) = server(vec![
        redirect(Some("/api/redirected")),
        response(200, br#"{"releases":[],"retirements":{}}"#),
        redirect(None),
    ]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    assert!(registry.package("widget").await.unwrap().is_some());
    let missing = registry.package("missing-location").await.unwrap_err();
    assert_eq!(
        refusal_reason(&missing),
        Some(RefusalReason::RegistryRedirectLocationInvalid)
    );
    assert!(missing.to_string().contains("Location"), "{missing}");
    let requests = server.finish();
    assert_eq!(requests[0].target, "/api/packages/widget");
    assert_eq!(requests[1].target, "/api/redirected");
    assert!(
        requests
            .iter()
            .all(|request| authorization(request) == Some("Bearer secret"))
    );
}

#[tokio::test]
async fn get_and_credential_audit_retries_are_bounded_and_never_change_method() {
    let retry = || -> Reply {
        Response::new(503)
            .header("Retry-After", "0")
            .body("busy")
            .into()
    };
    let (get_base, mut get_server) = server(vec![retry(), retry(), retry()]);
    let registry = HexRegistry::from_config(&custom_config(&get_base), Some("secret")).unwrap();
    let error = registry.package("widget").await.unwrap_err().to_string();
    assert!(error.contains("temporarily unavailable"), "{error}");
    let requests = get_server.finish();
    assert!(requests.iter().all(|request| request.method == "GET"));

    let (audit_base, mut audit_server) = server(vec![retry(), retry(), retry()]);
    let registry = HexRegistry::from_config(&custom_config(&audit_base), Some("secret")).unwrap();
    let error = registry.audit_credential().await.unwrap_err().to_string();
    assert!(error.contains("temporarily unavailable"), "{error}");
    let requests = audit_server.finish();
    assert!(requests.iter().all(|request| request.method == "GET"));
}

#[tokio::test]
async fn transport_failures_and_redirect_loops_exhaust_a_fixed_read_budget() {
    let (base, mut disconnect_server) = server(vec![Reply::Close, Reply::Close, Reply::Close]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    let error = registry.package("widget").await.unwrap_err();
    assert!(
        error.downcast_ref::<reqwest::Error>().is_some(),
        "{error:#}"
    );
    let requests = disconnect_server.finish();
    assert!(requests.iter().all(|request| request.method == "GET"));

    let redirect = || -> Reply { Response::new(302).header("Location", "/api/loop").into() };
    let (base, mut redirect_server) = server((0..6).map(|_| redirect()).collect());
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    let error = registry.package("loop").await.unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::RegistryRedirectLimitExceeded)
    );
    let error = error.to_string();
    assert!(error.contains("too many same-origin redirects"), "{error}");
    let requests = redirect_server.finish();
    assert_eq!(requests[0].target, "/api/packages/loop");
    assert!(
        requests[1..]
            .iter()
            .all(|request| request.target == "/api/loop")
    );
}

#[tokio::test]
async fn permanent_get_errors_fail_without_retrying_or_leaking_credentials() {
    let (base, mut server) = server(vec![response(400, br#"{"message":"never-print-me"}"#)]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("never-print-me")).unwrap();
    let error = registry.package("widget").await.unwrap_err().to_string();
    assert!(error.contains("400"), "{error}");
    assert!(!error.contains("never-print-me"), "{error}");
    let requests = server.finish();
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn registry_json_downloads_are_bounded_and_an_empty_credential_is_not_sent() {
    let oversized = vec![b'x'; 4 * 1024 * 1024 + 1];
    let (base, mut server) = server(vec![
        response(200, &oversized),
        response(200, br#"{"releases":[],"retirements":{}}"#),
    ]);
    let with_token = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    let oversized_error = with_token.package("oversized").await.unwrap_err();
    assert_eq!(
        refusal_reason(&oversized_error),
        Some(RefusalReason::RegistryResponseTooLarge)
    );
    assert!(
        oversized_error.to_string().contains("download limit"),
        "{oversized_error}"
    );
    let without_token = HexRegistry::from_config(&custom_config(&base), Some("")).unwrap();
    assert!(without_token.package("public").await.unwrap().is_some());
    let [oversized_request, public_request] = server.finish().try_into().unwrap();
    assert_eq!(authorization(&oversized_request), Some("Bearer secret"));
    assert!(authorization(&public_request).is_none());
}

#[tokio::test]
async fn registry_download_limit_accepts_the_exact_boundary_and_counts_streamed_bytes() {
    let exact = vec![b'x'; 4 * 1024 * 1024];
    let streamed_oversized = vec![b'x'; 4 * 1024 * 1024 + 1];
    let (base, mut server) = server(vec![
        response(200, &exact),
        Response::new(200)
            .body(streamed_oversized)
            .until_close()
            .into(),
    ]);
    let registry = HexRegistry::from_config(&custom_config(&base), None).unwrap();

    let exact_error = registry.package("exact").await.unwrap_err();
    assert_eq!(
        refusal_reason(&exact_error),
        Some(RefusalReason::RegistryPackageInvalid)
    );
    let exact_error = exact_error.to_string();
    assert!(
        exact_error.contains("invalid registry package response"),
        "{exact_error}"
    );
    assert!(!exact_error.contains("download limit"), "{exact_error}");

    let oversized_error = registry.package("streamed-oversized").await.unwrap_err();
    assert_eq!(
        refusal_reason(&oversized_error),
        Some(RefusalReason::RegistryResponseTooLarge)
    );
    let oversized_error = oversized_error.to_string();
    assert!(
        oversized_error.contains("download limit"),
        "{oversized_error}"
    );
    let requests = server.finish();
    assert_eq!(requests[0].target, "/api/packages/exact");
    assert_eq!(requests[1].target, "/api/packages/streamed-oversized");
}

#[tokio::test]
async fn credential_audit_refuses_cross_origin_redirects() {
    let (base, mut server) = server(vec![
        Response::new(302)
            .header("Location", "https://other.example/auth")
            .into(),
    ]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    let error = registry.audit_credential().await.unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::RegistryRedirectCrossOrigin)
    );
    let error = error.to_string();
    assert!(error.contains("cross-origin"), "{error}");
    assert_eq!(
        server.finish()[0].target,
        "/api/auth?domain=api&resource=write"
    );
}

#[tokio::test]
async fn wait_for_returns_the_observed_ready_state() {
    let (base, mut server) = server(vec![response(
        200,
        br#"{"releases":[{"version":"1.2.3","has_docs":true}],"retirements":{}}"#,
    )]);
    let registry = HexRegistry::from_config(&custom_config(&base), None).unwrap();
    let version = Version::new(1, 2, 3);
    let state = registry.wait_for("widget", &version, true).await.unwrap();
    let release = state.release(&version).unwrap();
    assert!(release.has_docs);
    assert_eq!(server.finish()[0].target, "/api/packages/widget");
}

/// Polling with no wait between observations.
///
/// The schedule tests in `src/registry.rs` assert the waits on paused time, which a request to a loopback server would race against its timeouts.
fn back_to_back(attempts: usize) -> VisibilityPoll {
    VisibilityPoll {
        attempts,
        interval: std::time::Duration::ZERO,
    }
}

#[tokio::test]
async fn wait_for_keeps_polling_until_the_release_is_visible() {
    let (base, mut server) = server(vec![
        response(200, br#"{"releases":[],"retirements":{}}"#),
        response(
            200,
            br#"{"releases":[{"version":"1.2.3","has_docs":false}],"retirements":{}}"#,
        ),
        response(
            200,
            br#"{"releases":[{"version":"1.2.3","has_docs":true}],"retirements":{}}"#,
        ),
    ]);
    let registry = HexRegistry::from_config(&custom_config(&base), None)
        .unwrap()
        .with_visibility_poll(back_to_back(3));
    let version = Version::new(1, 2, 3);

    let state = registry.wait_for("widget", &version, true).await.unwrap();

    assert!(state.release(&version).unwrap().has_docs);
    for request in server.finish() {
        assert_eq!(request.target, "/api/packages/widget");
    }
}

/// The wait reports its timeout right after its last poll instead of sleeping once more first.
#[tokio::test]
async fn wait_for_reports_its_timeout_without_sleeping_after_the_last_poll() {
    let (base, mut server) = server(vec![response(200, br#"{"releases":[],"retirements":{}}"#)]);
    let registry = HexRegistry::from_config(&custom_config(&base), None)
        .unwrap()
        .with_visibility_poll(VisibilityPoll {
            attempts: 1,
            interval: std::time::Duration::from_secs(60),
        });

    let waited = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        registry.wait_for("widget", &Version::new(1, 2, 3), false),
    )
    .await
    .expect("the wait must not sleep after its last poll");
    let error = waited.unwrap_err();
    assert_eq!(
        (refusal_reason(&error), error.to_string()),
        (
            Some(RefusalReason::RegistryReleaseNotVisible),
            "timed out waiting for widget 1.2.3 to appear on the registry".to_owned()
        )
    );
    assert_eq!(server.finish().len(), 1);
}

#[tokio::test]
async fn wait_for_stops_after_its_attempts() {
    let (base, mut server) = server(vec![
        response(200, br#"{"releases":[],"retirements":{}}"#),
        response(200, br#"{"releases":[],"retirements":{}}"#),
    ]);
    let registry = HexRegistry::from_config(&custom_config(&base), None)
        .unwrap()
        .with_visibility_poll(back_to_back(2));

    let error = registry
        .wait_for("widget", &Version::new(1, 2, 3), false)
        .await
        .unwrap_err();

    assert_eq!(
        (refusal_reason(&error), error.to_string()),
        (
            Some(RefusalReason::RegistryReleaseNotVisible),
            "timed out waiting for widget 1.2.3 to appear on the registry".to_owned()
        )
    );
    assert_eq!(server.finish().len(), 2);
}

/// A registry request waits a quarter of a second after a busy response that names no wait, at most a minute after one that names a wait, and one step more after each transport failure.
#[test]
fn registry_requests_follow_their_retry_schedule() {
    use release_glz_core::{Answer, Next, REGISTRY_RETRIES};
    assert_eq!(
        REGISTRY_RETRIES.after(0, Answer::Busy(None)),
        Next::Retry(250)
    );
    assert_eq!(
        REGISTRY_RETRIES.after(1, Answer::Busy(Some(90))),
        Next::Retry(60_000)
    );
    assert_eq!(
        REGISTRY_RETRIES.after(0, Answer::Unreachable),
        Next::Retry(100)
    );
    assert_eq!(
        REGISTRY_RETRIES.after(1, Answer::Unreachable),
        Next::Retry(200)
    );
    assert_eq!(REGISTRY_RETRIES.after(2, Answer::Busy(None)), Next::Stop);
}

fn custom_config(base: &str) -> RegistryConfig {
    RegistryConfig {
        provider: RegistryProvider::HexCompatible,
        repository: None,
        api_url: format!("{base}/api"),
        repository_url: format!("{base}/repo"),
        docs_url: format!("{base}/repo/docs"),
        credential_env: "TEST_TOKEN".into(),
        auth: AuthKind::Bearer,
    }
}

fn response(status: u16, body: &[u8]) -> Reply {
    Response::new(status).body(body).into()
}

/// A fake registry that answers its requests with `replies` in order, and its origin.
fn server(replies: Vec<Reply>) -> (String, FakeServer) {
    let server = FakeServer::start();
    server.script(replies);
    (server.base_url(), server)
}

/// The credential that `request` carried.
fn authorization(request: &Request) -> Option<&str> {
    request.header("authorization")
}
