use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use release_glz::config::{AuthKind, RegistryConfig, RegistryProvider};
use release_glz::registry::{HexRegistry, PublishOutcome, Registry, RegistryCredentialAudit};
use semver::Version;

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    disconnect: bool,
    omit_content_length: bool,
}

#[tokio::test]
async fn custom_registry_authenticates_reads_and_observes_outer_checksum() {
    let (base, requests, permission_server) = server(vec![
        response(200, br#"{"releases":[{"version":"1.2.3","has_docs":true}],"retirements":{}}"#),
        response(200, br#"{"version":"1.2.3","checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","has_docs":true}"#),
        response(200, b"package-bytes"),
        response(200, b"docs-bytes"),
    ]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    let version = Version::new(1, 2, 3);
    assert!(registry.package("widget").await.unwrap().is_some());
    let release = registry.release("widget", &version).await.unwrap().unwrap();
    assert_eq!(release.outer_checksum.unwrap(), "a".repeat(64));
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

    let requests: Vec<_> = (0..4).map(|_| requests.recv().unwrap()).collect();
    assert_eq!(requests[0].path, "/api/packages/widget");
    assert_eq!(requests[1].path, "/api/packages/widget/releases/1.2.3");
    assert_eq!(requests[2].path, "/repo/tarballs/widget-1.2.3.tar");
    assert_eq!(requests[3].path, "/repo/docs/widget-1.2.3.tar.gz");
    assert!(
        requests
            .iter()
            .all(|request| request.authorization.as_deref() == Some("Bearer secret"))
    );
    permission_server.join().unwrap();
}

#[tokio::test]
async fn organization_registry_uses_repos_prefix_and_publishes_exact_bytes() {
    let (base, requests, server) = server(vec![
        response(200, b"org-source"),
        response(200, b"org-docs"),
        response(201, b"{}"),
        response(201, b""),
    ]);
    let mut config = custom_config(&base);
    config.provider = RegistryProvider::HexPm;
    config.repository = Some("acme".into());
    // Hex's API root remains global. Repository-scoped API operations add
    // `/repos/REPO`, while `/auth` remains directly under this root.
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
    let source = requests.recv().unwrap();
    let downloaded_docs = requests.recv().unwrap();
    let package = requests.recv().unwrap();
    let docs = requests.recv().unwrap();
    assert_eq!(source.path, "/repo/repos/acme/tarballs/widget-1.2.3.tar");
    assert_eq!(
        downloaded_docs.path,
        "/repo/repos/acme/docs/widget-1.2.3.tar.gz"
    );
    assert_eq!(package.method, "POST");
    assert_eq!(package.path, "/api/repos/acme/publish");
    assert_eq!(package.body, b"sealed-package");
    assert_eq!(
        docs.path,
        "/api/repos/acme/packages/widget/releases/1.2.3/docs"
    );
    assert_eq!(docs.body, b"sealed-docs");
    assert_eq!(package.authorization.as_deref(), Some("org-token"));
    server.join().unwrap();
}

#[test]
fn registry_adapter_rejects_every_unsafe_base_url_without_contacting_it() {
    let cases = [
        ("http", "http://example.test/api", "HTTPS"),
        (
            "credentials",
            "https://user:secret@example.test/api",
            "credentials",
        ),
        ("relative", "not-a-url", "invalid"),
        (
            "query",
            "https://example.test/api?token=x",
            "query or fragment",
        ),
        (
            "fragment",
            "https://example.test/api#x",
            "query or fragment",
        ),
    ];
    for (name, url, expected) in cases {
        let config = RegistryConfig {
            api_url: url.into(),
            ..RegistryConfig::default()
        };
        let error = HexRegistry::from_config(&config, Some("never-print-me"))
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{name}: {error}");
        assert!(!error.contains("never-print-me"), "{name}: {error}");
    }
}

#[tokio::test]
async fn credential_audit_checks_publish_and_private_repository_permissions_without_mutation() {
    let (base, requests, server) = server(vec![response(204, b""), response(204, b"")]);
    let mut config = custom_config(&base);
    config.provider = RegistryProvider::HexPm;
    config.repository = Some("acme".into());
    config.auth = AuthKind::HexToken;
    let registry = HexRegistry::from_config(&config, Some("audit-token")).unwrap();

    assert_eq!(
        registry.audit_credential().await.unwrap(),
        RegistryCredentialAudit::PublishAndReadAllowed
    );

    let publish = requests.recv().unwrap();
    let repository = requests.recv().unwrap();
    assert_eq!(publish.method, "GET");
    assert_eq!(publish.path, "/api/auth?domain=api&resource=write");
    assert_eq!(repository.path, "/api/auth?domain=repository&resource=acme");
    assert_eq!(publish.authorization.as_deref(), Some("audit-token"));
    assert_eq!(repository.authorization.as_deref(), Some("audit-token"));
    assert!(publish.body.is_empty());
    assert!(repository.body.is_empty());
    server.join().unwrap();
}

#[tokio::test]
async fn credential_audit_distinguishes_missing_invalid_and_insufficient_credentials() {
    let missing = HexRegistry::from_config(&custom_config("http://127.0.0.1:9"), None).unwrap();
    assert_eq!(
        missing.audit_credential().await.unwrap(),
        RegistryCredentialAudit::Missing
    );

    let (invalid_base, invalid_requests, invalid_server) =
        server(vec![response(401, br#"{"message":"failed to authorize"}"#)]);
    let invalid =
        HexRegistry::from_config(&custom_config(&invalid_base), Some("never-print-me")).unwrap();
    assert_eq!(
        invalid.audit_credential().await.unwrap(),
        RegistryCredentialAudit::Invalid
    );
    assert_eq!(
        invalid_requests.recv().unwrap().path,
        "/api/auth?domain=api&resource=write"
    );
    invalid_server.join().unwrap();

    let (denied_base, denied_requests, denied_server) =
        server(vec![response(403, br#"{"message":"permission denied"}"#)]);
    let denied =
        HexRegistry::from_config(&custom_config(&denied_base), Some("also-secret")).unwrap();
    assert_eq!(
        denied.audit_credential().await.unwrap(),
        RegistryCredentialAudit::PublishPermissionDenied
    );
    assert_eq!(
        denied_requests.recv().unwrap().path,
        "/api/auth?domain=api&resource=write"
    );
    denied_server.join().unwrap();
}

#[tokio::test]
async fn credential_audit_reports_private_read_permission_separately_and_redacts_errors() {
    let (base, requests, permission_server) = server(vec![
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
    let _ = requests.recv().unwrap();
    let _ = requests.recv().unwrap();
    permission_server.join().unwrap();

    let (failure_base, _failure_requests, failure_server) =
        server(vec![response(400, br#"{"message":"super-secret"}"#)]);
    let failed = HexRegistry::from_config(&custom_config(&failure_base), Some("super-secret"))
        .unwrap()
        .audit_credential()
        .await
        .unwrap_err();
    let message = format!("{failed:#}");
    assert!(!message.contains("super-secret"), "{message}");
    failure_server.join().unwrap();
}

#[tokio::test]
async fn ambiguous_publish_is_reported_without_reposting() {
    let (base, requests, server) = server(vec![Response {
        status: 0,
        headers: vec![],
        body: vec![],
        disconnect: true,
        omit_content_length: false,
    }]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    assert_eq!(
        registry.publish_package(b"one-attempt").await.unwrap(),
        PublishOutcome::Unknown
    );
    assert_eq!(requests.recv().unwrap().body, b"one-attempt");
    assert!(requests.try_recv().is_err());
    server.join().unwrap();
}

#[tokio::test]
async fn get_retries_retry_after_but_refuses_cross_origin_redirects() {
    let redirect = Response {
        status: 302,
        headers: vec![("Location".into(), "http://example.test/stolen".into())],
        body: vec![],
        disconnect: false,
        omit_content_length: false,
    };
    let (base, requests, server) = server(vec![
        Response {
            status: 429,
            headers: vec![("Retry-After".into(), "0".into())],
            body: vec![],
            disconnect: false,
            omit_content_length: false,
        },
        response(200, br#"{"releases":[],"retirements":{}}"#),
        redirect,
    ]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    assert!(registry.package("widget").await.unwrap().is_some());
    let error = registry
        .source_tarball("widget", &Version::new(1, 2, 3))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("cross-origin"));
    let seen: Vec<_> = (0..3).map(|_| requests.recv().unwrap()).collect();
    assert!(
        seen.iter()
            .all(|request| request.authorization.as_deref() == Some("Bearer secret"))
    );
    server.join().unwrap();
}

#[tokio::test]
async fn registry_payloads_are_strictly_typed_and_release_checksums_are_exact() {
    let valid_checksum = "A".repeat(64);
    let (base, _requests, server) = server(vec![
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
    assert!(registry.package("widget").await.is_err());
    assert!(registry.package("widget").await.is_err());
    assert!(registry.release("widget", &version).await.is_err());
    assert!(registry.release("widget", &version).await.is_err());
    assert!(registry.release("widget", &version).await.is_err());
    assert!(registry.release("widget", &version).await.is_err());
    let release = registry.release("widget", &version).await.unwrap().unwrap();
    assert_eq!(
        release.outer_checksum.as_deref(),
        Some("a".repeat(64).as_str())
    );
    assert!(release.has_docs);
    assert!(release.retired);
    let package = registry.package("widget").await.unwrap().unwrap();
    assert!(package.release(&version).unwrap().retired);
    server.join().unwrap();
}

#[tokio::test]
async fn every_retryable_publish_status_is_ambiguous_and_permanent_errors_fail() {
    let (base, requests, server) = server(vec![
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
    let requests: Vec<_> = (0..5).map(|_| requests.recv().unwrap()).collect();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.method == "POST")
            .count(),
        5
    );
    server.join().unwrap();
}

#[tokio::test]
async fn same_origin_redirects_preserve_auth_while_missing_locations_fail_closed() {
    let redirect = |location: Option<&str>| Response {
        status: 302,
        headers: location
            .map(|value| vec![("Location".into(), value.into())])
            .unwrap_or_default(),
        body: vec![],
        disconnect: false,
        omit_content_length: false,
    };
    let (base, requests, server) = server(vec![
        redirect(Some("/api/redirected")),
        response(200, br#"{"releases":[],"retirements":{}}"#),
        redirect(None),
    ]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    assert!(registry.package("widget").await.unwrap().is_some());
    assert!(
        registry
            .package("missing-location")
            .await
            .unwrap_err()
            .to_string()
            .contains("Location")
    );
    let requests: Vec<_> = (0..3).map(|_| requests.recv().unwrap()).collect();
    assert_eq!(requests[0].path, "/api/packages/widget");
    assert_eq!(requests[1].path, "/api/redirected");
    assert!(
        requests
            .iter()
            .all(|request| request.authorization.as_deref() == Some("Bearer secret"))
    );
    server.join().unwrap();
}

#[tokio::test]
async fn get_and_credential_audit_retries_are_bounded_and_never_change_method() {
    let retry = || Response {
        status: 503,
        headers: vec![("Retry-After".into(), "0".into())],
        body: b"busy".to_vec(),
        disconnect: false,
        omit_content_length: false,
    };
    let (get_base, get_requests, get_server) = server(vec![retry(), retry(), retry()]);
    let registry = HexRegistry::from_config(&custom_config(&get_base), Some("secret")).unwrap();
    let error = registry.package("widget").await.unwrap_err().to_string();
    assert!(error.contains("temporarily unavailable"), "{error}");
    let requests: Vec<_> = (0..3)
        .map(|_| {
            get_requests
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap()
        })
        .collect();
    assert!(requests.iter().all(|request| request.method == "GET"));
    get_server.join().unwrap();

    let (audit_base, audit_requests, audit_server) = server(vec![retry(), retry(), retry()]);
    let registry = HexRegistry::from_config(&custom_config(&audit_base), Some("secret")).unwrap();
    let error = registry.audit_credential().await.unwrap_err().to_string();
    assert!(error.contains("temporarily unavailable"), "{error}");
    let requests: Vec<_> = (0..3)
        .map(|_| {
            audit_requests
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap()
        })
        .collect();
    assert!(requests.iter().all(|request| request.method == "GET"));
    audit_server.join().unwrap();
}

#[tokio::test]
async fn transport_failures_and_redirect_loops_exhaust_a_fixed_read_budget() {
    let disconnect = || Response {
        status: 0,
        headers: vec![],
        body: vec![],
        disconnect: true,
        omit_content_length: false,
    };
    let (base, requests, disconnect_server) =
        server(vec![disconnect(), disconnect(), disconnect()]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    assert!(registry.package("widget").await.is_err());
    let requests: Vec<_> = (0..3).map(|_| requests.recv().unwrap()).collect();
    assert!(requests.iter().all(|request| request.method == "GET"));
    disconnect_server.join().unwrap();

    let redirect = || Response {
        status: 302,
        headers: vec![("Location".into(), "/api/loop".into())],
        body: vec![],
        disconnect: false,
        omit_content_length: false,
    };
    let (base, requests, redirect_server) = server((0..6).map(|_| redirect()).collect());
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    let error = registry.package("loop").await.unwrap_err().to_string();
    assert!(error.contains("too many same-origin redirects"), "{error}");
    let requests: Vec<_> = (0..6).map(|_| requests.recv().unwrap()).collect();
    assert_eq!(requests[0].path, "/api/packages/loop");
    assert!(
        requests[1..]
            .iter()
            .all(|request| request.path == "/api/loop")
    );
    redirect_server.join().unwrap();
}

#[tokio::test]
async fn permanent_get_errors_fail_without_retrying_or_leaking_credentials() {
    let (base, requests, server) = server(vec![response(400, br#"{"message":"never-print-me"}"#)]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("never-print-me")).unwrap();
    let error = registry.package("widget").await.unwrap_err().to_string();
    assert!(error.contains("400"), "{error}");
    assert!(!error.contains("never-print-me"), "{error}");
    assert_eq!(requests.recv().unwrap().method, "GET");
    assert!(requests.try_recv().is_err());
    server.join().unwrap();
}

#[tokio::test]
async fn registry_json_downloads_are_bounded_and_an_empty_credential_is_not_sent() {
    let oversized = vec![b'x'; 4 * 1024 * 1024 + 1];
    let (base, requests, server) = server(vec![
        response(200, &oversized),
        response(200, br#"{"releases":[],"retirements":{}}"#),
    ]);
    let with_token = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    assert!(
        with_token
            .package("oversized")
            .await
            .unwrap_err()
            .to_string()
            .contains("download limit")
    );
    let without_token = HexRegistry::from_config(&custom_config(&base), Some("")).unwrap();
    assert!(without_token.package("public").await.unwrap().is_some());
    let oversized_request = requests.recv().unwrap();
    let public_request = requests.recv().unwrap();
    assert_eq!(
        oversized_request.authorization.as_deref(),
        Some("Bearer secret")
    );
    assert!(public_request.authorization.is_none());
    server.join().unwrap();
}

#[tokio::test]
async fn registry_download_limit_accepts_the_exact_boundary_and_counts_streamed_bytes() {
    let exact = vec![b'x'; 4 * 1024 * 1024];
    let streamed_oversized = vec![b'x'; 4 * 1024 * 1024 + 1];
    let (base, requests, server) = server(vec![
        response(200, &exact),
        Response {
            status: 200,
            headers: vec![],
            body: streamed_oversized,
            disconnect: false,
            omit_content_length: true,
        },
    ]);
    let registry = HexRegistry::from_config(&custom_config(&base), None).unwrap();

    let exact_error = registry.package("exact").await.unwrap_err().to_string();
    assert!(
        exact_error.contains("invalid registry package response"),
        "{exact_error}"
    );
    assert!(!exact_error.contains("download limit"), "{exact_error}");

    let oversized_error = registry
        .package("streamed-oversized")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        oversized_error.contains("download limit"),
        "{oversized_error}"
    );
    let requests: Vec<_> = (0..2).map(|_| requests.recv().unwrap()).collect();
    assert_eq!(requests[0].path, "/api/packages/exact");
    assert_eq!(requests[1].path, "/api/packages/streamed-oversized");
    server.join().unwrap();
}

#[tokio::test]
async fn credential_audit_refuses_cross_origin_redirects() {
    let (base, requests, server) = server(vec![Response {
        status: 302,
        headers: vec![("Location".into(), "https://other.example/auth".into())],
        body: vec![],
        disconnect: false,
        omit_content_length: false,
    }]);
    let registry = HexRegistry::from_config(&custom_config(&base), Some("secret")).unwrap();
    let error = registry.audit_credential().await.unwrap_err().to_string();
    assert!(error.contains("cross-origin"), "{error}");
    assert_eq!(
        requests.recv().unwrap().path,
        "/api/auth?domain=api&resource=write"
    );
    server.join().unwrap();
}

#[tokio::test]
async fn wait_for_returns_the_observed_ready_state() {
    let (base, requests, server) = server(vec![response(
        200,
        br#"{"releases":[{"version":"1.2.3","has_docs":true}],"retirements":{}}"#,
    )]);
    let registry = HexRegistry::from_config(&custom_config(&base), None).unwrap();
    let version = Version::new(1, 2, 3);
    let state = registry.wait_for("widget", &version, true).await.unwrap();
    let release = state.release(&version).unwrap();
    assert!(release.has_docs);
    assert_eq!(requests.recv().unwrap().path, "/api/packages/widget");
    server.join().unwrap();
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
        allow_http_loopback: true,
    }
}

fn response(status: u16, body: &[u8]) -> Response {
    Response {
        status,
        headers: vec![],
        body: body.to_vec(),
        disconnect: false,
        omit_content_length: false,
    }
}

fn server(responses: Vec<Response>) -> (String, mpsc::Receiver<Request>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = mpsc::channel();
    let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
    let handle = thread::spawn(move || {
        loop {
            let response = responses.lock().unwrap().pop_front();
            let Some(response) = response else { break };
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            sender.send(request).unwrap();
            if response.disconnect {
                continue;
            }
            let reason = match response.status {
                200 => "OK",
                201 => "Created",
                302 => "Found",
                429 => "Too Many Requests",
                _ => "Error",
            };
            if response.omit_content_length {
                write!(
                    stream,
                    "HTTP/1.1 {} {}\r\nConnection: close\r\n",
                    response.status, reason
                )
                .unwrap();
            } else {
                write!(
                    stream,
                    "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    response.status,
                    reason,
                    response.body.len()
                )
                .unwrap();
            }
            for (name, value) in response.headers {
                write!(stream, "{name}: {value}\r\n").unwrap();
            }
            write!(stream, "\r\n").unwrap();
            // A bounded client may intentionally close as soon as the
            // Content-Length exceeds its limit.
            let _ = stream.write_all(&response.body);
        }
    });
    (format!("http://{address}"), receiver, handle)
}

fn read_request(stream: &mut std::net::TcpStream) -> Request {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end;
    loop {
        let read = stream.read(&mut buffer).unwrap();
        assert!(read > 0);
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = index + 4;
            break;
        }
    }
    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let mut lines = headers.lines();
    let mut request_line = lines.next().unwrap().split_whitespace();
    let method = request_line.next().unwrap().to_owned();
    let path = request_line.next().unwrap().to_owned();
    let mut length = 0_usize;
    let mut authorization = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap();
            }
            if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_owned());
            }
        }
    }
    while bytes.len() < header_end + length {
        let read = stream.read(&mut buffer).unwrap();
        bytes.extend_from_slice(&buffer[..read]);
    }
    Request {
        method,
        path,
        authorization,
        body: bytes[header_end..header_end + length].to_vec(),
    }
}
