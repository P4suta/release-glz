use release_glz::authorization::{
    GithubOidcClaims, GithubOidcVerifier, JwkSet, OidcAudience, OidcExpectation, RsaJwk,
    VerifiedGithubOidc, verify_github_oidc_token,
};
use release_glz::failure::{RefusalReason, refusal_reason};
use release_glz_test_support::http::{FakeServer, Response};
use release_glz_test_support::oidc;

const NOW: i64 = 1_800_000_000;
type ClaimsMutation = Box<dyn Fn(&mut GithubOidcClaims)>;

/// The reason and message of the refusal that verifying `claims` against `expected` ends in.
fn refusal(
    claims: GithubOidcClaims,
    expected: &OidcExpectation,
) -> (Option<RefusalReason>, String) {
    let error = verify(claims, expected).unwrap_err();
    (refusal_reason(&error), error.to_string())
}

/// A claims refusal with `message`.
fn mismatch(message: &str) -> (Option<RefusalReason>, String) {
    (Some(RefusalReason::OidcClaimsMismatch), message.to_owned())
}

fn claims() -> GithubOidcClaims {
    GithubOidcClaims {
        issuer: "https://token.actions.githubusercontent.com".into(),
        audience: OidcAudience::One("release-glz".into()),
        subject: "repo:owner/widget:environment:release".into(),
        repository: "owner/widget".into(),
        environment: Some("release".into()),
        workflow_ref: "owner/widget/.github/workflows/release-glz.yml@refs/heads/main".into(),
        git_ref: "refs/heads/main".into(),
        source_sha: "a".repeat(40),
        run_id: "12345".into(),
        run_attempt: "2".into(),
        event_name: "push".into(),
        issued_at: NOW - 10,
        not_before: Some(NOW - 10),
        expires_at: NOW + 300,
    }
}

fn expectation() -> OidcExpectation {
    OidcExpectation {
        repository: "owner/widget".into(),
        environment: "release".into(),
        workflow_path: ".github/workflows/release-glz.yml".into(),
        source_sha: "a".repeat(40),
        run_id: Some("12345".into()),
    }
}

/// Sign `claims` and verify the token against `expected`, the only way to a verified identity.
fn verify(
    claims: GithubOidcClaims,
    expected: &OidcExpectation,
) -> anyhow::Result<VerifiedGithubOidc> {
    let (token, key) = sign_claims(&claims);
    verify_github_oidc_token(&token, &JwkSet { keys: vec![key] }, expected, NOW)
}

#[test]
fn exact_github_environment_identity_is_accepted() {
    let verified = verify(claims(), &expectation()).unwrap();
    assert_eq!(verified.repository(), "owner/widget");
    assert_eq!(verified.environment(), "release");
    assert_eq!(verified.run_id(), "12345");
    assert_eq!(verified.git_ref(), "refs/heads/main");
    assert_eq!(verified.source_sha(), "a".repeat(40));
    assert_eq!(verified.run_attempt(), 2);
    assert_eq!(verified.event_name(), "push");
}

#[test]
fn every_security_boundary_is_fail_closed() {
    let outside_validity = |message: &str| {
        (
            Some(RefusalReason::OidcTokenOutsideValidity),
            message.to_owned(),
        )
    };
    let mutations: Vec<(ClaimsMutation, (Option<RefusalReason>, String))> = vec![
        (
            Box::new(|claims| claims.issuer = "https://attacker.invalid".into()),
            mismatch("GitHub OIDC issuer is not trusted"),
        ),
        (
            Box::new(|claims| claims.audience = OidcAudience::One("other".into())),
            mismatch("GitHub OIDC audience is not release-glz"),
        ),
        (
            Box::new(|claims| claims.subject = "repo:owner/widget:ref:refs/heads/main".into()),
            mismatch("GitHub OIDC subject is not the approved Environment"),
        ),
        (
            Box::new(|claims| claims.repository = "fork/widget".into()),
            mismatch("GitHub OIDC repository does not match the sealed Candidate"),
        ),
        (
            Box::new(|claims| claims.environment = Some("staging".into())),
            mismatch("GitHub OIDC environment does not match the sealed Candidate"),
        ),
        (
            Box::new(|claims| {
                claims.workflow_ref =
                    "owner/widget/.github/workflows/other.yml@refs/heads/main".into()
            }),
            mismatch("GitHub OIDC workflow is not the managed release workflow"),
        ),
        (
            Box::new(|claims| claims.git_ref = "refs/pull/1/merge".into()),
            mismatch("GitHub OIDC ref is not an allowed full branch or tag ref"),
        ),
        (
            Box::new(|claims| claims.source_sha = "b".repeat(40)),
            mismatch("GitHub OIDC source SHA does not match the sealed Candidate"),
        ),
        (
            Box::new(|claims| claims.run_id = "999".into()),
            mismatch("GitHub OIDC run ID does not match the publishing run"),
        ),
        (
            Box::new(|claims| claims.run_attempt = "0".into()),
            mismatch("GitHub OIDC run attempt is invalid"),
        ),
        (
            Box::new(|claims| claims.event_name = "pull_request".into()),
            mismatch("GitHub OIDC event is not an authorized release trigger"),
        ),
        (
            Box::new(|claims| claims.expires_at = NOW),
            outside_validity("GitHub OIDC token has expired"),
        ),
        (
            Box::new(|claims| claims.issued_at = NOW + 31),
            outside_validity("GitHub OIDC token was issued in the future"),
        ),
        (
            Box::new(|claims| claims.not_before = Some(NOW + 31)),
            outside_validity("GitHub OIDC token is not valid yet"),
        ),
    ];

    for (mutate, expected) in mutations {
        let mut candidate = claims();
        mutate(&mut candidate);
        assert_eq!(refusal(candidate, &expectation()), expected);
    }
}

/// The fail-closed test refuses a token issued or starting 31 seconds ahead, so together they pin the 30-second clock skew.
#[test]
fn a_token_may_be_issued_or_start_exactly_the_clock_skew_ahead() {
    let mut candidate = claims();
    candidate.issued_at = NOW + 30;
    candidate.not_before = Some(NOW + 30);
    verify(candidate, &expectation()).unwrap();
}

/// A runner token URL has to name `actions.githubusercontent.com` or a host that a dot separates from it.
#[tokio::test]
async fn a_runner_token_url_outside_githubs_zone_is_refused_before_any_request() {
    let verifier = GithubOidcVerifier::github().unwrap();
    for url in [
        "https://evilactions.githubusercontent.com/token",
        "https://actions.githubusercontent.com.evil.example/token",
        "https://evil.example/token",
    ] {
        let error = verifier
            .verify_actions_token(url, "request-token", &expectation(), NOW)
            .await
            .unwrap_err();
        assert_eq!(
            (refusal_reason(&error), error.to_string()),
            (
                Some(RefusalReason::OidcUrlUntrusted),
                "GitHub OIDC URL origin is not trusted".to_owned()
            ),
            "{url}"
        );
    }
}

#[test]
fn audience_arrays_are_supported_but_must_contain_release_glz() {
    let mut candidate = claims();
    candidate.audience = OidcAudience::Many(vec!["other".into(), "release-glz".into()]);
    verify(candidate, &expectation()).unwrap();

    let mut candidate = claims();
    candidate.audience = OidcAudience::Many(vec!["other".into()]);
    assert_eq!(
        refusal(candidate, &expectation()),
        mismatch("GitHub OIDC audience is not release-glz")
    );
}

#[test]
fn optional_and_alternate_valid_github_claim_forms_are_explicit() {
    let mut expected = expectation();
    expected.run_id = None;
    let mut candidate = claims();
    candidate.git_ref = "refs/tags/v1.2.3".into();
    candidate.workflow_ref =
        "owner/widget/.github/workflows/release-glz.yml@refs/tags/v1.2.3".into();
    candidate.run_id = "000123".into();
    candidate.run_attempt = "1".into();
    candidate.event_name = "workflow_dispatch".into();
    candidate.not_before = None;
    let verified = verify(candidate, &expected).unwrap();
    assert_eq!(verified.git_ref(), "refs/tags/v1.2.3");
    assert_eq!(verified.run_attempt(), 1);
    assert_eq!(verified.event_name(), "workflow_dispatch");
}

#[test]
fn claim_values_that_match_textually_still_require_canonical_safe_shapes() {
    let invalid_run_id = "GitHub OIDC run ID is invalid";
    let invalid_attempt = "GitHub OIDC run attempt is invalid";
    for (case, message) in [
        (
            "unsafe-full-ref",
            "GitHub OIDC ref is not an allowed full branch or tag ref",
        ),
        (
            "invalid-sha-format",
            "GitHub OIDC source SHA does not match the sealed Candidate",
        ),
        (
            "sha256-sha",
            "GitHub OIDC source SHA does not match the sealed Candidate",
        ),
        ("empty-run-id", invalid_run_id),
        ("nondigit-run-id", invalid_run_id),
        ("invalid-attempt", invalid_attempt),
        ("overflow-attempt", invalid_attempt),
        ("signed-attempt", invalid_attempt),
    ] {
        let mut expected = expectation();
        let mut candidate = claims();
        match case {
            "unsafe-full-ref" => {
                candidate.git_ref = "refs/heads/main.lock".into();
                candidate.workflow_ref =
                    "owner/widget/.github/workflows/release-glz.yml@refs/heads/main.lock".into();
            }
            "invalid-sha-format" => {
                candidate.source_sha = "A".repeat(40);
                expected.source_sha = candidate.source_sha.clone();
            }
            "sha256-sha" => {
                candidate.source_sha = "a".repeat(64);
                expected.source_sha = candidate.source_sha.clone();
            }
            "empty-run-id" => {
                candidate.run_id.clear();
                expected.run_id = Some(String::new());
            }
            "nondigit-run-id" => {
                candidate.run_id = "12a".into();
                expected.run_id = Some(candidate.run_id.clone());
            }
            "invalid-attempt" => candidate.run_attempt = "not-a-number".into(),
            "overflow-attempt" => candidate.run_attempt = "18446744073709551616".into(),
            "signed-attempt" => candidate.run_attempt = "+3".into(),
            _ => unreachable!(),
        }
        assert_eq!(refusal(candidate, &expected), mismatch(message), "{case}");
    }
}

#[test]
fn signed_compact_token_is_verified_before_github_claims_are_returned() {
    let (token, key) = sign_claims(&claims());
    let verified =
        verify_github_oidc_token(&token, &JwkSet { keys: vec![key] }, &expectation(), NOW).unwrap();
    assert_eq!(verified.workflow_ref(), claims().workflow_ref);

    let mut tampered = token;
    let payload_start = tampered.find('.').unwrap() + 1;
    tampered.replace_range(payload_start..payload_start + 1, "A");
    let error = verify_github_oidc_token(
        &tampered,
        &JwkSet {
            keys: vec![public_jwk()],
        },
        &expectation(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(
        (refusal_reason(&error), error.to_string()),
        (
            Some(RefusalReason::OidcTokenUnverified),
            "GitHub OIDC JWT signature is invalid".to_owned()
        )
    );
}

#[tokio::test]
async fn actions_token_discovery_and_jwks_are_fetched_under_fixed_policy() {
    let (token, key) = sign_claims(&claims());
    let server = OidcServer::start(token, key);
    let verifier =
        GithubOidcVerifier::new(&format!("{}/discovery", server.base_url()), true).unwrap();
    let verified = verifier
        .verify_actions_token(
            &format!("{}/token?runner=1", server.base_url()),
            "runner-secret",
            &expectation(),
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(verified.run_id(), "12345");

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("get /token?runner=1&audience=release-glz "));
    assert!(requests[0].contains("authorization: bearer runner-secret"));
    assert!(requests[1].starts_with("get /discovery "));
    assert!(requests[2].starts_with("get /jwks "));
    assert!(!requests[1].contains("runner-secret"));
    assert!(!requests[2].contains("runner-secret"));
}

/// Each OIDC request in the order the verifier sends it, with the description that its refusal names.
const OIDC_REQUESTS: [(&str, &str); 3] = [
    ("/token?audience=release-glz", "GitHub Actions OIDC token"),
    ("/discovery", "GitHub OIDC discovery"),
    ("/jwks", "GitHub OIDC JWKS"),
];

/// An OIDC request refuses every redirect, so neither the runner's request token nor a key request reaches the `Location` origin.
#[tokio::test]
async fn each_oidc_request_refuses_each_redirect_and_sends_nothing_to_its_location() {
    for (redirected, (_, description)) in OIDC_REQUESTS.into_iter().enumerate() {
        for (status, phrase) in [
            (301, "301 Moved Permanently"),
            (302, "302 Found"),
            (307, "307 Temporary Redirect"),
            (308, "308 Permanent Redirect"),
        ] {
            let case = format!("{description} answered with {status}");
            let mut server = FakeServer::start();
            let mut elsewhere = FakeServer::start();
            let location = format!(
                "http://user:runner-secret@{}/runner-secret?token=runner-secret#runner-secret",
                elsewhere.address()
            );
            let earlier = [
                json_reply(&serde_json::json!({"value": "header.payload.signature"})),
                json_reply(&serde_json::json!({
                    "issuer": "https://token.actions.githubusercontent.com",
                    "jwks_uri": format!("{}/jwks", server.base_url())
                })),
            ];
            server.script(
                earlier
                    .into_iter()
                    .take(redirected)
                    .chain([Response::new(status).header("Location", &location)]),
            );
            let verifier =
                GithubOidcVerifier::new(&format!("{}/discovery", server.base_url()), true).unwrap();

            let error = verifier
                .verify_actions_token(
                    &format!("{}/token", server.base_url()),
                    "runner-secret",
                    &expectation(),
                    NOW,
                )
                .await
                .unwrap_err();

            assert_eq!(
                (refusal_reason(&error), error.to_string()),
                (
                    Some(RefusalReason::OidcRedirectRefused),
                    format!(
                        "refusing {description} redirect {phrase} to {}",
                        elsewhere.base_url()
                    )
                ),
                "{case}"
            );
            let targets = server
                .finish()
                .into_iter()
                .map(|request| request.target)
                .collect::<Vec<_>>();
            let expected = OIDC_REQUESTS[..=redirected]
                .iter()
                .map(|(target, _)| *target)
                .collect::<Vec<_>>();
            assert_eq!(targets, expected, "{case}");
            assert_eq!(elsewhere.finish(), [], "{case}");
            assert_eq!(elsewhere.connections(), 0, "{case}");
        }
    }
}

/// A JSON response with `value` as its body.
fn json_reply(value: &serde_json::Value) -> Response {
    Response::new(200)
        .header("Content-Type", "application/json")
        .body(value.to_string())
}

struct OidcServer {
    server: FakeServer,
}

impl OidcServer {
    fn start(token: String, key: RsaJwk) -> Self {
        let server = FakeServer::start();
        let address = server.address();
        server.route(move |request| {
            let path = request.target.as_str();
            let body = if path.starts_with("/token?") {
                serde_json::json!({"value": token}).to_string()
            } else if path == "/discovery" {
                serde_json::json!({
                    "issuer": "https://token.actions.githubusercontent.com",
                    "jwks_uri": format!("http://{address}/jwks")
                })
                .to_string()
            } else {
                serde_json::json!({
                    "keys": [{
                        "kty": key.key_type,
                        "kid": key.key_id,
                        "alg": key.algorithm,
                        "use": key.usage,
                        "n": key.modulus,
                        "e": key.exponent
                    }]
                })
                .to_string()
            };
            Response::new(200)
                .header("Content-Type", "application/json")
                .body(body)
                .into()
        });
        Self { server }
    }

    fn base_url(&self) -> String {
        self.server.base_url()
    }

    /// Each request as it arrived, in lowercase.
    fn requests(&self) -> Vec<String> {
        self.server
            .requests()
            .iter()
            .map(|request| request.text().to_ascii_lowercase())
            .collect()
    }
}

fn sign_claims(claims: &GithubOidcClaims) -> (String, RsaJwk) {
    (oidc::sign_rs256(claims), public_jwk())
}

fn public_jwk() -> RsaJwk {
    RsaJwk {
        key_type: "RSA".into(),
        key_id: Some(oidc::KEY_ID.into()),
        algorithm: Some("RS256".into()),
        usage: Some("sig".into()),
        modulus: oidc::MODULUS.into(),
        exponent: oidc::EXPONENT.into(),
    }
}
