use base64::Engine;
use release_glz::authorization::{
    GithubOidcClaims, GithubOidcVerifier, JwkSet, OidcAudience, OidcExpectation, RsaJwk,
    validate_github_claims, verify_github_oidc_token,
};
use ring::rand::SystemRandom;
use ring::rsa::{KeyPairComponents, PublicKeyComponents};
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const NOW: i64 = 1_800_000_000;
type ClaimsMutation = Box<dyn Fn(&mut GithubOidcClaims)>;

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

#[test]
fn exact_github_environment_identity_is_accepted() {
    let verified = validate_github_claims(claims(), &expectation(), NOW).unwrap();
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
    let mutations: Vec<ClaimsMutation> = vec![
        Box::new(|claims| claims.issuer = "https://attacker.invalid".into()),
        Box::new(|claims| claims.audience = OidcAudience::One("other".into())),
        Box::new(|claims| claims.subject = "repo:owner/widget:ref:refs/heads/main".into()),
        Box::new(|claims| claims.repository = "fork/widget".into()),
        Box::new(|claims| claims.environment = Some("staging".into())),
        Box::new(|claims| {
            claims.workflow_ref = "owner/widget/.github/workflows/other.yml@refs/heads/main".into()
        }),
        Box::new(|claims| claims.git_ref = "refs/pull/1/merge".into()),
        Box::new(|claims| claims.source_sha = "b".repeat(40)),
        Box::new(|claims| claims.run_id = "999".into()),
        Box::new(|claims| claims.run_attempt = "0".into()),
        Box::new(|claims| claims.event_name = "pull_request".into()),
        Box::new(|claims| claims.expires_at = NOW),
        Box::new(|claims| claims.issued_at = NOW + 31),
        Box::new(|claims| claims.not_before = Some(NOW + 31)),
    ];

    for mutate in mutations {
        let mut candidate = claims();
        mutate(&mut candidate);
        assert!(validate_github_claims(candidate, &expectation(), NOW).is_err());
    }
}

#[test]
fn audience_arrays_are_supported_but_must_contain_release_glz() {
    let mut candidate = claims();
    candidate.audience = OidcAudience::Many(vec!["other".into(), "release-glz".into()]);
    validate_github_claims(candidate, &expectation(), NOW).unwrap();

    let mut candidate = claims();
    candidate.audience = OidcAudience::Many(vec!["other".into()]);
    assert!(validate_github_claims(candidate, &expectation(), NOW).is_err());
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
    let verified = validate_github_claims(candidate, &expected, NOW).unwrap();
    assert_eq!(verified.git_ref(), "refs/tags/v1.2.3");
    assert_eq!(verified.run_attempt(), 1);
    assert_eq!(verified.event_name(), "workflow_dispatch");
}

#[test]
fn claim_values_that_match_textually_still_require_canonical_safe_shapes() {
    for case in [
        "unsafe-full-ref",
        "invalid-sha-format",
        "empty-run-id",
        "nondigit-run-id",
        "invalid-attempt",
        "overflow-attempt",
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
            _ => unreachable!(),
        }
        assert!(
            validate_github_claims(candidate, &expected, NOW).is_err(),
            "accepted malformed matching claim {case}"
        );
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
    assert!(
        verify_github_oidc_token(
            &tampered,
            &JwkSet {
                keys: vec![public_jwk()]
            },
            &expectation(),
            NOW,
        )
        .is_err()
    );
}

#[tokio::test]
async fn actions_token_discovery_and_jwks_are_fetched_under_fixed_policy() {
    let (token, key) = sign_claims(&claims());
    let server = OidcServer::start(token, key).await;
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

struct OidcServer {
    address: std::net::SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
}

impl OidcServer {
    async fn start(token: String, key: RsaJwk) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let read = stream.read(&mut buffer).await.unwrap();
                    request.extend_from_slice(&buffer[..read]);
                    if read == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8_lossy(&request).into_owned();
                let request_lower = request.to_ascii_lowercase();
                captured.lock().unwrap().push(request_lower);
                let path = request.split_whitespace().nth(1).unwrap();
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
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
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

fn sign_claims(claims: &GithubOidcClaims) -> (String, RsaJwk) {
    let decode = |value: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .unwrap()
    };
    let n = decode(MODULUS);
    let e = decode("AQAB");
    let d = decode(PRIVATE_EXPONENT);
    let p = decode(PRIME_P);
    let q = decode(PRIME_Q);
    let dp = decode(EXPONENT_P);
    let dq = decode(EXPONENT_Q);
    let inverse_q = decode(INVERSE_Q);
    let key = RsaKeyPair::from_components(&KeyPairComponents {
        public_key: PublicKeyComponents { n: &n, e: &e },
        d: &d,
        p: &p,
        q: &q,
        dP: &dp,
        dQ: &dq,
        qInv: &inverse_q,
    })
    .unwrap();
    let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = encoder.encode(br#"{"alg":"RS256","kid":"rfc7515"}"#);
    let payload = encoder.encode(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{header}.{payload}");
    let mut signature = vec![0_u8; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        signing_input.as_bytes(),
        &mut signature,
    )
    .unwrap();
    (
        format!("{signing_input}.{}", encoder.encode(signature)),
        public_jwk(),
    )
}

fn public_jwk() -> RsaJwk {
    RsaJwk {
        key_type: "RSA".into(),
        key_id: Some("rfc7515".into()),
        algorithm: Some("RS256".into()),
        usage: Some("sig".into()),
        modulus: MODULUS.into(),
        exponent: "AQAB".into(),
    }
}

const MODULUS: &str = concat!(
    "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx",
    "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs",
    "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH",
    "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV",
    "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8",
    "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
);
const PRIVATE_EXPONENT: &str = concat!(
    "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I",
    "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0",
    "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn",
    "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT",
    "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh",
    "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"
);
const PRIME_P: &str = concat!(
    "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi",
    "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG",
    "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"
);
const PRIME_Q: &str = concat!(
    "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa",
    "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA",
    "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"
);
const EXPONENT_P: &str = concat!(
    "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q",
    "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb",
    "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"
);
const EXPONENT_Q: &str = concat!(
    "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa",
    "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky",
    "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"
);
const INVERSE_Q: &str = concat!(
    "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o",
    "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU",
    "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
);
