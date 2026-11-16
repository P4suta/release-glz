//! Properties of the readers of GitHub Actions OIDC responses and tokens.
//!
//! An input is read as the runner's token response, the issuer's discovery document, the issuer's key set, the claims of a token that the RFC 7515 example key signs, and a compact token.
//! An accepted response reads back from its rendering, and the discovery document names only GitHub's key set URL.
//! A key set verifies a token exactly when one eligible key is the signing key, and a compact token verifies only with the signature that the signing key makes.
//! Accepted claims canonically name the expected run, and every refusal names its typed reason or is a documented error of its response.

use std::sync::OnceLock;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use release_glz::authorization::{
    GITHUB_OIDC_ISSUER, GithubOidcClaims, JwkSet, OidcAudience, OidcExpectation,
    RELEASE_GLZ_AUDIENCE, RsaJwk, VerifiedGithubOidc, parse_discovery, parse_jwks,
    parse_token_response, verify_github_oidc_token,
};
use release_glz::failure::{RefusalReason, refusal_reason};
use ring::rand::SystemRandom;
use ring::rsa::{KeyPairComponents, PublicKeyComponents};
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde_json::json;

/// The RSA example key of RFC 7515, appendix A.2, which `release_glz_test_support::oidc` also signs with.
pub mod rfc7515 {
    pub const KEY_ID: &str = "rfc7515";
    pub const EXPONENT: &str = "AQAB";
    pub const MODULUS: &str = concat!(
        "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx",
        "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs",
        "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH",
        "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV",
        "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8",
        "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
    );
    pub(super) const PRIVATE_EXPONENT: &str = concat!(
        "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I",
        "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0",
        "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn",
        "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT",
        "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh",
        "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"
    );
    pub(super) const PRIME_P: &str = concat!(
        "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi",
        "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG",
        "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc"
    );
    pub(super) const PRIME_Q: &str = concat!(
        "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa",
        "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA",
        "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"
    );
    pub(super) const EXPONENT_P: &str = concat!(
        "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q",
        "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb",
        "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0"
    );
    pub(super) const EXPONENT_Q: &str = concat!(
        "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa",
        "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky",
        "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU"
    );
    pub(super) const INVERSE_Q: &str = concat!(
        "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o",
        "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU",
        "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
    );
}

/// The verifier's clock, in Unix seconds.
pub const NOW: i64 = 1_800_000_000;

const ISSUER_HOST: &str = "token.actions.githubusercontent.com";
const REPOSITORY: &str = "acme/widget";
const ENVIRONMENT: &str = "release";
const WORKFLOW_PATH: &str = ".github/workflows/release-glz.yml";
const SOURCE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const RUN_ID: &str = "4242";
const CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_COMPACT_JWT_BYTES: usize = 32 * 1024;
const MAX_JWT_PART_BYTES: usize = 16 * 1024;

/// A reader that accepted an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reached {
    TokenResponse,
    Discovery,
    KeySet,
    Claims,
    Token,
}

pub fn check(data: &[u8]) -> Vec<Reached> {
    let mut reached = Vec::new();
    for (accepted, reader) in [
        (token_response(data), Reached::TokenResponse),
        (discovery(data), Reached::Discovery),
        (key_set(data), Reached::KeySet),
        (claims(data), Reached::Claims),
        (token(data), Reached::Token),
    ] {
        if accepted {
            reached.push(reader);
        }
    }
    reached
}

/// What the claims of an acceptable token have to name.
pub fn expectation() -> OidcExpectation {
    OidcExpectation {
        repository: REPOSITORY.to_owned(),
        environment: ENVIRONMENT.to_owned(),
        workflow_path: WORKFLOW_PATH.to_owned(),
        source_sha: SOURCE_SHA.to_owned(),
        run_id: Some(RUN_ID.to_owned()),
    }
}

/// The key set that holds only the RFC 7515 key.
pub fn rfc_key_set() -> JwkSet {
    JwkSet {
        keys: vec![RsaJwk {
            key_type: "RSA".to_owned(),
            key_id: Some(rfc7515::KEY_ID.to_owned()),
            algorithm: Some("RS256".to_owned()),
            usage: Some("sig".to_owned()),
            modulus: rfc7515::MODULUS.to_owned(),
            exponent: rfc7515::EXPONENT.to_owned(),
        }],
    }
}

fn key_pair() -> &'static RsaKeyPair {
    static KEY: OnceLock<RsaKeyPair> = OnceLock::new();
    KEY.get_or_init(|| {
        let decode = |value: &str| {
            URL_SAFE_NO_PAD
                .decode(value)
                .expect("the RFC 7515 key is base64url")
        };
        let [n, e, d, p, q, dp, dq, qi] = [
            rfc7515::MODULUS,
            rfc7515::EXPONENT,
            rfc7515::PRIVATE_EXPONENT,
            rfc7515::PRIME_P,
            rfc7515::PRIME_Q,
            rfc7515::EXPONENT_P,
            rfc7515::EXPONENT_Q,
            rfc7515::INVERSE_Q,
        ]
        .map(decode);
        RsaKeyPair::from_components(&KeyPairComponents {
            public_key: PublicKeyComponents { n: &n, e: &e },
            d: &d,
            p: &p,
            q: &q,
            dP: &dp,
            dQ: &dq,
            qInv: &qi,
        })
        .expect("the RFC 7515 key is a valid RSA key")
    })
}

/// The base64url signature that the RFC 7515 key makes over `signing_input`, which PKCS #1 v1.5 makes the same every time.
fn signature_of(signing_input: &str) -> String {
    let key = key_pair();
    let mut signature = vec![0_u8; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        signing_input.as_bytes(),
        &mut signature,
    )
    .expect("RSA signing succeeds");
    URL_SAFE_NO_PAD.encode(signature)
}

/// A compact RS256 token whose payload is `payload`, signed by the RFC 7515 key.
pub fn signed_token(payload: &[u8]) -> String {
    let header =
        URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"RS256","kid":"{}"}}"#, rfc7515::KEY_ID));
    let signing_input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(payload));
    format!("{signing_input}.{}", signature_of(&signing_input))
}

/// Claims that name the expected run and are valid at [`NOW`].
pub fn valid_claims() -> serde_json::Value {
    json!({
        "iss": GITHUB_OIDC_ISSUER,
        "aud": RELEASE_GLZ_AUDIENCE,
        "sub": format!("repo:{REPOSITORY}:environment:{ENVIRONMENT}"),
        "repository": REPOSITORY,
        "environment": ENVIRONMENT,
        "workflow_ref": format!("{REPOSITORY}/{WORKFLOW_PATH}@refs/heads/main"),
        "ref": "refs/heads/main",
        "sha": SOURCE_SHA,
        "run_id": RUN_ID,
        "run_attempt": "1",
        "event_name": "push",
        "iat": NOW - 10,
        "exp": NOW + 300,
    })
}

fn verify(token: &str, keys: &JwkSet) -> anyhow::Result<VerifiedGithubOidc> {
    verify_github_oidc_token(token, keys, &expectation(), NOW)
}

fn assert_documented(error: &anyhow::Error, messages: &[&str]) {
    assert_eq!(refusal_reason(error), None, "{error:#}");
    let message = error.to_string();
    assert!(messages.contains(&message.as_str()), "{error:#}");
}

fn token_response(data: &[u8]) -> bool {
    let token = match parse_token_response(data) {
        Ok(token) => token,
        Err(error) => {
            assert_documented(
                &error,
                &[
                    "GitHub Actions OIDC token response is invalid",
                    "GitHub Actions OIDC token exceeds the size limit",
                ],
            );
            return false;
        }
    };
    assert!(token.len() <= MAX_COMPACT_JWT_BYTES);
    let rendered =
        serde_json::to_vec(&json!({"value": token})).expect("a token response serializes");
    assert_eq!(
        parse_token_response(&rendered).expect("a rendered token response reads back"),
        token
    );
    true
}

fn discovery(data: &[u8]) -> bool {
    let tested = parse_discovery(data, true);
    let url = match parse_discovery(data, false) {
        Ok(url) => url,
        Err(error) => {
            if refusal_reason(&error).is_some() {
                assert_eq!(
                    refusal_reason(&error),
                    Some(RefusalReason::OidcUrlUntrusted),
                    "{error:#}"
                );
            } else {
                assert_documented(
                    &error,
                    &[
                        "GitHub OIDC discovery document is invalid",
                        "GitHub OIDC discovery issuer is not trusted",
                    ],
                );
            }
            if let Ok(url) = tested {
                assert_eq!(url.scheme(), "http", "{url}");
            }
            return false;
        }
    };
    assert_eq!(url.scheme(), "https", "{url}");
    assert_eq!(url.host_str(), Some(ISSUER_HOST), "{url}");
    assert!(url.username().is_empty() && url.password().is_none() && url.fragment().is_none());
    assert_eq!(
        tested
            .expect("allowing loopback HTTP keeps every HTTPS key set URL")
            .as_str(),
        url.as_str()
    );
    let rendered =
        serde_json::to_vec(&json!({"issuer": GITHUB_OIDC_ISSUER, "jwks_uri": url.as_str()}))
            .expect("a discovery document serializes");
    assert_eq!(
        parse_discovery(&rendered, false)
            .expect("a rendered discovery document reads back")
            .as_str(),
        url.as_str()
    );
    true
}

/// The bytes of a base64url value without leading zero bytes, which name the same RSA integer.
fn integer(value: &str) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    Some(bytes.split_at(start).1.to_vec())
}

fn key_set(data: &[u8]) -> bool {
    let keys = match parse_jwks(data) {
        Ok(keys) => keys,
        Err(error) => {
            assert_documented(&error, &["GitHub OIDC JWKS is invalid"]);
            return false;
        }
    };
    let rendered: Vec<_> = keys
        .keys
        .iter()
        .map(|key| {
            json!({
                "kty": key.key_type,
                "kid": key.key_id,
                "alg": key.algorithm,
                "use": key.usage,
                "n": key.modulus,
                "e": key.exponent,
            })
        })
        .collect();
    assert_eq!(
        parse_jwks(&serde_json::to_vec(&json!({"keys": rendered})).expect("a key set serializes"))
            .expect("a rendered key set reads back"),
        keys
    );
    let eligible: Vec<&RsaJwk> = keys
        .keys
        .iter()
        .filter(|key| {
            key.key_type == "RSA"
                && key
                    .algorithm
                    .as_deref()
                    .is_none_or(|algorithm| algorithm == "RS256")
                && key.usage.as_deref().is_none_or(|usage| usage == "sig")
                && key.key_id.as_deref() == Some(rfc7515::KEY_ID)
        })
        .collect();
    let token = signed_token(valid_claims().to_string().as_bytes());
    match verify(&token, &keys) {
        Ok(_) => {
            let [key] = eligible.as_slice() else {
                panic!("a token verified with {} eligible keys", eligible.len());
            };
            assert_eq!(integer(&key.modulus), integer(rfc7515::MODULUS));
            assert_eq!(integer(&key.exponent), integer(rfc7515::EXPONENT));
        }
        Err(error) => {
            assert_eq!(
                refusal_reason(&error),
                Some(RefusalReason::OidcTokenUnverified),
                "{error:#}"
            );
            if let [key] = eligible.as_slice() {
                assert!(
                    key.modulus != rfc7515::MODULUS || key.exponent != rfc7515::EXPONENT,
                    "the signing key failed to verify: {error:#}"
                );
            }
        }
    }
    true
}

fn audience_names_release_glz(audience: &OidcAudience) -> bool {
    match audience {
        OidcAudience::One(audience) => audience == RELEASE_GLZ_AUDIENCE,
        OidcAudience::Many(audiences) => audiences
            .iter()
            .any(|audience| audience == RELEASE_GLZ_AUDIENCE),
    }
}

fn claims(data: &[u8]) -> bool {
    let token = signed_token(data);
    let unsignable = data.is_empty()
        || URL_SAFE_NO_PAD.encode(data).len() > MAX_JWT_PART_BYTES
        || token.len() > MAX_COMPACT_JWT_BYTES;
    let verified = match verify(&token, &rfc_key_set()) {
        Ok(verified) => verified,
        Err(error) => {
            match refusal_reason(&error) {
                Some(RefusalReason::OidcTokenUnverified) => assert!(unsignable, "{error:#}"),
                Some(reason) => assert!(
                    matches!(
                        reason,
                        RefusalReason::OidcClaimsMismatch | RefusalReason::OidcTokenOutsideValidity
                    ),
                    "{error:#}"
                ),
                None => {
                    assert_documented(&error, &["GitHub OIDC JWT claims are invalid"]);
                    assert!(serde_json::from_slice::<GithubOidcClaims>(data).is_err());
                }
            }
            return false;
        }
    };
    let claims: GithubOidcClaims =
        serde_json::from_slice(data).expect("verified claims are the claims JSON");
    assert_canonical(&claims, &verified);
    let resigned = signed_token(&serde_json::to_vec(&claims).expect("claims serialize"));
    assert_eq!(
        verify(&resigned, &rfc_key_set()).expect("re-signed claims verify"),
        verified
    );
    true
}

/// Verified claims name the trusted issuer, the release-glz audience, and exactly the expected run, and are valid now.
fn assert_canonical(claims: &GithubOidcClaims, verified: &VerifiedGithubOidc) {
    assert_eq!(claims.issuer, GITHUB_OIDC_ISSUER);
    assert!(audience_names_release_glz(&claims.audience), "{claims:?}");
    assert_eq!(
        claims.subject,
        format!("repo:{REPOSITORY}:environment:{ENVIRONMENT}")
    );
    assert!(
        claims.git_ref.starts_with("refs/heads/") || claims.git_ref.starts_with("refs/tags/"),
        "{claims:?}"
    );
    assert_eq!(
        claims.workflow_ref,
        format!("{REPOSITORY}/{WORKFLOW_PATH}@{}", claims.git_ref)
    );
    assert!(matches!(
        claims.event_name.as_str(),
        "push" | "workflow_dispatch"
    ));
    assert!(claims.expires_at > NOW);
    assert!(claims.issued_at <= NOW + CLOCK_SKEW_SECONDS);
    assert!(
        claims
            .not_before
            .is_none_or(|not_before| not_before <= NOW + CLOCK_SKEW_SECONDS)
    );
    let attempt: u64 = claims
        .run_attempt
        .parse()
        .expect("a verified run attempt is a number");
    assert!(attempt > 0 && claims.run_attempt.bytes().all(|byte| byte.is_ascii_digit()));
    assert_eq!(verified.repository(), REPOSITORY);
    assert_eq!(Some(verified.environment()), claims.environment.as_deref());
    assert_eq!(verified.environment(), ENVIRONMENT);
    assert_eq!(verified.workflow_ref(), claims.workflow_ref);
    assert_eq!(verified.git_ref(), claims.git_ref);
    assert_eq!(verified.source_sha(), SOURCE_SHA);
    assert_eq!(verified.run_id(), RUN_ID);
    assert_eq!(verified.run_attempt(), attempt);
    assert_eq!(verified.event_name(), claims.event_name);
}

/// Whether `token` is three parts whose last is the signature that the RFC 7515 key makes over the first two.
fn signed_by_the_rfc_key(token: &str) -> bool {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    signature == signature_of(&format!("{header}.{payload}"))
}

fn token(data: &[u8]) -> bool {
    let Ok(token) = std::str::from_utf8(data) else {
        return false;
    };
    match verify(token, &rfc_key_set()) {
        Ok(_) => {
            assert!(
                signed_by_the_rfc_key(token),
                "a token verified without the key's signature"
            );
            true
        }
        Err(error) => {
            if refusal_reason(&error) != Some(RefusalReason::OidcTokenUnverified) {
                assert!(signed_by_the_rfc_key(token), "{error:#}");
            }
            false
        }
    }
}
