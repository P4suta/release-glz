use anyhow::{Result, bail};
use base64::Engine;
use reqwest::{Client, StatusCode, Url};
use ring::signature;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::config::host_is_loopback_ip;

pub const GITHUB_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
pub const RELEASE_GLZ_AUDIENCE: &str = "release-glz";
const CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_COMPACT_JWT_BYTES: usize = 32 * 1024;
const MAX_JWT_PART_BYTES: usize = 16 * 1024;
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_DISCOVERY_BYTES: usize = 64 * 1024;
const MAX_JWKS_BYTES: usize = 1024 * 1024;
const GITHUB_DISCOVERY_URL: &str =
    "https://token.actions.githubusercontent.com/.well-known/openid-configuration";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<RsaJwk>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RsaJwk {
    #[serde(rename = "kty")]
    pub key_type: String,
    #[serde(rename = "kid", default)]
    pub key_id: Option<String>,
    #[serde(rename = "alg", default)]
    pub algorithm: Option<String>,
    #[serde(rename = "use", default)]
    pub usage: Option<String>,
    #[serde(rename = "n")]
    pub modulus: String,
    #[serde(rename = "e")]
    pub exponent: String,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    crit: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ActionsTokenResponse {
    value: String,
}

#[derive(Debug, Deserialize)]
struct OpenIdConfiguration {
    issuer: String,
    jwks_uri: String,
}

#[derive(Debug)]
pub struct GithubOidcVerifier {
    client: Client,
    discovery_url: Url,
    allow_http_loopback: bool,
}

impl GithubOidcVerifier {
    pub fn github() -> Result<Self> {
        Self::new(GITHUB_DISCOVERY_URL, false)
    }

    pub fn new(discovery_url: &str, allow_http_loopback: bool) -> Result<Self> {
        let discovery_url =
            validate_oidc_url(discovery_url, allow_http_loopback, OidcUrlKind::Discovery)?;
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            discovery_url,
            allow_http_loopback,
        })
    }

    pub async fn verify_actions_token(
        &self,
        request_url: &str,
        request_token: &str,
        expected: &OidcExpectation,
        now_unix_seconds: i64,
    ) -> Result<VerifiedGithubOidc> {
        if request_token.is_empty() || request_token.len() > 16 * 1024 {
            bail!("GitHub Actions OIDC request token is missing or invalid");
        }
        let mut request_url = validate_oidc_url(
            request_url,
            self.allow_http_loopback,
            OidcUrlKind::RunnerToken,
        )?;
        request_url
            .query_pairs_mut()
            .append_pair("audience", RELEASE_GLZ_AUDIENCE);
        let token_response = self
            .client
            .get(request_url)
            .bearer_auth(request_token)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("GitHub Actions OIDC token request failed"))?;
        let token_response = checked_body(
            token_response,
            MAX_TOKEN_RESPONSE_BYTES,
            "GitHub Actions OIDC token",
        )
        .await?;
        let token_response: ActionsTokenResponse = serde_json::from_slice(&token_response)
            .map_err(|_| anyhow::anyhow!("GitHub Actions OIDC token response is invalid"))?;
        if token_response.value.len() > MAX_COMPACT_JWT_BYTES {
            bail!("GitHub Actions OIDC token exceeds the size limit");
        }

        let discovery = self
            .client
            .get(self.discovery_url.clone())
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("GitHub OIDC discovery request failed"))?;
        let discovery =
            checked_body(discovery, MAX_DISCOVERY_BYTES, "GitHub OIDC discovery").await?;
        let discovery: OpenIdConfiguration = serde_json::from_slice(&discovery)
            .map_err(|_| anyhow::anyhow!("GitHub OIDC discovery document is invalid"))?;
        if discovery.issuer != GITHUB_OIDC_ISSUER {
            bail!("GitHub OIDC discovery issuer is not trusted");
        }
        let jwks_url = validate_oidc_url(
            &discovery.jwks_uri,
            self.allow_http_loopback,
            OidcUrlKind::Jwks,
        )?;
        if self.allow_http_loopback
            && self.discovery_url.scheme() == "http"
            && jwks_url.origin() != self.discovery_url.origin()
        {
            bail!("test OIDC discovery and JWKS must use the same loopback origin");
        }
        let keys = self
            .client
            .get(jwks_url)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("GitHub OIDC JWKS request failed"))?;
        let keys = checked_body(keys, MAX_JWKS_BYTES, "GitHub OIDC JWKS").await?;
        let keys: JwkSet = serde_json::from_slice(&keys)
            .map_err(|_| anyhow::anyhow!("GitHub OIDC JWKS is invalid"))?;
        verify_github_oidc_token(&token_response.value, &keys, expected, now_unix_seconds)
    }
}

#[derive(Clone, Copy)]
enum OidcUrlKind {
    Discovery,
    RunnerToken,
    Jwks,
}

fn validate_oidc_url(raw: &str, allow_http_loopback: bool, kind: OidcUrlKind) -> Result<Url> {
    let url = Url::parse(raw).map_err(|_| anyhow::anyhow!("GitHub OIDC URL is invalid"))?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        bail!("GitHub OIDC URL contains forbidden credentials or fragments");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("GitHub OIDC URL has no host"))?;
    let loopback = url.scheme() == "http" && host_is_loopback_ip(host);
    if allow_http_loopback && loopback {
        return Ok(url);
    }
    if url.scheme() != "https" {
        bail!("GitHub OIDC URLs must use HTTPS");
    }
    let trusted = match kind {
        OidcUrlKind::Discovery | OidcUrlKind::Jwks => {
            host.eq_ignore_ascii_case("token.actions.githubusercontent.com")
        }
        OidcUrlKind::RunnerToken => {
            host.eq_ignore_ascii_case("actions.githubusercontent.com")
                || host
                    .to_ascii_lowercase()
                    .ends_with(".actions.githubusercontent.com")
        }
    };
    if !trusted {
        bail!("GitHub OIDC URL origin is not trusted");
    }
    Ok(url)
}

async fn checked_body(
    mut response: reqwest::Response,
    maximum: usize,
    description: &str,
) -> Result<Vec<u8>> {
    if response.status() != StatusCode::OK {
        bail!(
            "{description} request failed with HTTP {}",
            response.status()
        );
    }
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        bail!("{description} response exceeds the size limit");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("{description} response was truncated"))?
    {
        if body.len().saturating_add(chunk.len()) > maximum {
            bail!("{description} response exceeds the size limit");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OidcAudience {
    One(String),
    Many(Vec<String>),
}

impl OidcAudience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}

/// Claims emitted by GitHub Actions after the compact JWT signature has been
/// verified against GitHub's OpenID key set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubOidcClaims {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "aud")]
    pub audience: OidcAudience,
    #[serde(rename = "sub")]
    pub subject: String,
    pub repository: String,
    #[serde(default)]
    pub environment: Option<String>,
    pub workflow_ref: String,
    #[serde(rename = "ref")]
    pub git_ref: String,
    #[serde(rename = "sha")]
    pub source_sha: String,
    pub run_id: String,
    pub run_attempt: String,
    pub event_name: String,
    #[serde(rename = "iat")]
    pub issued_at: i64,
    #[serde(rename = "nbf", default)]
    pub not_before: Option<i64>,
    #[serde(rename = "exp")]
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcExpectation {
    pub repository: String,
    pub environment: String,
    pub workflow_path: String,
    pub source_sha: String,
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGithubOidc {
    repository: String,
    environment: String,
    workflow_ref: String,
    git_ref: String,
    source_sha: String,
    run_id: String,
    run_attempt: u64,
    event_name: String,
}

impl VerifiedGithubOidc {
    pub fn repository(&self) -> &str {
        &self.repository
    }

    pub fn environment(&self) -> &str {
        &self.environment
    }

    pub fn workflow_ref(&self) -> &str {
        &self.workflow_ref
    }

    pub fn git_ref(&self) -> &str {
        &self.git_ref
    }

    pub fn source_sha(&self) -> &str {
        &self.source_sha
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn run_attempt(&self) -> u64 {
        self.run_attempt
    }

    pub fn event_name(&self) -> &str {
        &self.event_name
    }
}

pub fn validate_github_claims(
    claims: GithubOidcClaims,
    expected: &OidcExpectation,
    now_unix_seconds: i64,
) -> Result<VerifiedGithubOidc> {
    if claims.issuer != GITHUB_OIDC_ISSUER {
        bail!("GitHub OIDC issuer is not trusted");
    }
    if !claims.audience.contains(RELEASE_GLZ_AUDIENCE) {
        bail!("GitHub OIDC audience is not release-glz");
    }
    if claims.repository != expected.repository {
        bail!("GitHub OIDC repository does not match the sealed Candidate");
    }
    if claims.environment.as_deref() != Some(expected.environment.as_str()) {
        bail!("GitHub OIDC environment does not match the sealed Candidate");
    }
    let expected_subject = format!(
        "repo:{}:environment:{}",
        expected.repository, expected.environment
    );
    if claims.subject != expected_subject {
        bail!("GitHub OIDC subject is not the approved Environment");
    }
    let workflow_prefix = format!("{}/{}@", expected.repository, expected.workflow_path);
    if !(claims.git_ref.starts_with("refs/heads/") || claims.git_ref.starts_with("refs/tags/"))
        || crate::config::validate_git_ref(&claims.git_ref, "GitHub OIDC ref").is_err()
    {
        bail!("GitHub OIDC ref is not an allowed full branch or tag ref");
    }
    if claims.workflow_ref != format!("{workflow_prefix}{}", claims.git_ref) {
        bail!("GitHub OIDC workflow is not the managed release workflow");
    }
    if claims.source_sha != expected.source_sha || !is_full_sha(&claims.source_sha) {
        bail!("GitHub OIDC source SHA does not match the sealed Candidate");
    }
    if claims.run_id.is_empty() || !claims.run_id.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("GitHub OIDC run ID is invalid");
    }
    if let Some(expected_run) = &expected.run_id
        && &claims.run_id != expected_run
    {
        bail!("GitHub OIDC run ID does not match the publishing run");
    }
    let run_attempt = claims
        .run_attempt
        .parse::<u64>()
        .ok()
        .filter(|attempt| *attempt > 0)
        .ok_or_else(|| anyhow::anyhow!("GitHub OIDC run attempt is invalid"))?;
    if !matches!(claims.event_name.as_str(), "push" | "workflow_dispatch") {
        bail!("GitHub OIDC event is not an authorized release trigger");
    }
    if claims.expires_at <= now_unix_seconds {
        bail!("GitHub OIDC token has expired");
    }
    if claims.issued_at > now_unix_seconds.saturating_add(CLOCK_SKEW_SECONDS) {
        bail!("GitHub OIDC token was issued in the future");
    }
    if claims
        .not_before
        .is_some_and(|not_before| not_before > now_unix_seconds.saturating_add(CLOCK_SKEW_SECONDS))
    {
        bail!("GitHub OIDC token is not valid yet");
    }

    Ok(VerifiedGithubOidc {
        repository: claims.repository,
        environment: claims.environment.expect("validated environment"),
        workflow_ref: claims.workflow_ref,
        git_ref: claims.git_ref,
        source_sha: claims.source_sha,
        run_id: claims.run_id,
        run_attempt,
        event_name: claims.event_name,
    })
}

pub fn verify_github_oidc_token(
    token: &str,
    keys: &JwkSet,
    expected: &OidcExpectation,
    now_unix_seconds: i64,
) -> Result<VerifiedGithubOidc> {
    let payload = verify_compact_rs256(token, keys)?;
    let claims: GithubOidcClaims = serde_json::from_slice(&payload)
        .map_err(|_| anyhow::anyhow!("GitHub OIDC JWT claims are invalid"))?;
    validate_github_claims(claims, expected, now_unix_seconds)
}

fn is_full_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn verify_rs256_signature(
    signing_input: &[u8],
    signature_base64: &str,
    modulus_base64: &str,
    exponent_base64: &str,
) -> Result<()> {
    let decoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let signature = decoder
        .decode(signature_base64)
        .map_err(|_| anyhow::anyhow!("OIDC JWT signature is not valid base64url"))?;
    let modulus = decoder
        .decode(modulus_base64)
        .map_err(|_| anyhow::anyhow!("OIDC JWK modulus is not valid base64url"))?;
    let exponent = decoder
        .decode(exponent_base64)
        .map_err(|_| anyhow::anyhow!("OIDC JWK exponent is not valid base64url"))?;
    signature::RsaPublicKeyComponents {
        n: &modulus,
        e: &exponent,
    }
    .verify(
        &signature::RSA_PKCS1_2048_8192_SHA256,
        signing_input,
        &signature,
    )
    .map_err(|_| anyhow::anyhow!("GitHub OIDC JWT signature is invalid"))
}

fn verify_compact_rs256(token: &str, keys: &JwkSet) -> Result<Vec<u8>> {
    if token.len() > MAX_COMPACT_JWT_BYTES {
        bail!("GitHub OIDC JWT exceeds the size limit");
    }
    let mut parts = token.split('.');
    let header_part = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| anyhow::anyhow!("GitHub OIDC JWT has no protected header"))?;
    let payload_part = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| anyhow::anyhow!("GitHub OIDC JWT has no payload"))?;
    let signature_part = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(|| anyhow::anyhow!("GitHub OIDC JWT has no signature"))?;
    if parts.next().is_some()
        || header_part.len() > MAX_JWT_PART_BYTES
        || payload_part.len() > MAX_JWT_PART_BYTES
        || signature_part.len() > MAX_JWT_PART_BYTES
    {
        bail!("GitHub OIDC JWT compact serialization is invalid");
    }

    let decoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_bytes = decoder
        .decode(header_part)
        .map_err(|_| anyhow::anyhow!("GitHub OIDC JWT header is not valid base64url"))?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| anyhow::anyhow!("GitHub OIDC JWT header is invalid"))?;
    if header.alg != "RS256" {
        bail!("GitHub OIDC JWT must use RS256");
    }
    if header
        .crit
        .as_ref()
        .is_some_and(|values| !values.is_empty())
    {
        bail!("GitHub OIDC JWT uses unsupported critical headers");
    }

    let matching = keys
        .keys
        .iter()
        .filter(|key| {
            key.key_type == "RSA"
                && key.algorithm.as_deref().is_none_or(|alg| alg == "RS256")
                && key.usage.as_deref().is_none_or(|usage| usage == "sig")
                && match &header.kid {
                    Some(kid) => key.key_id.as_deref() == Some(kid),
                    None => true,
                }
        })
        .collect::<Vec<_>>();
    let [key] = matching.as_slice() else {
        bail!("GitHub OIDC JWT key selection is missing or ambiguous");
    };
    let signing_input = format!("{header_part}.{payload_part}");
    verify_rs256_signature(
        signing_input.as_bytes(),
        signature_part,
        &key.modulus,
        &key.exponent,
    )?;
    decoder
        .decode(payload_part)
        .map_err(|_| anyhow::anyhow!("GitHub OIDC JWT payload is not valid base64url"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7515 Appendix A.2 RS256 validation vector.
    const SIGNING_INPUT: &str = concat!(
        "eyJhbGciOiJSUzI1NiJ9.",
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt",
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    );
    const MODULUS: &str = concat!(
        "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx",
        "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs",
        "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH",
        "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV",
        "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8",
        "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ"
    );
    const SIGNATURE: &str = concat!(
        "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7",
        "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4",
        "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K",
        "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv",
        "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB",
        "p0igcN_IoypGlUPQGe77Rw"
    );

    fn rfc_key_set() -> JwkSet {
        JwkSet {
            keys: vec![RsaJwk {
                key_type: "RSA".into(),
                key_id: None,
                algorithm: Some("RS256".into()),
                usage: Some("sig".into()),
                modulus: MODULUS.into(),
                exponent: "AQAB".into(),
            }],
        }
    }

    #[test]
    fn rs256_signature_is_verified_before_claims_are_used() {
        verify_rs256_signature(SIGNING_INPUT.as_bytes(), SIGNATURE, MODULUS, "AQAB").unwrap();
        assert!(
            verify_rs256_signature(
                format!("{SIGNING_INPUT}x").as_bytes(),
                SIGNATURE,
                MODULUS,
                "AQAB"
            )
            .is_err()
        );
    }

    #[test]
    fn compact_jws_is_parsed_without_changing_the_signed_bytes() {
        let token = format!("{SIGNING_INPUT}.{SIGNATURE}");
        let payload = verify_compact_rs256(&token, &rfc_key_set()).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload["iss"], "joe");
        assert_eq!(payload["exp"], 1_300_819_380_i64);

        let mut tampered = token.clone();
        tampered.replace_range(30..31, "A");
        assert!(verify_compact_rs256(&tampered, &rfc_key_set()).is_err());
        assert!(verify_compact_rs256(&"x".repeat(32_769), &rfc_key_set()).is_err());
    }

    #[test]
    fn algorithm_and_key_selection_fail_closed() {
        let unsigned = "eyJhbGciOiJub25lIn0.e30.";
        assert!(verify_compact_rs256(unsigned, &rfc_key_set()).is_err());

        let token = format!("{SIGNING_INPUT}.{SIGNATURE}");
        let mut ambiguous = rfc_key_set();
        ambiguous.keys.push(ambiguous.keys[0].clone());
        assert!(verify_compact_rs256(&token, &ambiguous).is_err());
    }

    #[test]
    fn oidc_urls_are_origin_pinned_and_test_http_is_numeric_loopback_only() {
        GithubOidcVerifier::github().unwrap();
        for (url, kind) in [
            (
                "https://token.actions.githubusercontent.com/discovery",
                OidcUrlKind::Discovery,
            ),
            (
                "https://token.actions.githubusercontent.com/jwks",
                OidcUrlKind::Jwks,
            ),
            (
                "https://actions.githubusercontent.com/token",
                OidcUrlKind::RunnerToken,
            ),
            (
                "https://pipelines.actions.githubusercontent.com/token",
                OidcUrlKind::RunnerToken,
            ),
        ] {
            validate_oidc_url(url, false, kind).unwrap();
        }
        for url in ["http://127.0.0.1:8080/path", "http://[::1]:8080/path"] {
            validate_oidc_url(url, true, OidcUrlKind::Discovery).unwrap();
        }

        for (url, allow_loopback, kind) in [
            ("not a URL", false, OidcUrlKind::Discovery),
            (
                "https://user@token.actions.githubusercontent.com/path",
                false,
                OidcUrlKind::Discovery,
            ),
            (
                "https://:password@token.actions.githubusercontent.com/path",
                false,
                OidcUrlKind::Discovery,
            ),
            (
                "https://token.actions.githubusercontent.com/path#fragment",
                false,
                OidcUrlKind::Discovery,
            ),
            ("file:///tmp/token", false, OidcUrlKind::Discovery),
            ("http://127.0.0.1:8080/path", false, OidcUrlKind::Discovery),
            ("http://localhost:8080/path", true, OidcUrlKind::Discovery),
            ("http://192.0.2.1/path", true, OidcUrlKind::Discovery),
            (
                "https://evil.example/discovery",
                false,
                OidcUrlKind::Discovery,
            ),
            (
                "https://actions.githubusercontent.com/discovery",
                false,
                OidcUrlKind::Discovery,
            ),
        ] {
            assert!(
                validate_oidc_url(url, allow_loopback, kind).is_err(),
                "accepted untrusted OIDC URL {url}"
            );
        }
    }

    #[test]
    fn compact_jwt_parser_rejects_each_malformed_part_independently() {
        let valid = format!("{SIGNING_INPUT}.{SIGNATURE}");
        for token in [
            "".to_owned(),
            ".payload.signature".to_owned(),
            "header..signature".to_owned(),
            "header.payload.".to_owned(),
            "header.payload.signature.extra".to_owned(),
            format!("{}.e30.x", "A".repeat(MAX_JWT_PART_BYTES + 1)),
            format!("e30.{}.x", "A".repeat(MAX_JWT_PART_BYTES + 1)),
            format!("e30.e30.{}", "A".repeat(MAX_JWT_PART_BYTES + 1)),
            "%.e30.x".to_owned(),
            format!("{}.e30.x", encode_json(&serde_json::json!("not an object"))),
            format!(
                "{}.e30.x",
                encode_json(&serde_json::json!({"alg": "HS256"}))
            ),
            format!(
                "{}.e30.x",
                encode_json(&serde_json::json!({"alg": "RS256", "crit": ["exp"]}))
            ),
        ] {
            assert!(
                verify_compact_rs256(&token, &rfc_key_set()).is_err(),
                "accepted malformed token with length {}",
                token.len()
            );
        }
        assert!(verify_compact_rs256(&valid, &rfc_key_set()).is_ok());
    }

    #[test]
    fn compact_jwt_key_filters_and_key_material_fail_closed_independently() {
        let token = format!("{SIGNING_INPUT}.{SIGNATURE}");
        for mutate in [
            |key: &mut RsaJwk| key.key_type = "EC".into(),
            |key: &mut RsaJwk| key.algorithm = Some("RS512".into()),
            |key: &mut RsaJwk| key.usage = Some("enc".into()),
        ] {
            let mut keys = rfc_key_set();
            mutate(&mut keys.keys[0]);
            assert!(verify_compact_rs256(&token, &keys).is_err());
        }

        for clear_optional in [
            |key: &mut RsaJwk| key.algorithm = None,
            |key: &mut RsaJwk| key.usage = None,
        ] {
            let mut keys = rfc_key_set();
            clear_optional(&mut keys.keys[0]);
            verify_compact_rs256(&token, &keys).unwrap();
        }

        let kid_header = encode_json(&serde_json::json!({"alg": "RS256", "kid": "wanted"}));
        let kid_token = format!("{kid_header}.e30.eA");
        let mut matching = rfc_key_set();
        matching.keys[0].key_id = Some("wanted".into());
        assert!(verify_compact_rs256(&kid_token, &matching).is_err());
        matching.keys[0].key_id = Some("other".into());
        assert!(verify_compact_rs256(&kid_token, &matching).is_err());

        for case in ["signature", "modulus", "exponent"] {
            let mut keys = rfc_key_set();
            let candidate = match case {
                "signature" => format!("{SIGNING_INPUT}.%"),
                "modulus" => {
                    keys.keys[0].modulus = "%".into();
                    token.clone()
                }
                "exponent" => {
                    keys.keys[0].exponent = "%".into();
                    token.clone()
                }
                _ => unreachable!(),
            };
            assert!(verify_compact_rs256(&candidate, &keys).is_err());
        }
    }

    fn encode_json(value: &serde_json::Value) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap())
    }
}
