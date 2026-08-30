use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use reqwest::{StatusCode, Url};
use semver::Version;
use serde::Deserialize;

use crate::config::{
    AuthKind, RegistryConfig, RegistryProvider, url_is_http_loopback, validate_registry_repository,
};

const JSON_LIMIT: u64 = 4 * 1024 * 1024;
const ARCHIVE_LIMIT: u64 = 128 * 1024 * 1024;
const DEFAULT_RETRIES: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexRelease {
    pub version: Version,
    pub has_docs: bool,
    pub retired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryRelease {
    pub version: Version,
    pub has_docs: bool,
    pub retired: bool,
    pub outer_checksum: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    Accepted,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryCredentialAudit {
    Missing,
    Invalid,
    PublishPermissionDenied,
    RepositoryReadPermissionDenied,
    PublishAndReadAllowed,
    Unavailable,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageState {
    pub releases: Vec<HexRelease>,
}

impl PackageState {
    pub fn latest(&self) -> Option<&HexRelease> {
        self.releases
            .iter()
            .max_by(|a, b| a.version.cmp(&b.version))
    }

    pub fn latest_stable(&self) -> Option<&HexRelease> {
        self.releases
            .iter()
            .filter(|release| release.version.pre.is_empty())
            .max_by(|a, b| a.version.cmp(&b.version))
    }

    pub fn release(&self, version: &Version) -> Option<&HexRelease> {
        self.releases
            .iter()
            .find(|release| &release.version == version)
    }
}

#[async_trait]
pub trait Registry: Send + Sync {
    async fn package(&self, name: &str) -> Result<Option<PackageState>>;
    async fn source_tarball(&self, name: &str, version: &Version) -> Result<Vec<u8>>;
    async fn docs_tarball(&self, name: &str, version: &Version) -> Result<Option<Vec<u8>>>;

    async fn release(&self, name: &str, version: &Version) -> Result<Option<RegistryRelease>> {
        Ok(self
            .package(name)
            .await?
            .and_then(|package| package.release(version).cloned())
            .map(|release| RegistryRelease {
                version: release.version,
                has_docs: release.has_docs,
                retired: release.retired,
                outer_checksum: None,
            }))
    }

    async fn publish_package(&self, _tarball: &[u8]) -> Result<PublishOutcome> {
        bail!("registry adapter does not support publishing")
    }

    async fn publish_docs(
        &self,
        _name: &str,
        _version: &Version,
        _tarball: &[u8],
    ) -> Result<PublishOutcome> {
        bail!("registry adapter does not support documentation publishing")
    }
}

#[derive(Clone)]
struct Credential(String);

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Debug, Clone)]
pub struct HexRegistry {
    client: reqwest::Client,
    api_url: Url,
    repository_url: Url,
    docs_url: Url,
    repository: Option<String>,
    credential: Option<Credential>,
    auth: AuthKind,
    retries: usize,
}

impl Default for HexRegistry {
    fn default() -> Self {
        let api = std::env::var("RELEASE_GLZ_HEX_API_URL")
            .unwrap_or_else(|_| "https://hex.pm/api".to_owned());
        let repository = std::env::var("RELEASE_GLZ_HEX_REPOSITORY_URL")
            .unwrap_or_else(|_| "https://repo.hex.pm".to_owned());
        let docs = std::env::var("RELEASE_GLZ_HEX_DOCS_URL")
            .unwrap_or_else(|_| format!("{}/docs", repository.trim_end_matches('/')));
        let allow_http_loopback = allow_environment_http_loopback(
            std::env::var("RELEASE_GLZ_ALLOW_HTTP_LOOPBACK")
                .ok()
                .as_deref(),
        );
        let config = RegistryConfig {
            provider: RegistryProvider::HexPm,
            repository: None,
            api_url: api,
            repository_url: repository,
            docs_url: docs,
            credential_env: "HEXPM_API_KEY".into(),
            auth: AuthKind::HexToken,
            allow_http_loopback,
        };
        Self::from_config(&config, std::env::var("HEXPM_API_KEY").ok().as_deref())
            .expect("valid Hex registry environment URLs")
    }
}

impl HexRegistry {
    pub fn new(api_url: impl Into<String>, repository_url: impl Into<String>) -> Self {
        let repository_url = repository_url.into();
        let config = RegistryConfig {
            api_url: api_url.into(),
            docs_url: format!("{}/docs", repository_url.trim_end_matches('/')),
            repository_url,
            allow_http_loopback: true,
            ..RegistryConfig::default()
        };
        Self::from_config(&config, None).expect("valid registry URLs")
    }

    pub fn from_config(config: &RegistryConfig, credential: Option<&str>) -> Result<Self> {
        validate_registry_repository(config.provider, config.repository.as_deref())?;
        let api_url = parse_base_url(&config.api_url, config.allow_http_loopback, "api_url")?;
        let repository_url = parse_base_url(
            &config.repository_url,
            config.allow_http_loopback,
            "repository_url",
        )?;
        let docs_url = parse_base_url(&config.docs_url, config.allow_http_loopback, "docs_url")?;
        let loopback_only = [&api_url, &repository_url, &docs_url]
            .into_iter()
            .all(url_is_http_loopback);
        let mut client = reqwest::Client::builder()
            .user_agent(concat!("release-glz/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none());
        if loopback_only {
            client = client.no_proxy();
        }
        let client = client.build()?;
        Ok(Self {
            client,
            api_url,
            repository_url,
            docs_url,
            repository: config.repository.clone(),
            credential: credential
                .filter(|value| !value.is_empty())
                .map(|value| Credential(value.to_owned())),
            auth: config.auth,
            retries: DEFAULT_RETRIES,
        })
    }

    pub fn from_environment(config: &RegistryConfig) -> Result<Self> {
        let credential = std::env::var(&config.credential_env).ok();
        Self::from_config(config, credential.as_deref())
    }

    /// Non-destructively verifies the exact permissions needed by the release
    /// reconciler. Hex's `/auth` endpoint performs the authorization check
    /// without publishing or otherwise changing registry state.
    pub async fn audit_credential(&self) -> Result<RegistryCredentialAudit> {
        if self.credential.is_none() {
            return Ok(RegistryCredentialAudit::Missing);
        }

        match self.audit_permission("api", Some("write")).await? {
            PermissionAudit::Allowed => {}
            PermissionAudit::Invalid => return Ok(RegistryCredentialAudit::Invalid),
            PermissionAudit::Denied => {
                return Ok(RegistryCredentialAudit::PublishPermissionDenied);
            }
        }

        if let Some(repository) = &self.repository {
            match self
                .audit_permission("repository", Some(repository))
                .await?
            {
                PermissionAudit::Allowed => {}
                PermissionAudit::Invalid => return Ok(RegistryCredentialAudit::Invalid),
                PermissionAudit::Denied => {
                    return Ok(RegistryCredentialAudit::RepositoryReadPermissionDenied);
                }
            }
        }

        Ok(RegistryCredentialAudit::PublishAndReadAllowed)
    }

    async fn audit_permission(
        &self,
        domain: &str,
        resource: Option<&str>,
    ) -> Result<PermissionAudit> {
        let mut url = append_segments(&self.api_url, &["auth"])?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("domain", domain);
            if let Some(resource) = resource {
                query.append_pair("resource", resource);
            }
        }

        let mut last_error = None;
        for attempt in 0..self.retries {
            match self.audit_permission_once(url.clone()).await {
                Ok(AuditRequest::Result(result)) => return Ok(result),
                Ok(AuditRequest::Retry(delay)) => {
                    if !retry_available(attempt, self.retries) {
                        bail!("registry credential audit remained temporarily unavailable");
                    }
                    tokio::time::sleep(delay).await;
                }
                Err(error) => {
                    if error.downcast_ref::<reqwest::Error>().is_none() {
                        return Err(error);
                    }
                    last_error = Some(error);
                    if retry_available(attempt, self.retries) {
                        tokio::time::sleep(transport_retry_delay(attempt)).await;
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("registry credential audit failed")))
    }

    async fn audit_permission_once(&self, url: Url) -> Result<AuditRequest> {
        let mut current = url;
        for _ in 0..=5 {
            let request = self.authenticated(
                self.client
                    .get(current.clone())
                    .header(reqwest::header::ACCEPT, "application/json"),
            )?;
            let response = request.send().await?;
            if response.status().is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .context("registry redirect has no Location header")?
                    .to_str()
                    .context("registry redirect Location is not ASCII")?;
                let next = current.join(location)?;
                if !same_origin(&current, &next) {
                    bail!("refusing cross-origin registry redirect from {current} to {next}");
                }
                current = next;
                continue;
            }
            return classify_audit_status(response.status(), retry_after(response.headers()));
        }
        bail!("too many same-origin redirects during registry credential audit")
    }

    async fn get_bytes(&self, url: Url, optional: bool, limit: u64) -> Result<Option<Vec<u8>>> {
        let mut last_error = None;
        for attempt in 0..self.retries {
            match self.get_once(url.clone(), optional, limit).await {
                Ok(GetResult::Value(value)) => return Ok(value),
                Ok(GetResult::Retry(delay)) => {
                    if !retry_available(attempt, self.retries) {
                        bail!("registry GET {url} remained temporarily unavailable");
                    }
                    tokio::time::sleep(delay).await;
                }
                Err(error) => {
                    if error.downcast_ref::<reqwest::Error>().is_none() {
                        return Err(error);
                    }
                    last_error = Some(error);
                    if retry_available(attempt, self.retries) {
                        tokio::time::sleep(transport_retry_delay(attempt)).await;
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("registry GET failed")))
    }

    async fn get_once(&self, url: Url, optional: bool, limit: u64) -> Result<GetResult> {
        let mut current = url;
        for _ in 0..=5 {
            let request = self.authenticated(self.client.get(current.clone()))?;
            let mut response = request.send().await?;
            if response.status().is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .context("registry redirect has no Location header")?
                    .to_str()
                    .context("registry redirect Location is not ASCII")?;
                let next = current.join(location)?;
                if !same_origin(&current, &next) {
                    bail!("refusing cross-origin registry redirect from {current} to {next}");
                }
                current = next;
                continue;
            }
            if response.status() == StatusCode::NOT_FOUND && optional {
                return Ok(GetResult::Value(None));
            }
            if response.status() == StatusCode::TOO_MANY_REQUESTS
                || response.status().is_server_error()
            {
                return Ok(GetResult::Retry(retry_after(response.headers())));
            }
            if !response.status().is_success() {
                bail!("registry GET {} failed with {}", current, response.status());
            }
            if response
                .content_length()
                .is_some_and(|length| length > limit)
            {
                bail!("registry response from {current} exceeds the download limit");
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if bytes.len() as u64 + chunk.len() as u64 > limit {
                    bail!("registry response from {current} exceeds the download limit");
                }
                bytes.extend_from_slice(&chunk);
            }
            return Ok(GetResult::Value(Some(bytes)));
        }
        bail!("too many same-origin redirects from {current}")
    }

    fn authenticated(&self, request: reqwest::RequestBuilder) -> Result<reqwest::RequestBuilder> {
        let Some(credential) = &self.credential else {
            return Ok(request);
        };
        let value = match self.auth {
            AuthKind::HexToken => credential.0.clone(),
            AuthKind::Bearer => format!("Bearer {}", credential.0),
        };
        let mut value = reqwest::header::HeaderValue::from_str(&value)
            .context("registry credential is not a valid HTTP header value")?;
        value.set_sensitive(true);
        Ok(request.header(reqwest::header::AUTHORIZATION, value))
    }

    fn api_endpoint(&self, segments: &[&str]) -> Result<Url> {
        let mut all = Vec::new();
        if let Some(repository) = &self.repository {
            all.extend(["repos", repository.as_str()]);
        }
        all.extend_from_slice(segments);
        append_segments(&self.api_url, &all)
    }

    fn repository_endpoint(&self, segments: &[&str]) -> Result<Url> {
        let mut all = Vec::new();
        if let Some(repository) = &self.repository {
            all.extend(["repos", repository.as_str()]);
        }
        all.extend_from_slice(segments);
        append_segments(&self.repository_url, &all)
    }

    fn docs_endpoint(&self, name: &str, version: &Version) -> Result<Url> {
        if self.repository.is_some() {
            self.repository_endpoint(&["docs", &format!("{name}-{version}.tar.gz")])
        } else {
            append_segments(&self.docs_url, &[&format!("{name}-{version}.tar.gz")])
        }
    }

    async fn post_bytes(&self, url: Url, bytes: &[u8]) -> Result<PublishOutcome> {
        let request = self.authenticated(
            self.client
                .post(url.clone())
                .header(reqwest::header::ACCEPT, "application/json")
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(bytes.to_vec()),
        )?;
        let response = match request.send().await {
            Ok(response) => response,
            Err(_) => return Ok(PublishOutcome::Unknown),
        };
        if response.status().is_success() {
            return Ok(PublishOutcome::Accepted);
        }
        if response.status() == StatusCode::CONFLICT
            || response.status() == StatusCode::REQUEST_TIMEOUT
            || response.status() == StatusCode::TOO_MANY_REQUESTS
            || response.status().is_server_error()
        {
            return Ok(PublishOutcome::Unknown);
        }
        bail!("registry POST {url} failed with {}", response.status())
    }

    pub async fn wait_for(
        &self,
        package: &str,
        version: &Version,
        require_docs: bool,
    ) -> Result<PackageState> {
        let attempts = std::env::var("RELEASE_GLZ_POLL_ATTEMPTS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(20);
        let delay = std::env::var("RELEASE_GLZ_POLL_INTERVAL_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(3_000);
        for _ in 0..attempts {
            let state = self.package(package).await?;
            if release_ready(state.as_ref(), version, require_docs) {
                return state.context("ready registry state unexpectedly disappeared");
            }
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        bail!("timed out waiting for {package} {version} to appear on the registry")
    }
}

enum GetResult {
    Value(Option<Vec<u8>>),
    Retry(Duration),
}

enum AuditRequest {
    Result(PermissionAudit),
    Retry(Duration),
}

enum PermissionAudit {
    Allowed,
    Invalid,
    Denied,
}

fn retry_available(attempt: usize, attempts: usize) -> bool {
    attempt < attempts.saturating_sub(1)
}

fn transport_retry_delay(attempt: usize) -> Duration {
    Duration::from_millis((attempt as u64 + 1) * 100)
}

fn classify_audit_status(status: StatusCode, delay: Duration) -> Result<AuditRequest> {
    match status {
        status if status.is_success() => Ok(AuditRequest::Result(PermissionAudit::Allowed)),
        StatusCode::UNAUTHORIZED => Ok(AuditRequest::Result(PermissionAudit::Invalid)),
        StatusCode::FORBIDDEN => Ok(AuditRequest::Result(PermissionAudit::Denied)),
        StatusCode::TOO_MANY_REQUESTS => Ok(AuditRequest::Retry(delay)),
        status if status.is_server_error() => Ok(AuditRequest::Retry(delay)),
        status => bail!("registry credential audit failed with {status}"),
    }
}

fn release_ready(state: Option<&PackageState>, version: &Version, require_docs: bool) -> bool {
    state
        .and_then(|state| state.release(version))
        .is_some_and(|release| !require_docs || release.has_docs)
}

#[derive(Debug, Deserialize)]
struct ApiPackage {
    #[serde(default)]
    releases: Vec<ApiRelease>,
    #[serde(default)]
    retirements: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ApiRelease {
    version: String,
    #[serde(default)]
    has_docs: bool,
}

#[derive(Debug, Deserialize)]
struct ApiReleaseDetail {
    version: String,
    checksum: String,
    #[serde(default)]
    has_docs: bool,
    #[serde(default)]
    retirement: Option<serde_json::Value>,
}

#[async_trait]
impl Registry for HexRegistry {
    async fn package(&self, name: &str) -> Result<Option<PackageState>> {
        let url = self.api_endpoint(&["packages", name])?;
        let Some(bytes) = self.get_bytes(url, true, JSON_LIMIT).await? else {
            return Ok(None);
        };
        let package: ApiPackage =
            serde_json::from_slice(&bytes).context("invalid registry package response")?;
        let mut releases = Vec::new();
        for release in package.releases {
            let version: Version = release.version.parse().with_context(|| {
                format!("registry returned invalid version `{}`", release.version)
            })?;
            releases.push(HexRelease {
                retired: package.retirements.contains_key(&release.version),
                version,
                has_docs: release.has_docs,
            });
        }
        Ok(Some(PackageState { releases }))
    }

    async fn release(&self, name: &str, version: &Version) -> Result<Option<RegistryRelease>> {
        let url = self.api_endpoint(&["packages", name, "releases", &version.to_string()])?;
        let Some(bytes) = self.get_bytes(url, true, JSON_LIMIT).await? else {
            return Ok(None);
        };
        let release: ApiReleaseDetail =
            serde_json::from_slice(&bytes).context("invalid registry release response")?;
        let parsed: Version = release
            .version
            .parse()
            .context("registry release has an invalid version")?;
        if &parsed != version {
            bail!("registry returned release {parsed} while observing {version}");
        }
        validate_checksum(&release.checksum)?;
        Ok(Some(RegistryRelease {
            version: parsed,
            has_docs: release.has_docs,
            retired: release.retirement.is_some(),
            outer_checksum: Some(release.checksum.to_ascii_lowercase()),
        }))
    }

    async fn source_tarball(&self, name: &str, version: &Version) -> Result<Vec<u8>> {
        let filename = format!("{name}-{version}.tar");
        let url = self.repository_endpoint(&["tarballs", &filename])?;
        self.get_bytes(url, false, ARCHIVE_LIMIT)
            .await?
            .context("registry source tarball was not found")
    }

    async fn docs_tarball(&self, name: &str, version: &Version) -> Result<Option<Vec<u8>>> {
        let url = self.docs_endpoint(name, version)?;
        self.get_bytes(url, true, ARCHIVE_LIMIT).await
    }

    async fn publish_package(&self, tarball: &[u8]) -> Result<PublishOutcome> {
        let url = self.api_endpoint(&["publish"])?;
        self.post_bytes(url, tarball).await
    }

    async fn publish_docs(
        &self,
        name: &str,
        version: &Version,
        tarball: &[u8],
    ) -> Result<PublishOutcome> {
        let url =
            self.api_endpoint(&["packages", name, "releases", &version.to_string(), "docs"])?;
        self.post_bytes(url, tarball).await
    }
}

fn allow_environment_http_loopback(value: Option<&str>) -> bool {
    value == Some("1")
}

fn append_segments(base: &Url, segments: &[&str]) -> Result<Url> {
    let mut url = base.clone();
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("registry base URL cannot accept path segments"))?;
        path.pop_if_empty();
        for segment in segments {
            path.push(segment);
        }
    }
    Ok(url)
}

fn parse_base_url(raw: &str, allow_http_loopback: bool, field: &str) -> Result<Url> {
    let url = Url::parse(raw).with_context(|| format!("registry.{field} is invalid"))?;
    let loopback = url_is_http_loopback(&url);
    if url.scheme() != "https" && !(allow_http_loopback && loopback) {
        bail!("registry.{field} must use HTTPS");
    }
    if !url.username().is_empty() {
        bail!("registry.{field} must not contain credentials");
    }
    if url.password().is_some() {
        bail!("registry.{field} must not contain credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("registry.{field} must not contain a query or fragment");
    }
    Ok(url)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn retry_after(headers: &reqwest::header::HeaderMap) -> Duration {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_millis(250))
}

fn validate_checksum(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("registry release checksum is not SHA-256");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct ReadOnlyRegistry {
        state: Option<PackageState>,
    }

    #[async_trait]
    impl Registry for ReadOnlyRegistry {
        async fn package(&self, _name: &str) -> Result<Option<PackageState>> {
            Ok(self.state.clone())
        }

        async fn source_tarball(&self, _name: &str, _version: &Version) -> Result<Vec<u8>> {
            Ok(vec![])
        }

        async fn docs_tarball(&self, _name: &str, _version: &Version) -> Result<Option<Vec<u8>>> {
            Ok(None)
        }
    }

    #[test]
    fn retired_versions_still_occupy_the_latest_version() {
        let state = PackageState {
            releases: vec![
                HexRelease {
                    version: "1.0.0".parse().unwrap(),
                    has_docs: true,
                    retired: false,
                },
                HexRelease {
                    version: "1.1.0".parse().unwrap(),
                    has_docs: true,
                    retired: true,
                },
            ],
        };
        assert_eq!(state.latest().unwrap().version, "1.1.0".parse().unwrap());
        assert!(state.latest().unwrap().retired);
    }

    #[tokio::test]
    async fn read_only_adapter_defaults_observe_exact_releases_and_refuse_writes() {
        let target = Version::new(1, 2, 3);
        let state = PackageState {
            releases: vec![
                HexRelease {
                    version: "1.3.0-alpha.1".parse().unwrap(),
                    has_docs: false,
                    retired: false,
                },
                HexRelease {
                    version: target.clone(),
                    has_docs: true,
                    retired: true,
                },
                HexRelease {
                    version: "1.1.9".parse().unwrap(),
                    has_docs: true,
                    retired: false,
                },
            ],
        };
        assert_eq!(
            state.latest().unwrap().version,
            "1.3.0-alpha.1".parse().unwrap()
        );
        assert_eq!(state.latest_stable().unwrap().version, target);
        assert!(state.release(&Version::new(9, 9, 9)).is_none());

        let registry = ReadOnlyRegistry { state: Some(state) };
        let observed = registry.release("widget", &target).await.unwrap().unwrap();
        assert_eq!(observed.version, target);
        assert!(observed.has_docs);
        assert!(observed.retired);
        assert_eq!(observed.outer_checksum, None);
        assert!(
            registry
                .release("widget", &Version::new(9, 9, 9))
                .await
                .unwrap()
                .is_none()
        );
        assert!(registry.publish_package(b"bytes").await.is_err());
        assert!(
            registry
                .publish_docs("widget", &target, b"docs")
                .await
                .is_err()
        );

        let missing = ReadOnlyRegistry { state: None };
        assert!(missing.release("widget", &target).await.unwrap().is_none());
    }

    #[test]
    fn credentials_are_always_redacted_from_debug_output() {
        assert_eq!(
            format!("{:?}", Credential("never-print-me".into())),
            "[REDACTED]"
        );
        let registry = HexRegistry::from_config(
            &RegistryConfig {
                api_url: "http://127.0.0.1:9/api".into(),
                repository_url: "http://127.0.0.1:9/repo".into(),
                docs_url: "http://127.0.0.1:9/docs".into(),
                allow_http_loopback: true,
                ..RegistryConfig::default()
            },
            Some("never-print-me"),
        )
        .unwrap();
        let debug = format!("{registry:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("never-print-me"));
    }

    #[test]
    fn registry_limits_and_retry_policy_are_exact() {
        assert_eq!(JSON_LIMIT, 4_194_304);
        assert_eq!(ARCHIVE_LIMIT, 134_217_728);
        assert_eq!(DEFAULT_RETRIES, 3);

        assert!(retry_available(0, 3));
        assert!(retry_available(1, 3));
        assert!(!retry_available(2, 3));
        assert!(!retry_available(0, 1));
        assert!(!retry_available(usize::MAX, 3));
        assert_eq!(transport_retry_delay(0), Duration::from_millis(100));
        assert_eq!(transport_retry_delay(1), Duration::from_millis(200));
        assert_eq!(transport_retry_delay(2), Duration::from_millis(300));
    }

    #[test]
    fn environment_registry_http_requires_an_exact_test_opt_in() {
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("true"),
            Some("yes"),
            Some("01"),
        ] {
            assert!(!allow_environment_http_loopback(value));
        }
        assert!(allow_environment_http_loopback(Some("1")));
    }

    #[test]
    fn environment_constructor_keeps_the_supplied_registry_identity() {
        let config = RegistryConfig {
            provider: RegistryProvider::HexPm,
            repository: Some("private-org".into()),
            api_url: "https://api.example.test/v1".into(),
            repository_url: "https://repo.example.test/packages".into(),
            docs_url: "https://docs.example.test/releases".into(),
            credential_env: "RELEASE_GLZ_TEST_ENV_THAT_MUST_NOT_EXIST_9E57".into(),
            auth: AuthKind::Bearer,
            allow_http_loopback: false,
        };

        let registry = HexRegistry::from_environment(&config).unwrap();
        assert_eq!(registry.api_url.as_str(), "https://api.example.test/v1");
        assert_eq!(
            registry.repository_url.as_str(),
            "https://repo.example.test/packages"
        );
        assert_eq!(
            registry.docs_url.as_str(),
            "https://docs.example.test/releases"
        );
        assert_eq!(registry.repository.as_deref(), Some("private-org"));
        assert_eq!(registry.auth, AuthKind::Bearer);
        assert_eq!(registry.retries, 3);
    }

    #[test]
    fn audit_statuses_distinguish_results_retries_and_permanent_failures() {
        let delay = Duration::from_millis(17);
        assert!(matches!(
            classify_audit_status(StatusCode::NO_CONTENT, delay).unwrap(),
            AuditRequest::Result(PermissionAudit::Allowed)
        ));
        assert!(matches!(
            classify_audit_status(StatusCode::UNAUTHORIZED, delay).unwrap(),
            AuditRequest::Result(PermissionAudit::Invalid)
        ));
        assert!(matches!(
            classify_audit_status(StatusCode::FORBIDDEN, delay).unwrap(),
            AuditRequest::Result(PermissionAudit::Denied)
        ));
        assert!(matches!(
            classify_audit_status(StatusCode::TOO_MANY_REQUESTS, delay).unwrap(),
            AuditRequest::Retry(actual) if actual == delay
        ));
        assert!(matches!(
            classify_audit_status(StatusCode::INTERNAL_SERVER_ERROR, delay).unwrap(),
            AuditRequest::Retry(actual) if actual == delay
        ));
        assert!(classify_audit_status(StatusCode::BAD_REQUEST, delay).is_err());
    }

    #[test]
    fn base_urls_enforce_each_security_boundary_independently() {
        assert!(parse_base_url("https://example.test/api", false, "api_url").is_ok());
        assert!(parse_base_url("http://127.0.0.1:8080/api", true, "api_url").is_ok());
        assert!(parse_base_url("http://127.0.0.1:8080/api", false, "api_url").is_err());
        assert!(parse_base_url("http://example.test/api", true, "api_url").is_err());
        assert!(parse_base_url("https://user@example.test/api", false, "api_url").is_err());
        assert!(parse_base_url("https://:pass@example.test/api", false, "api_url").is_err());
        assert!(parse_base_url("https://", false, "api_url").is_err());
        assert!(parse_base_url("https://example.test/api?q=1", false, "api_url").is_err());
        assert!(parse_base_url("https://example.test/api#frag", false, "api_url").is_err());
    }

    #[test]
    fn origin_comparison_binds_scheme_host_and_effective_port() {
        let base = Url::parse("https://example.test/path").unwrap();
        assert!(same_origin(
            &base,
            &Url::parse("https://example.test:443/other").unwrap()
        ));
        assert!(!same_origin(
            &base,
            &Url::parse("http://example.test/other").unwrap()
        ));
        assert!(!same_origin(
            &base,
            &Url::parse("https://other.test/other").unwrap()
        ));
        assert!(!same_origin(
            &base,
            &Url::parse("https://example.test:444/other").unwrap()
        ));
    }

    #[test]
    fn retry_after_and_checksums_validate_all_boundaries() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert_eq!(retry_after(&headers), Duration::from_millis(250));
        headers.insert(reqwest::header::RETRY_AFTER, "2".parse().unwrap());
        assert_eq!(retry_after(&headers), Duration::from_secs(2));
        headers.insert(reqwest::header::RETRY_AFTER, "invalid".parse().unwrap());
        assert_eq!(retry_after(&headers), Duration::from_millis(250));

        assert!(validate_checksum(&"a".repeat(64)).is_ok());
        assert!(validate_checksum(&"A".repeat(64)).is_ok());
        assert!(validate_checksum(&"a".repeat(63)).is_err());
        assert!(validate_checksum(&"g".repeat(64)).is_err());
    }

    #[test]
    fn release_readiness_treats_docs_as_an_optional_independent_requirement() {
        let version = Version::new(1, 2, 3);
        let without_docs = PackageState {
            releases: vec![HexRelease {
                version: version.clone(),
                has_docs: false,
                retired: false,
            }],
        };
        let with_docs = PackageState {
            releases: vec![HexRelease {
                version: version.clone(),
                has_docs: true,
                retired: false,
            }],
        };
        assert!(release_ready(Some(&without_docs), &version, false));
        assert!(!release_ready(Some(&without_docs), &version, true));
        assert!(release_ready(Some(&with_docs), &version, true));
        assert!(!release_ready(None, &version, false));
        assert!(!release_ready(
            Some(&with_docs),
            &Version::new(1, 2, 4),
            false
        ));
    }

    #[tokio::test]
    async fn byte_downloads_never_fabricate_a_value_after_a_transport_error() {
        let mut registry =
            HexRegistry::new("http://127.0.0.1:9/api", "http://127.0.0.1:9/repository");
        registry.retries = 1;
        let unsupported = Url::parse("file:///release-glz-must-not-be-read").unwrap();
        assert!(registry.get_bytes(unsupported, false, 16).await.is_err());
    }
}
