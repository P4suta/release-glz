//! Package registry access: Hex.pm, a Hex.pm Organization, or a hex-compatible private registry.
//!
//! Reads are separated from publication so that planning and verification never need a credential.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use release_glz_core::{AfterPoll, Answer, Next, REGISTRY_RETRIES};
use release_glz_domain::Sha256Digest;
use reqwest::{StatusCode, Url};
use semver::Version;
use serde::Deserialize;

use crate::config::{
    AuthKind, RegistryConfig, url_is_http_loopback, uses_trusted_transport,
    validate_registry_repository,
};
use crate::failure::{Refusal, RefusalReason, refused};
use crate::refuse;
use crate::units::MIB;

/// Size a JSON response may reach before it is refused.
const JSON_LIMIT: u64 = 4 * MIB;

/// Size an archive response may reach before it is refused.
const ARCHIVE_LIMIT: u64 = 128 * MIB;

/// Seconds a single registry request may take before it is abandoned.
const REQUEST_TIMEOUT_SECONDS: u64 = 60;

/// Seconds spent connecting before a request is abandoned.
const CONNECT_TIMEOUT_SECONDS: u64 = 10;

/// Observations made while waiting for a release to become visible.
const DEFAULT_POLL_ATTEMPTS: usize = 20;

/// Time between those observations.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// How often, and how many times, a client checks whether a release has become visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibilityPoll {
    /// Observations made before the wait fails.
    pub attempts: usize,
    /// Time after each observation that didn't show the release.
    pub interval: Duration,
}

impl Default for VisibilityPoll {
    fn default() -> Self {
        Self {
            attempts: DEFAULT_POLL_ATTEMPTS,
            interval: DEFAULT_POLL_INTERVAL,
        }
    }
}

impl VisibilityPoll {
    /// What the first observation that shows the release returns, or `None` once every attempt has shown nothing.
    ///
    /// The wait sleeps only between two observations, so it ends right after the last one.
    async fn first_visible<T, Observation>(
        self,
        mut observe: impl FnMut() -> Observation,
    ) -> Result<Option<T>>
    where
        Observation: Future<Output = Result<Option<T>>>,
    {
        for poll in 0..self.attempts {
            let observed = observe().await?;
            match release_glz_core::after_poll(poll, self.attempts, observed.is_some()) {
                AfterPoll::Visible => return Ok(observed),
                AfterPoll::PollAgain => tokio::time::sleep(self.interval).await,
                AfterPoll::TimedOut => break,
            }
        }
        Ok(None)
    }
}

/// Redirects one request may follow on the configured origin.
const MAX_REDIRECTS: usize = 5;

/// One release as the registry reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexRelease {
    /// Published version.
    pub version: Version,
    /// Whether documentation was published for it.
    pub has_docs: bool,
    /// Whether the release has been retired.
    pub retired: bool,
}

/// One release, including the checksum the registry recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryRelease {
    /// Published version.
    pub version: Version,
    /// Whether documentation was published for it.
    pub has_docs: bool,
    /// Whether the release has been retired.
    pub retired: bool,
    /// Outer tarball checksum, when the registry exposes one.
    pub outer_checksum: Option<Sha256Digest>,
}

/// What a publish request established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// The registry accepted the release.
    Accepted,
    /// The result is undetermined and has to be observed.
    ///
    /// A timeout or a conflict says nothing about whether the bytes landed, so the reconciler re-observes instead of retrying blindly.
    Unknown,
}

/// What a non-destructive credential audit found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryCredentialAudit {
    /// No credential was present in the environment.
    Missing,
    /// The registry rejected the credential.
    Invalid,
    /// The credential cannot publish this package.
    PublishPermissionDenied,
    /// The credential cannot read the configured repository.
    RepositoryReadPermissionDenied,
    /// The credential can publish and read; the release path is open.
    PublishAndReadAllowed,
    /// The registry could not be reached, so nothing was established.
    Unavailable,
}

/// Everything the registry knows about one package.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageState {
    /// Every published release.
    pub releases: Vec<HexRelease>,
}

impl PackageState {
    /// Release of the highest precedence, prereleases included.
    ///
    /// Refuses when two releases share that precedence and differ in build metadata.
    pub fn latest(&self) -> Result<Option<&HexRelease>> {
        highest(self.releases.iter(), "latest")
    }

    /// Release of the highest precedence that is not a prerelease, refused like [`PackageState::latest`].
    pub fn latest_stable(&self) -> Result<Option<&HexRelease>> {
        highest(
            self.releases
                .iter()
                .filter(|release| release.version.pre.is_empty()),
            "latest stable",
        )
    }

    /// One exact release, if it is published.
    pub fn release(&self, version: &Version) -> Option<&HexRelease> {
        self.releases
            .iter()
            .find(|release| &release.version == version)
    }
}

/// The release of the highest precedence among `releases`, which the core decides without build metadata.
///
/// Two releases that share the highest precedence and differ in build metadata are refused, since semantic versioning orders neither first.
/// A tie below the highest precedence is accepted, since it can't change the result.
fn highest<'a>(
    releases: impl Iterator<Item = &'a HexRelease>,
    which: &str,
) -> Result<Option<&'a HexRelease>> {
    let mut highest: Option<&HexRelease> = None;
    let mut tied: Option<&HexRelease> = None;
    for release in releases {
        let Some(current) = highest else {
            highest = Some(release);
            continue;
        };
        match release_glz_core::compare(
            &crate::version::view(&release.version),
            &crate::version::view(&current.version),
        ) {
            Ordering::Greater => {
                highest = Some(release);
                tied = None;
            }
            Ordering::Equal if tied.is_none() && release.version != current.version => {
                tied = Some(release);
            }
            Ordering::Equal | Ordering::Less => {}
        }
    }
    if let (Some(highest), Some(tied)) = (highest, tied) {
        refuse!(
            RegistryReleasePrecedenceTie,
            "the registry lists {} and {}, which share the highest precedence, so neither is the {which} release",
            highest.version,
            tied.version
        );
    }
    Ok(highest)
}

/// Read access to a package registry.
///
/// Only observation lives behind this trait; publication is part of the reconciler, which needs the credential and the retry contract.
#[async_trait]
pub trait Registry: Send + Sync {
    /// Every release of a package, or `None` when it is unknown.
    async fn package(&self, name: &str) -> Result<Option<PackageState>>;
    /// Source tarball of one published release.
    async fn source_tarball(&self, name: &str, version: &Version) -> Result<Vec<u8>>;
    /// Documentation tarball of one published release, when it has one.
    async fn docs_tarball(&self, name: &str, version: &Version) -> Result<Option<Vec<u8>>>;

    /// One release together with its recorded checksum.
    ///
    /// Derived from [`Registry::package`] by default; an implementation that can read the checksum directly overrides it.
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

    /// Publish a package tarball.
    ///
    /// Defaults to refusing: an adapter stays read-only until it deliberately implements publication.
    async fn publish_package(&self, _tarball: &[u8]) -> Result<PublishOutcome> {
        bail!("registry adapter does not support publishing")
    }

    /// Publish a documentation tarball.
    ///
    /// Defaults to refusing, for the same reason as [`Registry::publish_package`].
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

/// A Hex API and repository client.
///
/// Redirects are refused and every response is read under a size limit, so a hostile or misconfigured origin cannot redirect a credential or exhaust memory.
#[derive(Debug, Clone)]
pub struct HexRegistry {
    client: reqwest::Client,
    api_url: Url,
    repository_url: Url,
    docs_url: Url,
    repository: Option<String>,
    credential: Option<Credential>,
    auth: AuthKind,
    visibility_poll: VisibilityPoll,
}

impl HexRegistry {
    /// Build a client for a loopback test registry.
    pub fn new(api_url: impl Into<String>, repository_url: impl Into<String>) -> Result<Self> {
        let repository_url = repository_url.into();
        let config = RegistryConfig {
            api_url: api_url.into(),
            docs_url: format!("{}/docs", repository_url.trim_end_matches('/')),
            repository_url,
            ..RegistryConfig::default()
        };
        Self::from_config(&config, None)
    }

    /// Build a client from configuration and an explicit credential.
    pub fn from_config(config: &RegistryConfig, credential: Option<&str>) -> Result<Self> {
        validate_registry_repository(config.provider, config.repository.as_deref())?;
        let api_url = parse_base_url(&config.api_url, "api_url")?;
        let repository_url = parse_base_url(&config.repository_url, "repository_url")?;
        let docs_url = parse_base_url(&config.docs_url, "docs_url")?;
        let loopback_only = [&api_url, &repository_url, &docs_url]
            .into_iter()
            .all(url_is_http_loopback);
        let mut client = reqwest::Client::builder()
            .user_agent(concat!("release-glz/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECONDS))
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECONDS))
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
            visibility_poll: VisibilityPoll::default(),
        })
    }

    /// Check for a release with `poll` instead of the default polling.
    pub fn with_visibility_poll(mut self, poll: VisibilityPoll) -> Self {
        self.visibility_poll = poll;
        self
    }

    /// Build a client, reading the credential from `credential_env`.
    pub fn from_environment(config: &RegistryConfig) -> Result<Self> {
        let credential = std::env::var(&config.credential_env).ok();
        Self::from_config(config, credential.as_deref())
    }

    /// Non-destructively verifies the exact permissions needed by the release reconciler.
    /// Hex's `/auth` endpoint performs the authorization check without publishing or otherwise changing registry state.
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

        let policy = REGISTRY_RETRIES;
        let mut last_error = None;
        for attempt in 0..policy.attempts {
            match self.audit_permission_once(url.clone()).await {
                Ok(AuditRequest::Result(result)) => return Ok(result),
                Ok(AuditRequest::Retry(asked)) => {
                    match policy.after(attempt, Answer::Busy(asked)) {
                        Next::Retry(wait) => tokio::time::sleep(Duration::from_millis(wait)).await,
                        Next::Stop => {
                            bail!("registry credential audit remained temporarily unavailable")
                        }
                    }
                }
                Err(error) => {
                    if error.downcast_ref::<reqwest::Error>().is_none() {
                        return Err(error);
                    }
                    last_error = Some(error);
                    if let Next::Retry(wait) = policy.after(attempt, Answer::Unreachable) {
                        tokio::time::sleep(Duration::from_millis(wait)).await;
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("registry credential audit failed")))
    }

    async fn audit_permission_once(&self, url: Url) -> Result<AuditRequest> {
        let mut current = url.clone();
        for _ in 0..=MAX_REDIRECTS {
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
                    .ok_or_else(|| {
                        refused(
                            RefusalReason::RegistryRedirectLocationInvalid,
                            "registry redirect has no Location header",
                        )
                    })?
                    .to_str()
                    .with_context(|| {
                        Refusal::new(
                            RefusalReason::RegistryRedirectLocationInvalid,
                            "registry redirect Location is not ASCII",
                        )
                    })?;
                let next = current.join(location)?;
                if !same_origin(&current, &next) {
                    refuse!(
                        RegistryRedirectCrossOrigin,
                        "refusing cross-origin registry redirect from {url} to {}",
                        crate::secrets::redirect_target(&response, self.secret_values())
                    );
                }
                current = next;
                continue;
            }
            return classify_audit_status(response.status(), retry_after(response.headers()));
        }
        Err(refused(
            RefusalReason::RegistryRedirectLimitExceeded,
            "too many same-origin redirects during registry credential audit",
        ))
    }

    async fn get_bytes(&self, url: Url, optional: bool, limit: u64) -> Result<Option<Vec<u8>>> {
        let policy = REGISTRY_RETRIES;
        let mut last_error = None;
        for attempt in 0..policy.attempts {
            match self.get_once(url.clone(), optional, limit).await {
                Ok(GetResult::Value(value)) => return Ok(value),
                Ok(GetResult::Retry(asked)) => match policy.after(attempt, Answer::Busy(asked)) {
                    Next::Retry(wait) => tokio::time::sleep(Duration::from_millis(wait)).await,
                    Next::Stop => bail!("registry GET {url} remained temporarily unavailable"),
                },
                Err(error) => {
                    if error.downcast_ref::<reqwest::Error>().is_none() {
                        return Err(error);
                    }
                    last_error = Some(error);
                    if let Next::Retry(wait) = policy.after(attempt, Answer::Unreachable) {
                        tokio::time::sleep(Duration::from_millis(wait)).await;
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("registry GET failed")))
    }

    async fn get_once(&self, url: Url, optional: bool, limit: u64) -> Result<GetResult> {
        let mut current = url.clone();
        for _ in 0..=MAX_REDIRECTS {
            let request = self.authenticated(self.client.get(current.clone()))?;
            let mut response = request.send().await?;
            if response.status().is_redirection() {
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .ok_or_else(|| {
                        refused(
                            RefusalReason::RegistryRedirectLocationInvalid,
                            "registry redirect has no Location header",
                        )
                    })?
                    .to_str()
                    .with_context(|| {
                        Refusal::new(
                            RefusalReason::RegistryRedirectLocationInvalid,
                            "registry redirect Location is not ASCII",
                        )
                    })?;
                let next = current.join(location)?;
                if !same_origin(&current, &next) {
                    refuse!(
                        RegistryRedirectCrossOrigin,
                        "refusing cross-origin registry redirect from {url} to {}",
                        crate::secrets::redirect_target(&response, self.secret_values())
                    );
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
                bail!("registry GET {url} failed with {}", response.status());
            }
            if response
                .content_length()
                .is_some_and(|length| length > limit)
            {
                refuse!(
                    RegistryResponseTooLarge,
                    "registry response from {url} exceeds the download limit"
                );
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if bytes.len() as u64 + chunk.len() as u64 > limit {
                    refuse!(
                        RegistryResponseTooLarge,
                        "registry response from {url} exceeds the download limit"
                    );
                }
                bytes.extend_from_slice(&chunk);
            }
            return Ok(GetResult::Value(Some(bytes)));
        }
        Err(refused(
            RefusalReason::RegistryRedirectLimitExceeded,
            format_args!("too many same-origin redirects from {url}"),
        ))
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

    /// The credential's value, which a message that shows server-chosen text redacts.
    fn secret_values(&self) -> impl Iterator<Item = &str> {
        self.credential
            .iter()
            .map(|credential| credential.0.as_str())
    }

    fn api_endpoint(&self, segments: &[&str]) -> Result<Url> {
        if let Some(repository) = self.repository.as_deref() {
            let mut scoped = Vec::with_capacity(segments.len() + 2);
            scoped.extend(["repos", repository]);
            scoped.extend_from_slice(segments);
            append_segments(&self.api_url, &scoped)
        } else {
            append_segments(&self.api_url, segments)
        }
    }

    fn repository_endpoint(&self, segments: &[&str]) -> Result<Url> {
        append_segments(&self.repository_url, segments)
    }

    fn docs_endpoint(&self, name: &str, version: &Version) -> Result<Url> {
        append_segments(&self.docs_url, &[&format!("{name}-{version}.tar.gz")])
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
        // A publish never follows a redirect, even within the origin, because the archive and the credential go only to the configured URL.
        if response.status().is_redirection() {
            refuse!(
                RegistryPublishRedirectRefused,
                "refusing registry publish redirect {} from {url} to {}",
                response.status(),
                crate::secrets::redirect_target(&response, self.secret_values())
            );
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

    /// Poll until a version, and optionally its docs, are visible.
    ///
    /// A registry makes a release visible asynchronously, so publication is only complete once it can be observed.
    pub async fn wait_for(
        &self,
        package: &str,
        version: &Version,
        require_docs: bool,
    ) -> Result<PackageState> {
        let visible = self
            .visibility_poll
            .first_visible(move || async move {
                let state = self.package(package).await?;
                Ok(state.filter(|state| release_ready(Some(state), version, require_docs)))
            })
            .await?;
        match visible {
            Some(state) => Ok(state),
            None => refuse!(
                RegistryReleaseNotVisible,
                "timed out waiting for {package} {version} to appear on the registry"
            ),
        }
    }
}

enum GetResult {
    Value(Option<Vec<u8>>),
    /// The registry asked to repeat the request, after the seconds that it named, if any.
    Retry(Option<u64>),
}

enum AuditRequest {
    Result(PermissionAudit),
    /// The registry asked to repeat the audit, after the seconds that it named, if any.
    Retry(Option<u64>),
}

enum PermissionAudit {
    Allowed,
    Invalid,
    Denied,
}

fn classify_audit_status(status: StatusCode, asked: Option<u64>) -> Result<AuditRequest> {
    match status {
        status if status.is_success() => Ok(AuditRequest::Result(PermissionAudit::Allowed)),
        StatusCode::UNAUTHORIZED => Ok(AuditRequest::Result(PermissionAudit::Invalid)),
        StatusCode::FORBIDDEN => Ok(AuditRequest::Result(PermissionAudit::Denied)),
        StatusCode::TOO_MANY_REQUESTS => Ok(AuditRequest::Retry(asked)),
        status if status.is_server_error() => Ok(AuditRequest::Retry(asked)),
        status => bail!("registry credential audit failed with {status}"),
    }
}

fn release_ready(state: Option<&PackageState>, version: &Version, require_docs: bool) -> bool {
    let listed = state
        .and_then(|state| state.release(version))
        .map(|release| release.has_docs);
    release_glz_core::release_ready(listed, require_docs)
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
        parse_package_response(&bytes).map(Some)
    }

    async fn release(&self, name: &str, version: &Version) -> Result<Option<RegistryRelease>> {
        let url = self.api_endpoint(&["packages", name, "releases", &version.to_string()])?;
        let Some(bytes) = self.get_bytes(url, true, JSON_LIMIT).await? else {
            return Ok(None);
        };
        parse_release_response(&bytes, version).map(Some)
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

/// The releases that the body of the registry's package response lists.
///
/// A body that isn't the package JSON, or that lists an invalid version, is refused with [`RefusalReason::RegistryPackageInvalid`].
pub fn parse_package_response(body: &[u8]) -> Result<PackageState> {
    let package: ApiPackage = serde_json::from_slice(body).with_context(|| {
        Refusal::new(
            RefusalReason::RegistryPackageInvalid,
            "invalid registry package response",
        )
    })?;
    let mut releases = Vec::new();
    for release in package.releases {
        let version: Version = release.version.parse().with_context(|| {
            Refusal::new(
                RefusalReason::RegistryPackageInvalid,
                format!("registry returned invalid version `{}`", release.version),
            )
        })?;
        releases.push(HexRelease {
            retired: package.retirements.contains_key(&release.version),
            version,
            has_docs: release.has_docs,
        });
    }
    Ok(PackageState { releases })
}

/// The release of `observed` that the body of the registry's release response describes.
///
/// A body that isn't the release JSON, or that names another version or a checksum other than a SHA-256 digest, is refused with [`RefusalReason::RegistryReleaseInvalid`].
pub fn parse_release_response(body: &[u8], observed: &Version) -> Result<RegistryRelease> {
    let release: ApiReleaseDetail = serde_json::from_slice(body).with_context(|| {
        Refusal::new(
            RefusalReason::RegistryReleaseInvalid,
            "invalid registry release response",
        )
    })?;
    let parsed: Version = release.version.parse().with_context(|| {
        Refusal::new(
            RefusalReason::RegistryReleaseInvalid,
            "registry release has an invalid version",
        )
    })?;
    if &parsed != observed {
        refuse!(
            RegistryReleaseInvalid,
            "registry returned release {parsed} while observing {observed}"
        );
    }
    let checksum = parse_checksum(&release.checksum)?;
    Ok(RegistryRelease {
        version: parsed,
        has_docs: release.has_docs,
        retired: release.retirement.is_some(),
        outer_checksum: Some(checksum),
    })
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

fn parse_base_url(raw: &str, field: &str) -> Result<Url> {
    let url = Url::parse(raw).with_context(|| {
        Refusal::new(
            RefusalReason::UrlMalformed,
            format!("registry.{field} is invalid"),
        )
    })?;
    if !uses_trusted_transport(&url) {
        refuse!(
            UrlTransportUntrusted,
            "registry.{field} must use HTTPS, or HTTP to a numeric loopback address"
        );
    }
    if !url.username().is_empty() {
        refuse!(
            UrlCredentials,
            "registry.{field} must not contain credentials"
        );
    }
    if url.password().is_some() {
        refuse!(
            UrlCredentials,
            "registry.{field} must not contain credentials"
        );
    }
    if url.query().is_some() || url.fragment().is_some() {
        refuse!(
            UrlQueryOrFragment,
            "registry.{field} must not contain a query or fragment"
        );
    }
    Ok(url)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

/// The seconds that a `Retry-After` header names, when it names a number.
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| release_glz_core::delay_seconds(value.as_bytes()))
}

/// The outer checksum of a registry release, which the registry may spell in either case.
fn parse_checksum(value: &str) -> Result<Sha256Digest> {
    Sha256Digest::from_wire(value).with_context(|| {
        Refusal::new(
            RefusalReason::RegistryReleaseInvalid,
            "registry release checksum is not SHA-256",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RegistryProvider;
    use crate::failure::{RefusalReason, refusal_reason};

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
        let latest = state.latest().unwrap().unwrap();
        assert_eq!(latest.version, "1.1.0".parse().unwrap());
        assert!(latest.retired);
    }

    fn listing(versions: &[&str]) -> PackageState {
        PackageState {
            releases: versions
                .iter()
                .map(|version| HexRelease {
                    version: version.parse().unwrap(),
                    has_docs: false,
                    retired: false,
                })
                .collect(),
        }
    }

    /// Every order of `versions`, so no outcome can depend on the order that the registry lists releases in.
    fn every_order<'a>(versions: &[&'a str]) -> Vec<Vec<&'a str>> {
        if versions.is_empty() {
            return vec![Vec::new()];
        }
        (0..versions.len())
            .flat_map(|first| {
                let mut rest = versions.to_vec();
                let head = rest.remove(first);
                every_order(&rest).into_iter().map(move |mut order| {
                    order.insert(0, head);
                    order
                })
            })
            .collect()
    }

    /// The version that a lookup returns, or the reason that it refuses with.
    type Outcome = Result<Option<String>, Option<RefusalReason>>;

    const TIE: Outcome = Err(Some(RefusalReason::RegistryReleasePrecedenceTie));

    const NONE: Outcome = Ok(None);

    fn found(version: &str) -> Outcome {
        Ok(Some(version.to_owned()))
    }

    fn outcome(release: Result<Option<&HexRelease>>) -> Outcome {
        match release {
            Ok(release) => Ok(release.map(|release| release.version.to_string())),
            Err(error) => Err(refusal_reason(&error)),
        }
    }

    /// Asserts the latest and the latest stable release of every order of `versions`.
    fn assert_every_order(versions: &[&str], latest: &Outcome, latest_stable: &Outcome) {
        for order in every_order(versions) {
            let state = listing(&order);
            assert_eq!(
                (&outcome(state.latest()), &outcome(state.latest_stable())),
                (latest, latest_stable),
                "{order:?}"
            );
        }
    }

    #[test]
    fn a_build_metadata_tie_at_the_highest_precedence_is_refused_in_every_order() {
        for (first, second) in [("1.0.0+a", "1.0.0+b"), ("1.0.0+b", "1.0.0+a")] {
            let state = listing(&[first, second]);
            for (which, release) in [
                ("latest", state.latest()),
                ("latest stable", state.latest_stable()),
            ] {
                let error = release.unwrap_err();
                assert_eq!(
                    (refusal_reason(&error), error.to_string()),
                    (
                        Some(RefusalReason::RegistryReleasePrecedenceTie),
                        format!(
                            "the registry lists {first} and {second}, which share the highest precedence, so neither is the {which} release"
                        )
                    )
                );
            }
        }
        assert_every_order(&["1.0.0+a", "1.0.0+b", "0.9.0"], &TIE, &TIE);
        assert_every_order(&["1.0.0+a", "1.0.0+b", "1.0.0+a"], &TIE, &TIE);
        assert_every_order(
            &["1.0.0-rc.2+a", "1.0.0-rc.2+b", "1.0.0-rc.1", "0.9.0"],
            &TIE,
            &found("0.9.0"),
        );
        assert_every_order(
            &["1.0.0+a", "1.0.0+b", "1.0.1-rc.1"],
            &found("1.0.1-rc.1"),
            &TIE,
        );
    }

    /// Only the highest precedence decides, since a tie below it can't change the latest release.
    #[test]
    fn a_build_metadata_tie_below_the_highest_precedence_is_accepted_in_every_order() {
        assert_every_order(&["1.0.0+a", "1.1.0"], &found("1.1.0"), &found("1.1.0"));
        assert_every_order(
            &["1.0.0+a", "1.0.0+b", "1.1.0+c"],
            &found("1.1.0+c"),
            &found("1.1.0+c"),
        );
        assert_every_order(
            &["0.9.0", "1.0.0-rc.1+a", "1.0.0-rc.1+b", "1.0.0"],
            &found("1.0.0"),
            &found("1.0.0"),
        );
        assert_every_order(
            &["1.0.0+a", "1.0.0+a"],
            &found("1.0.0+a"),
            &found("1.0.0+a"),
        );
    }

    #[test]
    fn releases_order_by_precedence_and_the_stable_latest_skips_prereleases() {
        assert_every_order(&["1.0.0-rc.2", "1.0.0"], &found("1.0.0"), &found("1.0.0"));
        assert_every_order(&["1.0.0-rc.2", "1.0.0-rc.10"], &found("1.0.0-rc.10"), &NONE);
        assert_every_order(
            &["1.0.0-alpha.9", "1.0.0-beta.1", "0.9.9"],
            &found("1.0.0-beta.1"),
            &found("0.9.9"),
        );
        assert_every_order(
            &["1.0.0-rc", "1.0.0-rc.1", "1.0.0-rc.1.1"],
            &found("1.0.0-rc.1.1"),
            &NONE,
        );
        assert_every_order(
            &["2.0.0-alpha.1", "1.10.0", "1.9.0"],
            &found("2.0.0-alpha.1"),
            &found("1.10.0"),
        );
        assert_every_order(&[], &NONE, &NONE);
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
            state.latest().unwrap().unwrap().version,
            "1.3.0-alpha.1".parse().unwrap()
        );
        assert_eq!(state.latest_stable().unwrap().unwrap().version, target);
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
        assert_eq!(
            registry
                .publish_package(b"bytes")
                .await
                .unwrap_err()
                .to_string(),
            "registry adapter does not support publishing"
        );
        assert_eq!(
            registry
                .publish_docs("widget", &target, b"docs")
                .await
                .unwrap_err()
                .to_string(),
            "registry adapter does not support documentation publishing"
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
        assert_eq!(REGISTRY_RETRIES.attempts, 3);

        let retry_available = release_glz_core::another_attempt_follows;
        let transport_retry_delay =
            |attempt| Duration::from_millis(REGISTRY_RETRIES.transport_wait(attempt));
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
    fn environment_constructor_keeps_the_supplied_registry_identity() {
        let config = RegistryConfig {
            provider: RegistryProvider::HexPm,
            repository: Some("private-org".into()),
            api_url: "https://api.example.test/v1".into(),
            repository_url: "https://repo.example.test/packages".into(),
            docs_url: "https://docs.example.test/releases".into(),
            credential_env: "RELEASE_GLZ_TEST_ENV_THAT_MUST_NOT_EXIST_9E57".into(),
            auth: AuthKind::Bearer,
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
    }

    #[test]
    fn audit_statuses_distinguish_results_retries_and_permanent_failures() {
        let delay = Some(17);
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
        let Err(error) = classify_audit_status(StatusCode::BAD_REQUEST, delay) else {
            panic!("a 400 audit answer was not a failure");
        };
        assert_eq!(
            error.to_string(),
            "registry credential audit failed with 400 Bad Request"
        );
    }

    #[test]
    fn base_urls_enforce_each_security_boundary_independently() {
        assert!(parse_base_url("https://example.test/api", "api_url").is_ok());
        assert!(parse_base_url("http://127.0.0.1:8080/api", "api_url").is_ok());
        assert!(parse_base_url("http://[::1]:8080/api", "api_url").is_ok());
        let transport = (
            Some(RefusalReason::UrlTransportUntrusted),
            "registry.api_url must use HTTPS, or HTTP to a numeric loopback address",
        );
        let credentials = (
            Some(RefusalReason::UrlCredentials),
            "registry.api_url must not contain credentials",
        );
        let query = (
            Some(RefusalReason::UrlQueryOrFragment),
            "registry.api_url must not contain a query or fragment",
        );
        for (url, (reason, message)) in [
            ("http://localhost:8080/api", transport),
            ("http://example.test/api", transport),
            ("http://192.0.2.1/api", transport),
            ("https://user@example.test/api", credentials),
            ("https://:pass@example.test/api", credentials),
            ("http://user@127.0.0.1:8080/api", credentials),
            (
                "https://",
                (
                    Some(RefusalReason::UrlMalformed),
                    "registry.api_url is invalid",
                ),
            ),
            ("https://example.test/api?q=1", query),
            ("http://127.0.0.1:8080/api?q=1", query),
            ("https://example.test/api#frag", query),
        ] {
            let error = parse_base_url(url, "api_url").unwrap_err();
            assert_eq!(
                (refusal_reason(&error), error.to_string()),
                (reason, message.to_owned()),
                "{url}"
            );
        }
        assert_eq!(
            format!("{:#}", parse_base_url("https://", "api_url").unwrap_err()),
            format!(
                "registry.api_url is invalid: {}",
                Url::parse("https://").unwrap_err()
            )
        );
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
        let retry_after = |headers: &reqwest::header::HeaderMap| {
            Duration::from_millis(REGISTRY_RETRIES.busy_wait(0, super::retry_after(headers)))
        };
        let mut headers = reqwest::header::HeaderMap::new();
        assert_eq!(retry_after(&headers), Duration::from_millis(250));
        headers.insert(reqwest::header::RETRY_AFTER, "2".parse().unwrap());
        assert_eq!(retry_after(&headers), Duration::from_secs(2));
        for unnamed in ["invalid", "+5", "-5", "Wed, 21 Oct 2015 07:28:00 GMT"] {
            headers.insert(reqwest::header::RETRY_AFTER, unnamed.parse().unwrap());
            assert_eq!(
                retry_after(&headers),
                Duration::from_millis(250),
                "{unnamed}"
            );
        }
        headers.insert(reqwest::header::RETRY_AFTER, "60".parse().unwrap());
        assert_eq!(retry_after(&headers), Duration::from_secs(60));
        for excessive in ["61", "99999999", "18446744073709551615"] {
            headers.insert(reqwest::header::RETRY_AFTER, excessive.parse().unwrap());
            assert_eq!(
                retry_after(&headers),
                Duration::from_secs(60),
                "{excessive}"
            );
        }

        for spelled in [
            "a".repeat(64),
            "A".repeat(64),
            format!("A{}", "a".repeat(63)),
        ] {
            assert_eq!(
                parse_checksum(&spelled).unwrap().as_str(),
                "a".repeat(64),
                "{spelled}"
            );
        }
        for malformed in ["a".repeat(63), "g".repeat(64)] {
            let error = parse_checksum(&malformed).unwrap_err();
            assert_eq!(
                (refusal_reason(&error), error.to_string()),
                (
                    Some(RefusalReason::RegistryReleaseInvalid),
                    "registry release checksum is not SHA-256".to_owned()
                ),
                "{malformed}"
            );
        }
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

    /// When `poll` observes, what it returns, and when it returns, each time measured from its start, for a release that first shows at observation number `shows_at`, counting from one.
    async fn schedule(
        poll: VisibilityPoll,
        shows_at: Option<usize>,
    ) -> (Vec<Duration>, Option<usize>, Duration) {
        let started = tokio::time::Instant::now();
        let mut observations = Vec::new();
        let shown = poll
            .first_visible(|| {
                observations.push(started.elapsed());
                std::future::ready(Ok(
                    Some(observations.len()).filter(|&count| Some(count) == shows_at)
                ))
            })
            .await
            .unwrap();
        (observations, shown, started.elapsed())
    }

    /// The first `count` multiples of `interval`, starting at zero.
    fn every(interval: Duration, count: u32) -> Vec<Duration> {
        (0..count).map(|index| interval * index).collect()
    }

    /// A registry observes twenty times three seconds apart, so its wait gives up just under a minute after it starts, unless a caller sets another poll.
    #[tokio::test(start_paused = true)]
    async fn visibility_polling_waits_a_minute_unless_a_caller_sets_it() {
        let registry =
            HexRegistry::new("http://127.0.0.1:9/api", "http://127.0.0.1:9/repository").unwrap();
        assert_eq!(
            schedule(registry.visibility_poll, None).await,
            (
                every(Duration::from_secs(3), 20),
                None,
                Duration::from_secs(57)
            )
        );

        let registry = registry.with_visibility_poll(VisibilityPoll {
            attempts: 4,
            interval: Duration::from_secs(10),
        });
        assert_eq!(
            schedule(registry.visibility_poll, None).await,
            (
                every(Duration::from_secs(10), 4),
                None,
                Duration::from_secs(30)
            )
        );
    }

    /// A wait sleeps only between two observations, so it ends at the first one that shows the release, and a single attempt never sleeps.
    #[tokio::test(start_paused = true)]
    async fn a_visibility_wait_sleeps_only_between_observations() {
        assert_eq!(
            schedule(VisibilityPoll::default(), Some(3)).await,
            (
                every(Duration::from_secs(3), 3),
                Some(3),
                Duration::from_secs(6)
            )
        );
        let single = VisibilityPoll {
            attempts: 1,
            interval: Duration::from_secs(60),
        };
        assert_eq!(
            schedule(single, None).await,
            (vec![Duration::ZERO], None, Duration::ZERO)
        );
    }

    #[tokio::test]
    async fn byte_downloads_never_fabricate_a_value_after_a_transport_error() {
        let registry =
            HexRegistry::new("http://127.0.0.1:9/api", "http://127.0.0.1:9/repository").unwrap();
        let unsupported = Url::parse("file:///release-glz-must-not-be-read").unwrap();
        let error = registry
            .get_bytes(unsupported, false, 16)
            .await
            .unwrap_err();
        assert!(
            error.downcast_ref::<reqwest::Error>().is_some(),
            "{error:#}"
        );
    }
}
