use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use semver::Version;
use serde::{Deserialize, Serialize};
use toml_edit::{DocumentMut, Item, Table, value};

use crate::model::PrereleaseChannel;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepositoryConfig {
    pub kind: Option<String>,
    pub user: Option<String>,
    pub repo: Option<String>,
    pub path: Option<String>,
    pub tag_prefix: String,
}

impl RepositoryConfig {
    pub fn tag_for(&self, version: &Version) -> String {
        format!("{}v{version}", self.tag_prefix)
    }

    pub fn github_name(&self) -> Option<String> {
        match (&self.kind, &self.user, &self.repo) {
            (Some(kind), Some(user), Some(repo)) if kind == "github" => {
                Some(format!("{user}/{repo}"))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryProvider {
    #[default]
    #[serde(rename = "hexpm")]
    HexPm,
    HexCompatible,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthKind {
    #[default]
    HexToken,
    Bearer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryConfig {
    pub provider: RegistryProvider,
    #[serde(default)]
    pub repository: Option<String>,
    pub api_url: String,
    pub repository_url: String,
    pub docs_url: String,
    pub credential_env: String,
    pub auth: AuthKind,
    #[serde(default)]
    pub allow_http_loopback: bool,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            provider: RegistryProvider::HexPm,
            repository: None,
            api_url: "https://hex.pm/api".into(),
            repository_url: "https://repo.hex.pm".into(),
            docs_url: "https://repo.hex.pm/docs".into(),
            credential_env: "HEXPM_API_KEY".into(),
            auth: AuthKind::HexToken,
            allow_http_loopback: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalMode {
    ReleasePrAndEnvironment,
    Environment,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeparationMode {
    #[default]
    Solo,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConfig {
    pub normal: ApprovalMode,
    pub manual: ApprovalMode,
    pub environment: String,
    #[serde(default)]
    pub separation: SeparationMode,
    pub manual_refs: Vec<String>,
    #[serde(default)]
    pub private_repository_fallback: Option<String>,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            normal: ApprovalMode::ReleasePrAndEnvironment,
            manual: ApprovalMode::Environment,
            environment: "release".into(),
            separation: SeparationMode::Solo,
            manual_refs: vec!["refs/heads/main".into()],
            private_repository_fallback: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutputConfig {
    pub docs: bool,
    pub github_release: bool,
    pub sbom: bool,
    pub provenance: bool,
    pub signature: bool,
    pub allow_private_evidence_upload: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            docs: true,
            github_release: true,
            sbom: true,
            provenance: true,
            signature: false,
            allow_private_evidence_upload: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookConfig {
    pub id: String,
    pub argv: Vec<String>,
    #[serde(default = "default_hook_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default)]
    pub env: Vec<String>,
}

fn default_hook_timeout() -> u64 {
    300
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HooksConfig {
    pub verify: Vec<HookConfig>,
    pub sidecar: Vec<HookConfig>,
    pub notify: Vec<HookConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChangelogConfig {
    pub path: PathBuf,
    pub managed_block: bool,
    pub notes_dir: PathBuf,
}

impl Default for ChangelogConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("CHANGELOG.md"),
            managed_block: true,
            notes_dir: PathBuf::from(".release-glz/notes"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiException {
    pub version: Version,
    pub baseline: String,
    pub reason: String,
    pub expires: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseConfig {
    pub schema: u32,
    pub compiler: Version,
    pub registry: RegistryConfig,
    pub approval: ApprovalConfig,
    pub outputs: OutputConfig,
    pub hooks: HooksConfig,
    pub changelog: ChangelogConfig,
    pub api_exceptions: Vec<ApiException>,
    pub compatibility_warnings: Vec<String>,
    pub changelog_path: PathBuf,
    pub release_branch_prefix: String,
    pub allow_version_zero: bool,
    pub prerelease: Option<PrereleaseChannel>,
    pub allow_unknown_api_for: BTreeSet<Version>,
    pub baseline_refs: BTreeMap<Version, String>,
}

impl Default for ReleaseConfig {
    fn default() -> Self {
        Self {
            schema: 1,
            compiler: Version::new(1, 9, 0),
            registry: RegistryConfig::default(),
            approval: ApprovalConfig::default(),
            outputs: OutputConfig::default(),
            hooks: HooksConfig::default(),
            changelog: ChangelogConfig::default(),
            api_exceptions: Vec::new(),
            compatibility_warnings: vec![
                "legacy release-glz configuration; run `release-glz migrate --update`".into(),
            ],
            changelog_path: PathBuf::from("CHANGELOG.md"),
            release_branch_prefix: "release-glz/".to_owned(),
            allow_version_zero: false,
            prerelease: None,
            allow_unknown_api_for: BTreeSet::new(),
            baseline_refs: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Manifest {
    path: PathBuf,
    source: String,
    document: DocumentMut,
    pub package: String,
    pub version: Version,
    pub repository: RepositoryConfig,
    pub release: ReleaseConfig,
}

impl Manifest {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let source = fs::read_to_string(path)
            .with_context(|| format!("failed to read manifest `{}`", path.display()))?;
        Self::parse(path.to_path_buf(), source)
    }

    pub fn parse(path: PathBuf, source: String) -> Result<Self> {
        let document = source
            .parse::<DocumentMut>()
            .with_context(|| format!("invalid TOML in `{}`", path.display()))?;
        let package = required_string(&document, "name")?.to_owned();
        validate_package_name(&package)?;
        let version = required_string(&document, "version")?
            .parse::<Version>()
            .with_context(|| "`version` must be a valid semantic version")?;
        let repository = parse_repository(&document)?;
        let release = parse_release_config(&document)?;
        Ok(Self {
            path,
            source,
            document,
            package,
            version,
            repository,
            release,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn package_dir(&self) -> &Path {
        self.path.parent().unwrap_or_else(|| Path::new("."))
    }

    pub fn original_source(&self) -> &str {
        &self.source
    }

    pub fn has_release_config(&self) -> bool {
        self.document
            .get("tools")
            .and_then(Item::as_table_like)
            .and_then(|tools| tools.get("release-glz"))
            .is_some()
    }

    /// Render a complete schema 2 configuration for a package that has never
    /// been configured for release-glz. Existing release configuration is
    /// intentionally handled by migration or workflow refresh instead.
    pub fn render_initialized(&self, settings: &InitializationSettings) -> Result<String> {
        if self.has_release_config() {
            bail!("init profiles are only valid for an unconfigured package");
        }
        if self.version.major == 0 && !settings.allow_version_zero {
            bail!(
                "initializing a 0.x package requires the explicit --allow-version-zero policy opt-in"
            );
        }
        validate_git_ref(
            &format!("refs/heads/{}", settings.default_branch),
            "detected default branch",
        )?;
        validate_release_config(&ReleaseConfig {
            schema: 2,
            compiler: settings.compiler.clone(),
            registry: settings.registry.clone(),
            approval: ApprovalConfig {
                manual_refs: vec![format!("refs/heads/{}", settings.default_branch)],
                ..ApprovalConfig::default()
            },
            allow_version_zero: settings.allow_version_zero,
            compatibility_warnings: Vec::new(),
            ..ReleaseConfig::default()
        })?;
        if self
            .document
            .get("tools")
            .is_some_and(|tools| tools.as_table_like().is_none())
        {
            bail!("an inline or non-table `tools` value must be expanded before initialization");
        }

        let mut rendered = self.source.trim_end().to_owned();
        if !rendered.is_empty() {
            rendered.push_str("\n\n");
        }
        let registry = &settings.registry;
        rendered.push_str(&format!(
            "[tools.release-glz]\n\
schema = 2\n\
compiler = {}\n\
release_branch_prefix = \"release-glz/\"\n\
allow_version_zero = {}\n\
api_exceptions = []\n\n\
[tools.release-glz.registry]\n\
provider = {}\n{}\
api_url = {}\n\
repository_url = {}\n\
docs_url = {}\n\
credential_env = {}\n\
auth = {}\n\
allow_http_loopback = {}\n\n\
[tools.release-glz.approval]\n\
normal = \"release-pr-and-environment\"\n\
manual = \"environment\"\n\
environment = \"release\"\n\
separation = \"solo\"\n\
manual_refs = [{}]\n\n\
[tools.release-glz.outputs]\n\
docs = true\n\
github_release = true\n\
sbom = true\n\
provenance = true\n\
signature = false\n\
allow_private_evidence_upload = false\n\n\
[tools.release-glz.hooks]\n\
verify = []\n\
sidecar = []\n\
notify = []\n\n\
[tools.release-glz.changelog]\n\
path = \"CHANGELOG.md\"\n\
managed_block = true\n\
notes_dir = \".release-glz/notes\"\n\n\
[tools.release-glz.baseline_refs]\n",
            toml_string(&settings.compiler.to_string()),
            settings.allow_version_zero,
            toml_string(match registry.provider {
                RegistryProvider::HexPm => "hexpm",
                RegistryProvider::HexCompatible => "hex-compatible",
            }),
            registry
                .repository
                .as_ref()
                .map(|repository| format!("repository = {}\n", toml_string(repository)))
                .unwrap_or_default(),
            toml_string(&registry.api_url),
            toml_string(&registry.repository_url),
            toml_string(&registry.docs_url),
            toml_string(&registry.credential_env),
            toml_string(match registry.auth {
                AuthKind::HexToken => "hex-token",
                AuthKind::Bearer => "bearer",
            }),
            registry.allow_http_loopback,
            toml_string(&format!("refs/heads/{}", settings.default_branch)),
        ));
        Self::parse(self.path.clone(), rendered.clone())
            .context("generated schema 2 configuration did not validate")?;
        Ok(rendered)
    }

    pub fn replace_source(&mut self, rendered: String) -> Result<()> {
        let current = fs::read_to_string(&self.path)
            .with_context(|| format!("failed to re-read `{}`", self.path.display()))?;
        if current != self.source {
            bail!("manifest changed after initialization was prepared; refusing to replace it");
        }
        if rendered == self.source {
            return Ok(());
        }
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        use std::io::Write as _;
        temporary.write_all(rendered.as_bytes())?;
        let permissions = fs::metadata(&self.path)
            .with_context(|| format!("failed to inspect `{}` permissions", self.path.display()))?
            .permissions();
        temporary
            .as_file()
            .set_permissions(permissions)
            .with_context(|| format!("failed to preserve `{}` permissions", self.path.display()))?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&self.path)
            .map_err(|error| error.error)
            .with_context(|| format!("failed to atomically write `{}`", self.path.display()))?;
        self.source = rendered;
        Ok(())
    }

    pub fn render_with_version(&self, version: &Version) -> String {
        let mut document = self.document.clone();
        document["version"] = value(version.to_string());
        document.to_string()
    }

    pub fn set_version(&mut self, version: Version) {
        self.document["version"] = value(version.to_string());
        self.version = version;
    }

    pub fn set_prerelease(&mut self, channel: Option<PrereleaseChannel>) {
        ensure_release_table(&mut self.document);
        let release = self
            .document
            .get_mut("tools")
            .and_then(Item::as_table_like_mut)
            .and_then(|tools| tools.get_mut("release-glz"))
            .and_then(Item::as_table_like_mut)
            .expect("validated release-glz table");
        match channel {
            Some(channel) => {
                release.insert("prerelease", value(channel.as_str()));
            }
            None => {
                release.remove("prerelease");
            }
        }
        self.release.prerelease = channel;
    }

    pub fn render(&self) -> String {
        self.document.to_string()
    }

    pub fn write(&mut self) -> Result<()> {
        let rendered = self.render();
        self.replace_source(rendered)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitializationSettings {
    pub compiler: Version,
    pub default_branch: String,
    pub registry: RegistryConfig,
    pub allow_version_zero: bool,
}

fn toml_string(value: &str) -> String {
    toml_edit::Value::from(value).to_string()
}

fn required_string<'a>(document: &'a DocumentMut, key: &str) -> Result<&'a str> {
    document
        .get(key)
        .and_then(Item::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing string `{key}` in gleam.toml"))
}

fn parse_repository(document: &DocumentMut) -> Result<RepositoryConfig> {
    let mut output = RepositoryConfig::default();
    let Some(repository) = document.get("repository") else {
        return Ok(output);
    };
    let get = |key: &str| -> Option<String> {
        repository
            .get(key)
            .and_then(Item::as_str)
            .map(str::to_owned)
    };
    output.kind = get("type");
    output.user = get("user");
    output.repo = get("repo");
    output.path = get("path");
    output.tag_prefix = get("tag_prefix")
        .or_else(|| get("tag-prefix"))
        .unwrap_or_default();
    if let Some(path) = &output.path {
        validate_relative_path(Path::new(path), "repository.path")?;
    }
    validate_ref_prefix(&output.tag_prefix, "repository.tag_prefix", true)?;
    Ok(output)
}

fn parse_release_config(document: &DocumentMut) -> Result<ReleaseConfig> {
    let mut output = ReleaseConfig::default();
    let Some(tools) = document.get("tools") else {
        return Ok(output);
    };
    let tools = tools.as_table_like().context("`tools` must be a table")?;
    let Some(table) = tools.get("release-glz") else {
        return Ok(output);
    };
    if !table.is_table_like() {
        bail!("`tools.release-glz` must be a table");
    }

    if let Some(schema) = table.get("schema") {
        match schema.as_integer() {
            Some(2) => return parse_v2_release_config(&document.to_string()),
            Some(1) => {}
            Some(value) => {
                bail!("unsupported release-glz schema {value}; expected 1 or 2")
            }
            None => bail!("release-glz schema must be an integer"),
        }
    }
    if [
        "compiler",
        "registry",
        "approval",
        "outputs",
        "hooks",
        "changelog",
        "api_exceptions",
    ]
    .iter()
    .any(|key| table.get(key).is_some())
    {
        bail!("structured release-glz configuration requires explicit `schema = 2`");
    }

    if let Some(path) = table.get("changelog_path").and_then(Item::as_str) {
        output.changelog_path = PathBuf::from(path);
        output.changelog.path = output.changelog_path.clone();
    }
    if let Some(prefix) = table.get("release_branch_prefix").and_then(Item::as_str) {
        output.release_branch_prefix = prefix.to_owned();
    }
    if let Some(allow) = table.get("allow_version_zero").and_then(Item::as_bool) {
        output.allow_version_zero = allow;
    }
    if let Some(channel) = table.get("prerelease").and_then(Item::as_str) {
        output.prerelease = Some(channel.parse().map_err(anyhow::Error::msg)?);
    }
    if let Some(versions) = table.get("allow_unknown_api_for").and_then(Item::as_array) {
        for version in versions.iter() {
            let Some(version) = version.as_str() else {
                bail!("`allow_unknown_api_for` must contain version strings");
            };
            output.allow_unknown_api_for.insert(
                version
                    .parse()
                    .with_context(|| format!("invalid override version `{version}`"))?,
            );
        }
    }
    if let Some(refs) = table.get("baseline_refs").and_then(Item::as_table_like) {
        for (version, git_ref) in refs.iter() {
            let Some(git_ref) = git_ref.as_str() else {
                bail!("baseline ref for `{version}` must be a string");
            };
            output.baseline_refs.insert(
                version
                    .parse()
                    .with_context(|| format!("invalid baseline version `{version}`"))?,
                git_ref.to_owned(),
            );
        }
    }
    validate_release_config(&output)?;
    Ok(output)
}

#[derive(Debug, Deserialize)]
struct V2Root {
    tools: V2Tools,
}

#[derive(Debug, Deserialize)]
struct V2Tools {
    #[serde(rename = "release-glz")]
    release_glz: V2ReleaseConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V2ReleaseConfig {
    schema: u32,
    compiler: Version,
    registry: RegistryConfig,
    approval: ApprovalConfig,
    #[serde(default)]
    outputs: OutputConfig,
    #[serde(default)]
    hooks: HooksConfig,
    #[serde(default)]
    changelog: ChangelogConfig,
    #[serde(default = "default_release_branch_prefix")]
    release_branch_prefix: String,
    #[serde(default)]
    allow_version_zero: bool,
    #[serde(default)]
    prerelease: Option<PrereleaseChannel>,
    #[serde(default)]
    baseline_refs: BTreeMap<Version, String>,
    #[serde(default)]
    api_exceptions: Vec<ApiException>,
}

fn default_release_branch_prefix() -> String {
    "release-glz/".into()
}

fn parse_v2_release_config(source: &str) -> Result<ReleaseConfig> {
    let root: V2Root = toml_edit::de::from_str(source).map_err(|error| {
        anyhow::anyhow!("invalid `[tools.release-glz]` schema 2 configuration: {error}")
    })?;
    let raw = root.tools.release_glz;
    if raw.schema != 2 {
        bail!("unsupported release-glz schema {}; expected 2", raw.schema);
    }
    let allow_unknown_api_for = raw
        .api_exceptions
        .iter()
        .map(|exception| exception.version.clone())
        .collect();
    let mut output = ReleaseConfig {
        schema: raw.schema,
        compiler: raw.compiler,
        registry: raw.registry,
        approval: raw.approval,
        outputs: raw.outputs,
        hooks: raw.hooks,
        changelog_path: raw.changelog.path.clone(),
        changelog: raw.changelog,
        api_exceptions: raw.api_exceptions,
        compatibility_warnings: Vec::new(),
        release_branch_prefix: raw.release_branch_prefix,
        allow_version_zero: raw.allow_version_zero,
        prerelease: raw.prerelease,
        allow_unknown_api_for,
        baseline_refs: raw.baseline_refs,
    };
    validate_release_config(&output)?;
    // Keep the compatibility field exactly aligned with the structured value.
    output.changelog_path = output.changelog.path.clone();
    Ok(output)
}

fn validate_release_config(config: &ReleaseConfig) -> Result<()> {
    validate_relative_path(&config.changelog.path, "changelog.path")?;
    validate_relative_path(&config.changelog.notes_dir, "changelog.notes_dir")?;
    validate_release_branch_prefix(&config.release_branch_prefix)?;
    validate_registry(&config.registry)?;

    if config.approval.environment.is_empty()
        || config.approval.environment.contains(['\n', '\r', '\0'])
    {
        bail!("approval.environment must be a non-empty single-line name");
    }
    if config.approval.normal != ApprovalMode::ReleasePrAndEnvironment
        || config.approval.manual != ApprovalMode::Environment
    {
        bail!(
            "approval modes are fixed: normal must be `release-pr-and-environment` and manual must be `environment`"
        );
    }
    if let Some(fallback) = &config.approval.private_repository_fallback
        && fallback != "workflow-dispatch-digest"
    {
        bail!("approval.private_repository_fallback must be `workflow-dispatch-digest` when set");
    }
    if config.approval.manual_refs.is_empty() {
        bail!("approval.manual_refs must contain at least one explicit full ref");
    }
    let mut manual_refs = BTreeSet::new();
    for git_ref in &config.approval.manual_refs {
        if !(git_ref.starts_with("refs/heads/") || git_ref.starts_with("refs/tags/")) {
            bail!("approval.manual_refs entries must start with `refs/heads/` or `refs/tags/`");
        }
        validate_git_ref(git_ref, "approval.manual_refs")?;
        if !manual_refs.insert(git_ref) {
            bail!("approval.manual_refs contains duplicate `{git_ref}`");
        }
    }

    let mut ids = BTreeSet::new();
    for hook in config
        .hooks
        .verify
        .iter()
        .chain(&config.hooks.sidecar)
        .chain(&config.hooks.notify)
    {
        validate_hook_config(hook)?;
        if hook
            .env
            .iter()
            .any(|name| protected_hook_environment(name, &config.registry.credential_env))
        {
            bail!(
                "hook `{}` may not receive release-glz authorization or registry credentials",
                hook.id
            );
        }
        if !ids.insert(&hook.id) {
            bail!("duplicate hook id `{}`", hook.id);
        }
    }
    let mut exception_versions = BTreeSet::new();
    for exception in &config.api_exceptions {
        if !exception_versions.insert(&exception.version) {
            bail!("duplicate API exception for version {}", exception.version);
        }
        if exception.reason.trim().is_empty() {
            bail!("API exception for {} requires a reason", exception.version);
        }
        validate_git_ref(&exception.baseline, "api_exceptions.baseline")?;
        chrono::NaiveDate::parse_from_str(&exception.expires, "%Y-%m-%d").with_context(|| {
            format!(
                "API exception expiry `{}` must use YYYY-MM-DD",
                exception.expires
            )
        })?;
    }
    for git_ref in config.baseline_refs.values() {
        validate_git_ref(git_ref, "baseline_refs")?;
    }
    Ok(())
}

fn validate_registry(registry: &RegistryConfig) -> Result<()> {
    if !valid_env_name(&registry.credential_env) {
        bail!(
            "registry.credential_env must name an uppercase environment variable, not contain a credential"
        );
    }
    validate_registry_repository(registry.provider, registry.repository.as_deref())?;
    for (name, value) in [
        ("api_url", &registry.api_url),
        ("repository_url", &registry.repository_url),
        ("docs_url", &registry.docs_url),
    ] {
        let url = reqwest::Url::parse(value)
            .with_context(|| format!("registry.{name} is not a valid URL"))?;
        if !url.username().is_empty() || url.password().is_some() {
            bail!("registry.{name} must not contain credentials");
        }
        if url.host_str().is_none() || url.cannot_be_a_base() {
            bail!("registry.{name} must be an absolute hierarchical URL");
        }
        if url.query().is_some() || url.fragment().is_some() {
            bail!("registry.{name} must not contain a query or fragment");
        }
        let secure = url.scheme() == "https";
        let loopback = url_is_http_loopback(&url);
        if !(secure || registry.allow_http_loopback && loopback) {
            bail!("registry.{name} must use HTTPS (HTTP is test-only on loopback)");
        }
    }
    Ok(())
}

pub fn host_is_loopback_ip(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

pub fn url_is_http_loopback(url: &reqwest::Url) -> bool {
    url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("localhost") || host_is_loopback_ip(host))
}

pub fn validate_registry_repository(
    _provider: RegistryProvider,
    repository: Option<&str>,
) -> Result<()> {
    let Some(repository) = repository else {
        return Ok(());
    };
    let valid = repository.len() <= 255
        && repository
            .bytes()
            .enumerate()
            .all(|(index, byte)| match byte {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => true,
                b'_' | b'-' => index > 0,
                _ => false,
            });
    if !valid || repository.is_empty() {
        bail!("registry.repository must be a safe Hex organization name");
    }
    Ok(())
}

pub fn validate_hook_config(hook: &HookConfig) -> Result<()> {
    let valid_id = !hook.id.is_empty()
        && hook.id.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'A'..=b'Z' => true,
            b'0'..=b'9' | b'_' | b'-' | b'.' => index > 0,
            _ => false,
        });
    if !valid_id {
        bail!("hook id `{}` is unsafe", hook.id);
    }
    if hook.argv.is_empty()
        || hook
            .argv
            .iter()
            .any(|arg| arg.is_empty() || arg.contains('\0'))
    {
        bail!("hook `{}` must have a non-empty NUL-free argv", hook.id);
    }
    if !(1..=3_600).contains(&hook.timeout_seconds) {
        bail!(
            "hook `{}` timeout_seconds must be between 1 and 3600",
            hook.id
        );
    }
    if hook.env.iter().any(|name| !valid_env_name(name)) {
        bail!(
            "hook `{}` contains an invalid allowed environment name",
            hook.id
        );
    }
    if hook
        .env
        .iter()
        .any(|name| protected_hook_environment(name, ""))
    {
        bail!(
            "hook `{}` may not receive release-glz authorization credentials or GitHub control files",
            hook.id
        );
    }
    Ok(())
}

pub fn protected_hook_environment(name: &str, registry_credential_env: &str) -> bool {
    (!registry_credential_env.is_empty() && name == registry_credential_env)
        || matches!(
            name,
            "HEXPM_API_KEY"
                | "GITHUB_TOKEN"
                | "GH_TOKEN"
                | "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
                | "ACTIONS_ID_TOKEN_REQUEST_URL"
                | "ACTIONS_RUNTIME_TOKEN"
                | "GITHUB_ENV"
                | "GITHUB_OUTPUT"
                | "GITHUB_PATH"
                | "GITHUB_STEP_SUMMARY"
        )
}

pub fn valid_env_name(value: &str) -> bool {
    value.bytes().enumerate().all(|(index, byte)| match byte {
        b'A'..=b'Z' | b'_' => true,
        b'0'..=b'9' => index > 0,
        _ => false,
    }) && !value.is_empty()
}

pub fn validate_package_name(value: &str) -> Result<()> {
    let valid = value.bytes().enumerate().all(|(index, byte)| match byte {
        b'a'..=b'z' => true,
        b'0'..=b'9' | b'_' => index > 0,
        _ => false,
    });
    if value.is_empty() || !valid {
        bail!("package name must start with a lowercase letter and contain only a-z, 0-9, or _");
    }
    Ok(())
}

pub fn validate_relative_path(path: &Path, field: &str) -> Result<()> {
    if path.as_os_str().is_empty() || path.to_string_lossy().contains('\\') {
        bail!("{field} must be a non-empty repository-relative `/` path");
    }
    if path
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("{field} must stay within the repository");
    }
    Ok(())
}

fn validate_ref_prefix(value: &str, field: &str, empty_allowed: bool) -> Result<()> {
    if value.is_empty() && empty_allowed {
        return Ok(());
    }
    if value.is_empty() || value.starts_with(['/', '-', '.']) || value.starts_with("refs/") {
        bail!("{field} contains an unsafe git ref prefix");
    }
    validate_git_ref(&format!("{value}release-glz"), field)?;
    Ok(())
}

pub fn validate_release_branch_prefix(value: &str) -> Result<()> {
    validate_ref_prefix(value, "release_branch_prefix", false)
}

pub fn validate_git_ref(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value == "@"
        || value.starts_with(['/', '-', '.'])
        || value.ends_with(['/', '.'])
        || value.contains("..")
        || value.contains("//")
        || value.contains("@{")
        || value.bytes().any(|byte| {
            byte <= b' '
                || byte == 0x7f
                || matches!(byte, b'\\' | b'~' | b'^' | b':' | b'?' | b'*' | b'[')
        })
        || value
            .split('/')
            .any(|component| component.starts_with('.') || component.ends_with(".lock"))
    {
        bail!("{field} contains an unsafe git ref");
    }
    Ok(())
}

fn ensure_release_table(document: &mut DocumentMut) {
    if !document.as_table().contains_key("tools") {
        document["tools"] = Item::Table(Table::new());
    }
    let inline = document
        .get("tools")
        .and_then(Item::as_inline_table)
        .is_some();
    let tools = document
        .get_mut("tools")
        .and_then(Item::as_table_like_mut)
        .expect("validated tools table");
    if tools.get("release-glz").is_none() {
        let release = if inline {
            Item::Value(toml_edit::Value::InlineTable(toml_edit::InlineTable::new()))
        } else {
            Item::Table(Table::new())
        };
        tools.insert("release-glz", release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_edit_preserves_comments_order_and_spelling() {
        let source = r#"# leading comment
name = "wibble" # package
version = "1.2.3"

[repository]
type = "github"
user = "owner"
repo = "wibble"
tag-prefix = "packages/wibble/"

[tools.release-glz]
allow_unknown_api_for = ["1.2.3"]

[tools.release-glz.baseline_refs]
"1.2.3" = "abc123"
"#;
        let manifest = Manifest::parse(PathBuf::from("gleam.toml"), source.to_owned()).unwrap();
        let rendered = manifest.render_with_version(&Version::new(2, 0, 0));
        assert_eq!(
            rendered,
            source.replace("1.2.3\"\n\n[repository]", "2.0.0\"\n\n[repository]")
        );
        assert_eq!(
            manifest.repository.tag_for(&Version::new(2, 0, 0)),
            "packages/wibble/v2.0.0"
        );
        assert_eq!(
            manifest.release.baseline_refs[&Version::new(1, 2, 3)],
            "abc123"
        );
    }

    #[test]
    fn prerelease_setting_round_trips_other_content() {
        let source = "name = \"x\"\nversion = \"1.0.0\"\n# keep me\n";
        let mut manifest = Manifest::parse(PathBuf::from("gleam.toml"), source.to_owned()).unwrap();
        manifest.set_prerelease(Some(PrereleaseChannel::Rc));
        let rendered = manifest.render();
        assert!(rendered.contains("# keep me"));
        assert!(rendered.contains("prerelease = \"rc\""));
        manifest.set_prerelease(None);
        assert!(!manifest.render().contains("prerelease ="));
    }

    #[test]
    fn inline_repository_uses_gleams_snake_case_tag_prefix() {
        let source = r#"name = "x"
version = "1.0.0"
repository = { type = "github", user = "owner", repo = "x", tag_prefix = "x-" }
"#;
        let manifest = Manifest::parse(PathBuf::from("gleam.toml"), source.into()).unwrap();
        assert_eq!(
            manifest.repository.github_name().as_deref(),
            Some("owner/x")
        );
        assert_eq!(
            manifest.repository.tag_for(&Version::new(1, 2, 3)),
            "x-v1.2.3"
        );
    }

    #[test]
    fn prerelease_edits_preserve_inline_tools_and_release_tables() {
        let source = r#"name = "x"
version = "1.0.0"
tools = { other = { keep = true }, "release-glz" = { prerelease = "alpha" } }
"#;
        let mut manifest = Manifest::parse(PathBuf::from("gleam.toml"), source.into()).unwrap();
        manifest.set_prerelease(Some(PrereleaseChannel::Rc));
        let rendered = manifest.render();
        assert!(rendered.contains("keep = true"), "{rendered}");
        assert!(rendered.contains("prerelease = \"rc\""), "{rendered}");

        let source = r#"name = "x"
version = "1.0.0"
tools = { other = "preserve" }
"#;
        let mut manifest = Manifest::parse(PathBuf::from("gleam.toml"), source.into()).unwrap();
        manifest.set_prerelease(Some(PrereleaseChannel::Beta));
        let rendered = manifest.render();
        assert!(rendered.contains("other = \"preserve\""), "{rendered}");
        assert!(rendered.contains("prerelease = \"beta\""), "{rendered}");
    }

    #[test]
    fn initialization_preserves_unrelated_empty_prerelease_values() {
        let source = r#"name = "x"
version = "1.0.0"

[tools.other]
prerelease = ""
"#;
        let manifest = Manifest::parse(PathBuf::from("gleam.toml"), source.into()).unwrap();
        let rendered = manifest
            .render_initialized(&InitializationSettings {
                compiler: Version::new(1, 18, 1),
                default_branch: "main".into(),
                registry: RegistryConfig::default(),
                allow_version_zero: false,
            })
            .unwrap();
        assert!(rendered.contains("[tools.other]\nprerelease = \"\""));
        let parsed = Manifest::parse(PathBuf::from("gleam.toml"), rendered).unwrap();
        assert_eq!(parsed.release.prerelease, None);
    }

    #[test]
    fn manifest_write_is_atomic_and_refuses_a_changed_source() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("gleam.toml");
        let source = "name = \"x\"\nversion = \"1.0.0\"\n";
        fs::write(&path, source).unwrap();
        let mut manifest = Manifest::load(&path).unwrap();
        manifest.set_version(Version::new(1, 1, 0));

        let concurrent = "name = \"x\"\nversion = \"1.0.0\"\n# concurrent edit\n";
        fs::write(&path, concurrent).unwrap();
        assert!(manifest.write().is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), concurrent);

        let mut current = Manifest::load(&path).unwrap();
        current.set_version(Version::new(1, 1, 0));
        current.write().unwrap();
        assert!(fs::read_to_string(&path).unwrap().contains("1.1.0"));
    }
}
