//! Strictly typed `gleam.toml` configuration.
//!
//! Unknown keys, wrong types, paths outside the repository, unsafe ref prefixes, URLs carrying credentials, and registry origins that use neither HTTPS nor plain HTTP to a numeric loopback address are rejected here rather than at the point of use, so an invalid manifest cannot reach a publication path at all.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use semver::Version;
use serde::{Deserialize, Serialize};
use toml_edit::{DocumentMut, Item, TableLike, value};

use crate::failure::{Refusal, RefusalReason, refused};
use crate::model::PrereleaseChannel;
use crate::refuse;

/// Base URL of the hex.pm publish API.
const HEXPM_API_URL: &str = "https://hex.pm/api";

/// Base URL that serves hex.pm package tarballs.
const HEXPM_REPOSITORY_URL: &str = "https://repo.hex.pm";

/// Base URL that receives hex.pm documentation tarballs.
const HEXPM_DOCS_URL: &str = "https://repo.hex.pm/docs";

/// Base URL of the hex.pm package pages.
const HEXPM_PACKAGES_URL: &str = "https://hex.pm/packages";

/// The only `schema` that `[tools.release-glz]` may set.
const RELEASE_CONFIG_SCHEMA: i64 = 2;

/// The key under `[tools]` that holds the release-glz configuration.
const RELEASE_TABLE: &str = "release-glz";

/// The ASCII delete control character, which Git refuses in a ref.
const ASCII_DELETE: u8 = 0x7f;

/// The hook id of the SBOM and provenance that release-glz builds itself, which no configured hook may take.
pub const BUILT_IN_HOOK_ID: &str = "release-glz";

/// Seconds a hook may run for when the manifest names no timeout.
const DEFAULT_HOOK_TIMEOUT_SECONDS: u64 = 300;

/// Shortest hook timeout a manifest may configure.
const MIN_HOOK_TIMEOUT_SECONDS: u64 = 1;

/// Longest hook timeout a manifest may configure.
const MAX_HOOK_TIMEOUT_SECONDS: u64 = 3_600;

/// Characters a Hex organization name may use.
const MAX_REPOSITORY_LEN: usize = 255;

/// The `[repository]` table that names the package's forge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepositoryConfig {
    /// Forge kind; only `github` participates in the release path.
    pub kind: Option<String>,
    /// Owner of the repository on the forge.
    pub user: Option<String>,
    /// Repository name on the forge.
    pub repo: Option<String>,
    /// Package directory inside the repository, for a monorepo.
    pub path: Option<String>,
    /// Prefix placed before `v<version>` when building the release tag.
    pub tag_prefix: String,
}

impl RepositoryConfig {
    /// The release tag for a version, including the configured prefix.
    pub fn tag_for(&self, version: &Version) -> String {
        format!("{}v{version}", self.tag_prefix)
    }

    /// The `owner/name` GitHub slug, when this package lives on GitHub.
    pub fn github_name(&self) -> Option<String> {
        match (&self.kind, &self.user, &self.repo) {
            (Some(kind), Some(user), Some(repo)) if kind == "github" => {
                Some(format!("{user}/{repo}"))
            }
            _ => None,
        }
    }
}

/// The registry protocol a package publishes through.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RegistryProvider {
    /// Public Hex.pm, or a Hex.pm Organization repository.
    #[default]
    #[serde(rename = "hexpm")]
    HexPm,
    /// A private registry that speaks the Hex API and repository protocol.
    HexCompatible,
}

/// How the registry credential is presented on a request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthKind {
    /// A Hex API key, sent the way Hex.pm expects it.
    #[default]
    HexToken,
    /// An RFC 6750 bearer token.
    Bearer,
}

/// The `[tools.release-glz.registry]` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryConfig {
    /// Which registry protocol to use.
    pub provider: RegistryProvider,
    /// Hex.pm Organization name, for an organization repository.
    #[serde(default)]
    pub repository: Option<String>,
    /// Base URL of the publish API.
    pub api_url: String,
    /// Base URL that serves package tarballs.
    pub repository_url: String,
    /// Base URL that receives documentation tarballs.
    pub docs_url: String,
    /// Name of the environment variable holding the credential.
    ///
    /// This is a variable name, never a credential value, so a manifest can be committed and only the protected publish job resolves it.
    pub credential_env: String,
    /// How to present the credential.
    pub auth: AuthKind,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            provider: RegistryProvider::HexPm,
            repository: None,
            api_url: HEXPM_API_URL.into(),
            repository_url: HEXPM_REPOSITORY_URL.into(),
            docs_url: HEXPM_DOCS_URL.into(),
            credential_env: "HEXPM_API_KEY".into(),
            auth: AuthKind::HexToken,
        }
    }
}

impl RegistryConfig {
    /// The hex.pm configuration for a Hex.pm Organization repository.
    pub fn hexpm_organization(organization: &str) -> Self {
        Self {
            repository: Some(organization.to_owned()),
            repository_url: format!("{HEXPM_REPOSITORY_URL}/repos/{organization}"),
            docs_url: format!("{HEXPM_REPOSITORY_URL}/repos/{organization}/docs"),
            ..Self::default()
        }
    }

    /// The web page of a published package release.
    ///
    /// Only hex.pm serves package pages, so a Hex-compatible registry has none.
    pub fn package_page(&self, package: &str, version: &Version) -> Option<String> {
        if self.provider != RegistryProvider::HexPm {
            return None;
        }
        Some(match &self.repository {
            Some(organization) => {
                format!("{HEXPM_PACKAGES_URL}/{organization}/{package}/{version}")
            }
            None => format!("{HEXPM_PACKAGES_URL}/{package}/{version}"),
        })
    }
}

/// Which approvals a release has to collect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalMode {
    /// Both a merged Release PR and a protected environment.
    ReleasePrAndEnvironment,
    /// A protected environment alone.
    Environment,
}

/// How strictly the approver has to differ from the author.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeparationMode {
    /// A single maintainer may both propose and approve.
    #[default]
    Solo,
    /// Proposal and approval must come from different identities.
    Strict,
}

/// The `[tools.release-glz.approval]` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConfig {
    /// Approvals required for a release driven by the rolling Release PR.
    pub normal: ApprovalMode,
    /// Approvals required for a manually dispatched release.
    pub manual: ApprovalMode,
    /// GitHub Environment that gates publication.
    pub environment: String,
    /// Whether one identity may both propose and approve.
    #[serde(default)]
    pub separation: SeparationMode,
    /// Refs a manual release may be dispatched from.
    pub manual_refs: Vec<String>,
    /// Environment used when a private repository cannot run the normal protected path.
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

/// The `[tools.release-glz.outputs]` table: what a release produces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutputConfig {
    /// Publish the documentation tarball.
    pub docs: bool,
    /// Create a GitHub Release for the tag.
    pub github_release: bool,
    /// Attach an SBOM to the GitHub Release.
    pub sbom: bool,
    /// Attach in-toto provenance to the GitHub Release.
    pub provenance: bool,
    /// Attach a detached signature to the GitHub Release.
    pub signature: bool,
    /// Allow evidence to be uploaded from a private repository.
    ///
    /// Off by default: evidence describes internal build inputs, and a private package should not leak them without an explicit decision.
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

/// One configured hook invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookConfig {
    /// Identifier reported in hook evidence.
    pub id: String,
    /// Process arguments.
    /// A shell command string is never accepted, so there is no quoting boundary for an input to cross.
    pub argv: Vec<String>,
    /// Wall-clock budget, between 1 and 3600 seconds.
    #[serde(default = "default_hook_timeout")]
    pub timeout_seconds: u64,
    /// Whether failure of this hook fails the command.
    #[serde(default = "default_true")]
    pub required: bool,
    /// Environment variable names the hook may receive.
    ///
    /// Credentials and the GitHub control files are refused even when they are named here.
    #[serde(default)]
    pub env: Vec<String>,
}

fn default_hook_timeout() -> u64 {
    DEFAULT_HOOK_TIMEOUT_SECONDS
}

fn default_true() -> bool {
    true
}

/// The `[tools.release-glz.hooks]` table, grouped by phase.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HooksConfig {
    /// Run against the sealed bytes while the Candidate is built.
    pub verify: Vec<HookConfig>,
    /// Produce extra evidence that travels with the Candidate.
    pub sidecar: Vec<HookConfig>,
    /// Run after publication, with a least-privilege credential.
    pub notify: Vec<HookConfig>,
}

/// The `[tools.release-glz.changelog]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChangelogConfig {
    /// Repository-relative path of the changelog.
    pub path: PathBuf,
    /// Maintain a managed block instead of rewriting the whole file.
    pub managed_block: bool,
    /// Directory holding per-release note fragments.
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

/// An expiring permission to release one version without an API baseline.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiException {
    /// The exact version the exception applies to.
    pub version: Version,
    /// Ref to compare against instead of the missing baseline.
    pub baseline: String,
    /// Why the exception was granted.
    pub reason: String,
    /// Date the exception stops being accepted.
    pub expires: String,
}

impl ApiException {
    /// The `YYYY-MM-DD` date in `expires`, or a refusal when `expires` holds anything else.
    pub fn expiry(&self) -> Result<chrono::NaiveDate> {
        chrono::NaiveDate::parse_from_str(&self.expires, "%Y-%m-%d").with_context(|| {
            Refusal::new(
                RefusalReason::ApiExceptionExpiryInvalid,
                format!(
                    "API exception expiry `{}` must use YYYY-MM-DD",
                    self.expires
                ),
            )
        })
    }
}

/// The `[tools.release-glz]` table, after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseConfig {
    /// Exact Gleam compiler a Candidate must be built with.
    pub compiler: Version,
    /// Where the package is published.
    pub registry: RegistryConfig,
    /// What has to approve a publication.
    pub approval: ApprovalConfig,
    /// Which artifacts a release produces.
    pub outputs: OutputConfig,
    /// Hooks to run, by phase.
    pub hooks: HooksConfig,
    /// How the changelog is maintained.
    pub changelog: ChangelogConfig,
    /// Expiring API baseline exceptions.
    pub api_exceptions: Vec<ApiException>,
    /// Branch prefix for the rolling Release PR.
    pub release_branch_prefix: String,
    /// Permit a deliberate 0.x release line.
    pub allow_version_zero: bool,
    /// Prerelease channel currently selected, if any.
    pub prerelease: Option<PrereleaseChannel>,
    /// Explicit baseline commit per version, used when the artifact search cannot identify one.
    pub baseline_refs: BTreeMap<Version, String>,
}

/// The refusal of an operation that reads `[tools.release-glz]` from a manifest that has none.
///
/// [`crate::failure::classify`] reads it as a usage or configuration failure, so every command that refuses an unconfigured manifest exits the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingReleaseConfig;

impl fmt::Display for MissingReleaseConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "the manifest has no `[tools.release-glz]` configuration; run `release-glz init` to write it",
        )
    }
}

impl std::error::Error for MissingReleaseConfig {}

/// A parsed `gleam.toml`, kept alongside its original bytes.
///
/// Edits go through `toml_edit`, so formatting and comments a maintainer wrote survive a version bump.
#[derive(Debug, Clone)]
pub struct Manifest {
    path: PathBuf,
    source: String,
    document: DocumentMut,
    /// Package name.
    pub package: String,
    /// Version currently declared in the manifest.
    pub version: Version,
    /// The `[repository]` table.
    pub repository: RepositoryConfig,
    release: Option<ReleaseConfig>,
}

impl Manifest {
    /// Read and parse a manifest from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let source = fs::read_to_string(path)
            .with_context(|| format!("failed to read manifest `{}`", path.display()))?;
        Self::parse(path.to_path_buf(), source)
    }

    /// Parse manifest bytes that were already read.
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

    /// Path this manifest was read from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Directory that contains the manifest.
    pub fn package_dir(&self) -> &Path {
        match self.path.parent() {
            Some(directory) if !directory.as_os_str().is_empty() => directory,
            _ => Path::new("."),
        }
    }

    /// The bytes as they were read, before any edit.
    pub fn original_source(&self) -> &str {
        &self.source
    }

    /// The validated `[tools.release-glz]` table, or the refusal that names `release-glz init` when the manifest has none.
    pub fn release(&self) -> Result<&ReleaseConfig, MissingReleaseConfig> {
        self.release.as_ref().ok_or(MissingReleaseConfig)
    }

    /// The validated `[tools.release-glz]` table, for a command that also runs on an unconfigured package.
    pub fn configured_release(&self) -> Option<&ReleaseConfig> {
        self.release.as_ref()
    }

    /// Render a complete configuration for a package that has no `[tools.release-glz]` table.
    ///
    /// A configured package keeps its configuration, and `init` refreshes only its workflow.
    pub fn render_initialized(&self, settings: &InitializationSettings) -> Result<String> {
        if self.release.is_some() {
            bail!("init profiles are only valid for an unconfigured package");
        }
        if self.version.major == 0 && !settings.allow_version_zero {
            bail!(
                "initializing a 0.x package requires the explicit --allow-version-zero policy opt-in"
            );
        }
        // The rest of the rendered configuration is fixed text, so the settings it interpolates are all that can be invalid.
        validate_git_ref(
            &format!("refs/heads/{}", settings.default_branch),
            "detected default branch",
        )?;
        validate_registry(&settings.registry)?;
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
schema = {RELEASE_CONFIG_SCHEMA}\n\
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
auth = {}\n\n\
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
            toml_string(&format!("refs/heads/{}", settings.default_branch)),
        ));
        Self::parse(self.path.clone(), rendered.clone())
            .context("generated release-glz configuration did not validate")?;
        Ok(rendered)
    }

    /// Atomically replace the manifest on disk with rendered bytes.
    ///
    /// The file is re-read first and the write is refused when it changed, so a concurrent edit is never silently overwritten.
    pub fn replace_source(&mut self, rendered: String) -> Result<()> {
        let current = fs::read_to_string(&self.path)
            .with_context(|| format!("failed to re-read `{}`", self.path.display()))?;
        if current != self.source {
            refuse!(
                ManifestChanged,
                "manifest changed after initialization was prepared; refusing to replace it"
            );
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

    /// Render the manifest with a different version, without mutating it.
    pub fn render_with_version(&self, version: &Version) -> String {
        let mut document = self.document.clone();
        set_document_version(&mut document, version);
        document.to_string()
    }

    /// Set the manifest version in memory.
    pub fn set_version(&mut self, version: Version) {
        set_document_version(&mut self.document, &version);
        self.version = version;
    }

    /// Select or clear the prerelease channel in memory.
    ///
    /// Only a configured manifest has a channel, so an unconfigured one is refused and left unchanged.
    pub fn set_prerelease(
        &mut self,
        channel: Option<PrereleaseChannel>,
    ) -> Result<(), MissingReleaseConfig> {
        let release = self.release.as_mut().ok_or(MissingReleaseConfig)?;
        let table = release_table_mut(&mut self.document).ok_or(MissingReleaseConfig)?;
        match channel {
            Some(channel) => {
                table.insert("prerelease", value(channel.as_str()));
            }
            None => {
                table.remove("prerelease");
            }
        }
        release.prerelease = channel;
        Ok(())
    }

    /// Render the current in-memory manifest.
    pub fn render(&self) -> String {
        self.document.to_string()
    }

    /// Write the current in-memory manifest back to disk.
    pub fn write(&mut self) -> Result<()> {
        let rendered = self.render();
        self.replace_source(rendered)
    }
}

/// Everything `init` needs in order to render a first configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitializationSettings {
    /// The compiler that is actually installed.
    pub compiler: Version,
    /// The repository's default branch.
    pub default_branch: String,
    /// Registry the package will publish to.
    pub registry: RegistryConfig,
    /// Whether a 0.x release line was explicitly permitted.
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

/// The `[tools.release-glz]` table, which a manifest that release-glz has not configured lacks.
fn parse_release_config(document: &DocumentMut) -> Result<Option<ReleaseConfig>> {
    let Some(tools) = document.get("tools") else {
        return Ok(None);
    };
    let tools = tools.as_table_like().context("`tools` must be a table")?;
    let Some(table) = tools.get(RELEASE_TABLE) else {
        return Ok(None);
    };
    let table = table
        .as_table_like()
        .context("`tools.release-glz` must be a table")?;
    check_schema(table.get("schema"))?;
    deserialize_release_table(&document.to_string()).map(Some)
}

/// Refuse a `schema` other than [`RELEASE_CONFIG_SCHEMA`], before any other key can make the table fail for a less direct reason.
fn check_schema(schema: Option<&Item>) -> Result<()> {
    let found = match schema {
        Some(schema) if schema.as_integer() == Some(RELEASE_CONFIG_SCHEMA) => return Ok(()),
        Some(Item::Value(schema)) => {
            let mut schema = schema.clone();
            schema.decor_mut().clear();
            format!("`schema = {schema}`")
        }
        Some(_) => "a `schema` table".to_owned(),
        None => "no `schema`".to_owned(),
    };
    refuse!(
        ConfigSchemaUnsupported,
        "`[tools.release-glz]` requires `schema = {RELEASE_CONFIG_SCHEMA}`, but it sets {found}"
    )
}

#[derive(Debug, Deserialize)]
struct ManifestTables {
    tools: ToolsTable,
}

#[derive(Debug, Deserialize)]
struct ToolsTable {
    #[serde(rename = "release-glz")]
    release_glz: ReleaseTable,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseTable {
    /// Accepted here because [`check_schema`] already refused every other value.
    #[serde(rename = "schema")]
    _schema: serde::de::IgnoredAny,
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

fn deserialize_release_table(source: &str) -> Result<ReleaseConfig> {
    let root: ManifestTables = toml_edit::de::from_str(source).map_err(|error| {
        refused(
            RefusalReason::ConfigTableInvalid,
            format_args!("invalid `[tools.release-glz]` configuration: {error}"),
        )
    })?;
    let raw = root.tools.release_glz;
    let output = ReleaseConfig {
        compiler: raw.compiler,
        registry: raw.registry,
        approval: raw.approval,
        outputs: raw.outputs,
        hooks: raw.hooks,
        changelog: raw.changelog,
        api_exceptions: raw.api_exceptions,
        release_branch_prefix: raw.release_branch_prefix,
        allow_version_zero: raw.allow_version_zero,
        prerelease: raw.prerelease,
        baseline_refs: raw.baseline_refs,
    };
    validate_release_config(&output)?;
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
        refuse!(
            ApprovalEnvironmentInvalid,
            "approval.environment must be a non-empty single-line name"
        );
    }
    if config.approval.normal != ApprovalMode::ReleasePrAndEnvironment
        || config.approval.manual != ApprovalMode::Environment
    {
        refuse!(
            ApprovalModeFixed,
            "approval modes are fixed: normal must be `release-pr-and-environment` and manual must be `environment`"
        );
    }
    if let Some(fallback) = &config.approval.private_repository_fallback
        && fallback != "workflow-dispatch-digest"
    {
        refuse!(
            ApprovalFallbackUnsupported,
            "approval.private_repository_fallback must be `workflow-dispatch-digest` when set"
        );
    }
    if config.approval.manual_refs.is_empty() {
        bail!("approval.manual_refs must contain at least one explicit full ref");
    }
    let mut manual_refs = BTreeSet::new();
    for git_ref in &config.approval.manual_refs {
        if !(git_ref.starts_with("refs/heads/") || git_ref.starts_with("refs/tags/")) {
            refuse!(
                ManualRefKindUnsupported,
                "approval.manual_refs entries must start with `refs/heads/` or `refs/tags/`"
            );
        }
        validate_git_ref(git_ref, "approval.manual_refs")?;
        if !manual_refs.insert(git_ref) {
            refuse!(
                ManualRefDuplicate,
                "approval.manual_refs contains duplicate `{git_ref}`"
            );
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
            refuse!(
                HookEnvProtected,
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
            refuse!(
                ApiExceptionDuplicate,
                "duplicate API exception for version {}",
                exception.version
            );
        }
        if exception.reason.trim().is_empty() {
            refuse!(
                ApiExceptionReasonMissing,
                "API exception for {} requires a reason",
                exception.version
            );
        }
        validate_git_ref(&exception.baseline, "api_exceptions.baseline")?;
        exception.expiry()?;
    }
    for git_ref in config.baseline_refs.values() {
        validate_git_ref(git_ref, "baseline_refs")?;
    }
    Ok(())
}

fn validate_registry(registry: &RegistryConfig) -> Result<()> {
    if !valid_env_name(&registry.credential_env) {
        refuse!(
            CredentialEnvInvalid,
            "registry.credential_env must name an uppercase environment variable, not contain a credential"
        );
    }
    validate_registry_repository(registry.provider, registry.repository.as_deref())?;
    for (name, value) in [
        ("api_url", &registry.api_url),
        ("repository_url", &registry.repository_url),
        ("docs_url", &registry.docs_url),
    ] {
        let url = reqwest::Url::parse(value).with_context(|| {
            Refusal::new(
                RefusalReason::UrlMalformed,
                format!("registry.{name} is not a valid URL"),
            )
        })?;
        if !url.username().is_empty() || url.password().is_some() {
            refuse!(
                UrlCredentials,
                "registry.{name} must not contain credentials"
            );
        }
        if url.host_str().is_none() || url.cannot_be_a_base() {
            refuse!(
                UrlNotHierarchical,
                "registry.{name} must be an absolute hierarchical URL"
            );
        }
        if url.query().is_some() || url.fragment().is_some() {
            refuse!(
                UrlQueryOrFragment,
                "registry.{name} must not contain a query or fragment"
            );
        }
        if !uses_trusted_transport(&url) {
            refuse!(
                UrlTransportUntrusted,
                "registry.{name} must use HTTPS, or HTTP to a numeric loopback address"
            );
        }
    }
    Ok(())
}

/// Whether a host literal is a loopback IP address.
pub fn host_is_loopback_ip(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

/// Whether a URL is plain `http` to a numeric loopback address in `127.0.0.0/8` or `::1`.
pub fn url_is_http_loopback(url: &reqwest::Url) -> bool {
    url.scheme() == "http" && url.host_str().is_some_and(host_is_loopback_ip)
}

/// Whether a URL uses HTTPS, or plain `http` to a numeric loopback address in `127.0.0.0/8` or `::1`.
///
/// A host name, `localhost` included, needs HTTPS, because resolving it can leave the host.
/// No configuration key changes this rule.
pub fn uses_trusted_transport(url: &reqwest::Url) -> bool {
    url.scheme() == "https" || url_is_http_loopback(url)
}

/// Reject an organization name that is not a safe path segment.
pub fn validate_registry_repository(
    _provider: RegistryProvider,
    repository: Option<&str>,
) -> Result<()> {
    let Some(repository) = repository else {
        return Ok(());
    };
    let valid = repository.len() <= MAX_REPOSITORY_LEN
        && repository
            .bytes()
            .enumerate()
            .all(|(index, byte)| match byte {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => true,
                b'_' | b'-' => index > 0,
                _ => false,
            });
    if !valid || repository.is_empty() {
        refuse!(
            RegistryRepositoryInvalid,
            "registry.repository must be a safe Hex organization name"
        );
    }
    Ok(())
}

/// Reject a hook that is unsafe to execute.
///
/// Covers the id, the argv, the timeout bounds, and the environment allowlist, which may never name a credential.
pub fn validate_hook_config(hook: &HookConfig) -> Result<()> {
    let valid_id = !hook.id.is_empty()
        && hook.id.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'A'..=b'Z' => true,
            b'0'..=b'9' | b'_' | b'-' | b'.' => index > 0,
            _ => false,
        });
    if !valid_id {
        refuse!(HookIdUnsafe, "hook id `{}` is unsafe", hook.id);
    }
    if hook.id == BUILT_IN_HOOK_ID {
        refuse!(
            HookIdReserved,
            "hook id `{BUILT_IN_HOOK_ID}` is reserved for the evidence that release-glz builds itself"
        );
    }
    if hook.argv.is_empty()
        || hook
            .argv
            .iter()
            .any(|arg| arg.is_empty() || arg.contains('\0'))
    {
        refuse!(
            HookArgvInvalid,
            "hook `{}` must have a non-empty NUL-free argv",
            hook.id
        );
    }
    if !(MIN_HOOK_TIMEOUT_SECONDS..=MAX_HOOK_TIMEOUT_SECONDS).contains(&hook.timeout_seconds) {
        refuse!(
            HookTimeoutOutOfRange,
            "hook `{}` timeout_seconds must be between {MIN_HOOK_TIMEOUT_SECONDS} and {MAX_HOOK_TIMEOUT_SECONDS}",
            hook.id
        );
    }
    if hook.env.iter().any(|name| !valid_env_name(name)) {
        refuse!(
            HookEnvInvalid,
            "hook `{}` contains an invalid allowed environment name",
            hook.id
        );
    }
    if hook
        .env
        .iter()
        .any(|name| protected_hook_environment(name, ""))
    {
        refuse!(
            HookEnvProtected,
            "hook `{}` may not receive release-glz authorization credentials or GitHub control files",
            hook.id
        );
    }
    Ok(())
}

/// Whether an environment name is one a hook may never receive.
///
/// Covers registry and GitHub credentials plus the GitHub control files, which a hook could otherwise use to rewrite job outputs.
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
                | "GITHUB_STATE"
                | "GITHUB_STEP_SUMMARY"
        )
}

/// Whether a string is a safe environment variable name.
pub fn valid_env_name(value: &str) -> bool {
    value.bytes().enumerate().all(|(index, byte)| match byte {
        b'A'..=b'Z' | b'_' => true,
        b'0'..=b'9' => index > 0,
        _ => false,
    }) && !value.is_empty()
}

/// Reject a package name Hex would not accept.
pub fn validate_package_name(value: &str) -> Result<()> {
    let valid = value.bytes().enumerate().all(|(index, byte)| match byte {
        b'a'..=b'z' => true,
        b'0'..=b'9' | b'_' => index > 0,
        _ => false,
    });
    if value.is_empty() || !valid {
        refuse!(
            PackageNameInvalid,
            "package name must start with a lowercase letter and contain only a-z, 0-9, or _"
        );
    }
    Ok(())
}

/// Reject a path that escapes the repository or is not `/`-separated.
pub fn validate_relative_path(path: &Path, field: &str) -> Result<()> {
    if path.as_os_str().is_empty() || path.to_string_lossy().contains('\\') {
        refuse!(
            PathNotRelative,
            "{field} must be a non-empty repository-relative `/` path"
        );
    }
    if path
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        refuse!(
            PathOutsideRepository,
            "{field} must stay within the repository"
        );
    }
    Ok(())
}

fn validate_ref_prefix(value: &str, field: &str, empty_allowed: bool) -> Result<()> {
    if value.is_empty() && empty_allowed {
        return Ok(());
    }
    if value.is_empty() || value.starts_with(['/', '-', '.']) || value.starts_with("refs/") {
        refuse!(
            GitRefPrefixUnsafe,
            "{field} contains an unsafe git ref prefix"
        );
    }
    validate_git_ref(&format!("{value}release-glz"), field)?;
    Ok(())
}

/// Reject a branch prefix that could produce an unsafe ref.
pub fn validate_release_branch_prefix(value: &str) -> Result<()> {
    validate_ref_prefix(value, "release_branch_prefix", false)
}

/// Reject a git ref that is unsafe or that git itself would refuse.
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
                || byte == ASCII_DELETE
                || matches!(byte, b'\\' | b'~' | b'^' | b':' | b'?' | b'*' | b'[')
        })
        || value
            .split('/')
            .any(|component| component.starts_with('.') || component.ends_with(".lock"))
    {
        refuse!(GitRefUnsafe, "{field} contains an unsafe git ref");
    }
    Ok(())
}

fn set_document_version(document: &mut DocumentMut, version: &Version) {
    *document.entry("version").or_insert(Item::None) = value(version.to_string());
}

fn release_table_mut(document: &mut DocumentMut) -> Option<&mut dyn TableLike> {
    document
        .get_mut("tools")
        .and_then(Item::as_table_like_mut)
        .and_then(|tools| tools.get_mut(RELEASE_TABLE))
        .and_then(Item::as_table_like_mut)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The release table of a configured manifest, with `extra` after its first keys.
    fn release_table(extra: &str) -> String {
        format!(
            r#"[tools.release-glz]
schema = 2
compiler = "1.18.1"
{extra}
[tools.release-glz.registry]
provider = "hexpm"
api_url = "https://hex.pm/api"
repository_url = "https://repo.hex.pm"
docs_url = "https://repo.hex.pm/docs"
credential_env = "HEXPM_API_KEY"
auth = "hex-token"

[tools.release-glz.approval]
normal = "release-pr-and-environment"
manual = "environment"
environment = "release"
separation = "solo"
manual_refs = ["refs/heads/main"]
"#
        )
    }

    #[test]
    fn version_edit_preserves_comments_order_and_spelling() {
        let source = format!(
            r#"# leading comment
name = "wibble" # package
version = "1.2.3"

[repository]
type = "github"
user = "owner"
repo = "wibble"
tag-prefix = "packages/wibble/"

{}
[tools.release-glz.baseline_refs]
"1.2.3" = "abc123"
"#,
            release_table("# pinned by hand\n")
        );
        let manifest = Manifest::parse(PathBuf::from("gleam.toml"), source.clone()).unwrap();
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
            manifest.release().unwrap().baseline_refs[&Version::new(1, 2, 3)],
            "abc123"
        );
    }

    #[test]
    fn prerelease_setting_round_trips_other_content() {
        let source = format!(
            "name = \"x\"\nversion = \"1.0.0\"\n# keep me\n\n{}",
            release_table("")
        );
        let mut manifest = Manifest::parse(PathBuf::from("gleam.toml"), source.clone()).unwrap();
        manifest
            .set_prerelease(Some(PrereleaseChannel::Rc))
            .unwrap();
        let rendered = manifest.render();
        assert!(rendered.contains("# keep me"));
        assert!(rendered.contains("prerelease = \"rc\""));
        assert_eq!(
            manifest.release().unwrap().prerelease,
            Some(PrereleaseChannel::Rc)
        );
        manifest.set_prerelease(None).unwrap();
        assert_eq!(manifest.render(), source);
        assert_eq!(manifest.release().unwrap().prerelease, None);
    }

    #[test]
    fn an_unconfigured_manifest_refuses_a_channel_and_stays_unchanged() {
        for source in [
            "name = \"x\"\nversion = \"1.0.0\"\n",
            "name = \"x\"\nversion = \"1.0.0\"\ntools = { other = \"preserve\" }\n",
        ] {
            let mut manifest =
                Manifest::parse(PathBuf::from("gleam.toml"), source.to_owned()).unwrap();
            assert_eq!(manifest.release(), Err(MissingReleaseConfig));
            for channel in [Some(PrereleaseChannel::Beta), None] {
                assert_eq!(manifest.set_prerelease(channel), Err(MissingReleaseConfig));
                assert_eq!(manifest.render(), source);
            }
        }
    }

    #[test]
    fn only_hexpm_serves_package_pages_and_organizations_have_their_own() {
        let version = Version::new(1, 2, 3);
        assert_eq!(
            RegistryConfig::default()
                .package_page("widget", &version)
                .as_deref(),
            Some("https://hex.pm/packages/widget/1.2.3")
        );
        let organization = RegistryConfig::hexpm_organization("acme");
        assert_eq!(
            organization.package_page("widget", &version).as_deref(),
            Some("https://hex.pm/packages/acme/widget/1.2.3")
        );
        assert_eq!(
            organization.repository_url,
            "https://repo.hex.pm/repos/acme"
        );
        assert_eq!(organization.docs_url, "https://repo.hex.pm/repos/acme/docs");
        assert_eq!(organization.api_url, "https://hex.pm/api");
        let private = RegistryConfig {
            provider: RegistryProvider::HexCompatible,
            ..RegistryConfig::default()
        };
        assert_eq!(private.package_page("widget", &version), None);
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
tools = { other = { keep = true }, "release-glz" = { schema = 2, compiler = "1.18.1", prerelease = "alpha", registry = { provider = "hexpm", api_url = "https://hex.pm/api", repository_url = "https://repo.hex.pm", docs_url = "https://repo.hex.pm/docs", credential_env = "HEXPM_API_KEY", auth = "hex-token" }, approval = { normal = "release-pr-and-environment", manual = "environment", environment = "release", manual_refs = ["refs/heads/main"] } } }
"#;
        let mut manifest = Manifest::parse(PathBuf::from("gleam.toml"), source.into()).unwrap();
        manifest
            .set_prerelease(Some(PrereleaseChannel::Rc))
            .unwrap();
        let rendered = manifest.render();
        assert!(rendered.contains("keep = true"), "{rendered}");
        assert!(rendered.contains("prerelease = \"rc\""), "{rendered}");
        manifest.set_prerelease(None).unwrap();
        let rendered = manifest.render();
        assert!(!rendered.contains("prerelease"), "{rendered}");
        let reparsed = Manifest::parse(PathBuf::from("gleam.toml"), rendered).unwrap();
        assert_eq!(reparsed.release(), manifest.release());
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
        assert_eq!(parsed.release().unwrap().prerelease, None);
    }

    #[test]
    fn initialization_refuses_a_registry_before_it_renders_one() {
        let manifest = Manifest::parse(
            PathBuf::from("gleam.toml"),
            "name = \"x\"\nversion = \"1.0.0\"\n".into(),
        )
        .unwrap();
        let error = manifest
            .render_initialized(&InitializationSettings {
                compiler: Version::new(1, 18, 1),
                default_branch: "main".into(),
                registry: RegistryConfig {
                    api_url: "http://hex.example/api".into(),
                    ..RegistryConfig::default()
                },
                allow_version_zero: false,
            })
            .unwrap_err();
        assert_eq!(
            crate::failure::refusal_reason(&error),
            Some(crate::failure::RefusalReason::UrlTransportUntrusted)
        );
        assert_eq!(
            error.to_string(),
            "registry.api_url must use HTTPS, or HTTP to a numeric loopback address"
        );
    }

    #[test]
    fn trusted_transport_is_https_or_http_to_a_numeric_loopback_address() {
        for (raw, trusted) in [
            ("https://hex.pm/api", true),
            ("https://localhost/api", true),
            ("http://127.0.0.1:8080/api", true),
            ("http://127.255.255.254/api", true),
            ("http://127.1/api", true),
            ("http://[::1]:8080/api", true),
            ("http://[0:0:0:0:0:0:0:1]/api", true),
            ("http://localhost:8080/api", false),
            ("http://LOCALHOST/api", false),
            ("http://hex.pm/api", false),
            ("http://127.0.0.1.example.test/api", false),
            ("http://192.0.2.1/api", false),
            ("http://128.0.0.1/api", false),
            ("http://[::2]/api", false),
            ("http://[::ffff:127.0.0.1]/api", false),
            ("ftp://127.0.0.1/api", false),
            ("ws://127.0.0.1/api", false),
        ] {
            let url = reqwest::Url::parse(raw).unwrap();
            assert_eq!(uses_trusted_transport(&url), trusted, "{raw}");
        }
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
        assert_eq!(
            crate::failure::refusal_reason(&manifest.write().unwrap_err()),
            Some(crate::failure::RefusalReason::ManifestChanged)
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), concurrent);

        let mut current = Manifest::load(&path).unwrap();
        current.set_version(Version::new(1, 1, 0));
        current.write().unwrap();
        assert!(fs::read_to_string(&path).unwrap().contains("1.1.0"));
    }
}
