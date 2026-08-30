use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use semver::Version;
use serde::Serialize;
use toml_edit::{Array, DocumentMut, Item, Table, value};

use crate::config::{ApprovalMode, AuthKind, Manifest, RegistryProvider, SeparationMode};
use crate::diff::unified_diff;
use crate::gleam::Gleam;

const LEGACY_BACKUP: &str = ".release-glz/legacy-gleam.toml";

#[derive(Debug)]
pub struct Migration {
    manifest_path: PathBuf,
    backup_path: PathBuf,
    original: String,
    rendered: String,
    legacy: Option<String>,
    legacy_notes: Vec<(PathBuf, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrationOutcome {
    pub schema: String,
    pub changed: bool,
    pub written: bool,
    pub manifest_path: String,
    pub legacy_backup_path: Option<String>,
    pub diff: Option<String>,
}

impl Migration {
    pub fn prepare(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let manifest = Manifest::load(&path)?;
        if manifest.release.schema == 2 {
            return Self::prepare_loaded(path, manifest, None);
        }
        let compiler = Gleam::default().ensure_supported().context(
            "legacy schema does not record its compiler; install the intended Gleam version before migration",
        )?;
        Self::prepare_loaded(path, manifest, Some(&compiler))
    }

    /// Prepare a deterministic migration with a compiler version already
    /// established by the caller. Production CLI callers use [`Self::prepare`]
    /// so the version is observed from the installed compiler.
    pub fn prepare_with_compiler(path: impl AsRef<Path>, compiler: Version) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let manifest = Manifest::load(&path)?;
        if manifest.release.schema != 2 && compiler < Version::new(1, 9, 0) {
            bail!("release-glz requires Gleam 1.9 or newer; found {compiler}");
        }
        Self::prepare_loaded(path, manifest, Some(&compiler))
    }

    fn prepare_loaded(
        path: PathBuf,
        manifest: Manifest,
        legacy_compiler: Option<&Version>,
    ) -> Result<Self> {
        let original = manifest.original_source().to_owned();
        let backup_path = manifest.package_dir().join(LEGACY_BACKUP);
        let legacy_notes_dir = manifest
            .package_dir()
            .join(&manifest.release.changelog.notes_dir);
        if manifest.release.schema == 2 {
            return Ok(Self {
                manifest_path: path,
                backup_path,
                rendered: original.clone(),
                original,
                legacy: None,
                legacy_notes: Vec::new(),
            });
        }
        let compiler = legacy_compiler.context("legacy migration requires an observed compiler")?;
        if !manifest.release.allow_unknown_api_for.is_empty() {
            let versions = manifest
                .release
                .allow_unknown_api_for
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "legacy `allow_unknown_api_for` cannot be migrated without weakening policy; replace {versions} with schema 2 `api_exceptions` containing baseline, reason, and expiry"
            );
        }

        let mut document = original.parse::<DocumentMut>()?;
        let tools_item = document.entry("tools").or_insert(Item::Table(Table::new()));
        if !tools_item.is_table() {
            let original_tools = std::mem::replace(tools_item, Item::None);
            let table = original_tools
                .into_table()
                .map_err(|_| anyhow::anyhow!("`tools` must be a table before migration"))?;
            *tools_item = Item::Table(table);
        }
        let tools = tools_item
            .as_table_mut()
            .context("`tools` must be a table before migration")?;
        tools.remove("release-glz");
        tools.insert(
            "release-glz",
            Item::Table(schema_two_table(&manifest, compiler)),
        );
        let rendered = document.to_string();
        Manifest::parse(path.clone(), rendered.clone())
            .context("internal migration generated invalid schema 2 configuration")?;
        let legacy_notes = legacy_unreleased_notes(
            &manifest
                .package_dir()
                .join(&manifest.release.changelog.path),
        )?
        .into_iter()
        .map(|(filename, note)| (legacy_notes_dir.join(filename), note))
        .collect();
        Ok(Self {
            manifest_path: path,
            backup_path,
            original: original.clone(),
            rendered,
            legacy: Some(original),
            legacy_notes,
        })
    }

    pub fn changed(&self) -> bool {
        self.original != self.rendered
    }

    pub fn rendered(&self) -> &str {
        &self.rendered
    }

    pub fn legacy_source(&self) -> Option<&str> {
        self.legacy.as_deref()
    }

    pub fn diff(&self) -> Option<String> {
        self.changed().then(|| {
            unified_diff(
                &self.manifest_path.to_string_lossy(),
                &self.original,
                &self.rendered,
            )
        })
    }

    pub fn outcome(&self, written: bool) -> MigrationOutcome {
        MigrationOutcome {
            schema: "migration/v1".into(),
            changed: self.changed(),
            written,
            manifest_path: self.manifest_path.to_string_lossy().replace('\\', "/"),
            legacy_backup_path: self
                .legacy
                .as_ref()
                .map(|_| self.backup_path.to_string_lossy().replace('\\', "/")),
            diff: None,
        }
    }

    pub fn apply(self) -> Result<MigrationOutcome> {
        if !self.changed() {
            return Ok(self.outcome(false));
        }
        let current = fs::read_to_string(&self.manifest_path)?;
        if current != self.original {
            bail!("manifest changed after migration was prepared; refusing to replace it");
        }
        let legacy = self
            .legacy
            .as_deref()
            .context("changed migration has no legacy source")?;
        if self.backup_path.exists() && fs::read_to_string(&self.backup_path)? != legacy {
            bail!("legacy backup already exists with different contents; refusing to replace it");
        }
        for (path, note) in &self.legacy_notes {
            if path.exists() && fs::read_to_string(path)? != *note {
                bail!(
                    "legacy Unreleased note already exists with different contents; refusing to replace it"
                );
            }
        }
        if !self.backup_path.exists() {
            write_new(&self.backup_path, legacy.as_bytes())?;
        }
        for (path, note) in &self.legacy_notes {
            if !path.exists() {
                write_new(path, note.as_bytes())?;
            }
        }
        atomic_replace(&self.manifest_path, self.rendered.as_bytes())?;
        Ok(self.outcome(true))
    }
}

fn legacy_unreleased_notes(changelog_path: &Path) -> Result<Vec<(String, String)>> {
    let source = match fs::read_to_string(changelog_path) {
        Ok(source) => source,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let marker = "## [Unreleased]";
    let Some(start) = source.find(marker) else {
        return Ok(Vec::new());
    };
    let body_start = start + marker.len();
    let body_end = source[body_start..]
        .find("\n## [")
        .map(|offset| body_start + offset)
        .unwrap_or(source.len());
    let body = &source[body_start..body_end];
    let mut category = "changed";
    let mut entries = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if let Some(heading) = line.strip_prefix("### ") {
            category = legacy_category(heading);
            continue;
        }
        let Some(text) = line.strip_prefix("- ") else {
            continue;
        };
        if !text.is_empty() {
            entries.push((category, text));
        }
    }
    let multiple = entries.len() > 1;
    Ok(entries
        .into_iter()
        .enumerate()
        .map(|(index, (category, text))| {
            let id = if multiple {
                format!("legacy-unreleased-{:04}", index + 1)
            } else {
                "legacy-unreleased".to_owned()
            };
            let mut note = DocumentMut::new();
            note["id"] = value(id.clone());
            note["category"] = value(category);
            note["text"] = value(text);
            (format!("{id}.toml"), note.to_string())
        })
        .collect())
}

fn legacy_category(heading: &str) -> &'static str {
    match heading.to_ascii_lowercase().as_str() {
        "added" => "added",
        "deprecated" => "deprecated",
        "fixed" => "fixed",
        "removed" => "removed",
        "security" => "security",
        _ => "changed",
    }
}

fn schema_two_table(manifest: &Manifest, compiler: &Version) -> Table {
    let config = &manifest.release;
    let mut release = Table::new();
    release.insert("schema", value(2));
    release.insert("compiler", value(compiler.to_string()));
    release.insert(
        "release_branch_prefix",
        value(config.release_branch_prefix.clone()),
    );
    release.insert("allow_version_zero", value(config.allow_version_zero));
    if let Some(channel) = config.prerelease {
        release.insert("prerelease", value(channel.as_str()));
    }

    let mut registry = Table::new();
    registry.insert(
        "provider",
        value(match config.registry.provider {
            RegistryProvider::HexPm => "hexpm",
            RegistryProvider::HexCompatible => "hex-compatible",
        }),
    );
    if let Some(repository) = &config.registry.repository {
        registry.insert("repository", value(repository.clone()));
    }
    registry.insert("api_url", value(config.registry.api_url.clone()));
    registry.insert(
        "repository_url",
        value(config.registry.repository_url.clone()),
    );
    registry.insert("docs_url", value(config.registry.docs_url.clone()));
    registry.insert(
        "credential_env",
        value(config.registry.credential_env.clone()),
    );
    registry.insert(
        "auth",
        value(match config.registry.auth {
            AuthKind::HexToken => "hex-token",
            AuthKind::Bearer => "bearer",
        }),
    );
    if config.registry.allow_http_loopback {
        registry.insert("allow_http_loopback", value(true));
    }
    release.insert("registry", Item::Table(registry));

    let mut approval = Table::new();
    approval.insert("normal", value(approval_mode(config.approval.normal)));
    approval.insert("manual", value(approval_mode(config.approval.manual)));
    approval.insert("environment", value(config.approval.environment.clone()));
    approval.insert(
        "separation",
        value(match config.approval.separation {
            SeparationMode::Solo => "solo",
            SeparationMode::Strict => "strict",
        }),
    );
    let mut manual_refs = Array::new();
    for git_ref in &config.approval.manual_refs {
        manual_refs.push(git_ref.as_str());
    }
    approval.insert("manual_refs", value(manual_refs));
    if let Some(fallback) = &config.approval.private_repository_fallback {
        approval.insert("private_repository_fallback", value(fallback.clone()));
    }
    release.insert("approval", Item::Table(approval));

    let mut outputs = Table::new();
    outputs.insert("docs", value(config.outputs.docs));
    outputs.insert("github_release", value(config.outputs.github_release));
    outputs.insert("sbom", value(config.outputs.sbom));
    outputs.insert("provenance", value(config.outputs.provenance));
    outputs.insert("signature", value(config.outputs.signature));
    outputs.insert(
        "allow_private_evidence_upload",
        value(config.outputs.allow_private_evidence_upload),
    );
    release.insert("outputs", Item::Table(outputs));

    let mut changelog = Table::new();
    changelog.insert(
        "path",
        value(config.changelog.path.to_string_lossy().replace('\\', "/")),
    );
    changelog.insert("managed_block", value(config.changelog.managed_block));
    changelog.insert(
        "notes_dir",
        value(
            config
                .changelog
                .notes_dir
                .to_string_lossy()
                .replace('\\', "/"),
        ),
    );
    release.insert("changelog", Item::Table(changelog));

    if !config.baseline_refs.is_empty() {
        let mut refs = Table::new();
        for (version, reference) in &config.baseline_refs {
            refs.insert(&version.to_string(), value(reference.clone()));
        }
        release.insert("baseline_refs", Item::Table(refs));
    }
    release
}

fn approval_mode(mode: ApprovalMode) -> &'static str {
    match mode {
        ApprovalMode::ReleasePrAndEnvironment => "release-pr-and-environment",
        ApprovalMode::Environment => "environment",
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("legacy backup has no parent")?;
    fs::create_dir_all(parent)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    let permissions = fs::metadata(path)
        .with_context(|| format!("failed to inspect `{}` permissions", path.display()))?
        .permissions();
    temporary
        .as_file()
        .set_permissions(permissions)
        .with_context(|| format!("failed to preserve `{}` permissions", path.display()))?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to atomically migrate `{}`", path.display()))?;
    Ok(())
}
