#[cfg(any(windows, test))]
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
use flate2::{Compression, GzBuilder};
use semver::Version;
#[cfg(any(windows, test))]
use serde::Deserialize;
use tempfile::TempDir;

use crate::config::Manifest;

#[derive(Debug)]
pub struct PackageSnapshot {
    _temp: TempDir,
    package_dir: PathBuf,
}

impl PackageSnapshot {
    pub fn package_dir(&self) -> &Path {
        &self.package_dir
    }
}

#[derive(Debug, Clone)]
pub struct Gleam {
    executable: PathBuf,
}

impl Default for Gleam {
    fn default() -> Self {
        Self {
            executable: std::env::var_os("RELEASE_GLZ_GLEAM")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("gleam")),
        }
    }
}

impl Gleam {
    pub fn installed_version(&self) -> Result<Version> {
        let output = self.command(Path::new("."))?.arg("--version").output()?;
        check_output(&output, "gleam --version", None)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .split_whitespace()
            .find_map(|word| word.parse::<Version>().ok())
            .context("could not parse Gleam version")
    }

    pub fn ensure_supported(&self) -> Result<Version> {
        let version = self.installed_version()?;
        if version < Version::new(1, 9, 0) {
            bail!("release-glz requires Gleam 1.9 or newer; found {version}");
        }
        Ok(version)
    }

    pub fn snapshot(&self, package_dir: &Path) -> Result<PackageSnapshot> {
        let temp = tempfile::tempdir().context("failed to create package snapshot")?;
        let destination = temp.path().join("package");
        copy_tree(package_dir, &destination)?;
        Ok(PackageSnapshot {
            _temp: temp,
            package_dir: destination,
        })
    }

    pub fn snapshot_from_git(
        &self,
        repo: &crate::git::GitRepo,
        sha: &str,
        package_relative: &Path,
    ) -> Result<PackageSnapshot> {
        let temp = tempfile::tempdir().context("failed to create git snapshot")?;
        repo.archive(sha, temp.path())?;
        let package_dir = temp.path().join(package_relative);
        if !package_dir.join("gleam.toml").is_file() {
            bail!(
                "git snapshot {sha} does not contain `{}`",
                package_dir.join("gleam.toml").display()
            );
        }
        Ok(PackageSnapshot {
            _temp: temp,
            package_dir,
        })
    }

    pub fn export_hex_tarball(&self, package_dir: &Path) -> Result<Vec<u8>> {
        let manifest = Manifest::load(package_dir.join("gleam.toml"))?;
        let output = self
            .command(package_dir)?
            .args(["export", "hex-tarball"])
            .output()?;
        let credential = configured_registry_secret(&manifest);
        if !output.status.success() {
            #[cfg(windows)]
            {
                let version = self.installed_version()?;
                if is_windows_hex_tarball_regression(&version, &output.stderr) {
                    let package_information =
                        self.export_package_information(package_dir, credential.as_deref())?;
                    return build_hex_tarball_from_compiler_outputs(
                        package_dir,
                        &package_information,
                    )
                    .context("failed to recover from Gleam 1.18.1 Windows hex-tarball regression");
                }
            }
            check_output(&output, "gleam export hex-tarball", credential.as_deref())?;
            bail!("gleam export hex-tarball failed without an error status");
        }
        let path = package_dir
            .join("build")
            .join(format!("{}-{}.tar", manifest.package, manifest.version));
        fs::read(&path).with_context(|| format!("Gleam did not create `{}`", path.display()))
    }

    #[cfg(windows)]
    fn export_package_information(
        &self,
        package_dir: &Path,
        configured_secret: Option<&str>,
    ) -> Result<Vec<u8>> {
        const OUTPUT: &str = "build/release-glz-package-information.json";
        fs::create_dir_all(package_dir.join("build"))?;
        let output = self
            .command(package_dir)?
            .args(["export", "package-information", "--out", OUTPUT])
            .output()?;
        check_output(
            &output,
            "gleam export package-information",
            configured_secret,
        )?;
        read_regular_file_bounded(
            &package_dir.join(OUTPUT),
            1024 * 1024,
            "Gleam package information",
        )
    }

    pub fn export_package_interface(&self, package_dir: &Path) -> Result<Vec<u8>> {
        let manifest = Manifest::load(package_dir.join("gleam.toml"))?;
        let path = package_dir.join("release-glz-package-interface.json");
        let output = self
            .command(package_dir)?
            .args(["export", "package-interface", "--out"])
            .arg(&path)
            .output()?;
        let credential = configured_registry_secret(&manifest);
        check_output(
            &output,
            "gleam export package-interface",
            credential.as_deref(),
        )?;
        fs::read(&path).with_context(|| format!("Gleam did not create `{}`", path.display()))
    }

    pub fn docs_build(&self, package_dir: &Path) -> Result<()> {
        let manifest = Manifest::load(package_dir.join("gleam.toml"))?;
        let output = self
            .command(package_dir)?
            .args(["docs", "build"])
            .output()?;
        let credential = configured_registry_secret(&manifest);
        check_output(&output, "gleam docs build", credential.as_deref())
    }

    pub fn export_docs_tarball(&self, package_dir: &Path) -> Result<Vec<u8>> {
        let manifest = Manifest::load(package_dir.join("gleam.toml"))?;
        self.docs_build(package_dir)?;
        let docs = package_dir.join("build/dev/docs").join(&manifest.package);
        if !docs.is_dir() {
            bail!("Gleam did not create documentation at `{}`", docs.display());
        }
        deterministic_tar_gz(&docs)
    }

    fn command(&self, directory: &Path) -> Result<Command> {
        let directory = directory.canonicalize().with_context(|| {
            format!(
                "failed to canonicalize Gleam project root `{}`",
                directory.display()
            )
        })?;
        let mut command = Command::new(&self.executable);
        command.current_dir(directory);
        Ok(command)
    }
}

fn deterministic_tar_gz(root: &Path) -> Result<Vec<u8>> {
    let mut files = Vec::new();
    collect_regular_files(root, root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let limits = crate::artifact::ArchiveLimits::default();
    if files.len() > limits.max_entries {
        bail!("documentation exceeds the archive entry limit");
    }
    let mut total = 0_u64;
    let encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::best());
    let mut archive = tar::Builder::new(encoder);
    for (relative, path) in files {
        let contents = fs::read(&path)?;
        let size = contents.len() as u64;
        if size > limits.max_entry_bytes {
            bail!("documentation file `{relative}` exceeds the per-file limit");
        }
        total = total
            .checked_add(size)
            .context("documentation archive size overflow")?;
        if total > limits.max_total_bytes {
            bail!("documentation exceeds the expanded archive limit");
        }
        let mut header = tar::Header::new_gnu();
        header.set_size(size);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive.append_data(&mut header, relative, contents.as_slice())?;
    }
    let encoder = archive.into_inner()?;
    let bytes = encoder.finish()?;
    if bytes.len() as u64 > limits.max_archive_bytes {
        bail!("documentation archive exceeds the compressed byte limit");
    }
    Ok(bytes)
}

fn collect_regular_files(
    root: &Path,
    directory: &Path,
    output: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(directory)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_regular_files(root, &path, output)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            crate::config::validate_relative_path(Path::new(&relative), "documentation path")?;
            output.push((relative, path));
        } else {
            bail!(
                "documentation contains non-regular entry `{}`",
                path.display()
            );
        }
    }
    Ok(())
}

fn configured_registry_secret(manifest: &Manifest) -> Option<String> {
    std::env::var(&manifest.release.registry.credential_env).ok()
}

fn check_output(output: &Output, action: &str, configured_secret: Option<&str>) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stdout =
        crate::secrets::redact_with(&String::from_utf8_lossy(&output.stdout), configured_secret);
    let stderr =
        crate::secrets::redact_with(&String::from_utf8_lossy(&output.stderr), configured_secret);
    bail!("{action} failed\n{stdout}{stderr}")
}

#[cfg(any(windows, test))]
fn is_windows_hex_tarball_regression(version: &Version, stderr: &[u8]) -> bool {
    version == &Version::new(1, 18, 1)
        && String::from_utf8_lossy(stderr).contains("Cannot add path to tar archive")
        && String::from_utf8_lossy(stderr).contains("is outside this Gleam project")
}

#[cfg(any(windows, test))]
#[derive(Debug, Deserialize)]
struct PackageInformation {
    #[serde(rename = "gleam.toml")]
    config: PackageInformationConfig,
}

#[cfg(any(windows, test))]
#[derive(Debug, Deserialize)]
struct PackageInformationConfig {
    name: String,
    version: Version,
    licences: Vec<String>,
    description: String,
    #[serde(default)]
    dependencies: BTreeMap<String, PackageDependency>,
    #[serde(default)]
    repository: Option<PackageRepository>,
    #[serde(default)]
    links: Vec<PackageLink>,
    target: String,
}

#[cfg(any(windows, test))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageDependency {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    git: Option<String>,
    #[serde(default, rename = "ref")]
    reference: Option<String>,
}

#[cfg(any(windows, test))]
#[derive(Debug, Deserialize)]
struct PackageRepository {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

#[cfg(any(windows, test))]
#[derive(Debug, Deserialize)]
struct PackageLink {
    title: String,
    href: String,
}

#[cfg(any(windows, test))]
fn build_hex_tarball_from_compiler_outputs(
    package_dir: &Path,
    package_information: &[u8],
) -> Result<Vec<u8>> {
    if package_information.len() > 1024 * 1024 {
        bail!("Gleam package information exceeds the one MiB limit");
    }
    let information: PackageInformation = serde_json::from_slice(package_information)
        .context("Gleam package information is not valid JSON")?;
    let manifest = Manifest::load(package_dir.join("gleam.toml"))?;
    if information.config.name != manifest.package || information.config.version != manifest.version
    {
        bail!("Gleam package information does not match the package manifest");
    }
    if information.config.description.is_empty() || information.config.licences.is_empty() {
        bail!("Gleam package information is missing publish metadata");
    }

    let mut files = crate::artifact::package_publish_inputs(package_dir)?;
    add_compiler_generated_files(package_dir, &information.config, &mut files)?;
    let metadata = hex_metadata_config(package_dir, &information.config, files.keys())?;
    crate::artifact::build_hex_tarball(
        metadata.as_bytes(),
        &files,
        crate::artifact::ArchiveLimits::default(),
    )
}

#[cfg(any(windows, test))]
fn add_compiler_generated_files(
    package_dir: &Path,
    information: &PackageInformationConfig,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    match information.target.as_str() {
        "javascript" => return Ok(()),
        "erlang" => {}
        target => bail!("unsupported Gleam package target `{target}`"),
    }

    let build = package_dir
        .join("build/prod/erlang")
        .join(&information.name);
    let artefacts = build.join("_gleam_artefacts");
    let source_modules: Vec<_> = files
        .keys()
        .filter_map(|path| path.strip_prefix("src/")?.strip_suffix(".gleam"))
        .map(str::to_owned)
        .collect();
    for module in source_modules {
        let generated_name = format!("{}.erl", module.replace('/', "@"));
        insert_generated_file(
            files,
            format!("src/{generated_name}"),
            &artefacts.join(&generated_name),
        )?;
    }

    let include = build.join("include");
    if include.exists() {
        let mut headers = Vec::new();
        collect_generated_erlang_files(&include, &mut headers)?;
        headers.sort();
        for header in headers {
            let name = header
                .file_name()
                .and_then(|name| name.to_str())
                .context("generated Erlang header name is not UTF-8")?;
            insert_generated_file(files, format!("include/{name}"), &header)?;
        }
    }

    let app = format!("{}.app", information.name);
    insert_generated_file(
        files,
        format!("src/{app}.src"),
        &build.join("ebin").join(app),
    )
}

#[cfg(any(windows, test))]
fn collect_generated_erlang_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(directory)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_generated_erlang_files(&entry.path(), files)?;
        } else if file_type.is_file()
            && matches!(
                entry.path().extension().and_then(|value| value.to_str()),
                Some("erl" | "hrl")
            )
        {
            files.push(entry.path());
        } else if !file_type.is_file() {
            bail!(
                "generated compiler output `{}` is not a regular file",
                entry.path().display()
            );
        }
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn insert_generated_file(
    files: &mut BTreeMap<String, Vec<u8>>,
    path: String,
    source: &Path,
) -> Result<()> {
    if files.contains_key(&path) {
        bail!("generated compiler output collides with publish input `{path}`");
    }
    let contents = read_regular_file_bounded(
        source,
        crate::artifact::ArchiveLimits::default().max_entry_bytes,
        "generated compiler output",
    )?;
    files.insert(path, contents);
    Ok(())
}

#[cfg(any(windows, test))]
fn read_regular_file_bounded(path: &Path, limit: u64, description: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {description} `{}`", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{description} `{}` is not a regular file", path.display());
    }
    if metadata.len() > limit {
        bail!("{description} `{}` exceeds its byte limit", path.display());
    }
    let contents = fs::read(path)
        .with_context(|| format!("failed to read {description} `{}`", path.display()))?;
    if contents.len() as u64 != metadata.len() {
        bail!(
            "{description} `{}` changed while being read",
            path.display()
        );
    }
    Ok(contents)
}

#[cfg(any(windows, test))]
fn hex_metadata_config<'a>(
    package_dir: &Path,
    information: &PackageInformationConfig,
    files: impl Iterator<Item = &'a String>,
) -> Result<String> {
    use std::fmt::Write as _;

    let mut hex_dependencies = Vec::new();
    for (name, dependency) in &information.dependencies {
        let Some(version) = dependency.version.as_deref() else {
            bail!("cannot publish non-Hex dependency `{name}`");
        };
        if version.is_empty()
            || dependency.path.is_some()
            || dependency.git.is_some()
            || dependency.reference.is_some()
        {
            bail!("cannot publish non-Hex dependency `{name}`");
        }
        hex_dependencies.push((name, version));
    }

    let otp_apps = dependency_otp_apps(package_dir, hex_dependencies.is_empty())?;
    let mut requirements = Vec::new();
    for (name, version) in hex_dependencies {
        let app = otp_apps.get(name).map_or(name.as_str(), String::as_str);
        requirements.push(format!(
            "{{{}, [{{{}, {}}}, {{{}, false}}, {{{}, {}}}]}}",
            erlang_binary(name),
            erlang_binary("app"),
            erlang_binary(app),
            erlang_binary("optional"),
            erlang_binary("requirement"),
            erlang_binary(version)
        ));
    }

    let mut links: Vec<_> = information
        .links
        .iter()
        .map(|link| (link.title.clone(), link.href.clone()))
        .collect();
    if let Some(repository) = &information.repository {
        links.push(("Repository".into(), repository_url(repository)?));
    }
    let link_terms: Vec<_> = links
        .iter()
        .map(|(title, href)| format!("{{{}, {}}}", erlang_binary(title), erlang_binary(href)))
        .collect();
    let license_terms: Vec<_> = information
        .licences
        .iter()
        .map(|value| erlang_binary(value))
        .collect();
    let file_terms: Vec<_> = files.map(|value| erlang_binary(value)).collect();

    let mut metadata = String::new();
    for (key, value) in [
        ("name", erlang_binary(&information.name)),
        ("app", erlang_binary(&information.name)),
        ("version", erlang_binary(&information.version.to_string())),
        ("description", erlang_binary(&information.description)),
        ("licenses", format!("[{}]", license_terms.join(", "))),
        ("build_tools", format!("[{}]", erlang_binary("gleam"))),
        ("links", format!("[{}]", link_terms.join(", "))),
        ("requirements", format!("[{}]", requirements.join(", "))),
        ("files", format!("[{}]", file_terms.join(", "))),
    ] {
        writeln!(metadata, "{{{}, {value}}}.", erlang_binary(key))?;
    }
    Ok(metadata)
}

#[cfg(any(windows, test))]
fn dependency_otp_apps(
    package_dir: &Path,
    no_dependencies: bool,
) -> Result<BTreeMap<String, String>> {
    if no_dependencies {
        return Ok(BTreeMap::new());
    }
    let path = package_dir.join("manifest.toml");
    let source = read_regular_file_bounded(&path, 4 * 1024 * 1024, "Gleam manifest")?;
    let source = String::from_utf8(source).context("Gleam manifest is not UTF-8")?;
    let document = source
        .parse::<toml_edit::DocumentMut>()
        .context("Gleam manifest is invalid TOML")?;
    let packages = document
        .get("packages")
        .and_then(toml_edit::Item::as_array)
        .context("Gleam manifest has no package inventory")?;
    let mut output = BTreeMap::new();
    for package in packages {
        let table = package
            .as_inline_table()
            .context("Gleam manifest package is not an inline table")?;
        let name = table
            .get("name")
            .and_then(toml_edit::Value::as_str)
            .context("Gleam manifest package has no name")?;
        if let Some(app) = table.get("otp_app").and_then(toml_edit::Value::as_str)
            && output.insert(name.to_owned(), app.to_owned()).is_some()
        {
            bail!("Gleam manifest contains duplicate package `{name}`");
        }
    }
    Ok(output)
}

#[cfg(any(windows, test))]
fn repository_url(repository: &PackageRepository) -> Result<String> {
    let identity = || -> Result<(&str, &str)> {
        Ok((
            repository
                .user
                .as_deref()
                .context("Gleam repository has no user")?,
            repository
                .repo
                .as_deref()
                .context("Gleam repository has no repo")?,
        ))
    };
    let url = match repository.kind.as_str() {
        "github" => {
            let (user, repo) = identity()?;
            format!("https://github.com/{user}/{repo}")
        }
        "gitlab" => {
            let (user, repo) = identity()?;
            format!("https://gitlab.com/{user}/{repo}")
        }
        "bitbucket" => {
            let (user, repo) = identity()?;
            format!("https://bitbucket.com/{user}/{repo}")
        }
        "codeberg" => {
            let (user, repo) = identity()?;
            format!("https://codeberg.org/{user}/{repo}")
        }
        "sourcehut" => {
            let (user, repo) = identity()?;
            format!("https://git.sr.ht/~{user}/{repo}")
        }
        "tangled" => {
            let (user, repo) = identity()?;
            format!("https://tangled.sh/{user}/{repo}")
        }
        "gitea" | "forgejo" => {
            let (user, repo) = identity()?;
            let host = repository
                .host
                .as_deref()
                .context("Gleam repository has no host")?
                .trim_end_matches('/');
            format!("{host}/{user}/{repo}")
        }
        "custom" => repository
            .url
            .clone()
            .context("custom Gleam repository has no URL")?,
        kind => bail!("unsupported Gleam repository type `{kind}`"),
    };
    if url.is_empty() {
        bail!("Gleam repository URL is empty");
    }
    Ok(url)
}

#[cfg(any(windows, test))]
fn erlang_binary(value: &str) -> String {
    let bytes = value
        .as_bytes()
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("<<{bytes}>>")
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if matches!(name.to_str(), Some("build" | ".git" | "node_modules")) {
            continue;
        }
        let file_type = entry.file_type()?;
        let target = destination.join(&name);
        if file_type.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), target)?;
        } else if file_type.is_symlink() {
            bail!(
                "package snapshot refuses symlink `{}`",
                entry.path().display()
            );
        } else {
            bail!(
                "package snapshot refuses non-regular entry `{}`",
                entry.path().display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    #[test]
    fn package_snapshot_rejects_symlinks_and_every_other_non_regular_entry() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let gleam = Gleam::default();
        let linked = tempfile::tempdir().unwrap();
        fs::write(linked.path().join("target"), "secret").unwrap();
        symlink("target", linked.path().join("linked")).unwrap();
        let error = gleam.snapshot(linked.path()).unwrap_err().to_string();
        assert!(error.contains("symlink"), "{error}");

        let socket = tempfile::tempdir().unwrap();
        let _listener = match UnixListener::bind(socket.path().join("service.sock")) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("failed to create Unix socket fixture: {error}"),
        };
        let error = gleam.snapshot(socket.path()).unwrap_err().to_string();
        assert!(error.contains("non-regular"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn installed_version_and_minimum_are_read_from_a_bounded_process_result() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("gleam");
        write_executable(&executable, "printf 'gleam 1.18.1\\n'\n");
        let gleam = Gleam {
            executable: executable.clone(),
        };
        assert_eq!(gleam.installed_version().unwrap(), Version::new(1, 18, 1));
        assert_eq!(gleam.ensure_supported().unwrap(), Version::new(1, 18, 1));

        write_executable(&executable, "printf 'gleam 1.8.9\\n'\n");
        assert!(gleam.ensure_supported().is_err());

        write_executable(&executable, "printf 'gleam current\\n'\n");
        assert!(gleam.installed_version().is_err());

        write_executable(
            &executable,
            "printf 'failed output'\nprintf 'failed error' >&2\nexit 7\n",
        );
        let error = gleam.installed_version().unwrap_err().to_string();
        assert!(error.contains("gleam --version failed"), "{error}");
        assert!(error.contains("failed output"), "{error}");
        assert!(error.contains("failed error"), "{error}");
    }

    #[test]
    fn compiler_process_uses_the_canonical_project_root() {
        let temp = tempfile::tempdir().unwrap();
        let package = temp.path().join("package");
        fs::create_dir(&package).unwrap();

        #[cfg(unix)]
        let directory = {
            use std::os::unix::fs::symlink;

            let alias = temp.path().join("package-alias");
            symlink(&package, &alias).unwrap();
            alias
        };
        #[cfg(not(unix))]
        let directory = package;

        let command = Gleam::default().command(&directory).unwrap();

        assert_eq!(
            command.get_current_dir(),
            Some(fs::canonicalize(directory).unwrap().as_path())
        );
    }

    #[test]
    fn windows_hex_tarball_regression_match_is_version_and_message_scoped() {
        let affected = Version::new(1, 18, 1);
        let message = b"error: Cannot add path to tar archive\nThe path \\\\?\\C:\\pkg\\src\\x.gleam is outside this Gleam project";

        assert!(is_windows_hex_tarball_regression(&affected, message));
        assert!(!is_windows_hex_tarball_regression(
            &Version::new(1, 18, 2),
            message
        ));
        assert!(!is_windows_hex_tarball_regression(
            &affected,
            b"error: compilation failed"
        ));
    }

    #[test]
    fn compiler_output_fallback_builds_a_valid_deterministic_hex_v3_package() {
        let temp = tempfile::tempdir().unwrap();
        let package = temp.path();
        for directory in [
            "src",
            "priv",
            "build/prod/erlang/widget/_gleam_artefacts",
            "build/prod/erlang/widget/include",
            "build/prod/erlang/widget/ebin",
        ] {
            fs::create_dir_all(package.join(directory)).unwrap();
        }
        fs::write(
            package.join("gleam.toml"),
            "name = \"widget\"\nversion = \"1.2.3\"\ndescription = \"Fixture\"\nlicences = [\"MIT\"]\n",
        )
        .unwrap();
        fs::write(package.join("src/widget.gleam"), "pub fn value() { 1 }\n").unwrap();
        fs::write(package.join("src/widget_ffi.erl"), "% authored FFI\n").unwrap();
        fs::write(package.join("priv/data.bin"), b"private data").unwrap();
        fs::write(
            package.join("build/prod/erlang/widget/_gleam_artefacts/widget.erl"),
            "% generated Erlang\n",
        )
        .unwrap();
        fs::write(
            package.join("build/prod/erlang/widget/include/widget_Type.hrl"),
            "% generated header\n",
        )
        .unwrap();
        fs::write(
            package.join("build/prod/erlang/widget/ebin/widget.app"),
            "{application, widget, []}.\n",
        )
        .unwrap();
        fs::write(
            package.join("manifest.toml"),
            "packages = [\n  { name = \"dep_package\", version = \"1.0.0\", build_tools = [\"rebar3\"], requirements = [], otp_app = \"dep_app\", source = \"hex\", outer_checksum = \"00\" },\n]\n\n[requirements]\ndep_package = { version = \">= 1.0.0 and < 2.0.0\" }\n",
        )
        .unwrap();
        let package_information = br#"{
          "gleam.toml": {
            "name": "widget",
            "version": "1.2.3",
            "licences": ["MIT"],
            "description": "Fixture",
            "dependencies": {
              "dep_package": {"version": ">= 1.0.0 and < 2.0.0"}
            },
            "repository": {
              "type": "github",
              "user": "example",
              "repo": "widget"
            },
            "links": [{"title": "Docs", "href": "https://example.test/docs"}],
            "target": "erlang"
          }
        }"#;

        let first = build_hex_tarball_from_compiler_outputs(package, package_information).unwrap();
        let second = build_hex_tarball_from_compiler_outputs(package, package_information).unwrap();

        assert_eq!(first, second);
        let validation = crate::artifact::validate_hex_tarball(
            &first,
            crate::artifact::ArchiveLimits::default(),
        )
        .unwrap();
        assert_eq!(validation.content_entries, 7);
        let unpacked = temp.path().join("unpacked");
        crate::artifact::unpack_hex_source(&first, &unpacked).unwrap();
        assert_eq!(
            fs::read(unpacked.join("src/widget.gleam")).unwrap(),
            b"pub fn value() { 1 }\n"
        );
        assert_eq!(
            fs::read(unpacked.join("src/widget_ffi.erl")).unwrap(),
            b"% authored FFI\n"
        );
        assert!(!unpacked.join("src/widget.erl").exists());

        let metadata = crate::artifact::hex_metadata(&first).unwrap();
        let metadata = String::from_utf8(metadata).unwrap();
        assert!(metadata.contains(&erlang_binary("dep_package")));
        assert!(metadata.contains(&erlang_binary("dep_app")));
        assert!(metadata.contains(&erlang_binary("https://github.com/example/widget")));

        fs::write(package.join("src/widget.erl"), "% colliding source\n").unwrap();
        let error = build_hex_tarball_from_compiler_outputs(package, package_information)
            .unwrap_err()
            .to_string();
        assert!(error.contains("collides with publish input"), "{error}");
        fs::remove_file(package.join("src/widget.erl")).unwrap();

        fs::remove_file(package.join("build/prod/erlang/widget/_gleam_artefacts/widget.erl"))
            .unwrap();
        let error = build_hex_tarball_from_compiler_outputs(package, package_information)
            .unwrap_err()
            .to_string();
        assert!(error.contains("generated compiler output"), "{error}");
    }

    #[test]
    fn compiler_output_fallback_rejects_non_hex_dependencies_before_build_inventory() {
        let temp = tempfile::tempdir().unwrap();
        let information = PackageInformationConfig {
            name: "widget".into(),
            version: Version::new(1, 0, 0),
            licences: vec!["MIT".into()],
            description: "Fixture".into(),
            dependencies: BTreeMap::from([(
                "local_dep".into(),
                PackageDependency {
                    version: None,
                    path: Some("../local_dep".into()),
                    git: None,
                    reference: None,
                },
            )]),
            repository: None,
            links: Vec::new(),
            target: "javascript".into(),
        };

        let error = hex_metadata_config(temp.path(), &information, std::iter::empty())
            .unwrap_err()
            .to_string();

        assert!(error.contains("non-Hex dependency `local_dep`"), "{error}");
    }

    #[test]
    fn compiler_output_fallback_supports_javascript_without_erlang_outputs() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("gleam.toml"),
            "name = \"browser_widget\"\nversion = \"1.0.0\"\ndescription = \"Fixture\"\nlicences = [\"MIT\"]\ntarget = \"javascript\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/browser_widget.gleam"),
            "pub fn value() { 1 }\n",
        )
        .unwrap();
        let package_information = br#"{
          "gleam.toml": {
            "name": "browser_widget",
            "version": "1.0.0",
            "licences": ["MIT"],
            "description": "Fixture",
            "dependencies": {},
            "repository": null,
            "links": [],
            "target": "javascript"
          }
        }"#;

        let package =
            build_hex_tarball_from_compiler_outputs(temp.path(), package_information).unwrap();
        let validation = crate::artifact::validate_hex_tarball(
            &package,
            crate::artifact::ArchiveLimits::default(),
        )
        .unwrap();
        assert_eq!(validation.content_entries, 2);
    }

    #[test]
    fn fallback_repository_urls_cover_every_supported_gleam_variant() {
        let repository = |kind: &str| PackageRepository {
            kind: kind.into(),
            user: Some("owner".into()),
            repo: Some("project".into()),
            host: Some("https://forge.example.test/".into()),
            url: Some("https://custom.example.test/project".into()),
        };
        for (kind, expected) in [
            ("github", "https://github.com/owner/project"),
            ("gitlab", "https://gitlab.com/owner/project"),
            ("bitbucket", "https://bitbucket.com/owner/project"),
            ("codeberg", "https://codeberg.org/owner/project"),
            ("sourcehut", "https://git.sr.ht/~owner/project"),
            ("tangled", "https://tangled.sh/owner/project"),
            ("gitea", "https://forge.example.test/owner/project"),
            ("forgejo", "https://forge.example.test/owner/project"),
            ("custom", "https://custom.example.test/project"),
        ] {
            assert_eq!(repository_url(&repository(kind)).unwrap(), expected);
        }

        let mut missing_identity = repository("github");
        missing_identity.user = None;
        assert!(repository_url(&missing_identity).is_err());
        let mut missing_host = repository("gitea");
        missing_host.host = None;
        assert!(repository_url(&missing_host).is_err());
        let mut missing_url = repository("custom");
        missing_url.url = None;
        assert!(repository_url(&missing_url).is_err());
        let mut empty_url = repository("custom");
        empty_url.url = Some(String::new());
        assert!(repository_url(&empty_url).is_err());
        assert!(repository_url(&repository("unknown")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn successful_compiler_without_promised_outputs_is_an_error() {
        let temp = tempfile::tempdir().unwrap();
        let package = temp.path().join("package");
        fs::create_dir(&package).unwrap();
        fs::write(
            package.join("gleam.toml"),
            "name = \"widget\"\nversion = \"1.2.3\"\n",
        )
        .unwrap();
        let executable = temp.path().join("gleam");
        write_executable(&executable, "exit 0\n");
        let gleam = Gleam { executable };

        assert!(gleam.export_hex_tarball(&package).is_err());
        assert!(gleam.export_package_interface(&package).is_err());
        assert!(gleam.export_docs_tarball(&package).is_err());
    }

    #[test]
    fn snapshot_excludes_build_vcs_and_node_modules_but_keeps_nested_sources() {
        let source = tempfile::tempdir().unwrap();
        for directory in ["src/nested", "build", ".git", "node_modules"] {
            fs::create_dir_all(source.path().join(directory)).unwrap();
        }
        fs::write(
            source.path().join("src/nested/widget.gleam"),
            "pub fn x() { 1 }",
        )
        .unwrap();
        fs::write(
            source.path().join("gleam.toml"),
            "name = \"widget\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        fs::write(source.path().join("build/ignored"), "build").unwrap();
        fs::write(source.path().join(".git/ignored"), "git").unwrap();
        fs::write(source.path().join("node_modules/ignored"), "node").unwrap();

        let snapshot = Gleam::default().snapshot(source.path()).unwrap();
        assert!(
            snapshot
                .package_dir()
                .join("src/nested/widget.gleam")
                .is_file()
        );
        assert!(snapshot.package_dir().join("gleam.toml").is_file());
        assert!(!snapshot.package_dir().join("build").exists());
        assert!(!snapshot.package_dir().join(".git").exists());
        assert!(!snapshot.package_dir().join("node_modules").exists());
    }

    #[cfg(unix)]
    #[test]
    fn documentation_archives_are_deterministic_and_reject_non_regular_inputs() {
        use std::os::unix::fs::symlink;

        let docs = tempfile::tempdir().unwrap();
        fs::create_dir(docs.path().join("nested")).unwrap();
        fs::write(docs.path().join("z.html"), "z").unwrap();
        fs::write(docs.path().join("nested/a.html"), "a").unwrap();
        let first = deterministic_tar_gz(docs.path()).unwrap();
        let second = deterministic_tar_gz(docs.path()).unwrap();
        assert_eq!(first, second);
        crate::artifact::validate_docs_tarball(&first, crate::artifact::ArchiveLimits::default())
            .unwrap();

        symlink("z.html", docs.path().join("linked.html")).unwrap();
        let error = deterministic_tar_gz(docs.path()).unwrap_err().to_string();
        assert!(error.contains("non-regular"), "{error}");
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, body: &str) {
        fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }
}
