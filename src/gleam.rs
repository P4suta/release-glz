use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
use flate2::{Compression, GzBuilder};
use semver::Version;
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
        let output = self.command(Path::new(".")).arg("--version").output()?;
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
            .command(package_dir)
            .args(["export", "hex-tarball"])
            .output()?;
        let credential = configured_registry_secret(&manifest);
        check_output(&output, "gleam export hex-tarball", credential.as_deref())?;
        let path = package_dir
            .join("build")
            .join(format!("{}-{}.tar", manifest.package, manifest.version));
        fs::read(&path).with_context(|| format!("Gleam did not create `{}`", path.display()))
    }

    pub fn export_package_interface(&self, package_dir: &Path) -> Result<Vec<u8>> {
        let manifest = Manifest::load(package_dir.join("gleam.toml"))?;
        let path = package_dir.join("release-glz-package-interface.json");
        let output = self
            .command(package_dir)
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
        let output = self.command(package_dir).args(["docs", "build"]).output()?;
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

    fn command(&self, directory: &Path) -> Command {
        let mut command = Command::new(&self.executable);
        command.current_dir(directory);
        command
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
        let _listener = UnixListener::bind(socket.path().join("service.sock")).unwrap();
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
