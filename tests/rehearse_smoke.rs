use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Result, bail};
use release_glz::artifact::normalize_hex_tarball;
use release_glz::candidate::Candidate;
use release_glz::rehearse::{Rehearsal, RehearseOptions};

fn installed_gleam_version() -> Option<String> {
    let output = Command::new("gleam").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()?
        .split_whitespace()
        .find(|word| word.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .map(str::to_owned)
}

#[tokio::test]
async fn rehearsal_builds_only_the_requested_commit_and_seals_it() -> Result<()> {
    let Some(gleam_version) = installed_gleam_version() else {
        eprintln!("skipping Gleam smoke test because gleam is not installed");
        return Ok(());
    };
    let temp = tempfile::tempdir()?;
    let repository = temp.path().join("repo");
    fs::create_dir_all(repository.join("src"))?;
    fs::write(
        repository.join("gleam.toml"),
        format!(
            r#"name = "rehearse_fixture"
version = "1.0.0"
description = "A rehearsal fixture"
licences = ["MIT"]

[repository]
type = "github"
user = "acme"
repo = "rehearse_fixture"

[tools.release-glz]
schema = 2
compiler = "{gleam_version}"

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
manual_refs = ["refs/heads/main"]
"#
        ),
    )?;
    fs::write(repository.join("README.md"), "# Rehearse fixture\n")?;
    fs::write(
        repository.join("src/rehearse_fixture.gleam"),
        "pub fn committed() -> Int { 1 }\n",
    )?;
    git(&repository, &["init", "--initial-branch=main"])?;
    git(&repository, &["config", "core.hooksPath", ".git/no-hooks"])?;
    git(
        &repository,
        &["config", "user.email", "fixture@example.test"],
    )?;
    git(&repository, &["config", "user.name", "Fixture"])?;
    git(&repository, &["config", "commit.gpgsign", "false"])?;
    git(&repository, &["config", "tag.gpgsign", "false"])?;
    git(&repository, &["add", "."])?;
    git(&repository, &["commit", "-m", "feat: committed source"])?;
    let sha = git_stdout(&repository, &["rev-parse", "HEAD"])?;

    fs::write(
        repository.join("src/rehearse_fixture.gleam"),
        "pub fn dirty() -> Int { 999 }\n",
    )?;
    let output = temp.path().join("candidate");
    let manifest = Rehearsal::default()
        .run(&RehearseOptions {
            manifest_path: repository.join("gleam.toml"),
            source_ref: sha.clone(),
            output: output.clone(),
        })
        .await?;
    assert_eq!(manifest.source.commit_sha, sha);
    assert_eq!(manifest.source.manifest_path, "gleam.toml");
    assert!(manifest.artifacts.docs.is_some());

    let verified = Candidate::verify(&output)?;
    let package = Candidate::package_bytes(&output, &verified)?;
    let files = normalize_hex_tarball(&package)?;
    assert_eq!(
        files["src/rehearse_fixture.gleam"],
        b"pub fn committed() -> Int { 1 }\n"
    );
    assert!(!String::from_utf8_lossy(&files["src/rehearse_fixture.gleam"]).contains("dirty"));
    assert!(
        !repository.join("build").exists(),
        "rehearse dirtied the checkout"
    );
    Ok(())
}

#[tokio::test]
async fn rehearsal_rejects_noncanonical_source_identifiers_before_creating_output() {
    let temp = tempfile::tempdir().unwrap();
    for source_ref in [
        "a".repeat(39),
        "a".repeat(41),
        "A".repeat(40),
        "g".repeat(40),
        format!("{}g", "a".repeat(39)),
    ] {
        let output = temp.path().join(format!("candidate-{}", source_ref.len()));
        let error = Rehearsal::default()
            .run(&RehearseOptions {
                manifest_path: temp.path().join("missing.toml"),
                source_ref,
                output: output.clone(),
            })
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("full lowercase commit SHA"), "{error}");
        assert!(!output.exists());
    }
}

#[tokio::test]
async fn rehearsal_rejects_missing_symbolic_legacy_and_wrong_compiler_sources_without_output()
-> Result<()> {
    let temp = tempfile::tempdir()?;
    let repository = temp.path().join("repo");
    fs::create_dir_all(repository.join("src"))?;
    fs::write(
        repository.join("gleam.toml"),
        "name = \"rehearse_guard\"\nversion = \"1.0.0\"\n",
    )?;
    fs::write(
        repository.join("src/rehearse_guard.gleam"),
        "pub fn value() -> Int { 1 }\n",
    )?;
    init_git(&repository)?;
    let sha = git_stdout(&repository, &["rev-parse", "HEAD"])?;
    let manifest_path = repository.join("gleam.toml");

    let missing_output = temp.path().join("missing-candidate");
    let missing = Rehearsal::default()
        .run(&RehearseOptions {
            manifest_path: manifest_path.clone(),
            source_ref: "0".repeat(40),
            output: missing_output.clone(),
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(
        missing.contains("source commit does not exist"),
        "{missing}"
    );
    assert!(!missing_output.exists());

    // In a SHA-1 repository, 40 hexadecimal characters are parsed as an object
    // ID before DWIM ref lookup. A 64-character branch exercises the symbolic
    // ref guard while remaining a valid full SHA for SHA-256 repositories.
    let symbolic_ref = "a".repeat(64);
    git(&repository, &["branch", &symbolic_ref])?;
    let symbolic_output = temp.path().join("symbolic-candidate");
    let symbolic = Rehearsal::default()
        .run(&RehearseOptions {
            manifest_path: manifest_path.clone(),
            source_ref: symbolic_ref,
            output: symbolic_output.clone(),
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(symbolic.contains("exact full commit SHA"), "{symbolic}");
    assert!(!symbolic_output.exists());

    let legacy_output = temp.path().join("legacy-candidate");
    let legacy = Rehearsal::default()
        .run(&RehearseOptions {
            manifest_path: manifest_path.clone(),
            source_ref: sha,
            output: legacy_output.clone(),
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(legacy.contains("schema = 2"), "{legacy}");
    assert!(!legacy_output.exists());

    fs::write(
        &manifest_path,
        v2_manifest("rehearse_guard", "99.0.0", "hexpm", None, true),
    )?;
    git(&repository, &["add", "gleam.toml"])?;
    git(
        &repository,
        &["commit", "-m", "test: require unavailable compiler"],
    )?;
    let wrong_compiler_sha = git_stdout(&repository, &["rev-parse", "HEAD"])?;
    let wrong_output = temp.path().join("wrong-compiler-candidate");
    let wrong = Rehearsal::default()
        .run(&RehearseOptions {
            manifest_path,
            source_ref: wrong_compiler_sha,
            output: wrong_output.clone(),
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(
        wrong.contains("configured Gleam compiler 99.0.0"),
        "{wrong}"
    );
    assert!(!wrong_output.exists());
    Ok(())
}

#[tokio::test]
async fn rehearsal_marks_both_organization_and_compatible_registries_private() -> Result<()> {
    let Some(gleam_version) = installed_gleam_version() else {
        eprintln!("skipping Gleam smoke test because gleam is not installed");
        return Ok(());
    };
    let current = std::env::current_dir()?;
    for (index, (provider, repository)) in [("hexpm", Some("acme")), ("hex-compatible", None)]
        .into_iter()
        .enumerate()
    {
        let temp = tempfile::Builder::new()
            .prefix("rehearse-private-")
            .tempdir_in(&current)?;
        let package = temp.path();
        let package_name = format!("private_fixture_{index}");
        fs::create_dir_all(package.join("src"))?;
        fs::write(
            package.join("gleam.toml"),
            v2_manifest(&package_name, &gleam_version, provider, repository, false),
        )?;
        fs::write(package.join("README.md"), "# Private fixture\n")?;
        fs::write(
            package.join(format!("src/{package_name}.gleam")),
            "pub fn value() -> Int { 1 }\n",
        )?;
        init_git(package)?;
        let sha = git_stdout(package, &["rev-parse", "HEAD"])?;
        let relative_manifest = package
            .join("gleam.toml")
            .strip_prefix(&current)?
            .to_path_buf();
        let output = temp.path().join("candidate");

        let sealed = Rehearsal::default()
            .run(&RehearseOptions {
                manifest_path: relative_manifest,
                source_ref: sha,
                output: output.clone(),
            })
            .await?;
        assert!(sealed.private);
        assert_eq!(sealed.registry.repository.as_deref(), repository);
        assert!(sealed.artifacts.docs.is_none());
        Candidate::verify(&output)?;
    }
    Ok(())
}

fn init_git(directory: &Path) -> Result<()> {
    git(directory, &["init", "--initial-branch=main"])?;
    git(directory, &["config", "core.hooksPath", ".git/no-hooks"])?;
    git(directory, &["config", "user.email", "fixture@example.test"])?;
    git(directory, &["config", "user.name", "Fixture"])?;
    git(directory, &["config", "commit.gpgsign", "false"])?;
    git(directory, &["config", "tag.gpgsign", "false"])?;
    git(directory, &["add", "."])?;
    git(directory, &["commit", "-m", "test: fixture"])
}

fn v2_manifest(
    name: &str,
    compiler: &str,
    provider: &str,
    repository: Option<&str>,
    docs: bool,
) -> String {
    let repository = repository
        .map(|repository| format!("repository = \"{repository}\"\n"))
        .unwrap_or_default();
    format!(
        r#"name = "{name}"
version = "1.0.0"
description = "A rehearsal fixture"
licences = ["MIT"]

[repository]
type = "github"
user = "acme"
repo = "{name}"

[tools.release-glz]
schema = 2
compiler = "{compiler}"

[tools.release-glz.registry]
provider = "{provider}"
{repository}api_url = "https://registry.example.test/api"
repository_url = "https://registry.example.test/repository"
docs_url = "https://registry.example.test/docs"
credential_env = "HEX_API_KEY"
auth = "bearer"

[tools.release-glz.approval]
normal = "release-pr-and-environment"
manual = "environment"
environment = "release"
manual_refs = ["refs/heads/main"]

[tools.release-glz.outputs]
docs = {docs}
github_release = true
sbom = false
provenance = false
signature = false
allow_private_evidence_upload = false
"#
    )
}

fn git(directory: &Path, args: &[&str]) -> Result<()> {
    git_stdout(directory, args).map(|_| ())
}

fn git_stdout(directory: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()?;
    if !output.status.success() {
        bail!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
