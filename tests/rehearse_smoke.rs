use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Result, bail, ensure};
use release_glz::artifact::normalize_hex_tarball;
use release_glz::candidate::Candidate;
use release_glz::failure::{RefusalReason, refusal_reason};
use release_glz::rehearse::{Rehearsal, RehearseOptions};
use release_glz::release::SourceBoundCandidate;
use release_glz_test_support::require_gleam;

#[tokio::test]
async fn rehearsal_builds_only_the_requested_commit_and_seals_it() -> Result<()> {
    let gleam_version = require_gleam();
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
        repository.join("CHANGELOG.md"),
        "# Changelog\n\n## [1.0.0]\n\n- The first committed release.\n",
    )?;
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
    ensure!(manifest.source.commit_sha == sha);
    ensure!(manifest.source.manifest_path == "gleam.toml");
    ensure!(manifest.artifacts.docs.is_some());

    let verified = Candidate::verify(&output)?;
    ensure!(
        verified
            .release_notes
            .contains("The first committed release."),
        "{}",
        verified.release_notes
    );
    // The working tree is dirty, but publication reads the policy from the commit that rehearsal sealed.
    let bound = SourceBoundCandidate::bind(verified.clone(), &repository.join("gleam.toml"))?;
    ensure!(bound.manifest() == &verified);
    let package = Candidate::package_bytes(&output, &verified)?;
    let files = normalize_hex_tarball(&package)?;
    ensure!(files["src/rehearse_fixture.gleam"] == b"pub fn committed() -> Int { 1 }\n");
    ensure!(!String::from_utf8_lossy(&files["src/rehearse_fixture.gleam"]).contains("dirty"));
    ensure!(
        !repository.join("build").exists(),
        "rehearse dirtied the checkout"
    );
    Ok(())
}

#[tokio::test]
async fn rehearsal_rejects_noncanonical_source_identifiers_before_creating_output() {
    let temp = tempfile::tempdir().unwrap();
    for (index, (source_ref, reason)) in [
        ("a".repeat(39), "this value has 39 bytes"),
        ("a".repeat(41), "this value has 41 bytes"),
        ("g".repeat(64), "this value has 64 bytes"),
        ("HEAD".to_owned(), "this value has 4 bytes"),
        ("A".repeat(40), "only the lowercase hexadecimal digits"),
        ("g".repeat(40), "only the lowercase hexadecimal digits"),
        (
            format!("{}g", "a".repeat(39)),
            "only the lowercase hexadecimal digits",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let output = temp.path().join(format!("candidate-{index}"));
        let error = Rehearsal::default()
            .run(&RehearseOptions {
                manifest_path: temp.path().join("missing.toml"),
                source_ref,
                output: output.clone(),
            })
            .await
            .unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::CandidateSourceCommitInvalid)
        );
        let error = error.to_string();
        assert!(error.contains("full lowercase commit SHA"), "{error}");
        assert!(error.contains(reason), "{error}");
        assert!(!output.exists());
    }
}

#[tokio::test]
async fn rehearsal_refuses_a_sha256_repository_before_building() {
    let temp = tempfile::tempdir().unwrap();
    let repository = temp.path().join("repo");
    fs::create_dir_all(&repository).unwrap();
    fs::write(
        repository.join("gleam.toml"),
        "name = \"sha256_fixture\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();
    release_glz_test_support::git(
        &repository,
        &["init", "--object-format=sha256", "--initial-branch=main"],
    );
    release_glz_test_support::git(&repository, &["add", "."]);
    release_glz_test_support::git(&repository, &["commit", "-m", "test: fixture"]);
    let head = release_glz_test_support::git(&repository, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    assert_eq!(head.len(), 64, "{head}");

    // The repository decides, so a value that would be a commit ID of a SHA-1 repository is refused the same way.
    for (index, source_ref) in [head, "a".repeat(40)].into_iter().enumerate() {
        let output = temp.path().join(format!("candidate-{index}"));
        let error = Rehearsal::default()
            .run(&RehearseOptions {
                manifest_path: repository.join("gleam.toml"),
                source_ref,
                output: output.clone(),
            })
            .await
            .unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::RepositoryObjectFormatUnsupported)
        );
        let error = error.to_string();
        assert!(error.contains("`sha256`"), "{error}");
        assert!(!output.exists());
    }
}

#[tokio::test]
async fn rehearsal_rejects_missing_symbolic_unconfigured_and_wrong_compiler_sources_without_output()
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
        .unwrap_err();
    ensure!(refusal_reason(&missing) == Some(RefusalReason::SourceCommitUnresolved));
    let missing = missing.to_string();
    ensure!(
        missing.contains("source commit does not exist"),
        "{missing}"
    );
    ensure!(!missing_output.exists());

    // A SHA-256 object ID in a SHA-1 repository names no commit that GitHub serves.
    let sha256_output = temp.path().join("sha256-candidate");
    let sha256 = Rehearsal::default()
        .run(&RehearseOptions {
            manifest_path: manifest_path.clone(),
            source_ref: "a".repeat(64),
            output: sha256_output.clone(),
        })
        .await
        .unwrap_err();
    ensure!(refusal_reason(&sha256) == Some(RefusalReason::CandidateSourceCommitInvalid));
    let sha256 = sha256.to_string();
    ensure!(
        sha256.contains("a SHA-256 object ID isn't a GitHub commit ID"),
        "{sha256}"
    );
    ensure!(!sha256_output.exists());

    // An annotated tag's object ID is a full object ID that peels to a different commit ID, which the guard against symbolic refs refuses.
    git(
        &repository,
        &["tag", "--annotate", "guard", "--message", "guard"],
    )?;
    let symbolic_ref = git_stdout(&repository, &["rev-parse", "refs/tags/guard"])?;
    ensure!(symbolic_ref != sha);
    let symbolic_output = temp.path().join("symbolic-candidate");
    let symbolic = Rehearsal::default()
        .run(&RehearseOptions {
            manifest_path: manifest_path.clone(),
            source_ref: symbolic_ref,
            output: symbolic_output.clone(),
        })
        .await
        .unwrap_err();
    ensure!(refusal_reason(&symbolic) == Some(RefusalReason::SourceCommitUnresolved));
    let symbolic = symbolic.to_string();
    ensure!(symbolic.contains("exact full commit SHA"), "{symbolic}");
    ensure!(!symbolic_output.exists());

    let unconfigured_output = temp.path().join("unconfigured-candidate");
    let unconfigured = Rehearsal::default()
        .run(&RehearseOptions {
            manifest_path: manifest_path.clone(),
            source_ref: sha,
            output: unconfigured_output.clone(),
        })
        .await
        .unwrap_err();
    ensure!(refusal_reason(&unconfigured) == Some(RefusalReason::ConfigMissing));
    let unconfigured = unconfigured.to_string();
    ensure!(
        unconfigured.contains("[tools.release-glz]") && unconfigured.contains("release-glz init"),
        "{unconfigured}"
    );
    ensure!(!unconfigured_output.exists());

    require_gleam();
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
        .unwrap_err();
    ensure!(refusal_reason(&wrong) == Some(RefusalReason::GleamCompilerMismatch));
    let wrong = wrong.to_string();
    ensure!(
        wrong.contains("configured Gleam compiler 99.0.0"),
        "{wrong}"
    );
    ensure!(!wrong_output.exists());
    Ok(())
}

#[tokio::test]
async fn rehearsal_marks_both_organization_and_compatible_registries_private() -> Result<()> {
    let gleam_version = require_gleam();
    let current = std::env::current_dir()?;
    for (index, (provider, repository)) in [("hexpm", Some("acme")), ("hex-compatible", None)]
        .into_iter()
        .enumerate()
    {
        // A manifest path relative to the working directory must resolve, so the fixture lives under Cargo's per-target test directory.
        let temp = tempfile::Builder::new()
            .prefix("rehearse-private-")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
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
        ensure!(sealed.private);
        ensure!(sealed.registry.repository.as_deref() == repository);
        ensure!(sealed.artifacts.docs.is_none());
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
