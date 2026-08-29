use std::fs;
use std::path::Path;
use std::process::Command;

use release_glz::api;
use release_glz::config::{Manifest, RegistryProvider};
use release_glz::git::GitRepo;
use release_glz::version::{effective_bump, next_prerelease_with_core};
use release_glz::{Bump, PrereleaseChannel};
use semver::Version;

const KANGAROO: &str = "tests/fixtures/dogfood/kangaroo";
const GLEAM_MUTANTS: &str = "tests/fixtures/dogfood/gleam-mutants";

fn version(value: &str) -> Version {
    value.parse().unwrap()
}

#[test]
fn dogfood_manifests_cover_public_initial_and_private_prerelease_paths() {
    let kangaroo = Manifest::load(Path::new(KANGAROO).join("gleam.toml")).unwrap();
    assert_eq!(kangaroo.package, "kangaroo");
    assert_eq!(kangaroo.release.schema, 2);
    assert_eq!(kangaroo.release.registry.provider, RegistryProvider::HexPm);
    assert_eq!(kangaroo.version, version("1.0.0"));

    let mutants = Manifest::load(Path::new(GLEAM_MUTANTS).join("gleam.toml")).unwrap();
    assert_eq!(mutants.package, "gleam_mutants");
    assert_eq!(mutants.release.schema, 2);
    assert_eq!(mutants.version, version("0.1.0"));
    assert!(mutants.release.allow_version_zero);
    assert_eq!(
        mutants.release.registry.provider,
        RegistryProvider::HexCompatible
    );
    assert_eq!(mutants.release.prerelease, Some(PrereleaseChannel::Alpha));
}

#[test]
fn dogfood_api_snapshots_cover_additions_and_zero_major_breakage() {
    let kangaroo = api::compare(
        &fs::read(Path::new(KANGAROO).join("api/baseline.json")).unwrap(),
        &fs::read(Path::new(KANGAROO).join("api/current.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(kangaroo.impact, Bump::Minor);

    let mutants = api::compare(
        &fs::read(Path::new(GLEAM_MUTANTS).join("api/baseline.json")).unwrap(),
        &fs::read(Path::new(GLEAM_MUTANTS).join("api/current.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(mutants.impact, Bump::Major);
    assert_eq!(
        effective_bump(&version("0.1.0"), mutants.impact),
        Bump::Minor
    );
    assert_eq!(
        next_prerelease_with_core(
            &version("0.2.0-alpha.1"),
            &version("0.2.0"),
            PrereleaseChannel::Beta,
            false,
        )
        .unwrap(),
        version("0.2.0-beta.1")
    );
}

#[test]
fn dogfood_archive_uses_the_commit_and_excludes_dirty_worktree_content() {
    let temp = tempfile::tempdir().unwrap();
    let repository = temp.path().join("kangaroo");
    copy_fixture(Path::new(KANGAROO), &repository);
    git(&repository, &["init", "--initial-branch=main"]);
    git(&repository, &["config", "core.hooksPath", ".git/no-hooks"]);
    git(
        &repository,
        &["config", "user.email", "dogfood@example.test"],
    );
    git(&repository, &["config", "user.name", "Dogfood"]);
    git(&repository, &["config", "commit.gpgsign", "false"]);
    git(&repository, &["add", "."]);
    git(
        &repository,
        &["commit", "-m", "feat: committed dogfood snapshot"],
    );
    let repo = GitRepo::discover(&repository).unwrap();
    let sha = repo.head().unwrap();

    fs::write(
        repository.join("src/kangaroo.gleam"),
        "pub fn dirty_only() -> Int { 999 }\n",
    )
    .unwrap();
    let archive = temp.path().join("archive");
    fs::create_dir(&archive).unwrap();
    repo.archive(&sha, &archive).unwrap();

    let source = fs::read_to_string(archive.join("src/kangaroo.gleam")).unwrap();
    assert!(source.contains("pub fn run"));
    assert!(!source.contains("dirty_only"));
}

fn copy_fixture(source: &Path, destination: &Path) {
    for relative in [
        "gleam.toml",
        "src/kangaroo.gleam",
        "api/baseline.json",
        "api/current.json",
    ] {
        let target = destination.join(relative);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(source.join(relative), target).unwrap();
    }
}

fn git(directory: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
