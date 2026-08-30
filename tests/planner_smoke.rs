use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Result, bail};
use async_trait::async_trait;
use flate2::{Compression, write::GzEncoder};
use release_glz::config::Manifest;
use release_glz::git::GitRepo;
use release_glz::gleam::Gleam;
use release_glz::model::{
    ApiDiff, ApiStatus, Baseline, BaselineSource, Bump, ChangeEntry, PrereleaseChannel, ReasonKind,
    ReleasePlan, ReleaseState,
};
use release_glz::planner::{PlanOptions, Planner, prepare_release_files, update_local};
use release_glz::registry::{HexRelease, PackageState, Registry};
use semver::Version;

#[derive(Clone)]
struct MockRegistry {
    version: Version,
    source: Vec<u8>,
    docs: Vec<u8>,
}

#[derive(Clone)]
struct InitialRegistry {
    empty_package: bool,
}

#[async_trait]
impl Registry for InitialRegistry {
    async fn package(&self, _name: &str) -> Result<Option<PackageState>> {
        Ok(self.empty_package.then_some(PackageState::default()))
    }

    async fn source_tarball(&self, _name: &str, _version: &Version) -> Result<Vec<u8>> {
        bail!("initial release must not read a source tarball")
    }

    async fn docs_tarball(&self, _name: &str, _version: &Version) -> Result<Option<Vec<u8>>> {
        bail!("initial release must not read documentation")
    }
}

#[derive(Clone)]
struct ExistingRegistry {
    version: Version,
    source: Vec<u8>,
    docs: Vec<u8>,
    retired: bool,
}

#[async_trait]
impl Registry for ExistingRegistry {
    async fn package(&self, _name: &str) -> Result<Option<PackageState>> {
        Ok(Some(PackageState {
            releases: vec![HexRelease {
                version: self.version.clone(),
                has_docs: true,
                retired: self.retired,
            }],
        }))
    }

    async fn source_tarball(&self, _name: &str, _version: &Version) -> Result<Vec<u8>> {
        Ok(self.source.clone())
    }

    async fn docs_tarball(&self, _name: &str, _version: &Version) -> Result<Option<Vec<u8>>> {
        Ok(Some(self.docs.clone()))
    }
}

#[tokio::test]
async fn initial_plan_covers_empty_registry_version_floor_and_prerelease_train_edges() -> Result<()>
{
    if Command::new("gleam").arg("--version").output().is_err() {
        eprintln!("skipping Gleam smoke test because gleam is not installed");
        return Ok(());
    }
    let temp = tempfile::tempdir()?;
    let package = temp.path();
    init_gleam_fixture(package, "initial_fixture", "1.0.0")?;
    let manifest_path = package.join("gleam.toml");

    for empty_package in [false, true] {
        let planner = Planner::new(InitialRegistry { empty_package }, Gleam::default());
        let plan = planner
            .plan(&PlanOptions {
                manifest_path: manifest_path.clone(),
                ..PlanOptions::default()
            })
            .await?;
        assert_eq!(plan.version, Version::new(1, 0, 0));
        assert_eq!(plan.baseline.source, BaselineSource::Initial);
        assert_eq!(plan.reasons[0].kind, ReasonKind::InitialRelease);
    }

    let planner = Planner::new(
        InitialRegistry {
            empty_package: false,
        },
        Gleam::default(),
    );
    let error = planner
        .plan(&PlanOptions {
            manifest_path: manifest_path.clone(),
            version_override: Some(Version::new(0, 9, 0)),
            ..PlanOptions::default()
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("forbids lowering"), "{error}");

    let alpha = planner
        .plan(&PlanOptions {
            manifest_path: manifest_path.clone(),
            version_override: Some(Version::new(1, 1, 0)),
            prerelease_override: Some(Some(PrereleaseChannel::Alpha)),
            ..PlanOptions::default()
        })
        .await?;
    assert_eq!(alpha.version.to_string(), "1.1.0-alpha.1");

    let beta = planner
        .plan(&PlanOptions {
            manifest_path: manifest_path.clone(),
            version_override: Some("1.1.0-beta.7".parse()?),
            prerelease_override: Some(Some(PrereleaseChannel::Beta)),
            ..PlanOptions::default()
        })
        .await?;
    assert_eq!(beta.version.to_string(), "1.1.0-beta.7");

    let mismatched = planner
        .plan(&PlanOptions {
            manifest_path,
            version_override: Some("1.1.0-beta.7".parse()?),
            prerelease_override: Some(Some(PrereleaseChannel::Alpha)),
            ..PlanOptions::default()
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(mismatched.contains("does not belong"), "{mismatched}");
    Ok(())
}

#[tokio::test]
async fn unchanged_existing_release_is_noop_but_explicit_train_and_retirement_are_reported()
-> Result<()> {
    if Command::new("gleam").arg("--version").output().is_err() {
        eprintln!("skipping Gleam smoke test because gleam is not installed");
        return Ok(());
    }
    let temp = tempfile::tempdir()?;
    let package = temp.path();
    init_gleam_fixture(package, "noop_fixture", "1.0.0")?;
    git(package, &["tag", "v1.0.0"])?;
    let gleam = Gleam::default();
    let snapshot = gleam.snapshot(package)?;
    let source = gleam.export_hex_tarball(snapshot.package_dir())?;
    let interface = gleam.export_package_interface(snapshot.package_dir())?;
    let docs = docs_tarball(&interface)?;
    let manifest_path = package.join("gleam.toml");
    let registry = |retired| ExistingRegistry {
        version: Version::new(1, 0, 0),
        source: source.clone(),
        docs: docs.clone(),
        retired,
    };

    let plan = Planner::new(registry(false), gleam.clone())
        .plan(&PlanOptions {
            manifest_path: manifest_path.clone(),
            ..PlanOptions::default()
        })
        .await?;
    assert_eq!(plan.state, ReleaseState::UpToDate);
    assert!(!plan.release_required);
    assert!(!plan.artifacts_changed);
    assert!(plan.required_approvals.is_empty());
    assert!(plan.stages.is_empty());

    let explicit = Planner::new(registry(false), gleam.clone())
        .plan(&PlanOptions {
            manifest_path: manifest_path.clone(),
            version_override: Some(Version::new(1, 0, 1)),
            ..PlanOptions::default()
        })
        .await?;
    assert_eq!(explicit.version, Version::new(1, 0, 1));
    assert_eq!(explicit.bump, Bump::Patch);
    assert!(
        explicit
            .reasons
            .iter()
            .any(|reason| reason.kind == ReasonKind::ExplicitVersion)
    );

    let alpha = Planner::new(registry(false), gleam.clone())
        .plan(&PlanOptions {
            manifest_path: manifest_path.clone(),
            prerelease_override: Some(Some(PrereleaseChannel::Alpha)),
            ..PlanOptions::default()
        })
        .await?;
    assert_eq!(alpha.version.to_string(), "1.0.1-alpha.1");
    assert!(
        alpha
            .reasons
            .iter()
            .any(|reason| reason.kind == ReasonKind::Prerelease)
    );

    let retired = Planner::new(registry(true), gleam.clone())
        .plan(&PlanOptions {
            manifest_path: manifest_path.clone(),
            ..PlanOptions::default()
        })
        .await?;
    assert_eq!(retired.state, ReleaseState::UpToDate);
    assert!(
        retired
            .reasons
            .iter()
            .any(|reason| reason.kind == ReasonKind::RetiredBaseline)
    );

    let behind = Planner::new(
        ExistingRegistry {
            version: Version::new(1, 1, 0),
            source,
            docs,
            retired: false,
        },
        gleam,
    )
    .plan(&PlanOptions {
        manifest_path,
        ..PlanOptions::default()
    })
    .await
    .unwrap_err()
    .to_string();
    assert!(behind.contains("behind the latest"), "{behind}");
    Ok(())
}

#[tokio::test]
async fn existing_prerelease_trains_move_forward_promote_and_reject_backward_core_reuse()
-> Result<()> {
    if Command::new("gleam").arg("--version").output().is_err() {
        eprintln!("skipping Gleam smoke test because gleam is not installed");
        return Ok(());
    }
    let temp = tempfile::tempdir()?;
    let package = temp.path();
    init_gleam_fixture(package, "train_fixture", "1.1.0-rc.1")?;
    git(package, &["tag", "v1.1.0-rc.1"])?;
    git(package, &["tag", "v1.1.0-alpha.1"])?;
    let gleam = Gleam::default();
    let snapshot = gleam.snapshot(package)?;
    let source = gleam.export_hex_tarball(snapshot.package_dir())?;
    let interface = gleam.export_package_interface(snapshot.package_dir())?;
    let docs = docs_tarball(&interface)?;
    let manifest_path = package.join("gleam.toml");
    let registry = |version| ExistingRegistry {
        version,
        source: source.clone(),
        docs: docs.clone(),
        retired: false,
    };

    let promoted = Planner::new(registry("1.1.0-rc.1".parse()?), gleam.clone())
        .plan(&PlanOptions {
            manifest_path: manifest_path.clone(),
            prerelease_override: Some(None),
            ..PlanOptions::default()
        })
        .await?;
    assert_eq!(promoted.version, Version::new(1, 1, 0));

    let same = Planner::new(registry("1.1.0-rc.1".parse()?), gleam.clone())
        .plan(&PlanOptions {
            manifest_path: manifest_path.clone(),
            prerelease_override: Some(Some(PrereleaseChannel::Rc)),
            ..PlanOptions::default()
        })
        .await?;
    assert_eq!(same.state, ReleaseState::UpToDate);
    assert_eq!(same.version.to_string(), "1.1.0-rc.1");

    let backward = Planner::new(registry("1.1.0-rc.1".parse()?), gleam.clone())
        .plan(&PlanOptions {
            manifest_path: manifest_path.clone(),
            prerelease_override: Some(Some(PrereleaseChannel::Beta)),
            ..PlanOptions::default()
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(backward.contains("backward"), "{backward}");

    let beta = Planner::new(registry("1.1.0-alpha.1".parse()?), gleam)
        .plan(&PlanOptions {
            manifest_path,
            prerelease_override: Some(Some(PrereleaseChannel::Beta)),
            ignore_manifest_version: true,
            ..PlanOptions::default()
        })
        .await?;
    assert_eq!(beta.version.to_string(), "1.1.0-beta.1");
    Ok(())
}

#[tokio::test]
async fn explicit_baseline_ref_precedes_search_and_legacy_api_override_is_version_scoped()
-> Result<()> {
    if Command::new("gleam").arg("--version").output().is_err() {
        eprintln!("skipping Gleam smoke test because gleam is not installed");
        return Ok(());
    }
    let temp = tempfile::tempdir()?;
    let package = temp.path();
    fs::create_dir_all(package.join("src"))?;
    fs::write(
        package.join("gleam.toml"),
        r#"name = "baseline_fixture"
version = "1.0.0"
description = "Planner fixture"
licences = ["MIT"]

[tools.release-glz]
allow_unknown_api_for = ["1.0.0"]

[tools.release-glz.baseline_refs]
"1.0.0" = "HEAD"
"#,
    )?;
    fs::write(
        package.join("src/baseline_fixture.gleam"),
        "pub fn value() -> Int { 1 }\n",
    )?;
    git(package, &["init", "--initial-branch=main"])?;
    git(package, &["config", "core.hooksPath", ".git/no-hooks"])?;
    git(package, &["config", "user.email", "fixture@example.test"])?;
    git(package, &["config", "user.name", "Fixture"])?;
    git(package, &["config", "commit.gpgsign", "false"])?;
    git(package, &["add", "."])?;
    git(package, &["commit", "-m", "feat: baseline fixture"])?;

    let gleam = Gleam::default();
    let snapshot = gleam.snapshot(package)?;
    let source = gleam.export_hex_tarball(snapshot.package_dir())?;
    let plan = Planner::new(
        ExistingRegistry {
            version: Version::new(1, 0, 0),
            source,
            docs: b"not a docs archive".to_vec(),
            retired: false,
        },
        gleam,
    )
    .with_baseline_search_limit(1)
    .plan(&PlanOptions {
        manifest_path: package.join("gleam.toml"),
        ..PlanOptions::default()
    })
    .await?;
    assert_eq!(plan.baseline.source, BaselineSource::Config);
    assert_eq!(plan.api.status, ApiStatus::UnknownAllowed);
    assert!(
        plan.reasons
            .iter()
            .any(|reason| { reason.summary.contains("legacy version-scoped override") })
    );
    Ok(())
}

#[async_trait]
impl Registry for MockRegistry {
    async fn package(&self, _name: &str) -> Result<Option<PackageState>> {
        Ok(Some(PackageState {
            releases: vec![HexRelease {
                version: self.version.clone(),
                has_docs: true,
                retired: false,
            }],
        }))
    }

    async fn source_tarball(&self, _name: &str, _version: &Version) -> Result<Vec<u8>> {
        Ok(self.source.clone())
    }

    async fn docs_tarball(&self, _name: &str, _version: &Version) -> Result<Option<Vec<u8>>> {
        Ok(Some(self.docs.clone()))
    }
}

#[tokio::test]
async fn plan_uses_hex_api_and_tag_without_dirtying_the_package() -> Result<()> {
    if Command::new("gleam").arg("--version").output().is_err() {
        eprintln!("skipping Gleam smoke test because gleam is not installed");
        return Ok(());
    }
    let temp = tempfile::tempdir()?;
    let package = temp.path();
    fs::create_dir(package.join("src"))?;
    fs::write(
        package.join("gleam.toml"),
        r#"name = "planner_fixture"
version = "1.0.0"
description = "A release-glz planner fixture"
licences = ["MIT"]
"#,
    )?;
    fs::write(package.join("README.md"), "# Planner fixture\n")?;
    fs::write(
        package.join("src/planner_fixture.gleam"),
        "pub fn one() -> Int { 1 }\n",
    )?;
    git(package, &["init", "--initial-branch=main"])?;
    git(package, &["config", "core.hooksPath", ".git/no-hooks"])?;
    git(package, &["config", "user.email", "fixture@example.test"])?;
    git(package, &["config", "user.name", "Fixture"])?;
    git(package, &["config", "commit.gpgsign", "false"])?;
    git(package, &["config", "tag.gpgsign", "false"])?;
    git(package, &["add", "."])?;
    git(package, &["commit", "-m", "feat: initial API"])?;
    git(package, &["tag", "v1.0.0"])?;

    let gleam = Gleam::default();
    let baseline = gleam.snapshot(package)?;
    let source = gleam.export_hex_tarball(baseline.package_dir())?;
    let interface = gleam.export_package_interface(baseline.package_dir())?;
    let docs = docs_tarball(&interface)?;

    fs::write(
        package.join("src/planner_fixture.gleam"),
        "pub fn one() -> Int { 1 }\n\npub fn two() -> Int { 2 }\n",
    )?;
    git(package, &["add", "."])?;
    git(package, &["commit", "-m", "feat: add two"])?;
    let registry = MockRegistry {
        version: Version::new(1, 0, 0),
        source: source.clone(),
        docs,
    };
    let cache = temp.path().join("xdg-cache");
    let planner =
        Planner::new(registry.clone(), gleam.clone()).with_baseline_cache_dir(Some(cache.clone()));
    let options = PlanOptions {
        manifest_path: package.join("gleam.toml"),
        ..PlanOptions::default()
    };

    let plan = planner.plan(&options).await?;
    assert_eq!(plan.version, Version::new(1, 1, 0));
    assert_eq!(plan.bump, Bump::Minor);
    assert!(plan.artifacts_changed);
    assert_eq!(plan.api.impact, Bump::Minor);
    assert_eq!(plan.baseline.source, BaselineSource::Tag);
    assert!(!package.join("build").exists(), "plan dirtied the package");

    git(package, &["tag", "--delete", "v1.0.0"])?;
    let recovered = planner.plan(&options).await?;
    assert_eq!(
        recovered.baseline.source,
        BaselineSource::ArtifactFingerprint
    );
    assert!(
        cache.join("release-glz/baselines").is_dir(),
        "successful bounded fingerprint search was not cached"
    );
    let cached = Planner::new(registry.clone(), gleam.clone())
        .with_baseline_cache_dir(Some(cache.clone()))
        .with_baseline_search_limit(1)
        .plan(&options)
        .await?;
    assert_eq!(cached.baseline.source, BaselineSource::ArtifactFingerprint);

    let cache_directory = cache.join("release-glz/baselines");
    let cache_file = fs::read_dir(&cache_directory)?
        .next()
        .transpose()?
        .unwrap()
        .path();
    let mut poisoned: serde_json::Value = serde_json::from_slice(&fs::read(&cache_file)?)?;
    poisoned["sha"] = serde_json::Value::String("f".repeat(40));
    fs::write(&cache_file, serde_json::to_vec(&poisoned)?)?;
    let poisoned = Planner::new(registry.clone(), gleam.clone())
        .with_baseline_cache_dir(Some(cache))
        .with_baseline_search_limit(1)
        .plan(&options)
        .await
        .unwrap_err()
        .to_string();
    assert!(poisoned.contains("bounded"), "{poisoned}");

    let bounded = Planner::new(registry, gleam.clone())
        .with_baseline_cache_dir(None)
        .with_baseline_search_limit(1)
        .plan(&options)
        .await
        .unwrap_err()
        .to_string();
    assert!(bounded.contains("bounded"), "{bounded}");
    assert!(bounded.contains("1 commit"), "{bounded}");
    assert!(
        !package.join("build").exists(),
        "fingerprint recovery dirtied the package"
    );

    // Planning must describe HEAD, not uncommitted developer files.
    fs::write(
        package.join("src/planner_fixture.gleam"),
        "fn private_only() -> Int { 99 }\n",
    )?;
    let committed = planner.plan(&options).await?;
    assert_eq!(committed.version, Version::new(1, 1, 0));
    assert_eq!(committed.api.impact, Bump::Minor);

    let fallback = Planner::new(
        MockRegistry {
            version: Version::new(1, 0, 0),
            source,
            docs: tar_gz_file("index.html", b"<h1>old docs</h1>")?,
        },
        Gleam::default(),
    );
    let fallback_plan = fallback.plan(&options).await?;
    assert_eq!(fallback_plan.api.impact, Bump::Minor);
    Ok(())
}

#[tokio::test]
async fn breaking_zero_major_release_stays_on_the_zero_major_line() -> Result<()> {
    if Command::new("gleam").arg("--version").output().is_err() {
        eprintln!("skipping Gleam smoke test because gleam is not installed");
        return Ok(());
    }
    let temp = tempfile::tempdir()?;
    let package = temp.path();
    fs::create_dir(package.join("src"))?;
    fs::write(
        package.join("gleam.toml"),
        r#"name = "zero_fixture"
version = "0.4.0"
description = "A zero-major fixture"
licences = ["MIT"]

[tools.release-glz]
allow_version_zero = true
"#,
    )?;
    fs::write(package.join("README.md"), "# Zero fixture\n")?;
    fs::write(
        package.join("src/zero_fixture.gleam"),
        "pub fn public() -> Int { 1 }\n",
    )?;
    git(package, &["init", "--initial-branch=main"])?;
    git(package, &["config", "core.hooksPath", ".git/no-hooks"])?;
    git(package, &["config", "user.email", "fixture@example.test"])?;
    git(package, &["config", "user.name", "Fixture"])?;
    git(package, &["config", "commit.gpgsign", "false"])?;
    git(package, &["config", "tag.gpgsign", "false"])?;
    git(package, &["add", "."])?;
    git(package, &["commit", "-m", "feat: initial API"])?;
    git(package, &["tag", "v0.4.0"])?;

    let gleam = Gleam::default();
    let baseline = gleam.snapshot(package)?;
    let source = gleam.export_hex_tarball(baseline.package_dir())?;
    let interface = gleam.export_package_interface(baseline.package_dir())?;
    fs::write(
        package.join("src/zero_fixture.gleam"),
        "pub fn replacement() -> String { \"breaking\" }\n",
    )?;
    git(package, &["add", "."])?;
    git(package, &["commit", "-m", "feat!: replace API"])?;

    let planner = Planner::new(
        MockRegistry {
            version: Version::new(0, 4, 0),
            source,
            docs: docs_tarball(&interface)?,
        },
        gleam,
    );
    let plan = planner
        .plan(&PlanOptions {
            manifest_path: package.join("gleam.toml"),
            ..PlanOptions::default()
        })
        .await?;
    assert_eq!(plan.api.impact, Bump::Major);
    assert_eq!(plan.bump, Bump::Minor);
    assert_eq!(plan.version, Version::new(0, 5, 0));
    Ok(())
}

#[tokio::test]
async fn structured_api_exception_requires_an_active_expiry_and_resolvable_baseline() -> Result<()>
{
    let gleam_version = match Command::new("gleam").arg("--version").output() {
        Ok(output) if output.status.success() => String::from_utf8(output.stdout)?
            .split_whitespace()
            .find(|word| word.chars().next().is_some_and(|c| c.is_ascii_digit()))
            .unwrap()
            .to_owned(),
        _ => {
            eprintln!("skipping Gleam smoke test because gleam is not installed");
            return Ok(());
        }
    };
    let temp = tempfile::tempdir()?;
    let package = temp.path();
    fs::create_dir(package.join("src"))?;
    fs::write(
        package.join("gleam.toml"),
        exception_manifest(&gleam_version, "v1.0.0", "2999-12-31"),
    )?;
    fs::write(package.join("README.md"), "# API exception fixture\n")?;
    fs::write(
        package.join("src/exception_fixture.gleam"),
        "pub fn original() -> Int { 1 }\n",
    )?;
    git(package, &["init", "--initial-branch=main"])?;
    git(package, &["config", "core.hooksPath", ".git/no-hooks"])?;
    git(package, &["config", "user.email", "fixture@example.test"])?;
    git(package, &["config", "user.name", "Fixture"])?;
    git(package, &["config", "commit.gpgsign", "false"])?;
    git(package, &["config", "tag.gpgsign", "false"])?;
    git(package, &["add", "."])?;
    git(package, &["commit", "-m", "feat: initial API"])?;
    git(package, &["tag", "v1.0.0"])?;

    let gleam = Gleam::default();
    let baseline = gleam.snapshot(package)?;
    let source = gleam.export_hex_tarball(baseline.package_dir())?;
    fs::write(
        package.join("src/exception_fixture.gleam"),
        "pub fn replacement() -> String { \"changed\" }\n",
    )?;
    git(package, &["add", "."])?;
    git(package, &["commit", "-m", "feat!: replace API"])?;

    let planner = Planner::new(
        MockRegistry {
            version: Version::new(1, 0, 0),
            source,
            docs: b"not-a-docs-tarball".to_vec(),
        },
        gleam,
    );
    let options = PlanOptions {
        manifest_path: package.join("gleam.toml"),
        ..PlanOptions::default()
    };
    let allowed = planner.plan(&options).await?;
    assert_eq!(allowed.api.status, ApiStatus::UnknownAllowed);
    assert!(allowed.reasons.iter().any(|reason| {
        reason
            .summary
            .contains("Historical compiler output is unavailable")
            && reason.summary.contains("2999-12-31")
    }));

    fs::write(
        package.join("gleam.toml"),
        exception_manifest(&gleam_version, "v1.0.0", "2000-01-01"),
    )?;
    git(package, &["add", "gleam.toml"])?;
    git(package, &["commit", "-m", "test: expire exception"])?;
    let expired = planner.plan(&options).await.unwrap_err().to_string();
    assert!(expired.contains("expired"), "{expired}");
    assert!(expired.contains("2000-01-01"), "{expired}");

    fs::write(
        package.join("gleam.toml"),
        exception_manifest(&gleam_version, "refs/tags/missing", "2999-12-31"),
    )?;
    git(package, &["add", "gleam.toml"])?;
    git(
        package,
        &["commit", "-m", "test: missing exception baseline"],
    )?;
    let missing = planner.plan(&options).await.unwrap_err().to_string();
    assert!(missing.contains("refs/tags/missing"), "{missing}");
    assert!(missing.contains("cannot be resolved"), "{missing}");
    Ok(())
}

#[test]
fn release_files_are_repository_relative_structured_and_idempotently_updated() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let package = root.join("packages/widget");
    fs::create_dir_all(package.join(".release-glz/notes"))?;
    fs::create_dir_all(root.join(".github"))?;
    fs::write(
        package.join("gleam.toml"),
        r#"name = "widget"
version = "1.1.0"

[repository]
type = "github"
user = "owner"
repo = "widget"
"#,
    )?;
    fs::write(
        root.join(".github/release.yml"),
        r#"changelog:
  exclude:
    labels: [skip-release]
  categories:
    - title: Added
      labels: [feature]
    - title: Other
      labels: ["*"]
"#,
    )?;
    fs::write(
        package.join(".release-glz/notes/duplicate.toml"),
        "id = \"duplicate\"\ncategory = \"fixed\"\ntext = \"Duplicate PR note\"\npull_request = 7\n",
    )?;
    fs::write(
        package.join(".release-glz/notes/manual.toml"),
        "id = \"manual\"\ncategory = \"security\"\ntext = \"Harden candidate checks\"\n",
    )?;
    git(root, &["init", "--initial-branch=main"])?;

    let mut manifest = Manifest::load(package.join("gleam.toml"))?;
    let repo = GitRepo::discover(&package)?;
    let mut plan = release_file_plan();
    plan.changes = vec![
        ChangeEntry {
            category: "Changed".into(),
            title: "Add public API".into(),
            pull_request: Some(7),
            author: Some("contributor".into()),
            url: Some("https://github.test/pull/7".into()),
            labels: vec!["feature".into()],
        },
        ChangeEntry {
            category: "Changed".into(),
            title: "Internal maintenance".into(),
            pull_request: Some(8),
            author: Some("maintainer".into()),
            url: None,
            labels: vec!["skip-release".into()],
        },
    ];

    let files = prepare_release_files(&manifest, &repo, &plan, &plan.changes)?;
    assert_eq!(
        files.keys().map(String::as_str).collect::<Vec<_>>(),
        ["packages/widget/CHANGELOG.md", "packages/widget/gleam.toml"]
    );
    assert!(
        String::from_utf8_lossy(&files["packages/widget/gleam.toml"])
            .contains("version = \"1.2.0\"")
    );
    let changelog = String::from_utf8_lossy(&files["packages/widget/CHANGELOG.md"]);
    assert!(changelog.contains("## [1.2.0]"));
    assert!(changelog.contains("### Added"));
    assert!(changelog.contains("Add public API"));
    assert!(changelog.contains("### Security"));
    assert!(changelog.contains("Harden candidate checks"));
    assert!(!changelog.contains("Duplicate PR note"));
    assert!(!changelog.contains("Internal maintenance"));
    assert!(!package.join("CHANGELOG.md").exists());
    assert!(fs::read_to_string(package.join("gleam.toml"))?.contains("1.1.0"));

    let written = update_local(&mut manifest, &plan)?;
    assert_eq!(written.len(), 2);
    assert_eq!(manifest.version, Version::new(1, 2, 0));
    assert!(fs::read_to_string(package.join("gleam.toml"))?.contains("1.2.0"));
    assert!(fs::read_to_string(package.join("CHANGELOG.md"))?.contains("Harden candidate checks"));
    assert!(update_local(&mut manifest, &plan)?.is_empty());
    Ok(())
}

#[test]
fn release_file_generation_rejects_a_manifest_outside_the_discovered_repository() -> Result<()> {
    let repository = tempfile::tempdir()?;
    git(repository.path(), &["init", "--initial-branch=main"])?;
    let outside = tempfile::tempdir()?;
    let manifest_path = outside.path().join("gleam.toml");
    fs::write(&manifest_path, "name = \"outside\"\nversion = \"1.0.0\"\n")?;
    let manifest = Manifest::load(&manifest_path)?;
    let repo = GitRepo::discover(repository.path())?;

    let error = prepare_release_files(&manifest, &repo, &release_file_plan(), &[])
        .unwrap_err()
        .to_string();
    assert!(error.contains("outside git repository"), "{error}");
    Ok(())
}

fn release_file_plan() -> ReleasePlan {
    ReleasePlan {
        schema: ReleasePlan::SCHEMA.into(),
        state: ReleaseState::Planned,
        package: "widget".into(),
        manifest_path: "packages/widget/gleam.toml".into(),
        published_version: Some(Version::new(1, 1, 0)),
        manifest_version: Version::new(1, 1, 0),
        version: Version::new(1, 2, 0),
        bump: Bump::Minor,
        release_required: true,
        artifacts_changed: true,
        prerelease: None,
        tag: "v1.2.0".into(),
        baseline: Baseline {
            version: Some(Version::new(1, 1, 0)),
            git_ref: Some("v1.1.0".into()),
            sha: Some("a".repeat(40)),
            source: BaselineSource::Tag,
            retired: false,
        },
        reasons: vec![],
        api: ApiDiff::default(),
        changes: vec![],
        warnings: vec![],
        required_approvals: vec![],
        stages: vec![],
        intent_digest: None,
        pr_url: None,
        hex_url: None,
        github_release_url: None,
    }
}

fn exception_manifest(compiler: &str, baseline: &str, expires: &str) -> String {
    format!(
        r#"name = "exception_fixture"
version = "1.0.0"
description = "API exception fixture"
licences = ["MIT"]

[repository]
type = "github"
user = "acme"
repo = "exception_fixture"

[tools.release-glz]
schema = 2
compiler = "{compiler}"

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

[[tools.release-glz.api_exceptions]]
version = "1.0.0"
baseline = "{baseline}"
reason = "Historical compiler output is unavailable"
expires = "{expires}"
"#
    )
}

fn docs_tarball(interface: &[u8]) -> Result<Vec<u8>> {
    tar_gz_file("package-interface.json", interface)
}

fn tar_gz_file(path: &str, contents: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    {
        let encoder = GzEncoder::new(&mut bytes, Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, path, contents)?;
        let encoder = archive.into_inner()?;
        encoder.finish()?;
    }
    Ok(bytes)
}

fn init_gleam_fixture(package: &Path, name: &str, version: &str) -> Result<()> {
    fs::create_dir_all(package.join("src"))?;
    fs::write(
        package.join("gleam.toml"),
        format!(
            "name = \"{name}\"\nversion = \"{version}\"\ndescription = \"Planner fixture\"\nlicences = [\"MIT\"]\n"
        ),
    )?;
    fs::write(package.join("README.md"), "# Planner fixture\n")?;
    fs::write(
        package.join(format!("src/{name}.gleam")),
        "pub fn value() -> Int { 1 }\n",
    )?;
    git(package, &["init", "--initial-branch=main"])?;
    git(package, &["config", "core.hooksPath", ".git/no-hooks"])?;
    git(package, &["config", "user.email", "fixture@example.test"])?;
    git(package, &["config", "user.name", "Fixture"])?;
    git(package, &["config", "commit.gpgsign", "false"])?;
    git(package, &["config", "tag.gpgsign", "false"])?;
    git(package, &["add", "."])?;
    git(package, &["commit", "-m", "feat: initial fixture"])?;
    Ok(())
}

fn git(directory: &Path, args: &[&str]) -> Result<()> {
    let executable = if Path::new("/usr/bin/git").is_file() {
        "/usr/bin/git"
    } else {
        "git"
    };
    let output = Command::new(executable)
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
    Ok(())
}
