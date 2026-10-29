use std::path::{Path, PathBuf};

use release_glz::Manifest;
use release_glz::git::GitRepo;
use release_glz::handoff::{self, MAX_PLAN_BYTES, Refusal};
use release_glz::model::{
    ApiChange, ApiChangeKind, ApiDiff, ApprovalKind, ApprovalRequirement, Baseline, BaselineSource,
    Bump, ChangeEntry, Diagnostic, DiagnosticLevel, ReasonKind, ReleasePlan, ReleaseReason,
    ReleaseState,
};
use release_glz_test_support::{git, init_repository};
use semver::Version;
use serde_json::Value;

const MANIFEST: &str = "name = \"widget\"\nversion = \"1.0.0\"\n";

/// A repository whose `main` holds `first` and then `head`, beside a `side` commit that `main` lacks.
struct History {
    directory: tempfile::TempDir,
    first: String,
    side: String,
    head: String,
}

impl History {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        init_repository(root);
        std::fs::write(root.join("gleam.toml"), MANIFEST).unwrap();
        git(root, &["add", "gleam.toml"]);
        let first = commit(root, "feat: first");
        git(root, &["switch", "--quiet", "--create", "side"]);
        let side = commit(root, "chore: side");
        git(root, &["switch", "--quiet", "main"]);
        let head = commit(root, "fix: second");
        Self {
            directory,
            first,
            side,
            head,
        }
    }

    fn check(&self, plan: &ReleasePlan) -> anyhow::Result<()> {
        let root = self.directory.path();
        let manifest = Manifest::load(root.join("gleam.toml")).unwrap();
        handoff::check_checkout(plan, &manifest, &GitRepo::discover(root).unwrap())
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.directory.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }
}

fn commit(repository: &Path, message: &str) -> String {
    git(
        repository,
        &["commit", "--quiet", "--allow-empty", "--message", message],
    );
    git(repository, &["rev-parse", "HEAD"]).trim().to_owned()
}

/// A plan with one item in every nested list, so each nested type meets the reader.
fn plan(baseline: Option<&str>) -> ReleasePlan {
    ReleasePlan {
        schema: ReleasePlan::SCHEMA.into(),
        state: ReleaseState::Planned,
        package: "widget".into(),
        manifest_path: "gleam.toml".into(),
        published_version: Some(Version::new(0, 9, 0)),
        manifest_version: Version::new(1, 0, 0),
        version: Version::new(1, 0, 0),
        bump: Bump::Major,
        release_required: true,
        artifacts_changed: true,
        prerelease: None,
        tag: "v1.0.0".into(),
        baseline: Baseline {
            version: Some(Version::new(0, 9, 0)),
            git_ref: Some("v0.9.0".into()),
            sha: baseline.map(ToOwned::to_owned),
            source: BaselineSource::Tag,
            retired: false,
        },
        reasons: vec![ReleaseReason {
            kind: ReasonKind::ApiBreaking,
            bump: Bump::Major,
            summary: "removed widget/old".into(),
        }],
        api: ApiDiff {
            changes: vec![ApiChange {
                kind: ApiChangeKind::Removed,
                path: "widget/old".into(),
                breaking: true,
                summary: "removed".into(),
            }],
            ..ApiDiff::default()
        },
        changes: vec![ChangeEntry {
            title: "fix: second".into(),
            pull_request: None,
            author: Some("Fixture".into()),
            url: None,
            labels: vec![],
            category: "Fixed".into(),
        }],
        warnings: vec![Diagnostic {
            code: "fixture".into(),
            level: DiagnosticLevel::Warning,
            message: "fixture".into(),
            detail: None,
        }],
        required_approvals: vec![ApprovalRequirement {
            kind: ApprovalKind::Environment,
            environment: Some("release".into()),
        }],
        stages: vec![],
        intent_digest: None,
        pr_url: None,
        release_pr_head: None,
        hex_url: None,
        github_release_url: None,
    }
}

fn refusal(error: &anyhow::Error) -> &Refusal {
    error
        .downcast_ref::<Refusal>()
        .unwrap_or_else(|| panic!("not a handoff refusal: {error:#}"))
}

fn edited(change: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value = serde_json::to_value(plan(None)).unwrap();
    change(&mut value);
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn a_written_plan_reads_back_unchanged_and_is_never_replaced() {
    let history = History::new();
    let path = history.directory.path().join("plan.json");
    let written = plan(Some(&history.first));

    handoff::write_new(&path, &written).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(
        serde_json::to_value(handoff::read(&path).unwrap()).unwrap(),
        serde_json::to_value(&written).unwrap()
    );

    assert!(handoff::write_new(&path, &plan(None)).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn a_file_that_plan_out_could_not_have_written_is_refused_with_its_reason() {
    let history = History::new();
    let limit = usize::try_from(MAX_PLAN_BYTES).unwrap();
    let mut at_limit = serde_json::to_vec(&plan(None)).unwrap();
    at_limit.resize(limit, b' ');
    let mut above_limit = at_limit.clone();
    above_limit.push(b' ');
    assert!(handoff::read(&history.file("at-limit.json", &at_limit)).is_ok());

    let mut cases: Vec<(String, Vec<u8>, Refusal)> = vec![
        ("above the limit".into(), above_limit, Refusal::TooLarge),
        (
            "another schema".into(),
            edited(|plan| plan["schema"] = "plan/v1".into()),
            Refusal::Schema("plan/v1".into()),
        ),
        (
            "a Release PR head".into(),
            edited(|plan| plan["release_pr_head"] = "c".repeat(40).into()),
            Refusal::ReleasePrNamed,
        ),
        (
            "a Release PR page".into(),
            edited(|plan| plan["pr_url"] = "https://github.test/acme/widget/pull/1".into()),
            Refusal::ReleasePrNamed,
        ),
    ];
    for pointer in [
        "",
        "/baseline",
        "/reasons/0",
        "/api",
        "/api/changes/0",
        "/changes/0",
        "/warnings/0",
        "/required_approvals/0",
    ] {
        let bytes = edited(|plan| {
            plan.pointer_mut(pointer).unwrap()["unknown"] = true.into();
        });
        let expected = Refusal::NotAPlan(
            serde_json::from_slice::<ReleasePlan>(&bytes)
                .unwrap_err()
                .to_string(),
        );
        cases.push((format!("an unknown field at `{pointer}`"), bytes, expected));
    }
    for (case, bytes, expected) in cases {
        let error = handoff::read(&history.file("refused.json", &bytes)).unwrap_err();
        assert_eq!(refusal(&error), &expected, "{case}");
    }
    let error = handoff::read(&history.file("text.json", b"plan")).unwrap_err();
    assert!(matches!(refusal(&error), Refusal::NotAPlan(_)), "{error:#}");
}

#[test]
fn a_plan_for_another_checkout_is_refused_with_its_reason() {
    let history = History::new();
    for baseline in [
        None,
        Some(history.first.as_str()),
        Some(history.head.as_str()),
    ] {
        history
            .check(&plan(baseline))
            .unwrap_or_else(|error| panic!("{baseline:?}: {error:#}"));
    }

    let mut another_package = plan(None);
    another_package.package = "gadget".into();
    let mut another_version = plan(None);
    another_version.manifest_version = Version::new(1, 0, 1);
    for (case, refused) in [
        ("another package", another_package),
        ("another manifest version", another_version),
    ] {
        let error = history.check(&refused).unwrap_err();
        assert!(
            matches!(refusal(&error), Refusal::OtherManifest { .. }),
            "{case}: {error:#}"
        );
    }

    for baseline in [
        history.side.clone(),
        "f".repeat(40),
        history.first.to_ascii_uppercase(),
        history.first[..7].to_owned(),
        "HEAD".to_owned(),
        "main".to_owned(),
    ] {
        let error = history.check(&plan(Some(&baseline))).unwrap_err();
        assert_eq!(
            refusal(&error),
            &Refusal::BaselineOutsideHistory(baseline.clone()),
            "{baseline}"
        );
    }
}
