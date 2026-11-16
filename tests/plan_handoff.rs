use std::path::{Path, PathBuf};

use proptest::prelude::*;
use proptest::sample::{select, subsequence};
use release_glz::Manifest;
use release_glz::git::GitRepo;
use release_glz::handoff::{self, MAX_PLAN_BYTES, Refusal};
use release_glz::model::{
    ApiChange, ApiChangeKind, ApiDiff, ApiStatus, ApprovalKind, ApprovalRequirement, Baseline,
    BaselineSource, Bump, ChangeEntry, Diagnostic, DiagnosticLevel, PrereleaseChannel, ReasonKind,
    ReleasePlan, ReleaseReason, ReleaseStage, ReleaseState,
};
use release_glz_test_support::schema::assert_matches;
use release_glz_test_support::{git, init_repository, property};
use semver::{BuildMetadata, Prerelease, Version};
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

    let error = handoff::write_new(&path, &plan(None)).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!("failed to create plan `{}`", path.display())
    );
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::AlreadyExists),
        "{error:#}"
    );
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
            edited(|plan| plan["schema"] = "plan/v2".into()),
            Refusal::Schema("plan/v2".into()),
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
        (
            "a baseline whose members are listed by position".into(),
            edited(|plan| {
                plan["baseline"] = serde_json::json!(["0.9.0", "v0.9.0", null, "tag", false]);
            }),
            Refusal::NotAPlan(handoff::UNWRITTEN_SPELLING.into()),
        ),
        (
            "a state spelled as a map".into(),
            edited(|plan| plan["state"] = serde_json::json!({"planned": null})),
            Refusal::NotAPlan(handoff::UNWRITTEN_SPELLING.into()),
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
        history.first.chars().take(7).collect(),
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

#[test]
fn each_refusal_names_what_the_plan_file_got_wrong() {
    for (refusal, expected) in [
        (
            Refusal::TooLarge,
            format!("larger than {MAX_PLAN_BYTES} bytes"),
        ),
        (
            Refusal::NotAPlan("missing field `state`".into()),
            format!(
                "not a {} document: missing field `state`",
                ReleasePlan::SCHEMA
            ),
        ),
        (
            Refusal::Schema("plan/v2".into()),
            "has schema `plan/v2`".to_owned(),
        ),
        (
            Refusal::ReleasePrNamed,
            "already names a Release PR".to_owned(),
        ),
        (
            Refusal::OtherManifest {
                package: "widget".into(),
                version: Version::new(1, 2, 3),
            },
            "describes widget 1.2.3".to_owned(),
        ),
        (
            Refusal::BaselineOutsideHistory("abc".into()),
            "baseline `abc` is not in the checked-out history".to_owned(),
        ),
    ] {
        let message = refusal.to_string();
        assert!(
            message.contains(&expected),
            "{message:?} lacks {expected:?}"
        );
    }
}

proptest! {
    #![proptest_config(property::config(64))]

    /// A plan that `plan --out` writes reads back as the same plan.
    #[test]
    fn generated_plans_read_back_unchanged(plan in release_plan()) {
        let written = serde_json::to_value(&plan).unwrap();
        assert_matches("release-plan.schema.json", &written);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("plan.json");
        handoff::write_new(&path, &plan).unwrap();
        let read = handoff::read(&path).unwrap();
        prop_assert_eq!(serde_json::to_value(read).unwrap(), written);
    }

    /// The handoff carries no digest, so one changed, removed, or added byte is refused with a handoff reason or read as exactly the plan that the changed bytes spell.
    ///
    /// The writing job then holds the plan to its own checkout with `check_checkout`.
    #[test]
    fn a_changed_plan_file_is_refused_or_read_as_the_plan_it_spells(
        plan in release_plan(),
        changes in prop::collection::vec(property::byte_change(), 16),
    ) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("plan.json");
        handoff::write_new(&path, &plan).unwrap();
        let written = std::fs::read(&path).unwrap();
        let changed_path = directory.path().join("changed.json");
        for change in &changes {
            let changed = change.apply(&written);
            std::fs::write(&changed_path, &changed).unwrap();
            match handoff::read(&changed_path) {
                Ok(read) => {
                    prop_assert_eq!(read.schema.as_str(), ReleasePlan::SCHEMA, "{:?}", change);
                    prop_assert!(read.pr_url.is_none(), "{:?}", change);
                    prop_assert!(read.release_pr_head.is_none(), "{:?}", change);
                    prop_assert_eq!(
                        serde_json::to_value(&read).unwrap(),
                        serde_json::from_slice::<Value>(&changed).unwrap(),
                        "{:?}",
                        change
                    );
                }
                Err(error) => prop_assert!(
                    matches!(
                        error.downcast_ref::<Refusal>(),
                        Some(Refusal::NotAPlan(_) | Refusal::Schema(_))
                    ),
                    "{change:?}: {error:#}"
                ),
            }
        }
    }
}

/// Characters that JSON escapes, characters beyond the Basic Multilingual Plane, and plain letters.
const TEXT_CHARACTERS: &[char] = &[
    'a',
    'Z',
    '0',
    ' ',
    '"',
    '\\',
    '/',
    '\u{0}',
    '\n',
    '\u{1f}',
    '\u{7f}',
    'é',
    '\u{2028}',
    '\u{fffd}',
    '\u{10000}',
];

/// Free text, as a plan carries it in summaries, titles, and links.
fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => prop::collection::vec(select(TEXT_CHARACTERS), 0..12).prop_map(String::from_iter),
        1 => any::<String>(),
    ]
}

/// Semantic versions with and without prerelease identifiers and build metadata.
fn version() -> impl Strategy<Value = Version> {
    let number = || prop_oneof![0..20_u64, any::<u64>()];
    (
        number(),
        number(),
        number(),
        prop::option::of("[a-z]{1,5}(\\.(0|[1-9][0-9]{0,2}))?"),
        prop::option::of("[0-9a-zA-Z]{1,6}(\\.[0-9a-z]{1,3})?"),
    )
        .prop_map(|(major, minor, patch, pre, build)| Version {
            major,
            minor,
            patch,
            pre: pre.map_or(Prerelease::EMPTY, |pre| Prerelease::new(&pre).unwrap()),
            build: build.map_or(BuildMetadata::EMPTY, |build| {
                BuildMetadata::new(&build).unwrap()
            }),
        })
}

const STATES: &[ReleaseState] = &[
    ReleaseState::UpToDate,
    ReleaseState::Planned,
    ReleaseState::CandidateReady,
    ReleaseState::AwaitingApproval,
    ReleaseState::PartiallyReleased,
    ReleaseState::Released,
    ReleaseState::Conflict,
    ReleaseState::Blocked,
];

const BUMPS: &[Bump] = &[Bump::None, Bump::Patch, Bump::Minor, Bump::Major];

const STAGES: &[ReleaseStage] = &[
    ReleaseStage::VerifyHooks,
    ReleaseStage::PrepareGitTag,
    ReleaseStage::PrepareGithubDraft,
    ReleaseStage::PublishPackage,
    ReleaseStage::PublishDocs,
    ReleaseStage::FinalizeGithubRelease,
    ReleaseStage::NotifyHooks,
];

fn baseline() -> impl Strategy<Value = Baseline> {
    (
        prop::option::of(version()),
        prop::option::of(text()),
        prop::option::of("[0-9a-f]{40}"),
        select(
            &[
                BaselineSource::Tag,
                BaselineSource::ArtifactFingerprint,
                BaselineSource::Config,
                BaselineSource::Initial,
            ][..],
        ),
        any::<bool>(),
    )
        .prop_map(|(version, git_ref, sha, source, retired)| Baseline {
            version,
            git_ref,
            sha,
            source,
            retired,
        })
}

fn reason() -> impl Strategy<Value = ReleaseReason> {
    (
        select(
            &[
                ReasonKind::InitialRelease,
                ReasonKind::ArtifactChanged,
                ReasonKind::ConventionalCommit,
                ReasonKind::ApiAdded,
                ReasonKind::ApiBreaking,
                ReasonKind::ExplicitVersion,
                ReasonKind::Prerelease,
                ReasonKind::RetiredBaseline,
            ][..],
        ),
        select(BUMPS),
        text(),
    )
        .prop_map(|(kind, bump, summary)| ReleaseReason {
            kind,
            bump,
            summary,
        })
}

fn api_diff() -> impl Strategy<Value = ApiDiff> {
    let change = (
        select(
            &[
                ApiChangeKind::Added,
                ApiChangeKind::Removed,
                ApiChangeKind::Changed,
                ApiChangeKind::ConstructorAdded,
            ][..],
        ),
        text(),
        any::<bool>(),
        text(),
    )
        .prop_map(|(kind, path, breaking, summary)| ApiChange {
            kind,
            path,
            breaking,
            summary,
        });
    (
        select(
            &[
                ApiStatus::NotChecked,
                ApiStatus::Compatible,
                ApiStatus::Changed,
                ApiStatus::UnknownAllowed,
            ][..],
        ),
        select(BUMPS),
        prop::collection::vec(change, 0..3),
    )
        .prop_map(|(status, impact, changes)| ApiDiff {
            status,
            impact,
            changes,
        })
}

fn change_entry() -> impl Strategy<Value = ChangeEntry> {
    (
        text(),
        prop::option::of(1..=u64::MAX),
        prop::option::of(text()),
        prop::option::of(text()),
        prop::collection::vec(text(), 0..3),
        text(),
    )
        .prop_map(
            |(title, pull_request, author, url, labels, category)| ChangeEntry {
                title,
                pull_request,
                author,
                url,
                labels,
                category,
            },
        )
}

fn diagnostic() -> impl Strategy<Value = Diagnostic> {
    (
        text(),
        select(
            &[
                DiagnosticLevel::Info,
                DiagnosticLevel::Warning,
                DiagnosticLevel::Error,
            ][..],
        ),
        text(),
        prop::option::of(text()),
    )
        .prop_map(|(code, level, message, detail)| Diagnostic {
            code,
            level,
            message,
            detail,
        })
}

fn approval() -> impl Strategy<Value = ApprovalRequirement> {
    (
        select(
            &[
                ApprovalKind::ReleasePr,
                ApprovalKind::Environment,
                ApprovalKind::CandidateDigest,
            ][..],
        ),
        prop::option::of(text()),
    )
        .prop_map(|(kind, environment)| ApprovalRequirement { kind, environment })
}

/// Plans within the published schema, as `plan --out` writes them: before any Release PR exists.
fn release_plan() -> impl Strategy<Value = ReleasePlan> {
    let identity = (
        select(STATES),
        "[a-z][a-z0-9_]{0,11}",
        "([a-z]{1,6}/){0,2}gleam\\.toml",
        prop::option::of(version()),
        version(),
        version(),
        "([a-z]{1,6}/)?",
        prop::option::of(select(
            &[
                PrereleaseChannel::Alpha,
                PrereleaseChannel::Beta,
                PrereleaseChannel::Rc,
            ][..],
        )),
    );
    let decision = (select(BUMPS), any::<bool>(), any::<bool>(), baseline());
    let findings = (
        prop::collection::vec(reason(), 0..3),
        api_diff(),
        prop::collection::vec(change_entry(), 0..3),
        prop::collection::vec(diagnostic(), 0..3),
        prop::collection::vec(approval(), 0..3),
        subsequence(STAGES, 0..=STAGES.len()),
        prop::option::of(text()),
        prop::option::of(text()),
    );
    (identity, decision, findings).prop_map(
        |(
            (
                state,
                package,
                manifest_path,
                published_version,
                manifest_version,
                version,
                tag_prefix,
                prerelease,
            ),
            (bump, release_required, artifacts_changed, baseline),
            (
                reasons,
                api,
                changes,
                warnings,
                required_approvals,
                stages,
                hex_url,
                github_release_url,
            ),
        )| ReleasePlan {
            schema: ReleasePlan::SCHEMA.into(),
            state,
            package,
            manifest_path,
            published_version,
            manifest_version,
            tag: format!("{tag_prefix}v{version}"),
            version,
            bump,
            release_required,
            artifacts_changed,
            prerelease,
            baseline,
            reasons,
            api,
            changes,
            warnings,
            required_approvals,
            stages,
            pr_url: None,
            release_pr_head: None,
            hex_url,
            github_release_url,
        },
    )
}
