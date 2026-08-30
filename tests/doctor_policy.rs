use semver::Version;

use release_glz::config::{ApprovalConfig, SeparationMode};
use release_glz::doctor::{DoctorInput, assess, assess_local};
use release_glz::forge::GitHubEnvironmentAudit;
use release_glz::model::{DiagnosticLevel, ReleaseState};
use release_glz::registry::RegistryCredentialAudit;

fn audit() -> GitHubEnvironmentAudit {
    GitHubEnvironmentAudit {
        private_repository: true,
        plan: Some("enterprise".into()),
        default_branch: "main".into(),
        default_branch_protected: true,
        required_reviewers: 1,
        prevent_self_review: true,
        protected_branches_only: true,
    }
}

fn input() -> DoctorInput {
    DoctorInput {
        config_schema: 2,
        package_version: Version::new(1, 2, 3),
        required_compiler: Version::new(1, 12, 3),
        installed_compiler: Some(Version::new(1, 12, 3)),
        registry_credential: RegistryCredentialAudit::PublishAndReadAllowed,
        workflow_current: true,
        approval: ApprovalConfig {
            separation: SeparationMode::Strict,
            ..ApprovalConfig::default()
        },
        github_environment: Some(audit()),
    }
}

#[test]
fn strict_mode_requires_separate_review_protected_branch_and_exact_tooling() {
    let report = assess(&input());
    assert_eq!(report.schema, "doctor/v1");
    assert_eq!(report.state, ReleaseState::UpToDate);
    assert!(report.diagnostics.is_empty());

    let mut broken = input();
    broken.installed_compiler = Some(Version::new(1, 13, 0));
    broken.registry_credential = RegistryCredentialAudit::Missing;
    broken.workflow_current = false;
    let environment = broken.github_environment.as_mut().unwrap();
    environment.required_reviewers = 0;
    environment.prevent_self_review = false;
    environment.default_branch_protected = false;
    environment.protected_branches_only = false;

    let report = assess(&broken);
    assert_eq!(report.state, ReleaseState::Blocked);
    for code in [
        "compiler_mismatch",
        "registry_credential_missing",
        "workflow_outdated",
        "strict_reviewer_missing",
        "strict_self_review_allowed",
        "default_branch_unprotected",
        "environment_branch_policy_weak",
    ] {
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == code
                    && diagnostic.level == DiagnosticLevel::Error),
            "missing {code}: {:?}",
            report.diagnostics
        );
    }
}

#[test]
fn local_assessment_explicitly_reports_skipped_protection_checks() {
    let report = assess_local(&input());
    assert_eq!(report.state, ReleaseState::UpToDate);
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "online_checks_skipped" && diagnostic.level == DiagnosticLevel::Info
    }));
    assert!(
        report
            .next_actions
            .iter()
            .any(|action| { action.argv == ["release-glz", "doctor", "--online"] })
    );
}

#[test]
fn registry_credential_failures_have_actionable_non_secret_diagnostics() {
    for (status, code) in [
        (
            RegistryCredentialAudit::Invalid,
            "registry_credential_invalid",
        ),
        (
            RegistryCredentialAudit::PublishPermissionDenied,
            "registry_publish_permission_missing",
        ),
        (
            RegistryCredentialAudit::RepositoryReadPermissionDenied,
            "registry_repository_read_permission_missing",
        ),
        (
            RegistryCredentialAudit::Unavailable,
            "registry_credential_unobserved",
        ),
    ] {
        let mut value = input();
        value.registry_credential = status;
        let report = assess(&value);
        assert_eq!(report.state, ReleaseState::Blocked);
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == code && diagnostic.level == DiagnosticLevel::Error
        }));
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("token"));
        assert!(!serialized.contains("secret"));
    }
}

#[test]
fn private_solo_repositories_require_an_actual_gate_or_explicit_digest_promotion() {
    let mut solo = input();
    solo.approval.separation = SeparationMode::Solo;
    let environment = solo.github_environment.as_mut().unwrap();
    environment.plan = Some("team".into());
    environment.required_reviewers = 0;
    environment.prevent_self_review = false;

    let blocked = assess(&solo);
    assert_eq!(blocked.state, ReleaseState::Blocked);
    assert!(blocked.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "private_environment_reviewers_unavailable"
            && diagnostic.level == DiagnosticLevel::Error
    }));

    solo.approval.private_repository_fallback = Some("workflow-dispatch-digest".into());
    let allowed = assess(&solo);
    assert_eq!(allowed.state, ReleaseState::UpToDate);
    assert!(allowed.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "digest_promotion_fallback"
            && diagnostic.level == DiagnosticLevel::Warning
    }));
}

#[test]
fn schema_two_and_github_observation_are_shipping_requirements_but_zero_x_is_only_a_warning() {
    let mut incomplete = input();
    incomplete.config_schema = 1;
    incomplete.package_version = Version::new(0, 4, 2);
    incomplete.github_environment = None;

    let report = assess(&incomplete);
    assert_eq!(report.state, ReleaseState::Blocked);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "config_schema_legacy")
    );
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "github_environment_unobserved"
            && diagnostic.level == DiagnosticLevel::Error
    }));
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "version_zero" && diagnostic.level == DiagnosticLevel::Warning
    }));
}

#[test]
fn missing_compiler_and_every_approval_plan_boundary_are_diagnosed_exactly() {
    let mut missing_compiler = input();
    missing_compiler.installed_compiler = None;
    let report = assess(&missing_compiler);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "compiler_missing")
    );
    assert_eq!(
        report
            .next_actions
            .iter()
            .filter(|action| action.command == "install Gleam 1.12.3")
            .count(),
        1
    );
    assert!(
        !report
            .next_actions
            .iter()
            .any(|action| action.command == "configure GitHub Environment protections"),
        "unrelated compiler failures must not imply broken Environment protections"
    );

    let mut strict_private_without_reviewers = input();
    let environment = strict_private_without_reviewers
        .github_environment
        .as_mut()
        .unwrap();
    environment.plan = None;
    strict_private_without_reviewers
        .approval
        .private_repository_fallback = Some("workflow-dispatch-digest".into());
    let report = assess(&strict_private_without_reviewers);
    for code in [
        "strict_private_plan_unsupported",
        "strict_fallback_forbidden",
    ] {
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == code),
            "missing {code}: {:?}",
            report.diagnostics
        );
    }
    assert_eq!(
        report
            .next_actions
            .iter()
            .filter(|action| action.command == "configure GitHub Environment protections")
            .count(),
        1
    );

    let mut strict_public = input();
    strict_public
        .github_environment
        .as_mut()
        .unwrap()
        .private_repository = false;
    assert_eq!(assess(&strict_public).state, ReleaseState::UpToDate);

    let mut solo_public_without_reviewer = strict_public;
    solo_public_without_reviewer.approval.separation = SeparationMode::Solo;
    solo_public_without_reviewer
        .github_environment
        .as_mut()
        .unwrap()
        .required_reviewers = 0;
    let report = assess(&solo_public_without_reviewer);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "environment_reviewer_missing")
    );

    let mut solo_private_enterprise_without_reviewer = input();
    solo_private_enterprise_without_reviewer.approval.separation = SeparationMode::Solo;
    solo_private_enterprise_without_reviewer
        .github_environment
        .as_mut()
        .unwrap()
        .required_reviewers = 0;
    let report = assess(&solo_private_enterprise_without_reviewer);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "environment_reviewer_missing")
    );

    let mut solo_private_enterprise = input();
    solo_private_enterprise.approval.separation = SeparationMode::Solo;
    assert_eq!(
        assess(&solo_private_enterprise).state,
        ReleaseState::UpToDate
    );

    for unsupported in ["free", "pro", "team"] {
        let mut private = input();
        private.github_environment.as_mut().unwrap().plan = Some(unsupported.into());
        assert!(
            assess(&private)
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == "strict_private_plan_unsupported" }),
            "private {unsupported} unexpectedly exposed required reviewers"
        );
    }
}
