use semver::Version;
use serde::Serialize;

use crate::config::{ApprovalConfig, SeparationMode};
use crate::forge::GitHubEnvironmentAudit;
use crate::model::{Diagnostic, DiagnosticLevel, NextAction, ReleaseState};
use crate::registry::RegistryCredentialAudit;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorInput {
    pub config_schema: u32,
    pub package_version: Version,
    pub required_compiler: Version,
    pub installed_compiler: Option<Version>,
    pub registry_credential: RegistryCredentialAudit,
    pub workflow_current: bool,
    pub approval: ApprovalConfig,
    pub github_environment: Option<GitHubEnvironmentAudit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    pub schema: String,
    pub state: ReleaseState,
    pub config_schema: u32,
    pub required_compiler: Version,
    pub installed_compiler: Option<Version>,
    pub diagnostics: Vec<Diagnostic>,
    pub next_actions: Vec<NextAction>,
}

pub fn assess(input: &DoctorInput) -> DoctorReport {
    assess_mode(input, true)
}

/// Assess checks that require no network access and no registry credential.
pub fn assess_local(input: &DoctorInput) -> DoctorReport {
    assess_mode(input, false)
}

fn assess_mode(input: &DoctorInput, online: bool) -> DoctorReport {
    let mut diagnostics = Vec::new();
    let mut next_actions = Vec::new();

    if input.config_schema != 2 {
        error(
            &mut diagnostics,
            "config_schema_legacy",
            "release requires `[tools.release-glz] schema = 2`",
        );
        action(
            &mut next_actions,
            "release-glz migrate --update",
            "Migrate the manifest to schema 2 without discarding legacy settings.",
        );
    }
    if input.package_version.major == 0 {
        warning(
            &mut diagnostics,
            "version_zero",
            "Gleam recommends starting published packages at version 1.0.0; 0.x remains supported",
        );
    }
    match &input.installed_compiler {
        Some(actual) if actual == &input.required_compiler => {}
        Some(actual) => {
            error(
                &mut diagnostics,
                "compiler_mismatch",
                format!(
                    "configured Gleam {} is required, but {} is installed",
                    input.required_compiler, actual
                ),
            );
            action(
                &mut next_actions,
                format!("install Gleam {}", input.required_compiler),
                "Install the exact compiler sealed into each Candidate.",
            );
        }
        None => {
            error(
                &mut diagnostics,
                "compiler_missing",
                format!(
                    "configured Gleam {} is not available",
                    input.required_compiler
                ),
            );
            action(
                &mut next_actions,
                format!("install Gleam {}", input.required_compiler),
                "Install the exact compiler sealed into each Candidate.",
            );
        }
    }
    if online {
        match input.registry_credential {
            RegistryCredentialAudit::PublishAndReadAllowed => {}
            RegistryCredentialAudit::Missing => {
                error(
                    &mut diagnostics,
                    "registry_credential_missing",
                    "the configured registry credential environment variable is not present",
                );
                action(
                    &mut next_actions,
                    "configure registry credential",
                    "Add the publish credential only to the protected GitHub Environment.",
                );
            }
            RegistryCredentialAudit::Invalid => {
                error(
                    &mut diagnostics,
                    "registry_credential_invalid",
                    "the configured registry credential was rejected",
                );
                action(
                    &mut next_actions,
                    "replace registry credential",
                    "Configure a currently valid credential in the protected GitHub Environment.",
                );
            }
            RegistryCredentialAudit::PublishPermissionDenied => {
                error(
                    &mut diagnostics,
                    "registry_publish_permission_missing",
                    "the registry credential does not have API write permission",
                );
                action(
                    &mut next_actions,
                    "grant registry api:write",
                    "Grant only the API write capability required to publish the Candidate.",
                );
            }
            RegistryCredentialAudit::RepositoryReadPermissionDenied => {
                error(
                    &mut diagnostics,
                    "registry_repository_read_permission_missing",
                    "the registry credential cannot read the configured private repository",
                );
                action(
                    &mut next_actions,
                    "grant configured repository read access",
                    "Grant read access only to the configured private repository.",
                );
            }
            RegistryCredentialAudit::Unavailable => {
                error(
                    &mut diagnostics,
                    "registry_credential_unobserved",
                    "registry credential permissions could not be verified",
                );
                action(
                    &mut next_actions,
                    "release-glz doctor --online",
                    "Restore registry connectivity before attempting a release.",
                );
            }
        }
    }
    if !input.workflow_current {
        error(
            &mut diagnostics,
            "workflow_outdated",
            "the managed release workflow does not match the current configuration",
        );
        action(
            &mut next_actions,
            "release-glz init --update",
            "Update the managed workflow after reviewing its diff.",
        );
    }

    if online {
        match &input.github_environment {
            Some(environment) => assess_approval(
                &input.approval,
                environment,
                &mut diagnostics,
                &mut next_actions,
            ),
            None => {
                error(
                    &mut diagnostics,
                    "github_environment_unobserved",
                    "GitHub Environment and branch protection could not be verified",
                );
                action(
                    &mut next_actions,
                    "configure GITHUB_TOKEN",
                    "Provide read access so doctor can verify repository release protections.",
                );
            }
        }
    } else {
        diagnostics.push(Diagnostic {
            code: "online_checks_skipped".into(),
            level: DiagnosticLevel::Info,
            message: "registry credentials and GitHub release protections were not checked".into(),
            detail: Some("run `release-glz doctor --online` before a release".into()),
        });
        action(
            &mut next_actions,
            "release-glz doctor --online",
            "Verify registry credentials and GitHub release protections.",
        );
    }

    let state = if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.level == DiagnosticLevel::Error)
    {
        ReleaseState::Blocked
    } else {
        ReleaseState::UpToDate
    };
    DoctorReport {
        schema: "doctor/v1".into(),
        state,
        config_schema: input.config_schema,
        required_compiler: input.required_compiler.clone(),
        installed_compiler: input.installed_compiler.clone(),
        diagnostics,
        next_actions,
    }
}

fn assess_approval(
    approval: &ApprovalConfig,
    environment: &GitHubEnvironmentAudit,
    diagnostics: &mut Vec<Diagnostic>,
    next_actions: &mut Vec<NextAction>,
) {
    let diagnostics_start = diagnostics.len();

    match approval.separation {
        SeparationMode::Strict => {
            if environment.required_reviewers == 0 {
                error(
                    diagnostics,
                    "strict_reviewer_missing",
                    "strict separation requires at least one GitHub Environment reviewer",
                );
            }
            if !environment.prevent_self_review {
                error(
                    diagnostics,
                    "strict_self_review_allowed",
                    "strict separation requires prevent-self-review",
                );
            }
            if !environment.default_branch_protected {
                error(
                    diagnostics,
                    "default_branch_unprotected",
                    format!(
                        "default branch `{}` is not protected",
                        environment.default_branch
                    ),
                );
            }
            if !environment.protected_branches_only {
                error(
                    diagnostics,
                    "environment_branch_policy_weak",
                    "the release Environment must accept protected branches only",
                );
            }
            if environment.private_repository && !private_reviewers_supported(environment) {
                error(
                    diagnostics,
                    "strict_private_plan_unsupported",
                    "this private repository plan does not expose required Environment reviewers; strict mode cannot be weakened",
                );
            }
            if approval.private_repository_fallback.is_some() {
                error(
                    diagnostics,
                    "strict_fallback_forbidden",
                    "workflow-dispatch digest promotion is not a substitute for strict separation",
                );
            }
        }
        SeparationMode::Solo => {
            let private_reviewers_unavailable =
                environment.private_repository && !private_reviewers_supported(environment);
            if private_reviewers_unavailable {
                if approval.private_repository_fallback.as_deref()
                    == Some("workflow-dispatch-digest")
                {
                    warning(
                        diagnostics,
                        "digest_promotion_fallback",
                        "private Environment reviewers are unavailable on this plan; explicit Candidate-digest promotion is configured",
                    );
                } else {
                    error(
                        diagnostics,
                        "private_environment_reviewers_unavailable",
                        "private Environment reviewers are unavailable on this plan and no explicit Candidate-digest promotion is configured",
                    );
                }
            } else if environment.required_reviewers == 0 {
                error(
                    diagnostics,
                    "environment_reviewer_missing",
                    "solo mode still requires an explicit GitHub Environment approval gate",
                );
            }
        }
    }

    if diagnostics[diagnostics_start..]
        .iter()
        .any(|diagnostic| diagnostic.level == DiagnosticLevel::Error)
    {
        action(
            next_actions,
            "configure GitHub Environment protections",
            "Configure the reviewer and branch policies required by the selected separation mode.",
        );
    }
}

fn private_reviewers_supported(environment: &GitHubEnvironmentAudit) -> bool {
    environment
        .plan
        .as_deref()
        .is_some_and(|plan| plan.to_ascii_lowercase().contains("enterprise"))
}

fn error(diagnostics: &mut Vec<Diagnostic>, code: &str, message: impl Into<String>) {
    diagnostics.push(Diagnostic {
        code: code.into(),
        level: DiagnosticLevel::Error,
        message: message.into(),
        detail: None,
    });
}

fn warning(diagnostics: &mut Vec<Diagnostic>, code: &str, message: impl Into<String>) {
    diagnostics.push(Diagnostic {
        code: code.into(),
        level: DiagnosticLevel::Warning,
        message: message.into(),
        detail: None,
    });
}

fn action(
    actions: &mut Vec<NextAction>,
    command: impl Into<String>,
    description: impl Into<String>,
) {
    let command = command.into();
    if actions.iter().any(|action| action.command == command) {
        return;
    }
    let description = description.into();
    if command.starts_with("release-glz ") {
        actions.push(NextAction::executable(
            command.split_ascii_whitespace(),
            description,
        ));
    } else {
        actions.push(NextAction::guidance(command, description));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_next_actions_keep_the_first_explanation() {
        let mut actions = Vec::new();
        action(&mut actions, "fix policy", "first explanation");
        action(&mut actions, "fix policy", "replacement explanation");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].description, "first explanation");
    }

    #[test]
    fn cli_next_actions_are_executable_without_shell_parsing() {
        let mut actions = Vec::new();
        action(
            &mut actions,
            "release-glz doctor --online",
            "Retry online diagnostics.",
        );
        assert_eq!(actions[0].argv, ["release-glz", "doctor", "--online"]);
    }
}
