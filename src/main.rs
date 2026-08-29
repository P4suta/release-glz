use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use release_glz::ReleasePlan;
use release_glz::authorization::{
    GithubOidcClaims, GithubOidcVerifier, OidcAudience, OidcExpectation, validate_github_claims,
};
use release_glz::candidate::Candidate;
use release_glz::config::Manifest;
use release_glz::doctor::{DoctorInput, DoctorReport, assess as assess_doctor};
use release_glz::forge::{GitHubClient, GitHubRepository};
use release_glz::git::GitRepo;
use release_glz::gleam::Gleam;
use release_glz::model::{
    Diagnostic, DiagnosticLevel, NextAction, PrereleaseChannel, ReleaseState,
};
use release_glz::planner::{PlanOptions, Planner, prepare_release_files};
use release_glz::reconciler::ApprovalEvidence;
use release_glz::registry::{HexRegistry, RegistryCredentialAudit};
use release_glz::rehearse::{Rehearsal, RehearseOptions};
use release_glz::release::{
    CandidateReleaseRunner, LiveReleaseTarget, ReleaseExecutionOptions, ReleaseReport,
};
use semver::Version;

#[derive(Debug, Parser)]
#[command(
    name = "release-glz",
    version,
    about = "Hex-native release automation for Gleam"
)]
struct Cli {
    /// Path to the Gleam package manifest.
    #[arg(long, global = true, default_value = "gleam.toml")]
    manifest_path: PathBuf,

    /// Select human-readable or stable machine-readable output.
    #[arg(long, global = true, value_enum, default_value_t = Output::Human)]
    output: Output,

    /// Validate and describe mutations without performing them.
    #[arg(long, global = true)]
    dry_run: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Output {
    Human,
    Json,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Produce a complete, read-only release plan.
    Plan,
    /// Build and seal a Candidate from one exact committed source snapshot.
    Rehearse {
        /// Full source commit SHA (abbreviations and symbolic refs are rejected).
        #[arg(long = "ref")]
        source_ref: String,
        /// New directory in which to seal the Candidate.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a sealed Candidate without rebuilding it.
    Verify {
        #[arg(long)]
        candidate: PathBuf,
        /// Also compare the Candidate with registry and GitHub state.
        #[arg(long)]
        online: bool,
    },
    /// Update gleam.toml and CHANGELOG.md locally.
    Update,
    /// Create or update the rolling GitHub Release PR.
    ReleasePr {
        /// Bind a sealed Candidate intent to the verified managed PR head.
        #[arg(long)]
        candidate: Option<PathBuf>,
    },
    /// Reconcile Hex, HexDocs, git tag, and GitHub Release.
    Release {
        #[arg(long)]
        candidate: PathBuf,
    },
    /// Report partial release state and the next safe operation.
    Status {
        #[arg(long)]
        candidate: Option<PathBuf>,
        #[arg(long)]
        online: bool,
    },
    /// Diagnose compiler, configuration, workflow, environment, and credentials.
    Doctor,
    /// Generate the recommended GitHub Actions workflow.
    Init {
        #[arg(long)]
        check: bool,
        #[arg(long)]
        diff: bool,
        #[arg(long)]
        update: bool,
    },
    /// Losslessly migrate legacy configuration to schema 2.
    Migrate {
        #[arg(long)]
        check: bool,
        #[arg(long)]
        diff: bool,
        #[arg(long, alias = "write")]
        update: bool,
    },
    /// Raise the automatically selected version.
    SetVersion { version: Version },
    /// Start, move, or promote a prerelease train.
    Prerelease {
        #[arg(value_enum)]
        channel: Train,
        /// Explicit higher core version required for a backward channel move.
        #[arg(long)]
        version: Option<Version>,
    },
    /// Generate shell completion source.
    Completion {
        #[arg(value_enum)]
        shell: CompletionShell,
    },
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Rehearse { .. } => "rehearse",
            Self::Verify { .. } => "verify",
            Self::Update => "update",
            Self::ReleasePr { .. } => "release-pr",
            Self::Release { .. } => "release",
            Self::Status { .. } => "status",
            Self::Doctor => "doctor",
            Self::Init { .. } => "init",
            Self::Migrate { .. } => "migrate",
            Self::SetVersion { .. } => "set-version",
            Self::Prerelease { .. } => "prerelease",
            Self::Completion { .. } => "completion",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Train {
    Alpha,
    Beta,
    Rc,
    Stable,
}

impl Train {
    fn channel(self) -> Option<PrereleaseChannel> {
        match self {
            Self::Alpha => Some(PrereleaseChannel::Alpha),
            Self::Beta => Some(PrereleaseChannel::Beta),
            Self::Rc => Some(PrereleaseChannel::Rc),
            Self::Stable => None,
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let output = cli.output;
    let command = cli.command.name();
    let configured_credential = Manifest::load(&cli.manifest_path)
        .ok()
        .and_then(|manifest| std::env::var(manifest.release.registry.credential_env).ok());
    match run(cli).await {
        Ok(code) if code != 0 => std::process::exit(code),
        Ok(_) => {}
        Err(error) => {
            let message = release_glz::secrets::redact_with(
                &format!("{error:#}"),
                configured_credential.as_deref(),
            );
            if matches!(output, Output::Json) {
                let envelope = release_glz::model::CommandEnvelope::<serde_json::Value>::failure(
                    command,
                    vec![Diagnostic {
                        code: error_code(&error).into(),
                        level: DiagnosticLevel::Error,
                        message,
                        detail: None,
                    }],
                    vec![],
                );
                println!(
                    "{}",
                    serde_json::to_string(&envelope).expect("error envelope is serializable")
                );
            } else {
                eprintln!("error: {message}");
            }
            std::process::exit(exit_code(&error));
        }
    }
}

fn exit_code(error: &anyhow::Error) -> i32 {
    if let Some(release) = error.downcast_ref::<release_glz::release::ReleaseRunError>() {
        return match release.state() {
            ReleaseState::Conflict => 4,
            ReleaseState::PartiallyReleased => 7,
            ReleaseState::AwaitingApproval | ReleaseState::Blocked => 3,
            _ => 1,
        };
    }
    let message = format!("{error:#}").to_ascii_lowercase();
    if message.contains("hook") {
        6
    } else if message.contains("approval") || message.contains("policy") {
        3
    } else if message.contains("conflict")
        || message.contains("checksum mismatch")
        || message.contains("refusing to overwrite")
    {
        4
    } else if message.contains("timed out")
        || message.contains("temporarily")
        || message.contains("rate limit")
        || message.contains("connection")
    {
        5
    } else if message.contains("invalid toml")
        || message.contains("missing string")
        || message.contains("schema 2 configuration")
        || message.contains("choose only one")
        || message.contains("must be")
        || message.contains("unsupported release-glz schema")
    {
        2
    } else {
        1
    }
}

fn error_code(error: &anyhow::Error) -> &'static str {
    match exit_code(error) {
        2 => "usage_or_config",
        3 => "policy_or_approval",
        4 => "immutable_state_conflict",
        5 => "temporary_external_failure",
        6 => "hook_failure",
        7 => "partial_release",
        _ => "internal_failure",
    }
}

async fn run(cli: Cli) -> Result<i32> {
    let command_name = cli.command.name();
    if let Command::Completion { shell } = &cli.command {
        let source = completion_source(*shell);
        match cli.output {
            Output::Human => print!("{source}"),
            Output::Json => print_result(
                "completion",
                &serde_json::json!({"shell": shell_name(*shell), "source": source}),
                cli.output,
            )?,
        }
        return Ok(0);
    }
    let planning_manifest = Manifest::load(&cli.manifest_path)?;
    let planner = Planner::new(
        HexRegistry::from_environment(&planning_manifest.release.registry)?,
        Gleam::default(),
    );
    let base_options = PlanOptions {
        manifest_path: cli.manifest_path.clone(),
        ..PlanOptions::default()
    };

    let plan = match cli.command {
        Command::Plan => planner.plan(&base_options).await?,
        Command::Rehearse { source_ref, out } => {
            let candidate = Rehearsal::default()
                .run(&RehearseOptions {
                    manifest_path: cli.manifest_path,
                    source_ref,
                    output: out,
                })
                .await?;
            print_result("rehearse", &candidate, cli.output)?;
            return Ok(0);
        }
        Command::Verify { candidate, online } => {
            let sealed = Candidate::verify(&candidate)?;
            if online {
                let report = online_candidate_report(
                    &candidate,
                    &sealed,
                    approved_for_inspection(&sealed)?,
                    true,
                )
                .await?;
                print_result("verify", &report, cli.output)?;
            } else {
                let result = serde_json::json!({
                    "schema": "verify/v1",
                    "state": ReleaseState::CandidateReady,
                    "candidate": sealed,
                });
                print_result("verify", &result, cli.output)?;
            }
            return Ok(0);
        }
        Command::Update => {
            sync_rolling_release_pr(&planner, &base_options, &cli.manifest_path, cli.dry_run)
                .await?
        }
        Command::ReleasePr { candidate } => {
            if let Some(candidate_directory) = candidate {
                let sealed = Candidate::verify(&candidate_directory)?;
                let checkout_manifest = Manifest::load(&cli.manifest_path)?;
                if checkout_manifest.package != sealed.package
                    || checkout_manifest.version != sealed.version
                {
                    bail!("Candidate package and version do not match the managed PR checkout");
                }
                let repo = GitRepo::discover(checkout_manifest.package_dir())?;
                if repo.head()? != sealed.source.commit_sha {
                    bail!("Candidate source is not the checked-out managed PR head");
                }
                let github = GitHubClient::from_environment(GitHubRepository::parse(
                    &sealed.github_repository,
                )?);
                let merged = github
                    .merged_release_pr_for_head(
                        &sealed.source.commit_sha,
                        &sealed.package,
                        &sealed.version.to_string(),
                        &sealed.release_branch_prefix,
                        &sealed.intent_digest,
                    )
                    .await?;
                let (state, pr_url) = if let Some(pull) = merged {
                    (ReleaseState::AwaitingApproval, Some(pull.html_url))
                } else if cli.dry_run {
                    (ReleaseState::Blocked, None)
                } else {
                    (
                        ReleaseState::Planned,
                        Some(
                            github
                                .bind_release_pr_intent(
                                    &sealed.source.commit_sha,
                                    &sealed.package,
                                    &sealed.version.to_string(),
                                    &sealed.release_branch_prefix,
                                    &sealed.intent_digest,
                                )
                                .await?,
                        ),
                    )
                };
                print_result(
                    command_name,
                    &serde_json::json!({
                        "schema": "release-pr-intent/v1",
                        "state": state,
                        "version": sealed.version,
                        "intent_digest": sealed.intent_digest,
                        "candidate_digest": sealed.candidate_digest,
                        "pr_url": pr_url,
                    }),
                    cli.output,
                )?;
                return Ok(0);
            }
            sync_rolling_release_pr(&planner, &base_options, &cli.manifest_path, cli.dry_run)
                .await?
        }
        Command::Release { candidate } => {
            let sealed = Candidate::verify(&candidate)?;
            let approval = if cli.dry_run {
                approved_for_inspection(&sealed)?
            } else {
                approval_from_environment(&sealed).await?
            };
            let report =
                online_candidate_report(&candidate, &sealed, approval, cli.dry_run).await?;
            if report.state == ReleaseState::AwaitingApproval && !cli.dry_run {
                bail!(
                    "release approval is not bound to Candidate {}; set the approved digest evidence",
                    sealed.candidate_digest
                );
            }
            print_result("release", &report, cli.output)?;
            return Ok(0);
        }
        Command::Status { candidate, online } => {
            if let Some(candidate) = candidate {
                let sealed = Candidate::verify(&candidate)?;
                if online {
                    let report = online_candidate_report(
                        &candidate,
                        &sealed,
                        approved_for_inspection(&sealed)?,
                        true,
                    )
                    .await?;
                    print_result("status", &report, cli.output)?;
                } else {
                    let result = serde_json::json!({
                        "schema": "status/v1",
                        "state": ReleaseState::CandidateReady,
                        "candidate_digest": sealed.candidate_digest,
                        "next_action": format!("release-glz release --candidate {}", candidate.display()),
                    });
                    print_result("status", &result, cli.output)?;
                }
                return Ok(0);
            }
            planner.plan(&base_options).await?
        }
        Command::Doctor => {
            let manifest = Manifest::load(&cli.manifest_path)?;
            let installed_compiler = Gleam::default().installed_version().ok();
            let workflow_current = managed_workflow_is_current(&manifest).unwrap_or(false);
            let registry_credential =
                if std::env::var_os(&manifest.release.registry.credential_env).is_none() {
                    RegistryCredentialAudit::Missing
                } else {
                    match HexRegistry::from_environment(&manifest.release.registry) {
                        Ok(registry) => registry
                            .audit_credential()
                            .await
                            .unwrap_or(RegistryCredentialAudit::Unavailable),
                        Err(_) => RegistryCredentialAudit::Unavailable,
                    }
                };
            let github_environment = match github_client(&manifest) {
                Ok(client) => client
                    .environment_audit(&manifest.release.approval.environment)
                    .await
                    .ok(),
                Err(_) => None,
            };
            let report = assess_doctor(&DoctorInput {
                config_schema: manifest.release.schema,
                package_version: manifest.version.clone(),
                required_compiler: manifest.release.compiler.clone(),
                installed_compiler,
                registry_credential,
                workflow_current,
                approval: manifest.release.approval.clone(),
                github_environment,
            });
            print_doctor(&report, cli.output)?;
            return Ok(if report.state == ReleaseState::Blocked {
                3
            } else {
                0
            });
        }
        Command::Init {
            check,
            diff,
            update,
        } => {
            if [check, diff, update]
                .into_iter()
                .filter(|selected| *selected)
                .count()
                > 1
            {
                bail!("choose only one of --check, --diff, or --update");
            }
            let manifest = Manifest::load(&cli.manifest_path)?;
            let repo = GitRepo::discover(manifest.package_dir())?;
            let relative_manifest = absolute_or_join(manifest.path())?
                .strip_prefix(repo.root().canonicalize()?)
                .context("manifest is outside the git repository")?
                .to_path_buf();
            let mode = if diff {
                release_glz::workflow::WorkflowMode::Diff
            } else if check || cli.dry_run {
                release_glz::workflow::WorkflowMode::Check
            } else {
                let _ = update;
                release_glz::workflow::WorkflowMode::Update
            };
            let settings = release_glz::workflow::WorkflowSettings {
                default_branch: repo.default_branch()?,
                manifest_path: relative_manifest,
                compiler: manifest.release.compiler.to_string(),
                environment: manifest.release.approval.environment.clone(),
                registry_credential_env: manifest.release.registry.credential_env.clone(),
                release_branch_prefix: manifest.release.release_branch_prefix.clone(),
                action_sha: std::env::var("RELEASE_GLZ_ACTION_SHA")
                    .unwrap_or_else(|_| release_glz::workflow::default_action_sha().to_owned()),
            };
            let outcome = release_glz::workflow::sync(repo.root(), &settings, mode)?;
            if let Some(diff) = &outcome.diff
                && matches!(cli.output, Output::Human)
            {
                print!("{diff}");
            } else {
                let changed = check && outcome.changed;
                print_checked_result(
                    "init",
                    &outcome,
                    !changed,
                    changed.then(|| Diagnostic {
                        code: "managed_file_outdated".into(),
                        level: DiagnosticLevel::Error,
                        message: "the managed workflow differs from the required workflow".into(),
                        detail: None,
                    }),
                    changed.then(|| NextAction {
                        command: "release-glz init --update".into(),
                        description: "Review and update the managed workflow.".into(),
                    }),
                    cli.output,
                )?;
                if changed {
                    return Ok(3);
                }
            }
            return Ok(0);
        }
        Command::Migrate {
            check,
            diff,
            update,
        } => {
            if [check, diff, update]
                .into_iter()
                .filter(|selected| *selected)
                .count()
                > 1
            {
                bail!("choose only one of --check, --diff, or --update");
            }
            let migration = release_glz::migrate::Migration::prepare(&cli.manifest_path)?;
            if diff && matches!(cli.output, Output::Human) {
                if let Some(diff) = migration.diff() {
                    print!("{diff}");
                }
                return Ok(0);
            }
            let outcome = if update && !cli.dry_run {
                migration.apply()?
            } else {
                migration.outcome(false)
            };
            let changed = check && outcome.changed;
            print_checked_result(
                "migrate",
                &outcome,
                !changed,
                changed.then(|| Diagnostic {
                    code: "migration_required".into(),
                    level: DiagnosticLevel::Error,
                    message: "legacy configuration must be migrated to schema 2".into(),
                    detail: None,
                }),
                changed.then(|| NextAction {
                    command: "release-glz migrate --update".into(),
                    description: "Review and apply the lossless schema 2 migration.".into(),
                }),
                cli.output,
            )?;
            if changed {
                return Ok(3);
            }
            return Ok(0);
        }
        Command::SetVersion { version } => {
            let options = PlanOptions {
                version_override: Some(version.clone()),
                ..base_options
            };
            let mut plan = planner.plan(&options).await?;
            if plan.version != version {
                bail!(
                    "{version} is below the automatically required version {}",
                    plan.version
                );
            }
            if !cli.dry_run {
                let mut manifest = Manifest::load(&cli.manifest_path)?;
                manifest.set_version(version.clone());
                manifest.write()?;
            }
            plan.manifest_version = version;
            plan
        }
        Command::Prerelease { channel, version } => {
            let selected_channel = channel.channel();
            let options = PlanOptions {
                prerelease_override: Some(selected_channel),
                version_override: version,
                ignore_manifest_version: true,
                ..base_options
            };
            let mut plan = planner.plan(&options).await?;
            if !cli.dry_run {
                let mut manifest = Manifest::load(&cli.manifest_path)?;
                manifest.set_prerelease(selected_channel);
                if plan.release_required {
                    manifest.set_version(plan.version.clone());
                }
                manifest.write()?;
            }
            plan.prerelease = selected_channel;
            plan
        }
        Command::Completion { .. } => unreachable!("handled before planning"),
    };

    print_plan(&plan, cli.output, command_name)?;
    Ok(0)
}

async fn sync_rolling_release_pr(
    planner: &Planner<HexRegistry>,
    options: &PlanOptions,
    manifest_path: &Path,
    dry_run: bool,
) -> Result<ReleasePlan> {
    let mut plan = planner.plan(options).await?;
    let manifest = Manifest::load(manifest_path)?;
    let repo = GitRepo::discover(manifest.package_dir())?;
    let github = github_client(&manifest)?;
    if plan.release_required {
        let commits = repo.commits_since(plan.baseline.sha.as_deref())?;
        plan.changes = github.changes_for_commits(&commits).await?;
        let files = prepare_release_files(&manifest, &repo, &plan, &plan.changes)?;
        if !dry_run {
            let base = repo.default_branch()?;
            plan.pr_url = Some(
                github
                    .upsert_release_pr(
                        &plan,
                        &base,
                        &manifest.release.release_branch_prefix,
                        &files,
                    )
                    .await?,
            );
        }
    } else if !dry_run {
        github
            .close_managed_release_pr(&manifest.package, &manifest.release.release_branch_prefix)
            .await?;
    }
    Ok(plan)
}

async fn online_candidate_report(
    candidate_directory: &Path,
    manifest: &release_glz::candidate::CandidateManifest,
    approval: ApprovalEvidence,
    dry_run: bool,
) -> Result<ReleaseReport> {
    let repo = GitRepo::discover(&std::env::current_dir()?)?;
    let target = LiveReleaseTarget::from_candidate(manifest.clone(), repo)?;
    CandidateReleaseRunner::new(target)
        .run(
            candidate_directory,
            &approval,
            ReleaseExecutionOptions { dry_run },
        )
        .await
        .map_err(Into::into)
}

fn approved_for_inspection(
    manifest: &release_glz::candidate::CandidateManifest,
) -> Result<ApprovalEvidence> {
    let now = chrono::Utc::now().timestamp();
    let workflow_path = ".github/workflows/release-glz.yml";
    let github_oidc = validate_github_claims(
        GithubOidcClaims {
            issuer: "https://token.actions.githubusercontent.com".into(),
            audience: OidcAudience::One("release-glz".into()),
            subject: format!(
                "repo:{}:environment:{}",
                manifest.github_repository, manifest.approval.environment
            ),
            repository: manifest.github_repository.clone(),
            environment: Some(manifest.approval.environment.clone()),
            workflow_ref: format!(
                "{}/{workflow_path}@refs/heads/inspection",
                manifest.github_repository
            ),
            git_ref: "refs/heads/inspection".into(),
            source_sha: manifest.source.commit_sha.clone(),
            run_id: "1".into(),
            run_attempt: "1".into(),
            event_name: "push".into(),
            issued_at: now,
            not_before: Some(now),
            expires_at: now + 60,
        },
        &OidcExpectation {
            repository: manifest.github_repository.clone(),
            environment: manifest.approval.environment.clone(),
            workflow_path: workflow_path.into(),
            source_sha: manifest.source.commit_sha.clone(),
            run_id: Some("1".into()),
        },
        now,
    )?;
    Ok(ApprovalEvidence {
        release_pr_intent_digest: Some(manifest.intent_digest.clone()),
        environment_candidate_digest: Some(manifest.candidate_digest.clone()),
        environment: Some(manifest.approval.environment.clone()),
        source_sha: None,
        manual_reason: None,
        github_oidc: Some(github_oidc),
    })
}

async fn approval_from_environment(
    manifest: &release_glz::candidate::CandidateManifest,
) -> Result<ApprovalEvidence> {
    let request_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
        .context("release approval requires GitHub Actions OIDC request URL")?;
    let request_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        .context("release approval requires GitHub Actions OIDC request token")?;
    let run_id = std::env::var("GITHUB_RUN_ID")
        .context("release approval requires the GitHub Actions run ID")?;
    let expected = OidcExpectation {
        repository: manifest.github_repository.clone(),
        environment: manifest.approval.environment.clone(),
        workflow_path: ".github/workflows/release-glz.yml".into(),
        source_sha: manifest.source.commit_sha.clone(),
        run_id: Some(run_id),
    };
    let github_oidc = GithubOidcVerifier::github()?
        .verify_actions_token(
            &request_url,
            &request_token,
            &expected,
            chrono::Utc::now().timestamp(),
        )
        .await
        .context("release approval OIDC verification failed")?;
    let artifact_id = std::env::var("RELEASE_GLZ_ACTIONS_ARTIFACT_ID")
        .context("release approval requires the immutable Actions artifact ID")?
        .parse::<u64>()
        .context("release approval Actions artifact ID is invalid")?;
    let artifact_digest = std::env::var("RELEASE_GLZ_ACTIONS_ARTIFACT_DIGEST")
        .context("release approval requires the Actions artifact digest")?;
    let artifact_digest = artifact_digest
        .strip_prefix("sha256:")
        .unwrap_or(&artifact_digest);
    let repository = GitHubRepository::parse(&manifest.github_repository)?;
    let github = GitHubClient::from_environment(repository);
    github
        .verify_actions_artifact(
            artifact_id,
            artifact_digest,
            github_oidc.run_id(),
            &manifest.source.commit_sha,
        )
        .await
        .context("release approval Actions artifact verification failed")?;
    if github_oidc.event_name() == "push" {
        github
            .merged_release_pr_for_head(
                &manifest.source.commit_sha,
                &manifest.package,
                &manifest.version.to_string(),
                &manifest.release_branch_prefix,
                &manifest.intent_digest,
            )
            .await?
            .context(
                "release approval requires a server-verified merged managed Release PR for this Candidate",
            )?;
    }
    Ok(ApprovalEvidence {
        release_pr_intent_digest: std::env::var("RELEASE_GLZ_APPROVED_INTENT_DIGEST").ok(),
        environment_candidate_digest: std::env::var("RELEASE_GLZ_APPROVED_CANDIDATE_DIGEST").ok(),
        environment: std::env::var("RELEASE_GLZ_ENVIRONMENT").ok(),
        source_sha: std::env::var("RELEASE_GLZ_MANUAL_SOURCE_SHA").ok(),
        manual_reason: std::env::var("RELEASE_GLZ_MANUAL_REASON").ok(),
        github_oidc: Some(github_oidc),
    })
}

fn print_result<T: serde::Serialize>(command: &str, result: &T, output: Output) -> Result<()> {
    match output {
        Output::Json => {
            let envelope = release_glz::model::CommandEnvelope::success(
                command,
                serde_json::to_value(result)?,
                vec![],
                vec![],
            );
            println!("{}", serde_json::to_string(&envelope)?);
        }
        Output::Human => println!("{}", serde_json::to_string_pretty(result)?),
    }
    Ok(())
}

fn print_checked_result<T: serde::Serialize>(
    command: &str,
    result: &T,
    ok: bool,
    diagnostic: Option<Diagnostic>,
    next_action: Option<NextAction>,
    output: Output,
) -> Result<()> {
    match output {
        Output::Json => {
            let envelope = release_glz::model::CommandEnvelope {
                schema: "command/v2".into(),
                ok,
                command: command.into(),
                result: Some(result),
                diagnostics: diagnostic.into_iter().collect(),
                next_actions: next_action.into_iter().collect(),
            };
            println!("{}", serde_json::to_string(&envelope)?);
        }
        Output::Human => println!("{}", serde_json::to_string_pretty(result)?),
    }
    Ok(())
}

fn print_doctor(report: &DoctorReport, output: Output) -> Result<()> {
    match output {
        Output::Json => {
            let envelope = release_glz::model::CommandEnvelope {
                schema: "command/v2".into(),
                ok: report.state != ReleaseState::Blocked,
                command: "doctor".into(),
                result: Some(report),
                diagnostics: report.diagnostics.clone(),
                next_actions: report.next_actions.clone(),
            };
            println!("{}", serde_json::to_string(&envelope)?);
        }
        Output::Human => println!("{}", serde_json::to_string_pretty(report)?),
    }
    Ok(())
}

fn managed_workflow_is_current(manifest: &Manifest) -> Result<bool> {
    let repo = GitRepo::discover(manifest.package_dir())?;
    let relative_manifest = absolute_or_join(manifest.path())?
        .strip_prefix(repo.root().canonicalize()?)
        .context("manifest is outside the git repository")?
        .to_path_buf();
    let settings = release_glz::workflow::WorkflowSettings {
        default_branch: repo.default_branch()?,
        manifest_path: relative_manifest,
        compiler: manifest.release.compiler.to_string(),
        environment: manifest.release.approval.environment.clone(),
        registry_credential_env: manifest.release.registry.credential_env.clone(),
        release_branch_prefix: manifest.release.release_branch_prefix.clone(),
        action_sha: std::env::var("RELEASE_GLZ_ACTION_SHA")
            .unwrap_or_else(|_| release_glz::workflow::default_action_sha().to_owned()),
    };
    let outcome = release_glz::workflow::sync(
        repo.root(),
        &settings,
        release_glz::workflow::WorkflowMode::Check,
    )?;
    Ok(!outcome.changed)
}

fn completion_source(shell: CompletionShell) -> String {
    const COMMANDS: &str = "plan rehearse verify release status doctor release-pr update prerelease set-version init migrate completion";
    match shell {
        CompletionShell::Bash => format!(
            "_release_glz() {{ COMPREPLY=( $(compgen -W '{COMMANDS}' -- \"${{COMP_WORDS[1]}}\") ); }}\ncomplete -F _release_glz release-glz\n"
        ),
        CompletionShell::Zsh => {
            format!("#compdef release-glz\n_arguments '1:command:({COMMANDS})'\n")
        }
        CompletionShell::Fish => COMMANDS
            .split_whitespace()
            .map(|command| format!("complete -c release-glz -f -a {command}\n"))
            .collect(),
        CompletionShell::Powershell => format!(
            "Register-ArgumentCompleter -Native -CommandName release-glz -ScriptBlock {{ param($wordToComplete) '{COMMANDS}'.Split(' ') | Where-Object {{ $_ -like \"$wordToComplete*\" }} }}\n"
        ),
    }
}

fn shell_name(shell: CompletionShell) -> &'static str {
    match shell {
        CompletionShell::Bash => "bash",
        CompletionShell::Zsh => "zsh",
        CompletionShell::Fish => "fish",
        CompletionShell::Powershell => "powershell",
    }
}

fn github_client(manifest: &Manifest) -> Result<GitHubClient> {
    let repository = match std::env::var("GITHUB_REPOSITORY") {
        Ok(repository) => GitHubRepository::parse(&repository)?,
        Err(_) => GitHubRepository::parse(&manifest.repository.github_name().context(
            "set GITHUB_REPOSITORY or configure a GitHub `[repository]` in gleam.toml",
        )?)?,
    };
    Ok(GitHubClient::from_environment(repository))
}

fn print_plan(plan: &ReleasePlan, output: Output, command: &str) -> Result<()> {
    match output {
        Output::Json => {
            let envelope = release_glz::model::CommandEnvelope::success(
                command,
                plan,
                plan.warnings.clone(),
                vec![],
            );
            println!("{}", serde_json::to_string(&envelope)?);
        }
        Output::Human => {
            let from = plan
                .published_version
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unpublished".into());
            if plan.release_required {
                println!(
                    "{}: {} -> {} ({})",
                    plan.package, from, plan.version, plan.bump
                );
            } else {
                println!(
                    "{}: no release required (Hex has {})",
                    plan.package, plan.version
                );
            }
            for reason in &plan.reasons {
                println!("  - [{}] {}", reason.bump, reason.summary);
            }
            if !plan.api.changes.is_empty() {
                println!(
                    "  API: {} change(s), {} required",
                    plan.api.changes.len(),
                    plan.api.impact
                );
            }
            if let Some(url) = &plan.pr_url {
                println!("  PR: {url}");
            }
            if plan.state == ReleaseState::Released {
                println!("  Released: {}", plan.hex_url.as_deref().unwrap_or("Hex"));
            }
            if let Some(url) = &plan.github_release_url {
                println!("  GitHub Release: {url}");
            }
        }
    }
    Ok(())
}

fn absolute_or_join(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.canonicalize()?)
    } else {
        Ok(std::env::current_dir()?.join(path).canonicalize()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use release_glz::model::{
        ApiChange, ApiChangeKind, ApiDiff, ApiStatus, Baseline, BaselineSource, Bump, ReasonKind,
        ReleaseReason,
    };

    fn plan() -> ReleasePlan {
        ReleasePlan {
            schema: ReleasePlan::SCHEMA.into(),
            state: ReleaseState::Planned,
            package: "widget".into(),
            manifest_path: "gleam.toml".into(),
            published_version: Some(Version::new(1, 0, 0)),
            manifest_version: Version::new(1, 1, 0),
            version: Version::new(1, 1, 0),
            bump: Bump::Minor,
            release_required: true,
            artifacts_changed: true,
            prerelease: None,
            tag: "v1.1.0".into(),
            baseline: Baseline {
                version: Some(Version::new(1, 0, 0)),
                git_ref: Some("v1.0.0".into()),
                sha: Some("a".repeat(40)),
                source: BaselineSource::Tag,
                retired: false,
            },
            reasons: vec![ReleaseReason {
                kind: ReasonKind::ApiAdded,
                bump: Bump::Minor,
                summary: "added public API".into(),
            }],
            api: ApiDiff {
                status: ApiStatus::Changed,
                impact: Bump::Minor,
                changes: vec![ApiChange {
                    kind: ApiChangeKind::Added,
                    path: "widget::function new".into(),
                    breaking: false,
                    summary: "added widget.new".into(),
                }],
            },
            changes: vec![],
            warnings: vec![],
            required_approvals: vec![],
            stages: vec![],
            intent_digest: Some("b".repeat(64)),
            pr_url: Some("https://github.test/acme/widget/pull/1".into()),
            hex_url: Some("https://hex.pm/packages/widget".into()),
            github_release_url: Some("https://github.test/acme/widget/releases/v1.1.0".into()),
        }
    }

    #[test]
    fn every_command_and_prerelease_channel_has_a_stable_internal_name() {
        let commands = [
            (Command::Plan, "plan"),
            (
                Command::Rehearse {
                    source_ref: "a".repeat(40),
                    out: "candidate".into(),
                },
                "rehearse",
            ),
            (
                Command::Verify {
                    candidate: "candidate".into(),
                    online: false,
                },
                "verify",
            ),
            (Command::Update, "update"),
            (Command::ReleasePr { candidate: None }, "release-pr"),
            (
                Command::Release {
                    candidate: "candidate".into(),
                },
                "release",
            ),
            (
                Command::Status {
                    candidate: None,
                    online: false,
                },
                "status",
            ),
            (Command::Doctor, "doctor"),
            (
                Command::Init {
                    check: true,
                    diff: false,
                    update: false,
                },
                "init",
            ),
            (
                Command::Migrate {
                    check: true,
                    diff: false,
                    update: false,
                },
                "migrate",
            ),
            (
                Command::SetVersion {
                    version: Version::new(2, 0, 0),
                },
                "set-version",
            ),
            (
                Command::Prerelease {
                    channel: Train::Rc,
                    version: None,
                },
                "prerelease",
            ),
            (
                Command::Completion {
                    shell: CompletionShell::Bash,
                },
                "completion",
            ),
        ];
        for (command, expected) in commands {
            assert_eq!(command.name(), expected);
        }
        assert_eq!(Train::Alpha.channel(), Some(PrereleaseChannel::Alpha));
        assert_eq!(Train::Beta.channel(), Some(PrereleaseChannel::Beta));
        assert_eq!(Train::Rc.channel(), Some(PrereleaseChannel::Rc));
        assert_eq!(Train::Stable.channel(), None);
    }

    #[test]
    fn exit_codes_and_machine_codes_cover_every_public_failure_class() {
        for (message, expected_exit, expected_code) in [
            ("required hook failed", 6, "hook_failure"),
            ("approval is missing", 3, "policy_or_approval"),
            ("checksum mismatch", 4, "immutable_state_conflict"),
            ("connection timed out", 5, "temporary_external_failure"),
            ("field must be present", 2, "usage_or_config"),
            ("unexpected implementation error", 1, "internal_failure"),
        ] {
            let error = anyhow::anyhow!(message);
            assert_eq!(exit_code(&error), expected_exit, "{message}");
            assert_eq!(error_code(&error), expected_code, "{message}");
        }
    }

    #[test]
    fn completion_and_renderers_cover_every_human_and_json_path() {
        for (shell, name, marker) in [
            (CompletionShell::Bash, "bash", "complete -F"),
            (CompletionShell::Zsh, "zsh", "#compdef"),
            (CompletionShell::Fish, "fish", "complete -c"),
            (
                CompletionShell::Powershell,
                "powershell",
                "Register-ArgumentCompleter",
            ),
        ] {
            assert_eq!(shell_name(shell), name);
            assert!(completion_source(shell).contains(marker));
        }

        print_result(
            "verify",
            &serde_json::json!({"state": "candidate_ready"}),
            Output::Json,
        )
        .unwrap();
        print_result(
            "verify",
            &serde_json::json!({"state": "candidate_ready"}),
            Output::Human,
        )
        .unwrap();
        print_checked_result(
            "migrate",
            &serde_json::json!({"changed": true}),
            false,
            Some(Diagnostic {
                code: "migration_required".into(),
                level: DiagnosticLevel::Error,
                message: "migration required".into(),
                detail: None,
            }),
            Some(NextAction {
                command: "release-glz migrate --update".into(),
                description: "migrate".into(),
            }),
            Output::Json,
        )
        .unwrap();
        print_checked_result(
            "migrate",
            &serde_json::json!({"changed": false}),
            true,
            None,
            None,
            Output::Human,
        )
        .unwrap();

        let doctor = DoctorReport {
            schema: "doctor/v1".into(),
            state: ReleaseState::Blocked,
            config_schema: 1,
            required_compiler: Version::new(1, 18, 1),
            installed_compiler: None,
            diagnostics: vec![],
            next_actions: vec![],
        };
        print_doctor(&doctor, Output::Json).unwrap();
        print_doctor(&doctor, Output::Human).unwrap();

        let planned = plan();
        print_plan(&planned, Output::Json, "plan").unwrap();
        print_plan(&planned, Output::Human, "plan").unwrap();

        let mut released = planned;
        released.state = ReleaseState::Released;
        released.release_required = false;
        released.published_version = None;
        released.reasons.clear();
        released.api.changes.clear();
        released.pr_url = None;
        released.hex_url = None;
        print_plan(&released, Output::Human, "status").unwrap();
    }

    #[test]
    fn path_resolution_accepts_existing_absolute_and_relative_paths() {
        let relative = absolute_or_join(Path::new("Cargo.toml")).unwrap();
        assert!(relative.is_absolute());
        assert_eq!(absolute_or_join(&relative).unwrap(), relative);
    }
}
