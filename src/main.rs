use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{generate, shells};
use release_glz::ReleasePlan;
use release_glz::authorization::{
    GithubOidcClaims, GithubOidcVerifier, OidcAudience, OidcExpectation, validate_github_claims,
};
use release_glz::candidate::Candidate;
use release_glz::config::{
    AuthKind, InitializationSettings, Manifest, RegistryConfig, RegistryProvider,
};
use release_glz::doctor::{
    DoctorInput, DoctorReport, assess as assess_doctor, assess_local as assess_doctor_local,
};
use release_glz::failure::{FailureClass, classified};
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
    /// Create or update the rolling GitHub Release PR.
    Update {
        /// Validate and describe changes without mutating the repository or GitHub.
        #[arg(long)]
        dry_run: bool,
    },
    /// Create or update the rolling GitHub Release PR.
    ReleasePr {
        /// Bind a sealed Candidate intent to the verified managed PR head.
        #[arg(long)]
        candidate: Option<PathBuf>,
        /// Validate and describe changes without mutating GitHub.
        #[arg(long)]
        dry_run: bool,
    },
    /// Reconcile Hex, HexDocs, git tag, and GitHub Release.
    Release {
        #[arg(long)]
        candidate: PathBuf,
        /// Observe and report every remaining effect without publishing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Report partial release state and the next safe operation.
    Status {
        #[arg(long)]
        candidate: Option<PathBuf>,
        #[arg(long)]
        online: bool,
    },
    /// Diagnose compiler, configuration, workflow, environment, and credentials.
    Doctor {
        /// Also audit registry credentials and GitHub protection settings.
        #[arg(long)]
        online: bool,
        /// Build HEAD in an isolated, credential-free cache.
        #[arg(long)]
        candidate_build: bool,
    },
    /// Generate the recommended GitHub Actions workflow.
    Init {
        /// Configure a previously unconfigured package for a supported target.
        #[arg(long, value_enum)]
        profile: Option<InitProfile>,
        /// Hex.pm Organization name (required by `--profile organization`).
        #[arg(long)]
        organization: Option<String>,
        /// Private Hex API base URL.
        #[arg(long)]
        api_url: Option<String>,
        /// Private Hex repository base URL.
        #[arg(long)]
        repository_url: Option<String>,
        /// Private Hex documentation base URL.
        #[arg(long)]
        docs_url: Option<String>,
        /// Name of the protected registry credential environment variable.
        #[arg(long)]
        credential_env: Option<String>,
        /// Private registry authentication scheme.
        #[arg(long, value_enum)]
        auth: Option<InitAuth>,
        /// Explicitly opt a 0.x package into the release policy.
        #[arg(long)]
        allow_version_zero: bool,
        /// Offline override for the immutable release-glz Action commit.
        #[arg(long)]
        action_sha: Option<String>,
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
    SetVersion {
        version: Version,
        /// Validate the selected version without writing the manifest.
        #[arg(long)]
        dry_run: bool,
    },
    /// Start, move, or promote a prerelease train.
    Prerelease {
        #[arg(value_enum)]
        channel: Train,
        /// Explicit higher core version required for a backward channel move.
        #[arg(long)]
        version: Option<Version>,
        /// Validate the transition without writing the manifest.
        #[arg(long)]
        dry_run: bool,
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
            Self::Update { .. } => "update",
            Self::ReleasePr { .. } => "release-pr",
            Self::Release { .. } => "release",
            Self::Status { .. } => "status",
            Self::Doctor { .. } => "doctor",
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

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum InitProfile {
    Public,
    Organization,
    Private,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum InitAuth {
    HexToken,
    Bearer,
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
    let arguments = std::env::args_os().collect::<Vec<_>>();
    let cli = match Cli::try_parse_from(arguments.clone()) {
        Ok(cli) => cli,
        Err(error) => {
            let exit = error.exit_code();
            if exit == 0 {
                let _ = error.print();
                return;
            }
            if requested_json_output(&arguments) {
                let command = requested_command(&arguments);
                let envelope = release_glz::model::CommandEnvelope::<serde_json::Value>::failure(
                    command,
                    vec![Diagnostic {
                        code: FailureClass::UsageOrConfig.diagnostic_code().into(),
                        level: DiagnosticLevel::Error,
                        message: error.to_string(),
                        detail: None,
                    }],
                    vec![],
                );
                println!(
                    "{}",
                    serde_json::to_string(&envelope).expect("usage envelope is serializable")
                );
            } else {
                let _ = error.print();
            }
            std::process::exit(FailureClass::UsageOrConfig.exit_code());
        }
    };
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
                eprintln!("{command}: failed");
                eprintln!("  Error [{}]: {message}", error_code(&error));
            }
            std::process::exit(exit_code(&error));
        }
    }
}

fn requested_json_output(arguments: &[std::ffi::OsString]) -> bool {
    arguments.windows(2).any(|pair| {
        pair[0] == std::ffi::OsStr::new("--output") && pair[1] == std::ffi::OsStr::new("json")
    }) || arguments
        .iter()
        .any(|argument| argument == std::ffi::OsStr::new("--output=json"))
}

fn requested_command(arguments: &[std::ffi::OsString]) -> &'static str {
    let mut skip_value = false;
    for argument in arguments.iter().skip(1) {
        if skip_value {
            skip_value = false;
            continue;
        }
        let Some(argument) = argument.to_str() else {
            continue;
        };
        if matches!(argument, "--manifest-path" | "--output") {
            skip_value = true;
            continue;
        }
        if argument.starts_with('-') {
            continue;
        }
        if let Some(command) = [
            "plan",
            "rehearse",
            "verify",
            "update",
            "release-pr",
            "release",
            "status",
            "doctor",
            "init",
            "migrate",
            "set-version",
            "prerelease",
            "completion",
        ]
        .into_iter()
        .find(|command| argument == *command)
        {
            return command;
        }
    }
    "cli"
}

fn exit_code(error: &anyhow::Error) -> i32 {
    release_glz::failure::classify(error).exit_code()
}

fn error_code(error: &anyhow::Error) -> &'static str {
    release_glz::failure::classify(error).diagnostic_code()
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
    if let Command::Init {
        profile,
        organization,
        api_url,
        repository_url,
        docs_url,
        credential_env,
        auth,
        allow_version_zero,
        action_sha,
        check,
        diff,
        update,
    } = &cli.command
    {
        return run_init(
            &cli.manifest_path,
            cli.output,
            *profile,
            organization.as_deref(),
            api_url.as_deref(),
            repository_url.as_deref(),
            docs_url.as_deref(),
            credential_env.as_deref(),
            *auth,
            *allow_version_zero,
            action_sha.as_deref(),
            *check,
            *diff,
            *update,
        )
        .await;
    }
    if let Command::Migrate {
        check,
        diff,
        update,
    } = &cli.command
    {
        return run_migrate(&cli.manifest_path, cli.output, *check, *diff, *update);
    }
    if let Command::Doctor {
        online,
        candidate_build,
    } = &cli.command
    {
        return run_doctor(&cli.manifest_path, cli.output, *online, *candidate_build).await;
    }

    let planning_manifest = Manifest::load(&cli.manifest_path)
        .map_err(|error| classified(FailureClass::UsageOrConfig, error))?;
    let planner = Planner::new(
        HexRegistry::from_environment(&planning_manifest.release.registry)
            .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?,
        Gleam::default(),
    );
    let base_options = PlanOptions {
        manifest_path: cli.manifest_path.clone(),
        ..PlanOptions::default()
    };

    let plan = match cli.command {
        Command::Plan => planner
            .plan(&base_options)
            .await
            .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?,
        Command::Rehearse { source_ref, out } => {
            let candidate = Rehearsal::default()
                .run(&RehearseOptions {
                    manifest_path: cli.manifest_path,
                    source_ref,
                    output: out,
                })
                .await
                .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?;
            print_result("rehearse", &candidate, cli.output)?;
            return Ok(0);
        }
        Command::Verify { candidate, online } => {
            let sealed = Candidate::verify(&candidate)
                .map_err(|error| classified(FailureClass::ImmutableStateConflict, error))?;
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
        Command::Update { dry_run } => {
            sync_rolling_release_pr(&planner, &base_options, &cli.manifest_path, dry_run).await?
        }
        Command::ReleasePr { candidate, dry_run } => {
            if let Some(candidate_directory) = candidate {
                let sealed = Candidate::verify(&candidate_directory)
                    .map_err(|error| classified(FailureClass::ImmutableStateConflict, error))?;
                let checkout_manifest = Manifest::load(&cli.manifest_path)
                    .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?;
                if checkout_manifest.package != sealed.package
                    || checkout_manifest.version != sealed.version
                {
                    return Err(classified(
                        FailureClass::ImmutableStateConflict,
                        "Candidate package and version do not match the managed PR checkout",
                    ));
                }
                let repo = GitRepo::discover(checkout_manifest.package_dir())
                    .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?;
                if repo
                    .head()
                    .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?
                    != sealed.source.commit_sha
                {
                    return Err(classified(
                        FailureClass::ImmutableStateConflict,
                        "Candidate source is not the checked-out managed PR head",
                    ));
                }
                let github = GitHubClient::from_environment(
                    GitHubRepository::parse(&sealed.github_repository).map_err(|error| {
                        default_failure_class(error, FailureClass::ImmutableStateConflict)
                    })?,
                );
                let merged = github
                    .merged_release_pr_for_head(
                        &sealed.source.commit_sha,
                        &sealed.package,
                        &sealed.version.to_string(),
                        &sealed.release_branch_prefix,
                        &sealed.intent_digest,
                    )
                    .await
                    .map_err(|error| {
                        default_failure_class(error, FailureClass::TemporaryExternal)
                    })?;
                let (state, pr_url) = if let Some(pull) = merged {
                    (ReleaseState::AwaitingApproval, Some(pull.html_url))
                } else if dry_run {
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
                                .await
                                .map_err(|error| {
                                    default_failure_class(error, FailureClass::TemporaryExternal)
                                })?,
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
            sync_rolling_release_pr(&planner, &base_options, &cli.manifest_path, dry_run).await?
        }
        Command::Release { candidate, dry_run } => {
            let sealed = Candidate::verify(&candidate)
                .map_err(|error| classified(FailureClass::ImmutableStateConflict, error))?;
            let approval = if dry_run {
                approved_for_inspection(&sealed)?
            } else {
                approval_from_environment(&sealed)
                    .await
                    .map_err(|error| default_failure_class(error, FailureClass::PolicyOrApproval))?
            };
            let report = online_candidate_report(&candidate, &sealed, approval, dry_run).await?;
            if report.state == ReleaseState::AwaitingApproval && !dry_run {
                return Err(classified(
                    FailureClass::PolicyOrApproval,
                    format!(
                        "release approval is not bound to Candidate {}; set the approved digest evidence",
                        sealed.candidate_digest
                    ),
                ));
            }
            print_result("release", &report, cli.output)?;
            return Ok(0);
        }
        Command::Status { candidate, online } => {
            if let Some(candidate) = candidate {
                let sealed = Candidate::verify(&candidate)
                    .map_err(|error| classified(FailureClass::ImmutableStateConflict, error))?;
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
                    let next_action = manifest_executable_action(
                        &base_options.manifest_path,
                        [
                            "release".to_owned(),
                            "--candidate".to_owned(),
                            candidate.to_string_lossy().into_owned(),
                        ],
                        "Publish or dry-run the verified Candidate.",
                    );
                    let result = serde_json::json!({
                        "schema": "status/v1",
                        "state": ReleaseState::CandidateReady,
                        "candidate_digest": sealed.candidate_digest,
                    });
                    print_result_with_actions("status", &result, vec![next_action], cli.output)?;
                }
                return Ok(0);
            }
            planner
                .plan(&base_options)
                .await
                .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?
        }
        Command::Doctor { .. } | Command::Init { .. } | Command::Migrate { .. } => {
            unreachable!("handled before planning")
        }
        Command::SetVersion { version, dry_run } => {
            let options = PlanOptions {
                version_override: Some(version.clone()),
                ..base_options
            };
            let mut plan = planner
                .plan(&options)
                .await
                .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?;
            if plan.version != version {
                return Err(classified(
                    FailureClass::PolicyOrApproval,
                    format!(
                        "{version} is below the automatically required version {}",
                        plan.version
                    ),
                ));
            }
            if !dry_run {
                let mut manifest = Manifest::load(&cli.manifest_path)
                    .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?;
                manifest.set_version(version.clone());
                manifest.write().map_err(|error| {
                    default_failure_class(error, FailureClass::ImmutableStateConflict)
                })?;
            }
            plan.manifest_version = version;
            plan
        }
        Command::Prerelease {
            channel,
            version,
            dry_run,
        } => {
            let selected_channel = channel.channel();
            let options = PlanOptions {
                prerelease_override: Some(selected_channel),
                version_override: version,
                ignore_manifest_version: true,
                ..base_options
            };
            let mut plan = planner
                .plan(&options)
                .await
                .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?;
            if !dry_run {
                let mut manifest = Manifest::load(&cli.manifest_path)
                    .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?;
                manifest.set_prerelease(selected_channel);
                if plan.release_required {
                    manifest.set_version(plan.version.clone());
                }
                manifest.write().map_err(|error| {
                    default_failure_class(error, FailureClass::ImmutableStateConflict)
                })?;
            }
            plan.prerelease = selected_channel;
            plan
        }
        Command::Completion { .. } => unreachable!("handled before planning"),
    };

    print_plan(&plan, cli.output, command_name)?;
    Ok(0)
}

#[derive(Debug, serde::Serialize)]
struct InitOutcome {
    schema: &'static str,
    manifest_path: String,
    workflow_path: &'static str,
    action_sha: String,
    manifest_changed: bool,
    workflow_changed: bool,
    changed: bool,
    written: bool,
}

#[allow(clippy::too_many_arguments)]
async fn run_init(
    manifest_path: &Path,
    output: Output,
    profile: Option<InitProfile>,
    organization: Option<&str>,
    api_url: Option<&str>,
    repository_url: Option<&str>,
    docs_url: Option<&str>,
    credential_env: Option<&str>,
    auth: Option<InitAuth>,
    allow_version_zero: bool,
    explicit_action_sha: Option<&str>,
    check: bool,
    diff: bool,
    update: bool,
) -> Result<i32> {
    require_one_mode(check, diff, update)?;
    let mut manifest = Manifest::load(manifest_path)
        .map_err(|error| classified(FailureClass::UsageOrConfig, error))?;
    let repo = GitRepo::discover(manifest.package_dir())
        .map_err(|error| classified(FailureClass::UsageOrConfig, error))?;
    let default_branch = repo
        .default_branch()
        .map_err(|error| classified(FailureClass::UsageOrConfig, error))?;

    let profile_fields_present = organization.is_some()
        || api_url.is_some()
        || repository_url.is_some()
        || docs_url.is_some()
        || credential_env.is_some()
        || auth.is_some()
        || allow_version_zero;
    let initialized_source = if manifest.has_release_config() {
        if manifest.release.schema != 2 {
            return Err(classified(
                FailureClass::UsageOrConfig,
                "legacy release-glz configuration must use migrate before init",
            ));
        }
        if profile.is_some() || profile_fields_present {
            return Err(classified(
                FailureClass::UsageOrConfig,
                "--profile and profile configuration are forbidden for an existing schema 2 package",
            ));
        }
        None
    } else {
        let profile = profile.ok_or_else(|| {
            classified(
                FailureClass::UsageOrConfig,
                "an unconfigured package requires --profile public, organization, or private",
            )
        })?;
        let registry = initialization_registry(
            profile,
            organization,
            api_url,
            repository_url,
            docs_url,
            credential_env,
            auth,
        )?;
        let compiler = Gleam::default()
            .installed_version()
            .map_err(|error| classified(FailureClass::UsageOrConfig, error))?;
        let rendered = manifest
            .render_initialized(&InitializationSettings {
                compiler,
                default_branch: default_branch.clone(),
                registry,
                allow_version_zero,
            })
            .map_err(|error| classified(FailureClass::UsageOrConfig, error))?;
        Some(rendered)
    };

    let configured = match &initialized_source {
        Some(source) => Manifest::parse(manifest.path().to_path_buf(), source.clone())
            .map_err(|error| classified(FailureClass::UsageOrConfig, error))?,
        None => manifest.clone(),
    };
    let action_sha = resolve_action_sha(explicit_action_sha).await?;
    let relative_manifest = absolute_or_join(configured.path())?
        .strip_prefix(repo.root().canonicalize()?)
        .context("manifest is outside the git repository")?
        .to_path_buf();
    let workflow_settings = release_glz::workflow::WorkflowSettings {
        default_branch,
        manifest_path: relative_manifest,
        compiler: configured.release.compiler.to_string(),
        environment: configured.release.approval.environment.clone(),
        registry_credential_env: configured.release.registry.credential_env.clone(),
        release_branch_prefix: configured.release.release_branch_prefix.clone(),
        action_sha: action_sha.clone(),
    };
    let workflow_mode = if check {
        release_glz::workflow::WorkflowMode::Check
    } else if diff {
        release_glz::workflow::WorkflowMode::Diff
    } else {
        release_glz::workflow::WorkflowMode::Update
    };
    let workflow = release_glz::workflow::sync(repo.root(), &workflow_settings, workflow_mode)
        .map_err(|error| classified(FailureClass::ImmutableStateConflict, error))?;
    let manifest_changed = initialized_source
        .as_deref()
        .is_some_and(|source| source != manifest.original_source());

    if diff && matches!(output, Output::Human) {
        if let Some(source) = &initialized_source
            && manifest_changed
        {
            print!(
                "{}",
                text_diff(
                    &manifest.path().to_string_lossy(),
                    manifest.original_source(),
                    source,
                    "schema 2",
                )
            );
        }
        if let Some(workflow_diff) = &workflow.diff {
            print!("{workflow_diff}");
        }
        return Ok(0);
    }

    let mut manifest_written = false;
    if update
        && let Some(source) = initialized_source
        && manifest_changed
    {
        manifest
            .replace_source(source)
            .map_err(|error| classified(FailureClass::ImmutableStateConflict, error))?;
        manifest_written = true;
    }
    let changed = manifest_changed || workflow.changed;
    let outcome = InitOutcome {
        schema: "init/v1",
        manifest_path: manifest.path().to_string_lossy().replace('\\', "/"),
        workflow_path: release_glz::workflow::WORKFLOW_PATH,
        action_sha,
        manifest_changed,
        workflow_changed: workflow.changed,
        changed,
        written: workflow.written || manifest_written,
    };
    let stale = check && changed;
    let next_action = stale.then(|| {
        let mut argv = vec!["release-glz".to_owned()];
        if manifest_path != Path::new("gleam.toml") {
            argv.extend([
                "--manifest-path".to_owned(),
                manifest_path.to_string_lossy().into_owned(),
            ]);
        }
        argv.extend(["init".to_owned(), "--update".to_owned()]);
        if let Some(sha) = explicit_action_sha {
            argv.extend(["--action-sha".to_owned(), sha.to_owned()]);
        }
        if let Some(profile) = profile {
            argv.extend(["--profile".to_owned(), profile_name(profile).to_owned()]);
            append_profile_argv(
                &mut argv,
                organization,
                api_url,
                repository_url,
                docs_url,
                credential_env,
                auth,
                allow_version_zero,
            );
        }
        NextAction::executable(
            argv,
            "Review and apply the generated configuration and workflow.",
        )
    });
    print_checked_result(
        "init",
        &outcome,
        !stale,
        stale.then(|| Diagnostic {
            code: "managed_file_outdated".into(),
            level: DiagnosticLevel::Error,
            message: "the manifest or managed workflow differs from the required state".into(),
            detail: None,
        }),
        next_action,
        output,
    )?;
    Ok(if stale { 3 } else { 0 })
}

fn require_one_mode(check: bool, diff: bool, update: bool) -> Result<()> {
    if [check, diff, update]
        .into_iter()
        .filter(|selected| *selected)
        .count()
        != 1
    {
        return Err(classified(
            FailureClass::UsageOrConfig,
            "choose exactly one of --check, --diff, or --update",
        ));
    }
    Ok(())
}

fn manifest_executable_action(
    manifest_path: &Path,
    arguments: impl IntoIterator<Item = impl Into<String>>,
    description: impl Into<String>,
) -> NextAction {
    let mut argv = vec!["release-glz".to_owned()];
    if manifest_path != Path::new("gleam.toml") {
        argv.extend([
            "--manifest-path".to_owned(),
            manifest_path.to_string_lossy().into_owned(),
        ]);
    }
    argv.extend(arguments.into_iter().map(Into::into));
    NextAction::executable(argv, description)
}

fn scope_manifest_actions(actions: &mut [NextAction], manifest_path: &Path) {
    if manifest_path == Path::new("gleam.toml") {
        return;
    }
    for action in actions {
        if action
            .argv
            .first()
            .is_some_and(|value| value == "release-glz")
            && !action.argv.iter().any(|value| value == "--manifest-path")
        {
            let arguments = action.argv.iter().skip(1).cloned().collect::<Vec<_>>();
            *action =
                manifest_executable_action(manifest_path, arguments, action.description.clone());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn initialization_registry(
    profile: InitProfile,
    organization: Option<&str>,
    api_url: Option<&str>,
    repository_url: Option<&str>,
    docs_url: Option<&str>,
    credential_env: Option<&str>,
    auth: Option<InitAuth>,
) -> Result<RegistryConfig> {
    let private_fields = [api_url, repository_url, docs_url, credential_env]
        .into_iter()
        .any(|value| value.is_some())
        || auth.is_some();
    match profile {
        InitProfile::Public => {
            if organization.is_some() || private_fields {
                return Err(classified(
                    FailureClass::UsageOrConfig,
                    "the public profile does not accept organization or private registry options",
                ));
            }
            Ok(RegistryConfig::default())
        }
        InitProfile::Organization => {
            if private_fields {
                return Err(classified(
                    FailureClass::UsageOrConfig,
                    "the organization profile accepts only --organization",
                ));
            }
            let organization = organization
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    classified(
                        FailureClass::UsageOrConfig,
                        "the organization profile requires --organization",
                    )
                })?;
            Ok(RegistryConfig {
                repository: Some(organization.to_owned()),
                api_url: "https://hex.pm/api".into(),
                repository_url: format!("https://repo.hex.pm/repos/{organization}"),
                docs_url: format!("https://repo.hex.pm/repos/{organization}/docs"),
                ..RegistryConfig::default()
            })
        }
        InitProfile::Private => {
            if organization.is_some() {
                return Err(classified(
                    FailureClass::UsageOrConfig,
                    "the private profile does not accept --organization",
                ));
            }
            let required = |value: Option<&str>, option: &str| {
                value
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        classified(
                            FailureClass::UsageOrConfig,
                            format!("the private profile requires --{option}"),
                        )
                    })
            };
            Ok(RegistryConfig {
                provider: RegistryProvider::HexCompatible,
                repository: None,
                api_url: required(api_url, "api-url")?,
                repository_url: required(repository_url, "repository-url")?,
                docs_url: required(docs_url, "docs-url")?,
                credential_env: required(credential_env, "credential-env")?,
                auth: match auth.ok_or_else(|| {
                    classified(
                        FailureClass::UsageOrConfig,
                        "the private profile requires --auth",
                    )
                })? {
                    InitAuth::HexToken => AuthKind::HexToken,
                    InitAuth::Bearer => AuthKind::Bearer,
                },
                allow_http_loopback: false,
            })
        }
    }
}

async fn resolve_action_sha(explicit: Option<&str>) -> Result<String> {
    if let Some(sha) = explicit {
        release_glz::workflow::validate_action_sha(sha)
            .map_err(|error| classified(FailureClass::UsageOrConfig, error))?;
        return Ok(sha.to_owned());
    }
    let repository = GitHubRepository::parse("P4suta/release-glz")?;
    let client = GitHubClient::from_environment(repository);
    let tag = format!("v{}", env!("CARGO_PKG_VERSION"));
    let state = client
        .tag_state(&tag)
        .await
        .map_err(|error| classified(FailureClass::TemporaryExternal, error))?
        .ok_or_else(|| {
            classified(
                FailureClass::UsageOrConfig,
                format!("official Action tag {tag} does not exist; use --action-sha only for offline development"),
            )
        })?;
    if !state.annotated {
        return Err(classified(
            FailureClass::ImmutableStateConflict,
            format!("official Action tag {tag} is not annotated"),
        ));
    }
    release_glz::workflow::validate_action_sha(&state.target_sha)
        .map_err(|error| classified(FailureClass::ImmutableStateConflict, error))?;
    Ok(state.target_sha)
}

fn profile_name(profile: InitProfile) -> &'static str {
    match profile {
        InitProfile::Public => "public",
        InitProfile::Organization => "organization",
        InitProfile::Private => "private",
    }
}

#[allow(clippy::too_many_arguments)]
fn append_profile_argv(
    argv: &mut Vec<String>,
    organization: Option<&str>,
    api_url: Option<&str>,
    repository_url: Option<&str>,
    docs_url: Option<&str>,
    credential_env: Option<&str>,
    auth: Option<InitAuth>,
    allow_version_zero: bool,
) {
    for (option, value) in [
        ("--organization", organization),
        ("--api-url", api_url),
        ("--repository-url", repository_url),
        ("--docs-url", docs_url),
        ("--credential-env", credential_env),
    ] {
        if let Some(value) = value {
            argv.extend([option.to_owned(), value.to_owned()]);
        }
    }
    if let Some(auth) = auth {
        argv.extend([
            "--auth".to_owned(),
            match auth {
                InitAuth::HexToken => "hex-token",
                InitAuth::Bearer => "bearer",
            }
            .to_owned(),
        ]);
    }
    if allow_version_zero {
        argv.push("--allow-version-zero".to_owned());
    }
}

fn text_diff(path: &str, current: &str, rendered: &str, label: &str) -> String {
    let mut output = format!("--- {path}\n+++ {path} ({label})\n");
    for line in current.lines() {
        output.push_str(&format!("-{line}\n"));
    }
    for line in rendered.lines() {
        output.push_str(&format!("+{line}\n"));
    }
    output
}

fn run_migrate(
    manifest_path: &Path,
    output: Output,
    check: bool,
    diff: bool,
    update: bool,
) -> Result<i32> {
    require_one_mode(check, diff, update)?;
    let migration = release_glz::migrate::Migration::prepare(manifest_path)
        .map_err(|error| classified(FailureClass::UsageOrConfig, error))?;
    if diff && matches!(output, Output::Human) {
        if let Some(diff) = migration.diff() {
            print!("{diff}");
        }
        return Ok(0);
    }
    let outcome = if update {
        migration
            .apply()
            .map_err(|error| classified(FailureClass::ImmutableStateConflict, error))?
    } else {
        migration.outcome(false)
    };
    let stale = check && outcome.changed;
    print_checked_result(
        "migrate",
        &outcome,
        !stale,
        stale.then(|| Diagnostic {
            code: "migration_required".into(),
            level: DiagnosticLevel::Error,
            message: "legacy configuration must be migrated to schema 2".into(),
            detail: None,
        }),
        stale.then(|| {
            manifest_executable_action(
                manifest_path,
                ["migrate", "--update"],
                "Review and apply the lossless schema 2 migration.",
            )
        }),
        output,
    )?;
    Ok(if stale { 3 } else { 0 })
}

async fn run_doctor(
    manifest_path: &Path,
    output: Output,
    online: bool,
    candidate_build: bool,
) -> Result<i32> {
    let manifest = Manifest::load(manifest_path)
        .map_err(|error| classified(FailureClass::UsageOrConfig, error))?;
    let installed_compiler = Gleam::default().installed_version().ok();
    let action_sha = GitRepo::discover(manifest.package_dir())
        .ok()
        .and_then(|repo| release_glz::workflow::action_sha_from_workflow(repo.root()).ok());
    let workflow_current = action_sha
        .as_deref()
        .is_some_and(|sha| managed_workflow_is_current(&manifest, sha).unwrap_or(false));
    let (registry_credential, github_environment) = if online {
        let registry = if std::env::var_os(&manifest.release.registry.credential_env).is_none() {
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
        let github = match github_client(&manifest) {
            Ok(client) => client
                .environment_audit(&manifest.release.approval.environment)
                .await
                .ok(),
            Err(_) => None,
        };
        (registry, github)
    } else {
        (RegistryCredentialAudit::Missing, None)
    };
    let input = DoctorInput {
        config_schema: manifest.release.schema,
        package_version: manifest.version.clone(),
        required_compiler: manifest.release.compiler.clone(),
        installed_compiler,
        registry_credential,
        workflow_current,
        approval: manifest.release.approval.clone(),
        github_environment,
    };
    let mut report = if online {
        assess_doctor(&input)
    } else {
        assess_doctor_local(&input)
    };
    scope_manifest_actions(&mut report.next_actions, manifest_path);

    if candidate_build {
        match credential_free_candidate_build(&manifest).await {
            Ok(()) => report.diagnostics.push(Diagnostic {
                code: "candidate_build_succeeded".into(),
                level: DiagnosticLevel::Info,
                message: "HEAD builds as a Candidate with isolated caches and no credentials"
                    .into(),
                detail: None,
            }),
            Err(error) => {
                report.state = ReleaseState::Blocked;
                report.diagnostics.push(Diagnostic {
                    code: "candidate_build_failed".into(),
                    level: DiagnosticLevel::Error,
                    message: "the isolated v1 Candidate build failed without credentials".into(),
                    detail: Some(format!(
                        "{error}. If this is a dependency authentication failure, note that private dependencies are not supported in v1 Candidates; make them credential-free, replace/vendor them, or build outside the v1 publication path."
                    )),
                });
                report.next_actions.push(NextAction::guidance(
                    "fix the isolated Candidate build",
                    "Resolve the reported compiler or dependency error; every Candidate dependency must be available without registry credentials.",
                ));
            }
        }
    }
    print_doctor(&report, output)?;
    Ok(if report.state == ReleaseState::Blocked {
        3
    } else {
        0
    })
}

async fn credential_free_candidate_build(manifest: &Manifest) -> Result<()> {
    let repo = GitRepo::discover(manifest.package_dir())?;
    let source = repo.head()?;
    let temporary = tempfile::tempdir()?;
    let candidate = temporary.path().join("candidate");
    let cache = temporary.path().join("cache");
    std::fs::create_dir_all(&cache)?;
    let executable = std::env::current_exe()?;
    let mut command = tokio::process::Command::new(executable);
    command
        .env_clear()
        .current_dir(repo.root())
        .args(["--manifest-path"])
        .arg(absolute_or_join(manifest.path())?)
        .args(["--output", "json", "rehearse", "--ref"])
        .arg(source)
        .arg("--out")
        .arg(candidate)
        .env("GLEAM_HOME", &cache)
        .env("XDG_CACHE_HOME", &cache);
    for name in [
        "PATH",
        "RELEASE_GLZ_GLEAM",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "SYSTEMROOT",
        "WINDIR",
        "PATHEXT",
        "TMPDIR",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let output = tokio::time::timeout(std::time::Duration::from_secs(1_800), command.output())
        .await
        .context("isolated Candidate build timed out")??;
    if output.status.success() {
        return Ok(());
    }
    let detail = serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .ok()
        .and_then(|envelope| {
            envelope["diagnostics"].as_array().map(|diagnostics| {
                diagnostics
                    .iter()
                    .filter_map(|diagnostic| diagnostic["message"].as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            })
        })
        .filter(|detail| !detail.is_empty())
        .unwrap_or_else(|| "isolated Candidate subprocess failed".into());
    bail!("{detail}")
}

async fn sync_rolling_release_pr(
    planner: &Planner<HexRegistry>,
    options: &PlanOptions,
    manifest_path: &Path,
    dry_run: bool,
) -> Result<ReleasePlan> {
    let mut plan = planner
        .plan(options)
        .await
        .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?;
    let manifest = Manifest::load(manifest_path)
        .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?;
    let repo = GitRepo::discover(manifest.package_dir())
        .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?;
    let github = github_client(&manifest)
        .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?;
    if plan.release_required {
        let commits = repo.commits_since(plan.baseline.sha.as_deref())?;
        plan.changes = github
            .changes_for_commits(&commits)
            .await
            .map_err(|error| default_failure_class(error, FailureClass::TemporaryExternal))?;
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
                    .await
                    .map_err(|error| {
                        default_failure_class(error, FailureClass::TemporaryExternal)
                    })?,
            );
        }
    } else if !dry_run {
        github
            .close_managed_release_pr(&manifest.package, &manifest.release.release_branch_prefix)
            .await
            .map_err(|error| default_failure_class(error, FailureClass::TemporaryExternal))?;
    }
    Ok(plan)
}

async fn online_candidate_report(
    candidate_directory: &Path,
    manifest: &release_glz::candidate::CandidateManifest,
    approval: ApprovalEvidence,
    dry_run: bool,
) -> Result<ReleaseReport> {
    let current = std::env::current_dir()
        .map_err(|error| default_failure_class(error.into(), FailureClass::UsageOrConfig))?;
    let repo = GitRepo::discover(&current)
        .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?;
    if repo
        .head()
        .map_err(|error| default_failure_class(error, FailureClass::UsageOrConfig))?
        != manifest.source.commit_sha
    {
        return Err(classified(
            FailureClass::ImmutableStateConflict,
            "checked-out commit does not match the sealed Candidate source",
        ));
    }
    let target = LiveReleaseTarget::from_candidate(manifest.clone(), repo)
        .map_err(|error| default_failure_class(error, FailureClass::PolicyOrApproval))?;
    CandidateReleaseRunner::new(target)
        .run(
            candidate_directory,
            &approval,
            ReleaseExecutionOptions { dry_run },
        )
        .await
        .map_err(Into::into)
}

fn default_failure_class(error: anyhow::Error, fallback: FailureClass) -> anyhow::Error {
    release_glz::failure::with_default_class(error, fallback)
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
    let artifact_run_id = std::env::var("RELEASE_GLZ_ACTIONS_RUN_ID")
        .context("release approval requires the Candidate-generating Actions run ID")?;
    if github_oidc.event_name() == "workflow_dispatch" && artifact_run_id == github_oidc.run_id() {
        return Err(classified(
            FailureClass::PolicyOrApproval,
            "manual promotion must consume a Candidate from a completed prior prepare run",
        ));
    }
    let repository = GitHubRepository::parse(&manifest.github_repository)?;
    let github = GitHubClient::from_environment(repository);
    github
        .verify_actions_artifact(
            artifact_id,
            artifact_digest,
            &artifact_run_id,
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
    print_result_with_actions(command, result, Vec::new(), output)
}

fn print_result_with_actions<T: serde::Serialize>(
    command: &str,
    result: &T,
    next_actions: Vec<NextAction>,
    output: Output,
) -> Result<()> {
    match output {
        Output::Json => {
            let envelope = release_glz::model::CommandEnvelope::success(
                command,
                serde_json::to_value(result)?,
                vec![],
                next_actions,
            );
            println!("{}", serde_json::to_string(&envelope)?);
        }
        Output::Human => {
            render_human_result(command, &serde_json::to_value(result)?, &[], &next_actions)
        }
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
        Output::Human => {
            let diagnostics = diagnostic.into_iter().collect::<Vec<_>>();
            let actions = next_action.into_iter().collect::<Vec<_>>();
            render_human_result(
                command,
                &serde_json::to_value(result)?,
                &diagnostics,
                &actions,
            );
        }
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
        Output::Human => render_human_result(
            "doctor",
            &serde_json::to_value(report)?,
            &report.diagnostics,
            &report.next_actions,
        ),
    }
    Ok(())
}

fn render_human_result(
    command: &str,
    result: &serde_json::Value,
    diagnostics: &[Diagnostic],
    next_actions: &[NextAction],
) {
    let state = result
        .get("state")
        .or_else(|| result.get("candidate").and_then(|value| value.get("state")))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("completed");
    println!("{command}: {state}");
    for (label, key) in [
        ("Version", "version"),
        ("Candidate digest", "candidate_digest"),
        ("Intent digest", "intent_digest"),
        ("PR", "pr_url"),
        ("Hex", "hex_url"),
        ("GitHub Release", "github_release_url"),
    ] {
        let value = result.get(key).or_else(|| {
            result
                .get("candidate")
                .and_then(|candidate| candidate.get(key))
        });
        if let Some(value) = value.and_then(serde_json::Value::as_str)
            && !value.is_empty()
        {
            println!("  {label}: {value}");
        }
    }
    for (label, key) in [
        ("Changed", "changed"),
        ("Written", "written"),
        ("Manifest changed", "manifest_changed"),
        ("Workflow changed", "workflow_changed"),
    ] {
        if let Some(value) = result.get(key).and_then(serde_json::Value::as_bool) {
            println!("  {label}: {value}");
        }
    }
    for (label, key) in [("Applied", "applied"), ("Remaining", "remaining")] {
        if let Some(values) = result.get(key).and_then(serde_json::Value::as_array) {
            println!("  {label}: {}", values.len());
            for value in values {
                let kind = value
                    .get("kind")
                    .and_then(serde_json::Value::as_str)
                    .or_else(|| value.as_str())
                    .unwrap_or("effect");
                println!("    - {kind}");
            }
        }
    }
    for diagnostic in diagnostics {
        println!(
            "  {:?} [{}]: {}",
            diagnostic.level, diagnostic.code, diagnostic.message
        );
        if let Some(detail) = &diagnostic.detail {
            println!("    {detail}");
        }
    }
    for action in next_actions {
        println!("  Next: {}", action.command);
        if !action.description.is_empty() {
            println!("    {}", action.description);
        }
    }
}

fn managed_workflow_is_current(manifest: &Manifest, action_sha: &str) -> Result<bool> {
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
        action_sha: action_sha.to_owned(),
    };
    let outcome = release_glz::workflow::sync(
        repo.root(),
        &settings,
        release_glz::workflow::WorkflowMode::Check,
    )?;
    Ok(!outcome.changed)
}

fn completion_source(shell: CompletionShell) -> String {
    let mut command = Cli::command();
    let mut source = Vec::new();
    match shell {
        CompletionShell::Bash => generate(shells::Bash, &mut command, "release-glz", &mut source),
        CompletionShell::Zsh => generate(shells::Zsh, &mut command, "release-glz", &mut source),
        CompletionShell::Fish => generate(shells::Fish, &mut command, "release-glz", &mut source),
        CompletionShell::Powershell => {
            generate(shells::PowerShell, &mut command, "release-glz", &mut source)
        }
    }
    String::from_utf8(source).expect("clap completion generators emit UTF-8")
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
            (Command::Update { dry_run: false }, "update"),
            (
                Command::ReleasePr {
                    candidate: None,
                    dry_run: false,
                },
                "release-pr",
            ),
            (
                Command::Release {
                    candidate: "candidate".into(),
                    dry_run: false,
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
            (
                Command::Doctor {
                    online: false,
                    candidate_build: false,
                },
                "doctor",
            ),
            (
                Command::Init {
                    profile: None,
                    organization: None,
                    api_url: None,
                    repository_url: None,
                    docs_url: None,
                    credential_env: None,
                    auth: None,
                    allow_version_zero: false,
                    action_sha: None,
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
                    dry_run: false,
                },
                "set-version",
            ),
            (
                Command::Prerelease {
                    channel: Train::Rc,
                    version: None,
                    dry_run: false,
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
        for (class, expected_exit, expected_code) in [
            (FailureClass::Hook, 6, "hook_failure"),
            (FailureClass::PolicyOrApproval, 3, "policy_or_approval"),
            (
                FailureClass::ImmutableStateConflict,
                4,
                "immutable_state_conflict",
            ),
            (
                FailureClass::TemporaryExternal,
                5,
                "temporary_external_failure",
            ),
            (FailureClass::UsageOrConfig, 2, "usage_or_config"),
            (FailureClass::PartialRelease, 7, "partial_release"),
            (FailureClass::Internal, 1, "internal_failure"),
        ] {
            let error = classified(class, "message text is not classification");
            assert_eq!(exit_code(&error), expected_exit);
            assert_eq!(error_code(&error), expected_code);
        }
        let misleading = anyhow::anyhow!("hook approval conflict connection must be fixed");
        assert_eq!(exit_code(&misleading), 1);
    }

    #[test]
    fn manifest_scoping_preserves_non_shell_path_arguments() {
        let path = Path::new("package with space\nand newline/gleam.toml");
        let mut actions = vec![
            NextAction::executable(["release-glz", "migrate", "--update"], "Migrate."),
            NextAction::guidance("install Gleam", "Install it."),
        ];
        scope_manifest_actions(&mut actions, path);
        assert_eq!(
            actions[0].argv,
            [
                "release-glz",
                "--manifest-path",
                "package with space\nand newline/gleam.toml",
                "migrate",
                "--update",
            ]
        );
        assert!(actions[1].argv.is_empty());
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
            Some(NextAction::executable(
                ["release-glz", "migrate", "--update"],
                "migrate",
            )),
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
