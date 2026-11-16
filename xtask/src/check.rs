//! The fast gate: formatting, the crate structure, lints, the tests, the documentation, the dependency policy, the Action, the workflows, and the workflow that `release-glz init` generates.

use crate::container::Failure;
use crate::fs;
use crate::report::Report;
use crate::structure;
use crate::tool::{Tool, capture, refuse, succeed};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Which files a check covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    /// The whole checkout, as the push hook and CI see it.
    Everything,
    /// The staged files alone, as the pre-commit hook sees them.
    Staged,
    /// The checks whose outcome depends on the operating system, for a host that receives the files without their Git history.
    Platform,
    /// The repository workflows and the generated workflow, as the release gate checks them on the candidate.
    Workflows,
}

const RUST_EDITION: &str = "2024";
const WORKFLOWS: &str = ".github/workflows";
const FUZZ_MANIFEST: &str = "fuzz/Cargo.toml";
const SCRIPTS: &str = "scripts";
/// The package whose managed workflow the gate generates.
const WORKFLOW_FIXTURE: &str = "tests/fixtures/workflow/gleam.toml";
const GENERATED_WORKFLOW: &str = ".github/workflows/release-glz.yml";
/// A copy of the generated workflow with one planted defect, beside the generated one.
const PLANTED_WORKFLOW: &str = ".github/workflows/planted.yml";
/// The commit that the generated workflow pins release-glz to, which only has to be a full lowercase SHA.
const FIXTURE_ACTION_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
/// The exit code with which `scripts/verify-workflows.js` refuses a workflow.
const VERIFIER_REFUSAL: i32 = 1;
/// zizmor's exit code when its most severe finding is medium.
const ZIZMOR_MEDIUM: i32 = 13;
/// zizmor's exit code when its most severe finding is high.
const ZIZMOR_HIGH: i32 = 14;

fn staged_paths(root: &Path) -> Result<Vec<String>, Failure> {
    let listing = capture(
        Tool::Git
            .command(root)
            .args(["diff", "--cached", "--name-only", "--diff-filter=ACMR"]),
        "git diff --cached --name-only",
    )?;
    Ok(listing.lines().map(str::to_owned).collect())
}

fn with_suffix<'a>(paths: &'a [String], suffix: &str) -> Vec<&'a str> {
    paths
        .iter()
        .map(String::as_str)
        .filter(|path| path.ends_with(suffix))
        .collect()
}

fn rustfmt(root: &Path, files: Option<&[&str]>) -> Result<(), Failure> {
    match files {
        Some([]) => Ok(()),
        Some(files) => succeed(
            Tool::Rustfmt
                .command(root)
                .args(["--edition", RUST_EDITION, "--check"])
                .args(files),
            "rustfmt --check",
        ),
        None => {
            succeed(
                Tool::Cargo
                    .command(root)
                    .args(["fmt", "--all", "--", "--check"]),
                "cargo fmt --check",
            )?;
            succeed(
                Tool::Cargo.command(root).args([
                    "fmt",
                    "--manifest-path",
                    FUZZ_MANIFEST,
                    "--",
                    "--check",
                ]),
                "cargo fmt --check of the fuzz workspace",
            )
        }
    }
}

fn taplo(root: &Path, files: Option<&[&str]>) -> Result<(), Failure> {
    match files {
        Some([]) => Ok(()),
        Some(files) => succeed(
            Tool::Taplo
                .command(root)
                .args(["fmt", "--check"])
                .args(files),
            "taplo fmt --check",
        ),
        None => {
            succeed(
                Tool::Taplo.command(root).args(["fmt", "--check"]),
                "taplo fmt --check",
            )?;
            succeed(Tool::Taplo.command(root).arg("lint"), "taplo lint")
        }
    }
}

fn typos(root: &Path, files: Option<&[&str]>) -> Result<(), Failure> {
    match files {
        Some([]) => Ok(()),
        Some(files) => succeed(
            Tool::Typos.command(root).arg("--force-exclude").args(files),
            "typos",
        ),
        None => succeed(&mut Tool::Typos.command(root), "typos"),
    }
}

/// The fuzz workspace's lockfile still resolves every dependency it names.
fn fuzz_lockfile(root: &Path) -> Result<(), Failure> {
    succeed(
        Tool::Cargo
            .command(root)
            .args(["fetch", "--locked", "--manifest-path", FUZZ_MANIFEST]),
        "cargo fetch --locked of the fuzz workspace",
    )
}

fn clippy(root: &Path) -> Result<(), Failure> {
    succeed(
        Tool::Cargo.command(root).args([
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ]),
        "cargo clippy",
    )
}

fn tests(root: &Path) -> Result<(), Failure> {
    succeed(
        Tool::Cargo.command(root).args([
            "nextest",
            "run",
            "--workspace",
            "--all-targets",
            "--locked",
            "--no-tests=fail",
        ]),
        "cargo nextest",
    )
}

/// The released binary starts and prints its usage.
fn cli(root: &Path) -> Result<(), Failure> {
    succeed(
        Tool::Cargo
            .command(root)
            .args([
                "run",
                "--locked",
                "--package",
                "release-glz",
                "--",
                "--help",
            ])
            .stdout(Stdio::null()),
        "release-glz --help",
    )
}

fn documentation(root: &Path) -> Result<(), Failure> {
    succeed(
        Tool::Cargo
            .command(root)
            .env("RUSTDOCFLAGS", "-D warnings")
            .args(["doc", "--workspace", "--no-deps", "--locked"]),
        "cargo doc",
    )
}

/// Licenses, bans, and sources of the workspace lockfile.
fn deny(root: &Path) -> Result<(), Failure> {
    succeed(
        Tool::Cargo.command(root).args([
            "deny", "--locked", "check", "-D", "warnings", "bans", "licenses", "sources",
        ]),
        "cargo deny",
    )
}

/// The script tests, which Node runs only from the paths it is given.
fn script_tests(root: &Path) -> Result<Vec<String>, Failure> {
    let entries = std::fs::read_dir(root.join(SCRIPTS))
        .map_err(|error| Failure::new(format!("{SCRIPTS} is unreadable: {error}")))?;
    let mut tests = Vec::new();
    for entry in entries {
        let name = entry
            .map_err(|error| Failure::new(format!("{SCRIPTS} is unreadable: {error}")))?
            .file_name()
            .into_string()
            .map_err(|name| {
                Failure::new(format!(
                    "{SCRIPTS} holds a name that isn't UTF-8: {}",
                    name.display()
                ))
            })?;
        if name.ends_with(".test.js") {
            tests.push(format!("{SCRIPTS}/{name}"));
        }
    }
    if tests.is_empty() {
        return Err(Failure::new(format!("{SCRIPTS} holds no test")));
    }
    tests.sort();
    Ok(tests)
}

/// The Action and the release scripts: their dependencies, strict types, formatting and lints, and tests.
fn javascript(root: &Path) -> Result<(), Failure> {
    succeed(
        Tool::Npm
            .command(root)
            .args(["ci", "--ignore-scripts", "--no-audit", "--no-fund"]),
        "npm ci",
    )?;
    succeed(
        Tool::Npm.command(root).args(["run", "typecheck"]),
        "npm run typecheck",
    )?;
    succeed(
        Tool::Npm
            .command(root)
            .args(["exec", "--no", "--", "biome", "ci"]),
        "biome ci",
    )?;
    succeed(
        Tool::Npm.command(root).args(["test", "--prefix", "action"]),
        "npm test of the Action",
    )?;
    succeed(
        Tool::Node
            .command(root)
            .arg("--test")
            .args(script_tests(root)?),
        "node --test of the scripts",
    )
}

fn workflows(root: &Path) -> Result<(), Failure> {
    succeed(verify_workflows(root).arg(WORKFLOWS), "verify-workflows.js")?;
    succeed(
        Tool::Node
            .command(root)
            .args(["scripts/de-shell.js", WORKFLOWS]),
        "de-shell.js",
    )?;
    succeed(&mut Tool::Actionlint.command(root), "actionlint")?;
    succeed(zizmor(root).args([WORKFLOWS, "action.yml"]), "zizmor")?;
    succeed(
        Tool::Jq.command(root).args([
            "-L",
            ".github",
            "-n",
            "-e",
            "-f",
            ".github/check-required.jq",
        ]),
        "check-required.jq",
    )
}

/// zizmor with every audit at every severity, without network access.
fn zizmor(root: &Path) -> Command {
    let mut command = Tool::Zizmor.command(root);
    command.args(["--persona", "auditor", "--no-online-audits"]);
    command
}

fn verify_workflows(root: &Path) -> Command {
    let mut command = Tool::Node.command(root);
    command.arg("scripts/verify-workflows.js");
    command
}

/// `text` with its first line that `rewrite` changes replaced, or a failure naming the `wanted` line when no line changes.
fn rewrite_first_line(
    text: &str,
    wanted: &str,
    rewrite: impl Fn(&str) -> Option<String>,
) -> Result<String, Failure> {
    let mut lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
    let (line, rewritten) = lines
        .iter_mut()
        .find_map(|line| rewrite(line.as_str()).map(|rewritten| (line, rewritten)))
        .ok_or_else(|| Failure::new(format!("the generated workflow holds no {wanted}")))?;
    *line = rewritten;
    Ok(lines.join("\n"))
}

/// The workflow with its first checkout taken from a movable tag instead of a commit.
fn unpinned_checkout(workflow: &str) -> Result<String, Failure> {
    rewrite_first_line(workflow, "pinned checkout", |line| {
        line.split_once("uses: actions/checkout@")
            .map(|(indentation, _)| format!("{indentation}uses: actions/checkout@v7"))
    })
}

/// The workflow with its first checkout keeping its credentials, which zizmor finds at medium severity.
fn persisted_credentials(workflow: &str) -> Result<String, Failure> {
    rewrite_first_line(workflow, "checkout that drops its credentials", |line| {
        line.split_once("persist-credentials: false")
            .map(|(indentation, _)| format!("{indentation}persist-credentials: true"))
    })
}

/// Writes the fixture package into `package` as a repository of its own, and has `release-glz init` generate its workflow.
fn generate_workflow(root: &Path, package: &Path) -> Result<PathBuf, Failure> {
    let manifest = package.join("gleam.toml");
    fs::write(&manifest, fs::read_to_string(root.join(WORKFLOW_FIXTURE))?)?;
    succeed(
        Tool::Git
            .command(package)
            .args(["init", "--quiet", "--initial-branch=main"]),
        "git init of the fixture package",
    )?;
    succeed(
        Tool::Cargo
            .command(root)
            .args([
                "run",
                "--locked",
                "--package",
                "release-glz",
                "--",
                "--manifest-path",
            ])
            .arg(&manifest)
            .args(["init", "--update", "--action-sha", FIXTURE_ACTION_SHA])
            .stdout(Stdio::null()),
        "release-glz init",
    )?;
    Ok(package.join(GENERATED_WORKFLOW))
}

/// The checkers refuse each defect planted in a copy of the generated workflow, so a checker that stops finding the defect fails the gate.
fn planted_defects_fail(root: &Path, package: &Path, workflow: &str) -> Result<(), Failure> {
    let planted = package.join(PLANTED_WORKFLOW);
    fs::write(&planted, unpinned_checkout(workflow)?)?;
    refuse(
        verify_workflows(root).arg(&planted),
        "verify-workflows.js over an unpinned action",
        VERIFIER_REFUSAL,
    )?;
    refuse(
        zizmor(root).arg(&planted),
        "zizmor over an unpinned action",
        ZIZMOR_HIGH,
    )?;
    fs::write(&planted, persisted_credentials(workflow)?)?;
    refuse(
        zizmor(root).arg(&planted),
        "zizmor over a checkout that keeps its credentials",
        ZIZMOR_MEDIUM,
    )
}

/// The workflow that `release-glz init` generates for the fixture package meets the checkers of the repository workflows.
fn generated_workflow(root: &Path) -> Result<(), Failure> {
    let package = tempfile::tempdir().map_err(|error| {
        Failure::new(format!(
            "the directory of the fixture package wasn't created: {error}"
        ))
    })?;
    let workflow = generate_workflow(root, package.path())?;
    let text = fs::read_to_string(&workflow)?;
    if !text.contains(&format!("P4suta/release-glz@{FIXTURE_ACTION_SHA}")) {
        return Err(Failure::new(format!(
            "{GENERATED_WORKFLOW} doesn't pin release-glz to {FIXTURE_ACTION_SHA}"
        )));
    }
    succeed(verify_workflows(root).arg(&workflow), "verify-workflows.js")?;
    succeed(
        Tool::Node
            .command(root)
            .arg("scripts/de-shell.js")
            .arg(&workflow),
        "de-shell.js",
    )?;
    succeed(Tool::Actionlint.command(root).arg(&workflow), "actionlint")?;
    succeed(zizmor(root).arg(&workflow), "zizmor")?;
    planted_defects_fail(root, package.path(), &text)?;
    package.close().map_err(|error| {
        Failure::new(format!(
            "the directory of the fixture package wasn't removed: {error}"
        ))
    })
}

/// The README and license files equal what `repository.toml` generates, where the owner's `dotfiles` tool is installed.
fn repository(root: &Path) -> Result<(), Failure> {
    match Tool::Dotfiles
        .command(root)
        .args(["repository", "check"])
        .status()
    {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(Failure::new(format!(
            "dotfiles repository check failed with {status}"
        ))),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            eprintln!(
                "repository: the `dotfiles` tool is absent on this host, so the generated files are checked only where it is installed"
            );
            Ok(())
        }
        Err(error) => Err(Failure::new(format!(
            "dotfiles repository check didn't start: {error}"
        ))),
    }
}

fn everything(root: &Path) -> Result<(), Failure> {
    let mut report = Report::default();
    report.stage("rustfmt", || rustfmt(root, None));
    report.stage("taplo", || taplo(root, None));
    report.stage("typos", || typos(root, None));
    report.stage("structure", || structure::run(root));
    report.stage("fuzz lockfile", || fuzz_lockfile(root));
    report.stage("clippy", || clippy(root));
    report.stage("tests", || tests(root));
    report.stage("cli", || cli(root));
    report.stage("documentation", || documentation(root));
    report.stage("deny", || deny(root));
    report.stage("javascript", || javascript(root));
    report.stage("workflows", || workflows(root));
    report.stage("generated workflow", || generated_workflow(root));
    report.stage("repository", || repository(root));
    report.finish("check")
}

fn staged(root: &Path) -> Result<(), Failure> {
    let paths = staged_paths(root)?;
    let mut report = Report::default();
    report.stage("rustfmt", || {
        rustfmt(root, Some(&with_suffix(&paths, ".rs")))
    });
    report.stage("taplo", || taplo(root, Some(&with_suffix(&paths, ".toml"))));
    report.stage("typos", || {
        let all = paths.iter().map(String::as_str).collect::<Vec<_>>();
        typos(root, Some(&all))
    });
    report.stage("structure", || structure::run(root));
    if paths.iter().any(|path| path.starts_with(WORKFLOWS)) {
        report.stage("workflows", || workflows(root));
    }
    report.finish("check --staged")
}

fn platform(root: &Path) -> Result<(), Failure> {
    let mut report = Report::default();
    report.stage("clippy", || clippy(root));
    report.stage("tests", || tests(root));
    report.finish("check --platform")
}

fn workflow_checks(root: &Path) -> Result<(), Failure> {
    let mut report = Report::default();
    report.stage("workflows", || workflows(root));
    report.stage("generated workflow", || generated_workflow(root));
    report.finish("check --workflows")
}

/// Runs the checks of one scope and reports every failure together.
///
/// # Errors
///
/// Returns a failure naming every check of the scope that failed.
pub fn run(root: &Path, scope: Scope) -> Result<(), Failure> {
    match scope {
        Scope::Everything => everything(root),
        Scope::Staged => staged(root),
        Scope::Platform => platform(root),
        Scope::Workflows => workflow_checks(root),
    }
}

#[cfg(test)]
mod tests {
    use super::{persisted_credentials, script_tests, unpinned_checkout, with_suffix};
    use std::path::Path;

    const CHECKOUTS: &str = "\
jobs:
  plan:
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false";

    #[test]
    fn each_plant_changes_one_line_of_the_workflow() {
        for (planted, expected) in [
            (
                unpinned_checkout(CHECKOUTS).unwrap(),
                "      - uses: actions/checkout@v7",
            ),
            (
                persisted_credentials(CHECKOUTS).unwrap(),
                "          persist-credentials: true",
            ),
        ] {
            let changed = CHECKOUTS
                .lines()
                .zip(planted.lines())
                .filter(|(before, after)| before != after)
                .map(|(_, after)| after)
                .collect::<Vec<_>>();
            assert_eq!(changed, [expected]);
            assert_eq!(planted.lines().count(), CHECKOUTS.lines().count());
        }
        for plant in [unpinned_checkout, persisted_credentials] {
            assert!(plant("jobs: {}").is_err_and(|failure| {
                failure
                    .to_string()
                    .starts_with("the generated workflow holds no ")
            }));
        }
    }

    #[test]
    fn a_staged_scope_selects_files_by_suffix() {
        let paths = [
            "src/main.rs",
            "Cargo.toml",
            "docs/README.md",
            "xtask/src/check.rs",
        ]
        .map(str::to_owned);
        assert_eq!(
            with_suffix(&paths, ".rs"),
            ["src/main.rs", "xtask/src/check.rs"]
        );
        assert_eq!(with_suffix(&paths, ".toml"), ["Cargo.toml"]);
        assert_eq!(with_suffix(&paths, ".yml"), Vec::<&str>::new());
    }

    #[test]
    fn the_script_tests_are_every_test_file_in_order() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let tests = script_tests(root).unwrap();
        assert!(
            tests
                .iter()
                .all(|test| test.starts_with("scripts/") && test.ends_with(".test.js"))
        );
        assert!(tests.contains(&"scripts/check-coverage.test.js".to_owned()));
        assert!(tests.is_sorted());
    }
}
