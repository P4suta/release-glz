//! The fast gate: formatting, the crate structure, lints, the tests, the documentation, the dependency policy, the Action, and the workflows.

use crate::container::Failure;
use crate::report::Report;
use crate::structure;
use crate::tool::{Tool, capture, succeed};
use std::io::ErrorKind;
use std::path::Path;

/// Which files a check covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    /// The whole checkout, as the push hook and CI see it.
    Everything,
    /// The staged files alone, as the pre-commit hook sees them.
    Staged,
    /// The checks whose outcome depends on the operating system, for a host that receives the files without their Git history.
    Platform,
}

const RUST_EDITION: &str = "2024";
const WORKFLOWS: &str = ".github/workflows";
const FUZZ_MANIFEST: &str = "fuzz/Cargo.toml";
const SCRIPTS: &str = "scripts";

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
            .stdout(std::process::Stdio::null()),
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
    succeed(
        Tool::Node
            .command(root)
            .args(["scripts/verify-workflows.js", WORKFLOWS]),
        "verify-workflows.js",
    )?;
    succeed(
        Tool::Node
            .command(root)
            .args(["scripts/de-shell.js", WORKFLOWS]),
        "de-shell.js",
    )?;
    succeed(&mut Tool::Actionlint.command(root), "actionlint")?;
    succeed(
        Tool::Zizmor.command(root).args([
            "--persona",
            "auditor",
            "--min-severity",
            "high",
            "--no-online-audits",
            WORKFLOWS,
            "action.yml",
        ]),
        "zizmor",
    )?;
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
    }
}

#[cfg(test)]
mod tests {
    use super::{script_tests, with_suffix};
    use std::path::Path;

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
