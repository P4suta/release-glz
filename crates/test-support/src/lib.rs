//! Fixtures shared by the release-glz integration tests.
//!
//! A helper that cannot do what it names panics with the reason, so a missing tool or a failed command fails the test instead of letting it pass.

use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Output};

pub mod oidc;

/// The only environment variables a spawned binary under test inherits.
///
/// Everything else is withheld, so a developer's GitHub or registry token never reaches a test run.
/// The isolated Git configuration, the temporary directory, coverage instrumentation, and the platform's executable search still pass through.
const INHERITED_ENVIRONMENT: [&str; 12] = [
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
    "TMPDIR",
    "TMP",
    "TEMP",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_TERMINAL_PROMPT",
    "LLVM_PROFILE_FILE",
    "RUST_BACKTRACE",
];

/// A command whose environment holds only the variables a test may inherit.
///
/// Add what a test needs with [`Command::env`].
pub fn isolated_command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    for name in INHERITED_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

/// Panic with the command's output unless it exited successfully.
pub fn assert_success(output: &Output, description: &str) {
    assert!(
        output.status.success(),
        "{description} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Run `git` in `directory` and return its standard output.
///
/// # Panics
///
/// When git cannot start or exits unsuccessfully.
pub fn git(directory: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("git {arguments:?} could not start: {error}"));
    assert_success(&output, &format!("git {arguments:?}"));
    String::from_utf8(output.stdout)
        .unwrap_or_else(|error| panic!("git {arguments:?} printed non-UTF-8 output: {error}"))
}

/// Create a repository whose first branch is `main`.
pub fn init_repository(directory: &Path) {
    git(directory, &["init", "--initial-branch=main"]);
}

/// The installed Gleam version, for tests that build real packages.
///
/// # Panics
///
/// When `gleam` is missing or reports no version, because a test that needs the compiler must fail rather than pass without running.
pub fn require_gleam() -> String {
    let output = Command::new("gleam")
        .arg("--version")
        .output()
        .unwrap_or_else(|error| {
            panic!("this test needs Gleam on PATH; install the pinned version with `mise install`: {error}")
        });
    assert_success(&output, "gleam --version");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .find(|word| word.starts_with(|first: char| first.is_ascii_digit()))
        .map(str::to_owned)
        .unwrap_or_else(|| panic!("gleam --version reported no version"))
}
