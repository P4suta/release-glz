//! Fixtures shared by the release-glz integration tests.
//!
//! A helper that cannot do what it names panics with the reason, so a missing tool or a failed command fails the test instead of letting it pass.

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::{Command, Output};

pub mod fake_tool;
pub mod fs;
pub mod http;
pub mod oidc;
pub mod property;
pub mod schema;

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

/// Ends the calling test with `message`.
#[expect(
    clippy::panic,
    reason = "a test helper fails the test that called it when its tool, fixture, or assertion fails"
)]
#[track_caller]
fn fail(message: std::fmt::Arguments<'_>) -> ! {
    panic!("{message}")
}

/// A command that inherits the whole environment, for a test whose child needs what [`isolated_command`] withholds.
#[expect(
    clippy::disallowed_methods,
    reason = "the test support starts every child in this one place, from a program that its caller names"
)]
pub fn new_command(program: impl AsRef<OsStr>) -> Command {
    Command::new(program)
}

/// A command whose environment holds only the variables a test may inherit.
///
/// Add what a test needs with [`Command::env`].
pub fn isolated_command(program: impl AsRef<OsStr>) -> Command {
    let mut command = new_command(program);
    command.env_clear();
    for name in INHERITED_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

/// A `PATH` that searches `directory` before every directory of the inherited `PATH`.
///
/// A test that writes a fake `gleam` into `directory` passes this as the binary's `PATH`, so release-glz runs the fake.
///
/// # Panics
///
/// When `directory` contains the platform's `PATH` separator.
#[must_use]
pub fn path_searching_first(directory: &Path) -> OsString {
    let inherited = std::env::var_os("PATH");
    let directories = std::iter::once(directory.to_path_buf())
        .chain(inherited.iter().flat_map(std::env::split_paths));
    std::env::join_paths(directories).unwrap_or_else(|error| {
        fail(format_args!(
            "`{}` can't lead a PATH: {error}",
            directory.display()
        ))
    })
}

/// Panic with the command's output unless it exited successfully.
///
/// # Panics
///
/// When the command exited unsuccessfully.
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
#[expect(
    clippy::must_use_candidate,
    reason = "most callers run Git for its effect on the repository and leave its output unread"
)]
pub fn git(directory: &Path, arguments: &[&str]) -> String {
    let output = new_command("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| fail(format_args!("git {arguments:?} could not start: {error}")));
    assert_success(&output, &format!("git {arguments:?}"));
    String::from_utf8(output.stdout).unwrap_or_else(|error| {
        fail(format_args!(
            "git {arguments:?} printed non-UTF-8 output: {error}"
        ))
    })
}

/// Create a repository whose first branch is `main`.
pub fn init_repository(directory: &Path) {
    git(directory, &["init", "--initial-branch=main"]);
}

/// Bytes of the name field that opens every tar header block.
const TAR_NAME_BYTES: usize = 100;

/// Write `name` into the name field of the tar header block `header`, as the `tar` crate writes a short name on Unix, without its check that the name is a relative path on this OS.
///
/// A test that writes a name some OS can't represent then builds the same archive on every OS.
/// Refresh the header's checksum afterward.
///
/// # Panics
///
/// When `name` is longer than the field or holds a NUL byte.
pub fn write_tar_name(header: &mut [u8; 512], name: &[u8]) {
    if name.len() > TAR_NAME_BYTES || name.contains(&0) {
        fail(format_args!(
            "{:?} doesn't fit the {TAR_NAME_BYTES}-byte name field of a tar header",
            String::from_utf8_lossy(name)
        ));
    }
    let padded = name.iter().copied().chain(std::iter::repeat(0));
    for (slot, byte) in header.iter_mut().take(TAR_NAME_BYTES).zip(padded) {
        *slot = byte;
    }
}

/// The installed Gleam version, for tests that build real packages.
///
/// # Panics
///
/// When `gleam` is missing or reports no version, because a test that needs the compiler must fail rather than pass without running.
pub fn require_gleam() -> String {
    let output = new_command("gleam")
        .arg("--version")
        .output()
        .unwrap_or_else(|error| {
            fail(format_args!(
                "this test needs Gleam on PATH; install the pinned version with `mise install`: {error}"
            ))
        });
    assert_success(&output, "gleam --version");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .find(|word| word.starts_with(|first: char| first.is_ascii_digit()))
        .map_or_else(
            || fail(format_args!("gleam --version reported no version")),
            str::to_owned,
        )
}

#[cfg(test)]
mod tests {
    use super::path_searching_first;
    use std::path::{Path, PathBuf};

    #[test]
    fn the_directory_comes_before_the_whole_inherited_path() {
        let directory = Path::new("fake-compiler");
        let searched: Vec<PathBuf> =
            std::env::split_paths(&path_searching_first(directory)).collect();
        let inherited: Vec<PathBuf> = std::env::var_os("PATH")
            .iter()
            .flat_map(std::env::split_paths)
            .collect();
        assert_eq!(searched.first().map(PathBuf::as_path), Some(directory));
        assert_eq!(searched.get(1..), Some(inherited.as_slice()));
    }
}
