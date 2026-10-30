//! Fixtures shared by the release-glz integration tests.
//!
//! A helper that cannot do what it names panics with the reason, so a missing tool or a failed command fails the test instead of letting it pass.

use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Output};

pub mod oidc;
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

/// Read what `reader` has into `buffer` and return the count, retrying a read that a signal interrupted.
///
/// A single `read` reports `ErrorKind::Interrupted` instead of retrying, so a test server that unwraps it fails for a reason outside the code under test.
///
/// # Panics
///
/// When the read fails for any other reason.
pub fn read_some(reader: &mut impl std::io::Read, buffer: &mut [u8]) -> usize {
    loop {
        match reader.read(buffer) {
            Ok(count) => return count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => panic!("read failed: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::read_some;
    use std::io::{self, Read};

    /// Fails its first read with `error`, then serves `data`.
    struct FailsFirst {
        error: Option<io::ErrorKind>,
        data: &'static [u8],
    }

    impl Read for FailsFirst {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if let Some(error) = self.error.take() {
                return Err(error.into());
            }
            self.data.read(buffer)
        }
    }

    #[test]
    fn a_read_that_a_signal_interrupts_is_retried() {
        let mut reader = FailsFirst {
            error: Some(io::ErrorKind::Interrupted),
            data: b"request",
        };
        let mut buffer = [0_u8; 16];
        assert_eq!(read_some(&mut reader, &mut buffer), 7);
        assert_eq!(&buffer[..7], b"request");
    }

    #[test]
    #[should_panic(expected = "read failed")]
    fn any_other_read_error_still_fails_the_test() {
        let mut reader = FailsFirst {
            error: Some(io::ErrorKind::ConnectionReset),
            data: b"request",
        };
        read_some(&mut reader, &mut [0_u8; 16]);
    }
}
