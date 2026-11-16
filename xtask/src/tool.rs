//! The child processes of the repository checks, each a tool that the pinned `mise` environment puts on `PATH`.

use crate::container::Failure;
use std::path::Path;
use std::process::{Command, Stdio};

/// npm as Windows runs it, by its `.cmd` name.
const NPM: &str = if cfg!(windows) { "npm.cmd" } else { "npm" };

/// The variables a Git hook sets for its own repository, which a child must not inherit.
///
/// A hook exports `GIT_DIR` and `GIT_INDEX_FILE`, and a test that creates a repository of its own would otherwise write into this one.
const REPOSITORY_VARIABLES: [&str; 15] = [
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_OBJECT_DIRECTORY",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_PREFIX",
    "GIT_SHALLOW_FILE",
    "GIT_COMMON_DIR",
];

/// A tool that a check runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tool {
    Cargo,
    Rustfmt,
    Taplo,
    Typos,
    Actionlint,
    Zizmor,
    Git,
    Node,
    Npm,
    Jq,
    Dotfiles,
    /// Docker, which hosts the pinned verification images with the bounded runner's limits.
    Docker,
}

#[expect(
    clippy::disallowed_methods,
    reason = "the process owner constructs each command in one place, from a tool that names its program"
)]
fn new_command(program: &str) -> Command {
    Command::new(program)
}

impl Tool {
    const fn program(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Rustfmt => "rustfmt",
            Self::Taplo => "taplo",
            Self::Typos => "typos",
            Self::Actionlint => "actionlint",
            Self::Zizmor => "zizmor",
            Self::Git => "git",
            Self::Node => "node",
            Self::Npm => NPM,
            Self::Jq => "jq",
            Self::Dotfiles => "dotfiles",
            Self::Docker => "docker",
        }
    }

    /// A command for the tool, run from `root` without the invoking hook's repository context.
    #[must_use]
    pub fn command(self, root: &Path) -> Command {
        let mut command = self.anywhere();
        command.current_dir(root);
        command
    }

    /// A command for the tool, run from the current directory without the invoking hook's repository context.
    #[must_use]
    pub fn anywhere(self) -> Command {
        let mut command = new_command(self.program());
        for name in REPOSITORY_VARIABLES {
            command.env_remove(name);
        }
        command
    }
}

/// Runs a command with inherited streams and requires success.
///
/// # Errors
///
/// Returns a failure naming `what` when the command can't start or exits unsuccessfully.
pub fn succeed(command: &mut Command, what: &str) -> Result<(), Failure> {
    let status = command
        .status()
        .map_err(|error| Failure::new(format!("{what} didn't start: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure::new(format!("{what} failed with {status}")))
    }
}

/// The standard output of a command that must succeed.
///
/// # Errors
///
/// Returns a failure naming `what` when the command can't start, exits unsuccessfully, or prints output that isn't UTF-8.
pub fn capture(command: &mut Command, what: &str) -> Result<String, Failure> {
    let output = command
        .stdin(Stdio::null())
        .output()
        .map_err(|error| Failure::new(format!("{what} didn't start: {error}")))?;
    if !output.status.success() {
        return Err(Failure::new(format!(
            "{what} failed with {}:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| Failure::new(format!("{what} printed invalid UTF-8: {error}")))
}

#[cfg(test)]
mod tests {
    use super::{Tool, capture, succeed};
    use std::path::Path;

    #[test]
    fn a_child_inherits_no_repository_context_from_a_hook() {
        let command = Tool::Git.command(Path::new("."));
        let removed = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(removed.iter().any(|name| name == "GIT_DIR"));
        assert!(removed.iter().any(|name| name == "GIT_INDEX_FILE"));
    }

    #[test]
    fn a_failing_or_missing_tool_names_the_step() {
        let failure = succeed(
            Tool::Git.command(Path::new(".")).arg("no-such-subcommand"),
            "git no-such-subcommand",
        )
        .unwrap_err();
        assert!(
            failure
                .to_string()
                .starts_with("git no-such-subcommand failed with")
        );
        let missing = capture(
            &mut super::new_command("release-glz-no-such-tool"),
            "the missing tool",
        )
        .unwrap_err();
        assert!(
            missing
                .to_string()
                .starts_with("the missing tool didn't start")
        );
    }
}
