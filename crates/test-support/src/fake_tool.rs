//! A stand-in for the Gleam compiler and for hook programs that runs the same way on every OS.
//!
//! [`install`] copies the fake under a command name and writes its [`Behavior`] beside the copy, where the fake reads it.
//! The behavior lives in a file rather than in the environment, because release-glz runs the compiler and each hook with a scrubbed environment.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::{fail, new_command, path_searching_first};

/// The binary target of the fake, which the test support builds once in each test process.
pub const BINARY: &str = "release-glz-fake-tool";

/// The exit code of a fake whose rules all fail to match, which is `EX_USAGE` in `sysexits.h`.
pub const UNMATCHED_EXIT: u8 = 64;

/// The exit code of a fake that can't do what its behavior says, which is `EX_SOFTWARE` in `sysexits.h`.
pub const FAILED_EXIT: u8 = 70;

/// The suffix that turns the stem of an installed copy into the name of its behavior file.
const BEHAVIOR_SUFFIX: &str = ".behavior.json";

/// The variables that add compiler flags or wrap the compiler, which the build of the fake drops.
///
/// A hook runs with an empty environment, so an instrumented fake would write its coverage profile into the snapshot under test.
const COMPILER_CHANGING_VARIABLES: [&str; 7] = [
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
];

/// What one installed copy of the fake does each time it runs.
///
/// The fake runs the actions of the first rule whose conditions all hold, and exits with [`UNMATCHED_EXIT`] when no rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Behavior {
    /// The rules in the order the fake tries them.
    pub rules: Vec<Rule>,
}

impl Behavior {
    /// A fake that runs `actions` whatever its arguments, input, and environment.
    #[must_use]
    pub fn always(actions: Vec<Action>) -> Self {
        Self {
            rules: vec![Rule::always(actions)],
        }
    }

    /// A compiler that prints `gleam {version}` on every run.
    #[must_use]
    pub fn reporting_version(version: &str) -> Self {
        Self::always(vec![Action::Stdout(format!("gleam {version}\n"))])
    }
}

/// Actions that run when every condition holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// The conditions, where no condition matches every run.
    pub when: Vec<Condition>,
    /// The actions in the order the fake runs them.
    pub actions: Vec<Action>,
}

impl Rule {
    /// A rule that matches every run.
    #[must_use]
    pub const fn always(actions: Vec<Action>) -> Self {
        Self {
            when: Vec::new(),
            actions,
        }
    }
}

/// A fact about one run of the fake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    /// The arguments begin with these.
    ArgumentsStartWith(Vec<String>),
    /// The standard input, read to its end, contains this text.
    InputContains(String),
    /// The environment holds a variable with this name.
    EnvironmentHas(String),
    /// The environment holds no variable with this name.
    EnvironmentLacks(String),
    /// A file exists at this path, which is relative to the working directory.
    FileExists(PathBuf),
}

/// One step of what the fake does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Write this text to standard output.
    Stdout(String),
    /// Write this text to standard error.
    Stderr(String),
    /// Write this many zero bytes to a stream.
    Zeros {
        /// The stream that receives the bytes.
        stream: Stream,
        /// The number of bytes.
        count: usize,
    },
    /// Write the environment to this file as one JSON object from each name to its value.
    RecordEnvironment(PathBuf),
    /// Append the arguments to this file as one line, separated by spaces.
    RecordArguments(PathBuf),
    /// Copy a file.
    Copy {
        /// The file to copy.
        from: PathBuf,
        /// Where the copy goes.
        to: Destination,
    },
    /// Write text to a file at this path, which is relative to the working directory.
    Write {
        /// The file to write.
        path: PathBuf,
        /// Its whole new text.
        contents: String,
    },
    /// Start a program that inherits standard output and standard error, write its process id to a file, and leave it running.
    SpawnHoldingPipes {
        /// The program to start.
        program: PathBuf,
        /// The file that receives its process id.
        pid_file: PathBuf,
    },
    /// Keep running for this many seconds.
    Sleep(u64),
    /// Exit with this code without running the actions that follow.
    Exit(u8),
}

/// A standard stream that the fake writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Where a copied file goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Destination {
    /// This path, which is relative to the working directory, in a directory that the fake creates when it is missing.
    Path(PathBuf),
    /// The path that follows `--out` among the arguments, as the compiler's exports name it.
    OutArgument,
}

/// The behavior file of the installed copy at `executable`, beside the copy under its stem.
#[must_use]
pub fn behavior_file(executable: &Path) -> Option<PathBuf> {
    let mut name = executable.file_stem()?.to_os_string();
    name.push(BEHAVIOR_SUFFIX);
    Some(executable.with_file_name(name))
}

/// Copy the fake into `directory` as `command`, with the platform's executable suffix, and give the copy `behavior`.
///
/// The returned path is the copy, which a hook names as the first element of its argv.
///
/// # Panics
///
/// When `command` holds a dot, which would end the stem that names the behavior file, or when the fake can't be built or copied, or its behavior can't be written.
#[must_use]
pub fn install(directory: &Path, command: &str, behavior: &Behavior) -> PathBuf {
    place(directory, command, behavior, built())
}

/// Install the fake in `directory` as `gleam`, and return a `PATH` that finds it first.
///
/// # Panics
///
/// When [`install`] does, or when `directory` can't lead a `PATH`.
#[must_use]
pub fn gleam_on_path(directory: &Path, behavior: &Behavior) -> OsString {
    place(directory, "gleam", behavior, built());
    path_searching_first(directory)
}

#[expect(
    clippy::disallowed_methods,
    reason = "the test support owns the copies it installs and names each path in its failure"
)]
fn place(directory: &Path, command: &str, behavior: &Behavior, source: &Path) -> PathBuf {
    if command.contains('.') {
        fail(format_args!(
            "`{command}` holds a dot, so its stem would not name its behavior file"
        ));
    }
    let executable = directory.join(format!("{command}{}", std::env::consts::EXE_SUFFIX));
    let behavior_path = behavior_file(&executable)
        .unwrap_or_else(|| fail(format_args!("`{command}` names no file")));
    let behavior = serde_json::to_vec(behavior)
        .unwrap_or_else(|error| fail(format_args!("the behavior of `{command}`: {error}")));
    std::fs::create_dir_all(directory).unwrap_or_else(|error| {
        fail(format_args!(
            "`{}` can't be created: {error}",
            directory.display()
        ))
    });
    let lock = build_lock();
    lock.lock_shared().unwrap_or_else(|error| {
        fail(format_args!(
            "the fake's build lock can't be shared: {error}"
        ))
    });
    std::fs::copy(source, &executable).unwrap_or_else(|error| {
        fail(format_args!(
            "`{}` can't be copied to `{}`: {error}",
            source.display(),
            executable.display()
        ))
    });
    drop(lock);
    std::fs::write(&behavior_path, behavior).unwrap_or_else(|error| {
        fail(format_args!(
            "`{}` can't be written: {error}",
            behavior_path.display()
        ))
    });
    executable
}

/// The fake that this test process built.
fn built() -> &'static Path {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(build)
}

/// Build the fake with the Cargo that runs the tests and the workspace's locked dependencies.
///
/// The build has a target directory of its own, so it never waits for the lock that the running test build holds.
fn build() -> PathBuf {
    let cargo = std::env::var_os("CARGO")
        .or_else(|| option_env!("CARGO").map(OsString::from))
        .unwrap_or_else(|| {
            fail(format_args!(
                "no `CARGO` names the Cargo that builds {BINARY}"
            ))
        });
    let workspace = workspace();
    let mut command = new_command(cargo);
    command
        .current_dir(workspace)
        .args([
            "build",
            "--locked",
            "--message-format=json-render-diagnostics",
            "--package",
            env!("CARGO_PKG_NAME"),
            "--bin",
            BINARY,
            "--target-dir",
        ])
        .arg(target_directory(workspace));
    for name in COMPILER_CHANGING_VARIABLES {
        command.env_remove(name);
    }
    for (name, _) in std::env::vars_os() {
        let changes_flags = name.to_str().is_some_and(|name| {
            (name.starts_with("CARGO_TARGET_") && name.ends_with("_RUSTFLAGS"))
                || name.starts_with("__CARGO_LLVM_COV")
        });
        if changes_flags {
            command.env_remove(name);
        }
    }
    // Cargo replaces the executable on every build, so a copy in another test process waits until the build ends.
    let lock = build_lock();
    lock.lock().unwrap_or_else(|error| {
        fail(format_args!(
            "the fake's build lock can't be taken: {error}"
        ))
    });
    let output = command.output().unwrap_or_else(|error| {
        fail(format_args!(
            "cargo build of {BINARY} didn't start: {error}"
        ))
    });
    drop(lock);
    if !output.status.success() {
        fail(format_args!(
            "cargo build of {BINARY} failed with {}:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    announced_executable(&output.stdout)
}

/// The executable that Cargo's JSON messages name for the fake's binary target.
fn announced_executable(messages: &[u8]) -> PathBuf {
    String::from_utf8_lossy(messages)
        .lines()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line).unwrap_or_else(|error| {
                fail(format_args!(
                    "cargo build of {BINARY} printed a line that isn't JSON ({error}): {line}"
                ))
            })
        })
        .find_map(|message| {
            let field = |name: &str| message.get(name);
            let artifact = field("reason").and_then(serde_json::Value::as_str)
                == Some("compiler-artifact")
                && field("target")
                    .and_then(|target| target.get("name"))
                    .and_then(serde_json::Value::as_str)
                    == Some(BINARY);
            artifact
                .then(|| field("executable").and_then(serde_json::Value::as_str))
                .flatten()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| {
            fail(format_args!(
                "cargo build of {BINARY} named no executable:\n{}",
                String::from_utf8_lossy(messages)
            ))
        })
}

/// The workspace root, named without `..`, which keeps the deepest build outputs under the 260 characters that the Windows linker opens.
fn workspace() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap_or_else(|| {
            fail(format_args!(
                "{} lies outside `crates/` of a workspace",
                env!("CARGO_MANIFEST_DIR")
            ))
        })
}

/// The lock file that each build of the fake holds alone and each copy of it shares, across test processes.
#[expect(
    clippy::disallowed_methods,
    reason = "the test support owns the fake's build directory and names the lock file in its failure"
)]
fn build_lock() -> File {
    let directory = target_directory(workspace());
    std::fs::create_dir_all(&directory).unwrap_or_else(|error| {
        fail(format_args!(
            "`{}` can't be created: {error}",
            directory.display()
        ))
    });
    let path = directory.join("build.lock");
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .unwrap_or_else(|error| {
            fail(format_args!(
                "`{}` can't be opened: {error}",
                path.display()
            ))
        })
}

/// The directory that the fake builds into, beside the targets of the test build.
fn target_directory(workspace: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| workspace.join("target"), PathBuf::from)
        .join("fake-tool")
}

#[cfg(test)]
mod tests {
    use super::{Behavior, behavior_file, build, place};
    use std::path::{Path, PathBuf};

    /// Builders and copiers run at once, as separate test processes do, and Cargo replaces the executable on each build.
    ///
    /// The scope joins every thread and fails the test when one of them panics.
    #[test]
    fn concurrent_builds_and_copies_of_the_fake_never_meet() {
        let directory = tempfile::tempdir().unwrap();
        let built = build();
        std::thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(|| {
                    for _ in 0..10 {
                        assert_eq!(build(), built);
                    }
                });
            }
            for copier in 0..6 {
                let tools = directory.path().join(format!("tools-{copier}"));
                let built = &built;
                scope.spawn(move || {
                    for _ in 0..40 {
                        let executable =
                            place(&tools, "gleam", &Behavior { rules: Vec::new() }, built);
                        assert!(
                            std::fs::metadata(&executable).unwrap().is_file(),
                            "{}",
                            executable.display()
                        );
                    }
                });
            }
        });
    }

    #[test]
    fn a_copy_with_or_without_the_windows_suffix_reads_the_same_behavior_file() {
        let expected = Some(PathBuf::from("tools").join("gleam.behavior.json"));
        assert_eq!(behavior_file(&Path::new("tools").join("gleam")), expected);
        assert_eq!(
            behavior_file(&Path::new("tools").join("gleam.exe")),
            expected
        );
    }
}
