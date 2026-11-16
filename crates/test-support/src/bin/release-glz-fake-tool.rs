//! The fake compiler and hook program that `release_glz_test_support::fake_tool` installs.
//!
//! It reads its behavior from the file beside its own executable, so it needs nothing from the environment that release-glz scrubs.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::Duration;

use release_glz_test_support::fake_tool::{
    Action, BINARY, Behavior, Condition, Destination, FAILED_EXIT, Stream, UNMATCHED_EXIT,
    behavior_file,
};

fn main() -> ExitCode {
    match play() {
        Ok(code) => ExitCode::from(code),
        Err(failure) => {
            eprintln!("{BINARY}: {failure}");
            ExitCode::from(FAILED_EXIT)
        }
    }
}

/// Run the actions of the first rule that matches, and return the exit code.
fn play() -> Result<u8, String> {
    let behavior = behavior()?;
    let mut run = Run {
        arguments: std::env::args_os()
            .skip(1)
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect(),
        input: None,
    };
    for rule in &behavior.rules {
        if run.matches(&rule.when)? {
            return run.act(&rule.actions);
        }
    }
    Ok(UNMATCHED_EXIT)
}

/// The behavior in the file beside this executable.
fn behavior() -> Result<Behavior, String> {
    let executable =
        std::env::current_exe().map_err(|error| format!("its own path is unknown: {error}"))?;
    let file = behavior_file(&executable)
        .ok_or_else(|| format!("`{}` has no file name", executable.display()))?;
    serde_json::from_slice(&read(&file)?)
        .map_err(|error| format!("`{}` holds no behavior: {error}", file.display()))
}

/// One run of the fake.
struct Run {
    arguments: Vec<String>,
    /// The standard input, once a condition has read it.
    input: Option<String>,
}

impl Run {
    fn matches(&mut self, conditions: &[Condition]) -> Result<bool, String> {
        for condition in conditions {
            if !self.holds(condition)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn holds(&mut self, condition: &Condition) -> Result<bool, String> {
        Ok(match condition {
            Condition::ArgumentsStartWith(prefix) => self.arguments.starts_with(prefix),
            Condition::InputContains(text) => self.input()?.contains(text.as_str()),
            Condition::EnvironmentHas(name) => std::env::var_os(name).is_some(),
            Condition::EnvironmentLacks(name) => std::env::var_os(name).is_none(),
            Condition::FileExists(path) => exists(path)?,
        })
    }

    /// The standard input, read to its end on first use, because a program that never reads it must not.
    fn input(&mut self) -> Result<&str, String> {
        if self.input.is_none() {
            let mut bytes = Vec::new();
            std::io::stdin()
                .read_to_end(&mut bytes)
                .map_err(|error| format!("standard input is unreadable: {error}"))?;
            self.input = Some(String::from_utf8_lossy(&bytes).into_owned());
        }
        Ok(self.input.as_deref().unwrap_or_default())
    }

    fn act(&self, actions: &[Action]) -> Result<u8, String> {
        for action in actions {
            match action {
                Action::Stdout(text) => emit(Stream::Stdout, text.as_bytes())?,
                Action::Stderr(text) => emit(Stream::Stderr, text.as_bytes())?,
                Action::Zeros { stream, count } => emit(*stream, &vec![0; *count])?,
                Action::RecordEnvironment(path) => {
                    let environment: BTreeMap<String, String> = std::env::vars_os()
                        .map(|(name, value)| {
                            (
                                name.to_string_lossy().into_owned(),
                                value.to_string_lossy().into_owned(),
                            )
                        })
                        .collect();
                    let json = serde_json::to_vec(&environment)
                        .map_err(|error| format!("the environment isn't JSON: {error}"))?;
                    write(path, &json)?;
                }
                Action::RecordArguments(path) => {
                    append(path, format!("{}\n", self.arguments.join(" ")).as_bytes())?;
                }
                Action::Copy { from, to } => copy(from, &self.destination(to)?)?,
                Action::Write { path, contents } => write(path, contents.as_bytes())?,
                Action::SpawnHoldingPipes { program, pid_file } => {
                    let id = spawn_holding_pipes(program)?;
                    write(pid_file, id.to_string().as_bytes())?;
                }
                Action::Sleep(seconds) => sleep(*seconds),
                Action::Exit(code) => return Ok(*code),
            }
        }
        Ok(0)
    }

    fn destination(&self, to: &Destination) -> Result<PathBuf, String> {
        match to {
            Destination::Path(path) => Ok(path.clone()),
            Destination::OutArgument => self
                .arguments
                .iter()
                .skip_while(|argument| *argument != "--out")
                .nth(1)
                .map(PathBuf::from)
                .ok_or_else(|| format!("no path follows `--out` in {:?}", self.arguments)),
        }
    }
}

fn emit(stream: Stream, bytes: &[u8]) -> Result<(), String> {
    let written = match stream {
        Stream::Stdout => std::io::stdout()
            .write_all(bytes)
            .and_then(|()| std::io::stdout().flush()),
        Stream::Stderr => std::io::stderr().write_all(bytes),
    };
    written.map_err(|error| format!("writing to {stream:?} failed: {error}"))
}

fn exists(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("`{}` can't be inspected: {error}", path.display())),
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "the fake reads only its behavior file, and names it in the failure"
)]
fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| format!("`{}` is unreadable: {error}", path.display()))
}

#[expect(
    clippy::disallowed_methods,
    reason = "the fake writes the files its behavior names, and names each in its failure"
)]
fn write(path: &Path, contents: &[u8]) -> Result<(), String> {
    std::fs::write(path, contents)
        .map_err(|error| format!("`{}` can't be written: {error}", path.display()))
}

#[expect(
    clippy::disallowed_methods,
    reason = "the fake appends to the log its behavior names, and names it in the failure"
)]
fn append(path: &Path, contents: &[u8]) -> Result<(), String> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| file.write_all(contents))
        .map_err(|error| format!("`{}` can't be appended to: {error}", path.display()))
}

#[expect(
    clippy::disallowed_methods,
    reason = "the fake copies the fixtures its behavior names, and names both paths in its failure"
)]
fn copy(from: &Path, to: &Path) -> Result<(), String> {
    if let Some(parent) = to.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("`{}` can't be created: {error}", parent.display()))?;
    }
    std::fs::copy(from, to).map_err(|error| {
        format!(
            "`{}` can't be copied to `{}`: {error}",
            from.display(),
            to.display()
        )
    })?;
    Ok(())
}

#[expect(
    clippy::disallowed_methods,
    reason = "the fake starts the one program its behavior names, as a process that outlives it"
)]
fn spawn_holding_pipes(program: &Path) -> Result<u32, String> {
    let child = std::process::Command::new(program)
        .stdin(Stdio::null())
        .spawn()
        .map_err(|error| format!("`{}` didn't start: {error}", program.display()))?;
    Ok(child.id())
}

#[expect(
    clippy::disallowed_methods,
    reason = "a fake that stands in for a slow program runs exactly as long as its behavior says"
)]
fn sleep(seconds: u64) {
    std::thread::sleep(Duration::from_secs(seconds));
}
