//! Pinned verification images run with the same resource limits on every machine.

use crate::tool::Tool;
use std::fmt;
use std::path::Path;

/// Every proof image runs on this platform, so a verdict doesn't depend on the host's architecture.
const PLATFORM: &str = "linux/amd64";
const MEMORY: &str = "2048m";
const CPUS: &str = "2";
const PROCESSES: &str = "256";
/// The seconds a single command may run before it counts as inconclusive.
const SECONDS: &str = "900";
/// The exit status of `timeout` when the command ran out of time.
const TIMED_OUT: i32 = 124;
/// The hexadecimal length of a SHA-256 image digest.
const DIGEST_HEX: usize = 64;

/// Why a verification step refused or couldn't finish.
#[derive(Debug)]
pub struct Failure(String);

impl Failure {
    /// A failure with `message`.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// A failure to read or write local evidence.
    #[must_use]
    pub fn io(error: &std::io::Error) -> Self {
        Self(format!("evidence I/O failed: {error}"))
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// What a command in the container printed and how it ended.
#[derive(Debug)]
pub struct Exit {
    /// The exit status, or `None` when a signal ended it.
    pub code: Option<i32>,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

/// The directories a command sees and whether it may reach the network.
#[derive(Debug)]
pub struct Mounts<'a> {
    /// Mounted read-only at `/workspace`, which is also the working directory.
    pub workspace: &'a Path,
    /// Mounted writable at `/evidence`.
    pub evidence: &'a Path,
    /// Whether the command may reach the network.
    pub network: bool,
}

/// An image that Docker built from a pinned Dockerfile, named by its content digest.
#[derive(Debug)]
pub struct Container {
    image: String,
}

/// A container together with the directories that its commands see.
#[derive(Debug, Clone, Copy)]
pub struct Mounted<'a> {
    pub container: &'a Container,
    pub mounts: &'a Mounts<'a>,
}

impl Container {
    /// Build `dockerfile` from the repository at `root`, and keep the image's digest in this run's `evidence`.
    ///
    /// # Errors
    ///
    /// Returns a failure when Docker can't start or fails the build.
    /// Returns a failure when the image identity can't be read or isn't a SHA-256 digest.
    pub fn build(root: &Path, evidence: &Path, dockerfile: &str) -> Result<Self, Failure> {
        let identity = evidence.join("image-id");
        let status = Tool::Docker
            .command(root)
            .args([
                "build",
                "--quiet",
                "--platform",
                PLATFORM,
                "--file",
                dockerfile,
            ])
            .arg("--iidfile")
            .arg(&identity)
            .arg("verification")
            .status()
            .map_err(|error| Failure::new(format!("Docker could not start: {error}")))?;
        if !status.success() {
            return Err(Failure::new(format!(
                "the image build failed with {status}"
            )));
        }
        let image = crate::fs::read_to_string(&identity)?;
        let image = image.trim().to_owned();
        let digest = image.strip_prefix("sha256:").unwrap_or_default();
        if digest.len() != DIGEST_HEX || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Failure::new(format!(
                "Docker returned no immutable image identity: {image}"
            )));
        }
        Ok(Self { image })
    }

    /// The digest of the image.
    #[must_use]
    pub fn image(&self) -> &str {
        &self.image
    }

    /// Run `command` with the bounded runner's limits, and report how it ended.
    ///
    /// A command that runs out of time is inconclusive, so it is a failure rather than an exit to judge.
    ///
    /// # Errors
    ///
    /// Returns a failure when Docker can't start or the command reaches its time limit.
    pub fn run(
        &self,
        mounts: &Mounts<'_>,
        environment: &[(&str, &str)],
        command: &[&str],
    ) -> Result<Exit, Failure> {
        let mut docker = Tool::Docker.anywhere();
        docker.args([
            "run",
            "--rm",
            // An init process reaps the preprocessors that Kani orphans for every harness, which would otherwise fill the process limit.
            "--init",
            "--platform",
            PLATFORM,
            "--memory",
            MEMORY,
            "--memory-swap",
            MEMORY,
            "--cpus",
            CPUS,
            "--pids-limit",
            PROCESSES,
            "--workdir",
            "/workspace",
        ]);
        if !mounts.network {
            docker.args(["--network", "none"]);
        }
        for (name, value) in environment {
            docker.arg("--env").arg(format!("{name}={value}"));
        }
        let output = docker
            .arg("--volume")
            .arg(format!("{}:/workspace:ro", mounts.workspace.display()))
            .arg("--volume")
            .arg(format!("{}:/evidence", mounts.evidence.display()))
            .args([&self.image, "timeout", SECONDS])
            .args(command)
            .output()
            .map_err(|error| Failure::new(format!("Docker could not start: {error}")))?;
        if output.status.code() == Some(TIMED_OUT) {
            return Err(Failure::new(format!(
                "`{}` reached its {SECONDS} second limit, so the check is inconclusive",
                command.join(" ")
            )));
        }
        Ok(Exit {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    /// Run `command` without the network and return its standard output, or fail unless it exits with status 0.
    ///
    /// # Errors
    ///
    /// Returns a failure when the command can't run, reaches its time limit, or exits with another status.
    pub fn output(
        &self,
        workspace: &Path,
        evidence: &Path,
        command: &[&str],
    ) -> Result<String, Failure> {
        let mounts = Mounts {
            workspace,
            evidence,
            network: false,
        };
        let exit = self.run(&mounts, &[], command)?;
        match exit.code {
            Some(0) => Ok(exit.stdout),
            code => Err(Failure::new(format!(
                "`{}` failed with exit status {code:?}:\n{}{}",
                command.join(" "),
                exit.stdout,
                exit.stderr
            ))),
        }
    }
}
