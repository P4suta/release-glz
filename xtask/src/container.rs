//! Pinned verification images run with the same resource limits on every machine.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub fn io(error: std::io::Error) -> Self {
        Self(format!("evidence I/O failed: {error}"))
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A new directory under `target/assurance` for the evidence of one `kind` of run.
pub fn evidence_directory(root: &Path, kind: &str) -> Result<PathBuf, Failure> {
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Failure::new(error.to_string()))?
        .as_nanos();
    let directory = root
        .join("target")
        .join("assurance")
        .join(format!("{kind}-{started}-{}", std::process::id()));
    std::fs::create_dir_all(&directory).map_err(Failure::io)?;
    Ok(directory)
}

/// An image that Docker built from a pinned Dockerfile, named by its content digest.
pub struct Container {
    image: String,
    root: PathBuf,
}

impl Container {
    /// Build `dockerfile` from the repository at `root`, and keep the image's digest in this run's `evidence`.
    pub fn build(root: &Path, evidence: &Path, dockerfile: &str) -> Result<Self, Failure> {
        let identity = evidence.join("image-id");
        let status = Command::new("docker")
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
            .current_dir(root)
            .status()
            .map_err(|error| Failure::new(format!("Docker could not start: {error}")))?;
        if !status.success() {
            return Err(Failure::new(format!(
                "the image build failed with {status}"
            )));
        }
        let image = std::fs::read_to_string(&identity).map_err(Failure::io)?;
        let image = image.trim().to_owned();
        let digest = image.strip_prefix("sha256:").unwrap_or_default();
        if digest.len() != DIGEST_HEX || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Failure::new(format!(
                "Docker returned no immutable image identity: {image}"
            )));
        }
        Ok(Self {
            image,
            root: root.to_owned(),
        })
    }

    /// Run `command` with the repository mounted read-only at `/workspace` and `evidence` writable at `/evidence`, and return its standard output.
    pub fn output(&self, evidence: &Path, command: &[&str]) -> Result<String, Failure> {
        let output = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--platform",
                PLATFORM,
                "--network",
                "none",
                "--memory",
                MEMORY,
                "--memory-swap",
                MEMORY,
                "--cpus",
                CPUS,
                "--pids-limit",
                PROCESSES,
                "--volume",
            ])
            .arg(format!("{}:/workspace:ro", self.root.display()))
            .arg("--volume")
            .arg(format!("{}:/evidence", evidence.display()))
            .args([&self.image, "timeout", SECONDS])
            .args(command)
            .output()
            .map_err(|error| Failure::new(format!("Docker could not start: {error}")))?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        match output.status.code() {
            Some(0) => Ok(stdout),
            Some(TIMED_OUT) => Err(Failure::new(format!(
                "`{}` reached its {SECONDS} second limit, so the check is inconclusive",
                command.join(" ")
            ))),
            _ => Err(Failure::new(format!(
                "`{}` failed with {}:\n{stdout}{}",
                command.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ))),
        }
    }
}
