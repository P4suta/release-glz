//! Hook execution and the evidence it produces.
//!
//! Hooks are processes described by an argv array, never shell strings, and credentials and GitHub control files are withheld from them even when a manifest names those variables.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout};

use crate::candidate::{HookEvidence, HookKind};
use crate::canonical::canonical_json_bytes;
use crate::config::{HookConfig, validate_hook_config};
use crate::process::{SPAWN_ATTEMPTS, retryable_spawn_error, spawn_retry_delay};
use crate::sidecar::{
    MAX_ARTIFACT_BYTES as SIDECAR_ARTIFACT_LIMIT, MAX_COUNT as SIDECAR_COUNT_LIMIT,
    MAX_TOTAL_BYTES as SIDECAR_TOTAL_LIMIT, validate_media_type, validate_name,
};
use crate::units::{KIB, MIB};

/// Bytes of hook stdout that are read before the stream is cut off.
const STDOUT_LIMIT: usize = MIB as usize;

/// Bytes of hook stderr that are read before the stream is cut off.
const STDERR_LIMIT: usize = 256 * KIB as usize;

/// Seconds a terminated hook may take to be reaped before that is reported.
const REAP_GRACE_SECONDS: u64 = 1;

/// The process-group argument that makes a hook lead a new group of its own.
#[cfg(unix)]
const NEW_PROCESS_GROUP: i32 = 0;

/// Bytes read from a hook pipe in one call.
const PIPE_READ_BYTES: usize = 8 * KIB as usize;

/// What a hook is told about the release it is running for.
///
/// Digests appear only once they exist, so a verify hook cannot depend on a Candidate digest that has not been computed yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookContext {
    /// Package name.
    pub package: String,
    /// Version being released.
    pub version: Version,
    /// Commit the Candidate was built from.
    pub source_sha: String,
    /// Digest of the release decision, once planning has produced one.
    pub intent_digest: Option<String>,
    /// Digest of the sealed Candidate, once it has been sealed.
    pub candidate_digest: Option<String>,
    /// Key that makes a retried publication attempt recognizable.
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct HookRequest<'a> {
    schema: &'static str,
    phase: &'static str,
    context: &'a HookContext,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HookOutput {
    schema: String,
    success: bool,
    summary: String,
    evidence: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SidecarArtifactOutput {
    name: String,
    media_type: String,
    content_base64: String,
    #[serde(default)]
    public: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SidecarOutput {
    #[serde(default)]
    artifacts: Vec<SidecarArtifactOutput>,
}

/// One artifact produced by a sidecar hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarArtifact {
    /// Hook that produced it.
    pub hook_id: String,
    /// File name recorded in the Candidate inventory.
    pub name: String,
    /// Declared media type.
    pub media_type: String,
    /// Artifact bytes.
    pub bytes: Vec<u8>,
    /// Whether the artifact may be published, or stays internal.
    pub public: bool,
}

/// The result of running every sidecar hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarRun {
    /// Evidence recorded for each hook that ran.
    pub evidence: Vec<HookEvidence>,
    /// Artifacts the hooks produced.
    pub artifacts: Vec<SidecarArtifact>,
}

#[derive(Debug)]
struct ExecutedHook {
    success: bool,
    output_sha256: String,
    evidence: serde_json::Value,
}

impl ExecutedHook {
    fn as_evidence(&self, hook: &HookConfig, kind: HookKind) -> HookEvidence {
        HookEvidence {
            schema: "hook/v1".into(),
            id: hook.id.clone(),
            kind,
            required: hook.required,
            success: self.success,
            output_sha256: self.output_sha256.clone(),
        }
    }
}

/// Runs configured hooks as plain processes.
///
/// Hooks are spawned from an argv array, never through a shell, and their output is read under fixed limits.
#[derive(Debug, Clone)]
pub struct HookRunner {
    stdout_limit: usize,
    stderr_limit: usize,
}

impl Default for HookRunner {
    fn default() -> Self {
        Self {
            stdout_limit: STDOUT_LIMIT,
            stderr_limit: STDERR_LIMIT,
        }
    }
}

impl HookRunner {
    /// Run the verify hooks against a sealed snapshot.
    ///
    /// The snapshot is digested before and after each hook, so a hook that modifies the bytes under review is caught instead of trusted.
    pub async fn run_verify(
        &self,
        hooks: &[HookConfig],
        snapshot: &Path,
        context: &HookContext,
    ) -> Result<Vec<HookEvidence>> {
        let mut evidence = Vec::new();
        // Nothing between two hooks can touch the snapshot, so the digest taken after one hook is the digest before the next: k hooks need k + 1 walks of the tree rather than 2k.
        let mut unchanged = None;
        for hook in hooks {
            let before = match unchanged.take() {
                Some(digest) => digest,
                None => tree_digest(snapshot)?,
            };
            let result = self.run_one(hook, snapshot, "verify", context).await;
            let after = tree_digest(snapshot)?;
            if before != after {
                bail!("verify hook `{}` modified the source snapshot", hook.id);
            }
            unchanged = Some(after);
            match result {
                Ok(item) if item.success => evidence.push(item.as_evidence(hook, HookKind::Verify)),
                Ok(item) if !hook.required => {
                    evidence.push(item.as_evidence(hook, HookKind::Verify))
                }
                Ok(_) => bail!("required verify hook `{}` reported failure", hook.id),
                Err(error) if !hook.required => evidence.push(HookEvidence {
                    schema: "hook/v1".into(),
                    id: hook.id.clone(),
                    kind: HookKind::Verify,
                    required: false,
                    success: false,
                    output_sha256: crate::hex::lower(&Sha256::digest(error.to_string().as_bytes())),
                }),
                Err(error) => return Err(error),
            }
        }
        Ok(evidence)
    }

    /// Run the sidecar hooks and collect the artifacts they emit.
    pub async fn run_sidecars(
        &self,
        hooks: &[HookConfig],
        snapshot: &Path,
        context: &HookContext,
    ) -> Result<SidecarRun> {
        let mut evidence = Vec::new();
        let mut artifacts = Vec::new();
        let mut names = std::collections::BTreeSet::new();
        let mut total_size = 0_u64;
        // The digest after one hook is the digest before the next, for the same reason as in `run_verify`.
        let mut unchanged = None;
        for hook in hooks {
            let before = match unchanged.take() {
                Some(digest) => digest,
                None => tree_digest(snapshot)?,
            };
            let result = self.run_one(hook, snapshot, "sidecar", context).await;
            let after = tree_digest(snapshot)?;
            if before != after {
                bail!("sidecar hook `{}` modified the source snapshot", hook.id);
            }
            unchanged = Some(after);
            match result {
                Ok(item) if item.success => {
                    let output: SidecarOutput = serde_json::from_value(item.evidence.clone())
                        .with_context(|| {
                            format!("sidecar hook `{}` returned invalid artifacts", hook.id)
                        })?;
                    for artifact in output.artifacts {
                        if artifacts.len() >= SIDECAR_COUNT_LIMIT {
                            bail!("sidecar hooks exceeded the artifact count limit");
                        }
                        validate_name(&artifact.name)?;
                        validate_media_type(&artifact.media_type)?;
                        let key = format!("{}/{}", hook.id, artifact.name);
                        if !names.insert(key) {
                            bail!(
                                "sidecar hook `{}` returned duplicate artifact `{}`",
                                hook.id,
                                artifact.name
                            );
                        }
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(&artifact.content_base64)
                            .with_context(|| {
                                format!(
                                    "sidecar hook `{}` artifact `{}` is not valid base64",
                                    hook.id, artifact.name
                                )
                            })?;
                        let size = bytes.len() as u64;
                        if size > SIDECAR_ARTIFACT_LIMIT
                            || total_size.saturating_add(size) > SIDECAR_TOTAL_LIMIT
                        {
                            bail!("sidecar hook artifacts exceed their size limit");
                        }
                        total_size += size;
                        artifacts.push(SidecarArtifact {
                            hook_id: hook.id.clone(),
                            name: artifact.name,
                            media_type: artifact.media_type,
                            bytes,
                            public: artifact.public,
                        });
                    }
                    evidence.push(item.as_evidence(hook, HookKind::Sidecar));
                }
                Ok(item) if !hook.required => {
                    evidence.push(item.as_evidence(hook, HookKind::Sidecar));
                }
                Ok(_) => bail!("required sidecar hook `{}` reported failure", hook.id),
                Err(error) if !hook.required => evidence.push(HookEvidence {
                    schema: "hook/v1".into(),
                    id: hook.id.clone(),
                    kind: HookKind::Sidecar,
                    required: false,
                    success: false,
                    output_sha256: crate::hex::lower(&Sha256::digest(error.to_string().as_bytes())),
                }),
                Err(error) => return Err(error),
            }
        }
        Ok(SidecarRun {
            evidence,
            artifacts,
        })
    }

    /// Ask a notify hook whether its delivery has already completed.
    ///
    /// Observation comes first so that a retry does not send a second notification for the same release.
    pub async fn observe_notify(
        &self,
        hook: &HookConfig,
        directory: &Path,
        context: &HookContext,
    ) -> Result<bool> {
        let output = match self.run_one(hook, directory, "observe", context).await {
            Ok(output) => output,
            Err(_) if !hook.required => return Ok(false),
            Err(error) => return Err(error),
        };
        if !output.success {
            if hook.required {
                bail!(
                    "required notify hook `{}` could not observe delivery",
                    hook.id
                );
            }
            return Ok(false);
        }
        output
            .evidence
            .get("complete")
            .and_then(serde_json::Value::as_bool)
            .with_context(|| {
                format!(
                    "notify hook `{}` observe evidence must contain boolean `complete`",
                    hook.id
                )
            })
    }

    /// Run the delivering half of a notify hook.
    pub async fn apply_notify(
        &self,
        hook: &HookConfig,
        directory: &Path,
        context: &HookContext,
    ) -> Result<()> {
        let output = self.run_one(hook, directory, "apply", context).await?;
        if !output.success {
            bail!("notify hook `{}` reported apply failure", hook.id);
        }
        Ok(())
    }

    async fn run_one(
        &self,
        hook: &HookConfig,
        directory: &Path,
        phase: &'static str,
        context: &HookContext,
    ) -> Result<ExecutedHook> {
        validate_hook_config(hook)?;
        let executable = hook
            .argv
            .first()
            .context("hook argv unexpectedly empty after configuration validation")?;
        let input = canonical_json_bytes(&HookRequest {
            schema: "hook/v1",
            phase,
            context,
        })?;
        let mut command = tokio::process::Command::new(executable);
        command
            .args(&hook.argv[1..])
            .current_dir(directory)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for name in &hook.env {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let mut child = spawn_hook(command, &hook.id).await?;
        let (mut stdin, stdout, stderr) = child.take_pipes()?;
        let mut input_task = tokio::spawn(async move {
            stdin.write_all(&input).await?;
            stdin.shutdown().await
        });
        let mut stdout_task = tokio::spawn(drain_limited(stdout, self.stdout_limit));
        let mut stderr_task = tokio::spawn(drain_limited(stderr, self.stderr_limit));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(hook.timeout_seconds);
        let completed = tokio::time::timeout_at(deadline, async {
            let status = child.wait().await?;
            input_delivered((&mut input_task).await)?;
            let stdout = (&mut stdout_task).await??;
            let stderr = (&mut stderr_task).await??;
            Ok::<_, anyhow::Error>((status, stdout, stderr))
        })
        .await;
        let (status, (stdout, stdout_exceeded), (_, stderr_exceeded)) = match completed {
            Ok(result) => result?,
            Err(_) => {
                input_task.abort();
                stdout_task.abort();
                stderr_task.abort();
                let timed_out = format!(
                    "hook `{}` timed out after {} seconds",
                    hook.id, hook.timeout_seconds
                );
                return Err(match child.terminate().await {
                    Ok(()) => anyhow::anyhow!(timed_out),
                    Err(error) => error.context(timed_out),
                });
            }
        };
        if stdout_exceeded || stderr_exceeded {
            bail!("hook `{}` exceeded its output limit", hook.id);
        }
        let output_sha256 = crate::hex::lower(&Sha256::digest(&stdout));
        if !status.success() {
            return Ok(ExecutedHook {
                success: false,
                output_sha256,
                evidence: serde_json::json!({}),
            });
        }
        let output: HookOutput = serde_json::from_slice(&stdout)
            .with_context(|| format!("hook `{}` returned invalid JSON", hook.id))?;
        if output.schema != "hook/v1" {
            bail!(
                "hook `{}` returned unsupported schema `{}`",
                hook.id,
                output.schema
            );
        }
        if output.summary.trim().is_empty() {
            bail!("hook `{}` returned an empty summary", hook.id);
        }
        if !output.evidence.is_object() {
            bail!("hook `{}` evidence must be a JSON object", hook.id);
        }
        Ok(ExecutedHook {
            success: output.success,
            output_sha256,
            evidence: output.evidence,
        })
    }
}

async fn spawn_hook(command: tokio::process::Command, hook_id: &str) -> Result<HookProcess> {
    let mut command = HookProcess::command(command);
    let mut attempt = 1;
    loop {
        match HookProcess::spawn(&mut command) {
            Ok(process) => return Ok(process),
            Err(error) if retryable_spawn_error(&error) && attempt < SPAWN_ATTEMPTS => {
                tokio::time::sleep(spawn_retry_delay(attempt)).await;
                attempt += 1;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to start hook `{hook_id}`"));
            }
        }
    }
}

/// Accept the stdin writer's outcome, where a hook that exits without reading its request legitimately closes the pipe first.
fn input_delivered(
    outcome: std::result::Result<std::io::Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    match outcome.context("hook input writer stopped")? {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error).context("failed to deliver the hook request"),
    }
}

/// The command that starts a hook as the leader of a new process group.
#[cfg(unix)]
type HookCommand = tokio::process::Command;

/// The command that starts a hook inside a new job object.
#[cfg(windows)]
type HookCommand = process_wrap::tokio::CommandWrap;

/// A started hook and every process it starts, which end together when the hook times out.
///
/// On Unix the hook leads its own process group, and on Windows it runs in a job object from its first instruction.
/// Terminating the group or the job also ends descendants that would otherwise keep the hook's pipes open.
struct HookProcess {
    #[cfg(unix)]
    child: tokio::process::Child,
    /// The group the hook leads, whose id is the hook's own process id because the spawn made it a new group.
    #[cfg(unix)]
    group: rustix::process::Pid,
    #[cfg(windows)]
    child: Box<dyn process_wrap::tokio::ChildWrapper>,
}

impl HookProcess {
    #[cfg(unix)]
    fn command(mut command: tokio::process::Command) -> HookCommand {
        command.process_group(NEW_PROCESS_GROUP);
        command
    }

    #[cfg(windows)]
    fn command(command: tokio::process::Command) -> HookCommand {
        let mut command = process_wrap::tokio::CommandWrap::from(command);
        command.wrap(process_wrap::tokio::JobObject);
        command
    }

    #[cfg(unix)]
    fn spawn(command: &mut HookCommand) -> std::io::Result<Self> {
        let child = command.spawn()?;
        let group = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(rustix::process::Pid::from_raw)
            .ok_or_else(|| std::io::Error::other("started hook has no process id"))?;
        Ok(Self { child, group })
    }

    #[cfg(windows)]
    fn spawn(command: &mut HookCommand) -> std::io::Result<Self> {
        Ok(Self {
            child: command.spawn()?,
        })
    }

    /// The hook's stdin, stdout, and stderr, which its command pipes.
    fn take_pipes(&mut self) -> Result<(ChildStdin, ChildStdout, ChildStderr)> {
        let (stdin, stdout, stderr) = self.pipes();
        Ok((
            stdin.context("hook stdin was not piped")?,
            stdout.context("hook stdout was not piped")?,
            stderr.context("hook stderr was not piped")?,
        ))
    }

    #[cfg(unix)]
    fn pipes(&mut self) -> (Option<ChildStdin>, Option<ChildStdout>, Option<ChildStderr>) {
        (
            self.child.stdin.take(),
            self.child.stdout.take(),
            self.child.stderr.take(),
        )
    }

    #[cfg(windows)]
    fn pipes(&mut self) -> (Option<ChildStdin>, Option<ChildStdout>, Option<ChildStderr>) {
        (
            self.child.stdin().take(),
            self.child.stdout().take(),
            self.child.stderr().take(),
        )
    }

    #[cfg(unix)]
    async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.child.wait().await
    }

    /// Wait for the hook's own process, as on Unix, rather than for every process in its job.
    #[cfg(windows)]
    async fn wait(&mut self) -> std::io::Result<ExitStatus> {
        self.child.inner_mut().wait().await
    }

    async fn terminate(&mut self) -> Result<()> {
        self.end_every_process()?;
        tokio::time::timeout(Duration::from_secs(REAP_GRACE_SECONDS), self.wait())
            .await
            .context("terminated hook was not reaped in time")?
            .context("failed to reap the terminated hook")?;
        Ok(())
    }

    #[cfg(unix)]
    fn end_every_process(&mut self) -> Result<()> {
        match rustix::process::kill_process_group(self.group, rustix::process::Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
            Err(error) => Err(error).context("failed to terminate the hook process group"),
        }
    }

    #[cfg(windows)]
    fn end_every_process(&mut self) -> Result<()> {
        self.child
            .start_kill()
            .context("failed to terminate the hook job object")
    }
}

async fn drain_limited<R: AsyncRead + Unpin>(
    mut reader: R,
    limit: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut output = Vec::new();
    let mut exceeded = false;
    let mut buffer = [0_u8; PIPE_READ_BYTES];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(output.len());
        let retained = read.min(remaining);
        output.extend_from_slice(&buffer[..retained]);
        if retained != read {
            exceeded = true;
        }
    }
    Ok((output, exceeded))
}

fn tree_digest(root: &Path) -> Result<String> {
    let mut files = Vec::new();
    collect_tree(root, root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut digest = Sha256::new();
    for (relative, path) in files {
        let contents = fs::read(path)?;
        digest.update((relative.len() as u64).to_be_bytes());
        digest.update(relative.as_bytes());
        digest.update((contents.len() as u64).to_be_bytes());
        digest.update(contents);
    }
    Ok(crate::hex::lower(&digest.finalize()))
}

fn collect_tree(root: &Path, directory: &Path, output: &mut Vec<(String, PathBuf)>) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(directory)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect_tree(root, &path, output)?;
        } else if kind.is_file() {
            output.push((
                path.strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/"),
                path,
            ));
        } else {
            bail!("snapshot contains non-regular entry `{}`", path.display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::input_delivered;
    use std::io::{Error, ErrorKind};

    #[test]
    fn a_hook_may_close_its_request_pipe_but_other_delivery_failures_fail_closed() {
        input_delivered(Ok(Ok(()))).unwrap();
        input_delivered(Ok(Err(Error::from(ErrorKind::BrokenPipe)))).unwrap();
        for kind in [ErrorKind::PermissionDenied, ErrorKind::Other] {
            let error = input_delivered(Ok(Err(Error::from(kind)))).unwrap_err();
            assert!(
                error.to_string().contains("failed to deliver"),
                "{kind:?}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn a_stopped_request_writer_fails_closed() {
        let stopped = tokio::spawn(async { std::future::pending::<std::io::Result<()>>().await });
        stopped.abort();
        let error = input_delivered(stopped.await).unwrap_err();
        assert!(error.to_string().contains("stopped"), "{error}");
    }
}
