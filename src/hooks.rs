use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::candidate::{HookEvidence, HookKind};
use crate::canonical::canonical_json_bytes;
use crate::config::HookConfig;

const STDOUT_LIMIT: usize = 1024 * 1024;
const STDERR_LIMIT: usize = 256 * 1024;
const SIDECAR_ARTIFACT_LIMIT: usize = 64 * 1024 * 1024;
const SIDECAR_TOTAL_LIMIT: usize = 128 * 1024 * 1024;
const SIDECAR_COUNT_LIMIT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookContext {
    pub package: String,
    pub version: Version,
    pub source_sha: String,
    pub intent_digest: Option<String>,
    pub candidate_digest: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarArtifact {
    pub hook_id: String,
    pub name: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
    pub public: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarRun {
    pub evidence: Vec<HookEvidence>,
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
    pub async fn run_verify(
        &self,
        hooks: &[HookConfig],
        snapshot: &Path,
        context: &HookContext,
    ) -> Result<Vec<HookEvidence>> {
        let mut evidence = Vec::new();
        for hook in hooks {
            let before = tree_digest(snapshot)?;
            let result = self.run_one(hook, snapshot, "verify", context).await;
            let after = tree_digest(snapshot)?;
            if before != after {
                bail!("verify hook `{}` modified the source snapshot", hook.id);
            }
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
                    output_sha256: format!("{:x}", Sha256::digest(error.to_string().as_bytes())),
                }),
                Err(error) => return Err(error),
            }
        }
        Ok(evidence)
    }

    pub async fn run_sidecars(
        &self,
        hooks: &[HookConfig],
        snapshot: &Path,
        context: &HookContext,
    ) -> Result<SidecarRun> {
        let mut evidence = Vec::new();
        let mut artifacts = Vec::new();
        let mut names = std::collections::BTreeSet::new();
        let mut total_size = 0_usize;
        for hook in hooks {
            let before = tree_digest(snapshot)?;
            let result = self.run_one(hook, snapshot, "sidecar", context).await;
            let after = tree_digest(snapshot)?;
            if before != after {
                bail!("sidecar hook `{}` modified the source snapshot", hook.id);
            }
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
                        validate_sidecar_name(&artifact.name)?;
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
                        if bytes.len() > SIDECAR_ARTIFACT_LIMIT
                            || total_size.saturating_add(bytes.len()) > SIDECAR_TOTAL_LIMIT
                        {
                            bail!("sidecar hook artifacts exceed their size limit");
                        }
                        total_size += bytes.len();
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
                    output_sha256: format!("{:x}", Sha256::digest(error.to_string().as_bytes())),
                }),
                Err(error) => return Err(error),
            }
        }
        Ok(SidecarRun {
            evidence,
            artifacts,
        })
    }

    pub async fn observe_notify(
        &self,
        hook: &HookConfig,
        directory: &Path,
        context: &HookContext,
    ) -> Result<bool> {
        let output = self.run_one(hook, directory, "observe", context).await?;
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
        let mut child = command
            .spawn()
            .with_context(|| format!("failed to start hook `{}`", hook.id))?;
        let mut stdin = child.stdin.take().context("hook stdin was not piped")?;
        let stdout = child.stdout.take().context("hook stdout was not piped")?;
        let stderr = child.stderr.take().context("hook stderr was not piped")?;
        let input_task = tokio::spawn(async move {
            stdin.write_all(&input).await?;
            stdin.shutdown().await
        });
        let stdout_task = tokio::spawn(drain_limited(stdout, self.stdout_limit));
        let stderr_task = tokio::spawn(drain_limited(stderr, self.stderr_limit));
        let status =
            match tokio::time::timeout(Duration::from_secs(hook.timeout_seconds), child.wait())
                .await
            {
                Ok(status) => status?,
                Err(_) => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    input_task.abort();
                    stdout_task.abort();
                    stderr_task.abort();
                    bail!(
                        "hook `{}` timed out after {} seconds",
                        hook.id,
                        hook.timeout_seconds
                    );
                }
            };
        let _ = input_task.await;
        let (stdout, stdout_exceeded) = stdout_task.await??;
        let (_, stderr_exceeded) = stderr_task.await??;
        if stdout_exceeded || stderr_exceeded {
            bail!("hook `{}` exceeded its output limit", hook.id);
        }
        let output_sha256 = format!("{:x}", Sha256::digest(&stdout));
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

async fn drain_limited<R: AsyncRead + Unpin>(
    mut reader: R,
    limit: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut output = Vec::new();
    let mut exceeded = false;
    let mut buffer = [0_u8; 8 * 1024];
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
    Ok(format!("{:x}", digest.finalize()))
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

fn validate_sidecar_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 256
        || name.contains(['/', '\\', '\n', '\r', '\0'])
        || Path::new(name).is_absolute()
        || Path::new(name)
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("sidecar artifact name `{name}` is not a safe asset name");
    }
    Ok(())
}

fn validate_media_type(media_type: &str) -> Result<()> {
    if media_type.is_empty()
        || media_type.len() > 128
        || !media_type.contains('/')
        || !media_type
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
    {
        bail!("sidecar artifact media type is invalid");
    }
    Ok(())
}
