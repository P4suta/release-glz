use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::artifact::{
    ArchiveLimits, fingerprint_hex_tarball, fingerprint_tar_gz, validate_docs_tarball,
    validate_hex_tarball,
};
use crate::canonical::{canonical_json_bytes, canonical_sha256};
use crate::config::{
    ApprovalConfig, AuthKind, HookConfig, OutputConfig, RegistryProvider, url_is_http_loopback,
    valid_env_name, validate_git_ref, validate_hook_config, validate_package_name,
    validate_registry_repository, validate_relative_path,
};
use crate::hooks::SidecarArtifact;
use crate::sidecar::{
    MAX_ARTIFACT_BYTES as MAX_SIDECAR_BYTES, MAX_COUNT as MAX_SIDECAR_COUNT,
    MAX_TOTAL_BYTES as MAX_TOTAL_SIDECAR_BYTES, validate_hook_id as validate_sidecar_hook_id,
    validate_media_type as validate_sidecar_media_type, validate_name as validate_sidecar_name,
};

const MANIFEST_FILE: &str = "candidate.json";
const PACKAGE_FILE: &str = "artifacts/package.tar";
const DOCS_FILE: &str = "artifacts/docs.tar.gz";
const INTERFACE_FILE: &str = "artifacts/package-interface.json";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateSource {
    pub commit_sha: String,
    pub manifest_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryIdentity {
    pub provider: RegistryProvider,
    pub repository: Option<String>,
    pub api_url: String,
    pub repository_url: String,
    pub docs_url: String,
    pub credential_env: String,
    pub auth: AuthKind,
    #[serde(default)]
    pub allow_http_loopback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookKind {
    Verify,
    Sidecar,
    Notify,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookEvidence {
    pub schema: String,
    pub id: String,
    pub kind: HookKind,
    pub required: bool,
    pub success: bool,
    pub output_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedArtifact {
    pub path: String,
    pub sha256: String,
    pub semantic_sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateArtifacts {
    pub package: SealedArtifact,
    pub docs: Option<SealedArtifact>,
    pub package_interface: SealedArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedSidecarArtifact {
    pub hook_id: String,
    pub name: String,
    pub path: String,
    pub media_type: String,
    pub sha256: String,
    pub size: u64,
    pub public: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateManifest {
    pub schema: String,
    pub package: String,
    pub version: Version,
    pub tag: String,
    pub source: CandidateSource,
    pub compiler: Version,
    pub registry: RegistryIdentity,
    pub private: bool,
    pub github_repository: String,
    pub release_branch_prefix: String,
    pub release_notes: String,
    pub approval: ApprovalConfig,
    pub outputs: OutputConfig,
    pub artifacts: CandidateArtifacts,
    pub verify_hook_definitions: Vec<HookConfig>,
    pub sidecar_hook_definitions: Vec<HookConfig>,
    pub hook_evidence: Vec<HookEvidence>,
    pub sidecars: Vec<SealedSidecarArtifact>,
    pub notify_hooks: Vec<String>,
    pub notify_hook_definitions: Vec<HookConfig>,
    pub intent_digest: String,
    pub candidate_digest: String,
}

#[derive(Debug, Clone)]
pub struct CandidateInput {
    pub package: String,
    pub version: Version,
    pub tag: String,
    pub source: CandidateSource,
    pub compiler: Version,
    pub registry: RegistryIdentity,
    pub private: bool,
    pub github_repository: String,
    pub release_branch_prefix: String,
    pub release_notes: String,
    pub approval: ApprovalConfig,
    pub outputs: OutputConfig,
    pub package_tarball: Vec<u8>,
    pub docs_tarball: Option<Vec<u8>>,
    pub package_interface: Vec<u8>,
    pub verify_hook_definitions: Vec<HookConfig>,
    pub sidecar_hook_definitions: Vec<HookConfig>,
    pub hook_evidence: Vec<HookEvidence>,
    pub sidecars: Vec<SidecarArtifact>,
    pub notify_hooks: Vec<String>,
    pub notify_hook_definitions: Vec<HookConfig>,
}

pub struct Candidate;

impl Candidate {
    pub fn built_in_evidence(input: &CandidateInput) -> Result<Vec<SidecarArtifact>> {
        validate_package_name(&input.package)?;
        let artifacts = core_artifacts(input)?;
        let public = input.outputs.github_release
            && (!input.private || input.outputs.allow_private_evidence_upload);
        let mut evidence = Vec::new();
        if input.outputs.sbom {
            let value = serde_json::json!({
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "metadata": {
                    "component": {
                        "bom-ref": format!("pkg:hex/{}@{}", input.package, input.version),
                        "type": "library",
                        "name": input.package,
                        "version": input.version,
                    }
                },
                "components": []
            });
            evidence.push(SidecarArtifact {
                hook_id: "release-glz".into(),
                name: format!("{}-{}.cdx.json", input.package, input.version),
                media_type: "application/vnd.cyclonedx+json".into(),
                bytes: canonical_json_bytes(&value)?,
                public,
            });
        }
        if input.outputs.provenance {
            let mut subjects = vec![serde_json::json!({
                "name": artifacts.package.path,
                "digest": {"sha256": artifacts.package.sha256}
            })];
            if let Some(docs) = &artifacts.docs {
                subjects.push(serde_json::json!({
                    "name": docs.path,
                    "digest": {"sha256": docs.sha256}
                }));
            }
            subjects.push(serde_json::json!({
                "name": artifacts.package_interface.path,
                "digest": {"sha256": artifacts.package_interface.sha256}
            }));
            let value = serde_json::json!({
                "_type": "https://in-toto.io/Statement/v1",
                "subject": subjects,
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "buildDefinition": {
                        "buildType": "https://p4suta.github.io/release-glz/build/v1",
                        "externalParameters": {
                            "compiler": input.compiler,
                            "manifestPath": input.source.manifest_path,
                            "sourceSha": input.source.commit_sha,
                        },
                        "internalParameters": {},
                        "resolvedDependencies": [{
                            "uri": format!("git+https://github.com/{}.git@{}", input.github_repository, input.source.commit_sha),
                            "digest": {"gitCommit": input.source.commit_sha}
                        }]
                    },
                    "runDetails": {
                        "builder": {"id": "https://github.com/P4suta/release-glz"},
                        "metadata": {"invocationId": input.source.commit_sha}
                    }
                }
            });
            evidence.push(SidecarArtifact {
                hook_id: "release-glz".into(),
                name: format!("{}-{}.intoto.jsonl", input.package, input.version),
                media_type: "application/vnd.in-toto+json".into(),
                bytes: canonical_json_bytes(&value)?,
                public,
            });
        }
        Ok(evidence)
    }

    pub fn core_intent_digest(input: &CandidateInput) -> Result<String> {
        validate_package_name(&input.package)?;
        validate_source(&input.source)?;
        validate_candidate_tag(&input.tag, &input.version)?;
        validate_registry_identity(&input.registry)?;
        validate_github_repository(&input.github_repository)?;
        validate_release_branch_prefix(&input.release_branch_prefix)?;
        validate_release_notes(&input.release_notes)?;
        validate_approval(&input.approval)?;
        validate_candidate_hook_definitions(
            &input.verify_hook_definitions,
            &input.sidecar_hook_definitions,
            &input.notify_hook_definitions,
            &input.registry.credential_env,
        )?;
        validate_notify_hooks(&input.notify_hooks)?;
        validate_notify_hook_definitions(&input.notify_hooks, &input.notify_hook_definitions)?;
        let artifacts = core_artifacts(input)?;
        intent_digest(Intent::from_input(input, &artifacts))
    }

    pub fn seal(directory: &Path, input: CandidateInput) -> Result<CandidateManifest> {
        if directory.exists() {
            bail!(
                "candidate destination `{}` already exists; sealed candidates are never replaced",
                directory.display()
            );
        }
        validate_package_name(&input.package)?;
        validate_source(&input.source)?;
        validate_candidate_tag(&input.tag, &input.version)?;
        validate_registry_identity(&input.registry)?;
        validate_github_repository(&input.github_repository)?;
        validate_release_branch_prefix(&input.release_branch_prefix)?;
        validate_release_notes(&input.release_notes)?;
        validate_approval(&input.approval)?;
        let artifacts = core_artifacts(&input)?;
        validate_hook_evidence(&input.hook_evidence)?;
        let sidecars = input
            .sidecars
            .iter()
            .map(sidecar_descriptor)
            .collect::<Result<Vec<_>>>()?;
        validate_sidecars(&sidecars)?;
        validate_sidecar_output_policy(input.private, &input.outputs, &sidecars)?;
        validate_standard_output_artifacts(
            &input.package,
            &input.version,
            &input.outputs,
            &sidecars,
        )?;
        validate_candidate_hook_definitions(
            &input.verify_hook_definitions,
            &input.sidecar_hook_definitions,
            &input.notify_hook_definitions,
            &input.registry.credential_env,
        )?;
        validate_evidenced_hooks(
            &input.verify_hook_definitions,
            &input.sidecar_hook_definitions,
            &input.hook_evidence,
            &sidecars,
        )?;
        validate_notify_hooks(&input.notify_hooks)?;
        validate_notify_hook_definitions(&input.notify_hooks, &input.notify_hook_definitions)?;
        let intent_digest = intent_digest(Intent::from_input(&input, &artifacts))?;
        let mut manifest = CandidateManifest {
            schema: "candidate/v1".into(),
            package: input.package,
            version: input.version,
            tag: input.tag,
            source: input.source,
            compiler: input.compiler,
            registry: input.registry,
            private: input.private,
            github_repository: input.github_repository,
            release_branch_prefix: input.release_branch_prefix,
            release_notes: input.release_notes,
            approval: input.approval,
            outputs: input.outputs,
            artifacts,
            verify_hook_definitions: input.verify_hook_definitions,
            sidecar_hook_definitions: input.sidecar_hook_definitions,
            hook_evidence: input.hook_evidence,
            sidecars,
            notify_hooks: input.notify_hooks,
            notify_hook_definitions: input.notify_hook_definitions,
            intent_digest,
            candidate_digest: String::new(),
        };
        manifest.candidate_digest = candidate_digest(&manifest)?;

        let parent = directory.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let temporary = tempfile::Builder::new()
            .prefix(".release-glz-candidate-")
            .tempdir_in(parent)
            .context("failed to create candidate staging directory")?;
        fs::create_dir_all(temporary.path().join("artifacts"))?;
        write_new(temporary.path().join(PACKAGE_FILE), &input.package_tarball)?;
        if let Some(bytes) = &input.docs_tarball {
            write_new(temporary.path().join(DOCS_FILE), bytes)?;
        }
        write_new(
            temporary.path().join(INTERFACE_FILE),
            &input.package_interface,
        )?;
        for (artifact, descriptor) in input.sidecars.iter().zip(&manifest.sidecars) {
            let path = temporary.path().join(&descriptor.path);
            fs::create_dir_all(path.parent().context("sidecar path has no parent")?)?;
            write_new(path, &artifact.bytes)?;
        }
        write_new(
            temporary.path().join(MANIFEST_FILE),
            &canonical_json_bytes(&manifest)?,
        )?;
        let staged = temporary.keep();
        fs::rename(&staged, directory).with_context(|| {
            format!(
                "failed to atomically seal candidate at `{}`",
                directory.display()
            )
        })?;
        Ok(manifest)
    }

    pub fn verify(directory: &Path) -> Result<CandidateManifest> {
        let manifest_bytes = read_regular_limited(
            &directory.join(MANIFEST_FILE),
            MAX_MANIFEST_BYTES,
            "candidate manifest",
        )?;
        let manifest: CandidateManifest =
            serde_json::from_slice(&manifest_bytes).context("invalid candidate manifest")?;
        if manifest.schema != "candidate/v1" {
            bail!("unsupported candidate schema `{}`", manifest.schema);
        }
        validate_package_name(&manifest.package)?;
        validate_source(&manifest.source)?;
        validate_candidate_tag(&manifest.tag, &manifest.version)?;
        validate_registry_identity(&manifest.registry)?;
        validate_github_repository(&manifest.github_repository)?;
        validate_release_branch_prefix(&manifest.release_branch_prefix)?;
        validate_release_notes(&manifest.release_notes)?;
        validate_approval(&manifest.approval)?;
        validate_hook_evidence(&manifest.hook_evidence)?;
        validate_sidecars(&manifest.sidecars)?;
        validate_sidecar_output_policy(manifest.private, &manifest.outputs, &manifest.sidecars)?;
        validate_standard_output_artifacts(
            &manifest.package,
            &manifest.version,
            &manifest.outputs,
            &manifest.sidecars,
        )?;
        validate_candidate_hook_definitions(
            &manifest.verify_hook_definitions,
            &manifest.sidecar_hook_definitions,
            &manifest.notify_hook_definitions,
            &manifest.registry.credential_env,
        )?;
        validate_evidenced_hooks(
            &manifest.verify_hook_definitions,
            &manifest.sidecar_hook_definitions,
            &manifest.hook_evidence,
            &manifest.sidecars,
        )?;
        validate_notify_hooks(&manifest.notify_hooks)?;
        validate_notify_hook_definitions(
            &manifest.notify_hooks,
            &manifest.notify_hook_definitions,
        )?;
        validate_output_artifacts(&manifest.outputs, manifest.artifacts.docs.is_some())?;
        validate_descriptor_path(&manifest.artifacts.package, PACKAGE_FILE)?;
        validate_descriptor_path(&manifest.artifacts.package_interface, INTERFACE_FILE)?;
        if let Some(docs) = &manifest.artifacts.docs {
            validate_descriptor_path(docs, DOCS_FILE)?;
        }
        validate_candidate_inventory(directory, &manifest)?;
        for sidecar in &manifest.sidecars {
            verify_sidecar_file(directory, sidecar)?;
        }

        let package = verify_file(directory, &manifest.artifacts.package)?;
        validate_hex_tarball(&package, ArchiveLimits::default())?;
        let interface = verify_file(directory, &manifest.artifacts.package_interface)?;
        let interface_value: serde_json::Value =
            serde_json::from_slice(&interface).context("package interface is not valid JSON")?;
        let docs = manifest
            .artifacts
            .docs
            .as_ref()
            .map(|descriptor| verify_file(directory, descriptor))
            .transpose()?;
        if let Some(docs) = &docs {
            validate_docs_tarball(docs, ArchiveLimits::default())?;
        }

        let semantic_package = fingerprint_hex_tarball(&package)?;
        let semantic_interface = canonical_sha256(&interface_value)?;
        if semantic_package != manifest.artifacts.package.semantic_sha256
            || semantic_interface != manifest.artifacts.package_interface.semantic_sha256
        {
            bail!("candidate semantic checksum mismatch");
        }
        if let (Some(bytes), Some(descriptor)) = (&docs, &manifest.artifacts.docs)
            && fingerprint_tar_gz(bytes)? != descriptor.semantic_sha256
        {
            bail!("candidate documentation semantic checksum mismatch");
        }
        let intent = intent_digest(Intent::from_manifest(&manifest))?;
        if intent != manifest.intent_digest {
            bail!("candidate intent digest mismatch");
        }
        if candidate_digest(&manifest)? != manifest.candidate_digest {
            bail!("candidate digest mismatch");
        }
        Ok(manifest)
    }

    pub fn package_bytes(directory: &Path, manifest: &CandidateManifest) -> Result<Vec<u8>> {
        verify_file(directory, &manifest.artifacts.package)
    }

    pub fn docs_bytes(directory: &Path, manifest: &CandidateManifest) -> Result<Option<Vec<u8>>> {
        manifest
            .artifacts
            .docs
            .as_ref()
            .map(|descriptor| verify_file(directory, descriptor))
            .transpose()
    }

    pub fn sidecar_bytes(
        directory: &Path,
        manifest: &CandidateManifest,
    ) -> Result<Vec<(SealedSidecarArtifact, Vec<u8>)>> {
        manifest
            .sidecars
            .iter()
            .map(|descriptor| {
                Ok((
                    descriptor.clone(),
                    verify_sidecar_file(directory, descriptor)?,
                ))
            })
            .collect()
    }
}

#[derive(Serialize)]
struct Intent<'a> {
    schema: &'static str,
    package: &'a str,
    version: &'a Version,
    tag: &'a str,
    compiler: &'a Version,
    registry: &'a RegistryIdentity,
    github_repository: &'a str,
    release_branch_prefix: &'a str,
    release_notes: &'a str,
    approval: &'a ApprovalConfig,
    outputs: &'a OutputConfig,
    verify_hook_definitions: &'a [HookConfig],
    sidecar_hook_definitions: &'a [HookConfig],
    notify_hook_definitions: &'a [HookConfig],
    package_semantic_sha256: &'a str,
    docs_semantic_sha256: Option<&'a str>,
    interface_semantic_sha256: &'a str,
}

impl<'a> Intent<'a> {
    fn from_input(input: &'a CandidateInput, artifacts: &'a CandidateArtifacts) -> Self {
        Self {
            schema: "intent/v1",
            package: &input.package,
            version: &input.version,
            tag: &input.tag,
            compiler: &input.compiler,
            registry: &input.registry,
            github_repository: &input.github_repository,
            release_branch_prefix: &input.release_branch_prefix,
            release_notes: &input.release_notes,
            approval: &input.approval,
            outputs: &input.outputs,
            verify_hook_definitions: &input.verify_hook_definitions,
            sidecar_hook_definitions: &input.sidecar_hook_definitions,
            notify_hook_definitions: &input.notify_hook_definitions,
            package_semantic_sha256: &artifacts.package.semantic_sha256,
            docs_semantic_sha256: artifacts
                .docs
                .as_ref()
                .map(|artifact| artifact.semantic_sha256.as_str()),
            interface_semantic_sha256: &artifacts.package_interface.semantic_sha256,
        }
    }

    fn from_manifest(manifest: &'a CandidateManifest) -> Self {
        Self {
            schema: "intent/v1",
            package: &manifest.package,
            version: &manifest.version,
            tag: &manifest.tag,
            compiler: &manifest.compiler,
            registry: &manifest.registry,
            github_repository: &manifest.github_repository,
            release_branch_prefix: &manifest.release_branch_prefix,
            release_notes: &manifest.release_notes,
            approval: &manifest.approval,
            outputs: &manifest.outputs,
            verify_hook_definitions: &manifest.verify_hook_definitions,
            sidecar_hook_definitions: &manifest.sidecar_hook_definitions,
            notify_hook_definitions: &manifest.notify_hook_definitions,
            package_semantic_sha256: &manifest.artifacts.package.semantic_sha256,
            docs_semantic_sha256: manifest
                .artifacts
                .docs
                .as_ref()
                .map(|artifact| artifact.semantic_sha256.as_str()),
            interface_semantic_sha256: &manifest.artifacts.package_interface.semantic_sha256,
        }
    }
}

fn intent_digest(intent: Intent<'_>) -> Result<String> {
    canonical_sha256(&intent)
}

#[derive(Serialize)]
struct CandidateDigest<'a> {
    schema: &'a str,
    package: &'a str,
    version: &'a Version,
    tag: &'a str,
    source: &'a CandidateSource,
    compiler: &'a Version,
    registry: &'a RegistryIdentity,
    private: bool,
    github_repository: &'a str,
    release_branch_prefix: &'a str,
    release_notes: &'a str,
    approval: &'a ApprovalConfig,
    outputs: &'a OutputConfig,
    artifacts: &'a CandidateArtifacts,
    verify_hook_definitions: &'a [HookConfig],
    sidecar_hook_definitions: &'a [HookConfig],
    hook_evidence: &'a [HookEvidence],
    sidecars: &'a [SealedSidecarArtifact],
    notify_hooks: &'a [String],
    notify_hook_definitions: &'a [HookConfig],
    intent_digest: &'a str,
}

fn candidate_digest(manifest: &CandidateManifest) -> Result<String> {
    canonical_sha256(&CandidateDigest {
        schema: &manifest.schema,
        package: &manifest.package,
        version: &manifest.version,
        tag: &manifest.tag,
        source: &manifest.source,
        compiler: &manifest.compiler,
        registry: &manifest.registry,
        private: manifest.private,
        github_repository: &manifest.github_repository,
        release_branch_prefix: &manifest.release_branch_prefix,
        release_notes: &manifest.release_notes,
        approval: &manifest.approval,
        outputs: &manifest.outputs,
        artifacts: &manifest.artifacts,
        verify_hook_definitions: &manifest.verify_hook_definitions,
        sidecar_hook_definitions: &manifest.sidecar_hook_definitions,
        hook_evidence: &manifest.hook_evidence,
        sidecars: &manifest.sidecars,
        notify_hooks: &manifest.notify_hooks,
        notify_hook_definitions: &manifest.notify_hook_definitions,
        intent_digest: &manifest.intent_digest,
    })
}

fn core_artifacts(input: &CandidateInput) -> Result<CandidateArtifacts> {
    validate_output_artifacts(&input.outputs, input.docs_tarball.is_some())?;
    validate_hex_tarball(&input.package_tarball, ArchiveLimits::default())?;
    if let Some(docs) = &input.docs_tarball {
        validate_docs_tarball(docs, ArchiveLimits::default())?;
    }
    let interface: serde_json::Value = serde_json::from_slice(&input.package_interface)
        .context("package interface is not valid JSON")?;
    let package = artifact_descriptor(
        PACKAGE_FILE,
        &input.package_tarball,
        fingerprint_hex_tarball(&input.package_tarball)?,
    );
    let docs = input
        .docs_tarball
        .as_ref()
        .map(|bytes| {
            Ok::<_, anyhow::Error>(artifact_descriptor(
                DOCS_FILE,
                bytes,
                fingerprint_tar_gz(bytes)?,
            ))
        })
        .transpose()?;
    let package_interface = artifact_descriptor(
        INTERFACE_FILE,
        &input.package_interface,
        canonical_sha256(&interface)?,
    );
    Ok(CandidateArtifacts {
        package,
        docs,
        package_interface,
    })
}

fn validate_output_artifacts(outputs: &OutputConfig, docs_present: bool) -> Result<()> {
    if outputs.docs != docs_present {
        bail!(
            "candidate documentation artifact does not match outputs.docs policy (expected {}, found {})",
            outputs.docs,
            docs_present
        );
    }
    Ok(())
}

fn artifact_descriptor(path: &str, bytes: &[u8], semantic_sha256: String) -> SealedArtifact {
    SealedArtifact {
        path: path.into(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
        semantic_sha256,
        size: bytes.len() as u64,
    }
}

fn sidecar_descriptor(artifact: &SidecarArtifact) -> Result<SealedSidecarArtifact> {
    validate_sidecar_identity(&artifact.hook_id, &artifact.name, &artifact.media_type)?;
    Ok(SealedSidecarArtifact {
        hook_id: artifact.hook_id.clone(),
        name: artifact.name.clone(),
        path: format!("sidecars/{}/{}", artifact.hook_id, artifact.name),
        media_type: artifact.media_type.clone(),
        sha256: format!("{:x}", Sha256::digest(&artifact.bytes)),
        size: artifact.bytes.len() as u64,
        public: artifact.public,
    })
}

fn verify_file(directory: &Path, descriptor: &SealedArtifact) -> Result<Vec<u8>> {
    let bytes = read_regular_limited(
        &directory.join(&descriptor.path),
        descriptor.size,
        &descriptor.path,
    )?;
    if bytes.len() as u64 != descriptor.size
        || format!("{:x}", Sha256::digest(&bytes)) != descriptor.sha256
    {
        bail!("candidate checksum mismatch for `{}`", descriptor.path);
    }
    Ok(bytes)
}

fn verify_sidecar_file(directory: &Path, descriptor: &SealedSidecarArtifact) -> Result<Vec<u8>> {
    let bytes = read_regular_limited(
        &directory.join(&descriptor.path),
        descriptor.size,
        &descriptor.path,
    )?;
    if bytes.len() as u64 != descriptor.size
        || format!("{:x}", Sha256::digest(&bytes)) != descriptor.sha256
    {
        bail!("candidate checksum mismatch for `{}`", descriptor.path);
    }
    Ok(bytes)
}

fn read_regular_limited(path: &Path, limit: u64, description: &str) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("missing {description} `{}`", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{description} `{}` is not a regular file", path.display());
    }
    if metadata.len() > limit {
        bail!("{description} `{}` exceeds its size limit", path.display());
    }
    fs::read(path).with_context(|| format!("failed to read {description} `{}`", path.display()))
}

fn validate_candidate_inventory(directory: &Path, manifest: &CandidateManifest) -> Result<()> {
    let root_metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("missing Candidate directory `{}`", directory.display()))?;
    if !root_metadata.file_type().is_dir() {
        bail!("Candidate inventory root is not a directory");
    }
    let mut expected_files = std::collections::BTreeSet::from([
        MANIFEST_FILE.to_owned(),
        manifest.artifacts.package.path.clone(),
        manifest.artifacts.package_interface.path.clone(),
    ]);
    if let Some(docs) = &manifest.artifacts.docs {
        expected_files.insert(docs.path.clone());
    }
    expected_files.extend(manifest.sidecars.iter().map(|sidecar| sidecar.path.clone()));
    let mut expected_directories = std::collections::BTreeSet::new();
    for file in &expected_files {
        let mut parent = Path::new(file).parent();
        while let Some(path) = parent {
            if path.as_os_str().is_empty() {
                break;
            }
            expected_directories.insert(path.to_string_lossy().replace('\\', "/"));
            parent = path.parent();
        }
    }
    let mut actual_files = std::collections::BTreeSet::new();
    let mut actual_directories = std::collections::BTreeSet::new();
    collect_candidate_inventory(
        directory,
        directory,
        &mut actual_files,
        &mut actual_directories,
    )?;
    if actual_files != expected_files || actual_directories != expected_directories {
        bail!("Candidate inventory differs from the sealed manifest");
    }
    Ok(())
}

fn collect_candidate_inventory(
    root: &Path,
    directory: &Path,
    files: &mut std::collections::BTreeSet<String>,
    directories: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            directories.insert(relative);
            collect_candidate_inventory(root, &path, files, directories)?;
        } else if file_type.is_file() {
            files.insert(relative);
        } else {
            bail!("Candidate inventory contains a non-regular entry");
        }
    }
    Ok(())
}

fn write_new(path: PathBuf, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("refusing to replace `{}`", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn validate_descriptor_path(descriptor: &SealedArtifact, expected: &str) -> Result<()> {
    if descriptor.path != expected {
        bail!(
            "candidate artifact path `{}` must be `{expected}`",
            descriptor.path
        );
    }
    validate_sha256(&descriptor.sha256, "artifact checksum")?;
    validate_sha256(&descriptor.semantic_sha256, "semantic checksum")
}

fn validate_source(source: &CandidateSource) -> Result<()> {
    let sha = source.commit_sha.as_bytes();
    if !matches!(sha.len(), 40 | 64)
        || !sha
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("candidate source commit must be a full lowercase SHA");
    }
    validate_relative_path(
        Path::new(&source.manifest_path),
        "candidate source manifest_path",
    )
}

fn validate_registry_identity(registry: &RegistryIdentity) -> Result<()> {
    if !valid_env_name(&registry.credential_env) {
        bail!("candidate registry credential_env is not a safe environment variable name");
    }
    validate_registry_repository(registry.provider, registry.repository.as_deref())
        .context("invalid Candidate registry repository")?;
    for (field, raw) in [
        ("api_url", &registry.api_url),
        ("repository_url", &registry.repository_url),
        ("docs_url", &registry.docs_url),
    ] {
        let url = reqwest::Url::parse(raw)
            .with_context(|| format!("candidate registry {field} is invalid"))?;
        if url.host_str().is_none() || url.cannot_be_a_base() {
            bail!("candidate registry {field} must be an absolute hierarchical URL");
        }
        if url.query().is_some() || url.fragment().is_some() {
            bail!("candidate registry {field} must not contain a query or fragment");
        }
        let loopback = url_is_http_loopback(&url);
        if (url.scheme() != "https" && !(registry.allow_http_loopback && loopback))
            || !url.username().is_empty()
            || url.password().is_some()
        {
            bail!("candidate registry {field} must be credential-free HTTPS");
        }
    }
    Ok(())
}

fn validate_candidate_tag(tag: &str, version: &Version) -> Result<()> {
    validate_git_ref(tag, "candidate.tag")?;
    if tag.starts_with("refs/") || tag.ends_with("^{}") {
        bail!("candidate.tag contains a dangerous git ref form");
    }
    if !tag.ends_with(&format!("v{version}")) {
        bail!("candidate.tag must end with the Candidate version `v{version}`");
    }
    Ok(())
}

fn validate_github_repository(repository: &str) -> Result<()> {
    crate::forge::GitHubRepository::parse(repository)?;
    Ok(())
}

fn validate_release_branch_prefix(prefix: &str) -> Result<()> {
    if prefix.is_empty() || prefix.starts_with("refs/") || prefix.contains(['\n', '\r', '\0', ' '])
    {
        bail!("candidate release branch prefix is unsafe");
    }
    validate_git_ref(
        &format!("{prefix}candidate"),
        "candidate.release_branch_prefix",
    )
}

fn validate_release_notes(notes: &str) -> Result<()> {
    if notes.len() > 1024 * 1024 || notes.contains('\0') {
        bail!("candidate release notes are invalid or exceed 1 MiB");
    }
    Ok(())
}

fn validate_approval(approval: &ApprovalConfig) -> Result<()> {
    if approval.environment.is_empty() || approval.environment.contains(['\n', '\r', '\0']) {
        bail!("candidate approval environment is invalid");
    }
    if approval.normal != crate::config::ApprovalMode::ReleasePrAndEnvironment
        || approval.manual != crate::config::ApprovalMode::Environment
    {
        bail!("candidate approval modes are invalid");
    }
    if let Some(fallback) = &approval.private_repository_fallback
        && fallback != "workflow-dispatch-digest"
    {
        bail!("candidate approval fallback is unsupported");
    }
    if approval.manual_refs.is_empty() {
        bail!("candidate manual approval ref policy is empty");
    }
    let mut refs = std::collections::BTreeSet::new();
    for git_ref in &approval.manual_refs {
        if !(git_ref.starts_with("refs/heads/") || git_ref.starts_with("refs/tags/")) {
            bail!("candidate manual approval ref policy contains a non-release ref");
        }
        crate::config::validate_git_ref(git_ref, "candidate approval.manual_refs")?;
        if !refs.insert(git_ref) {
            bail!("candidate manual approval ref policy contains duplicates");
        }
    }
    Ok(())
}

fn validate_hook_evidence(evidence: &[HookEvidence]) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    for item in evidence {
        if item.schema != "hook/v1" {
            bail!("unsupported hook evidence schema `{}`", item.schema);
        }
        if item.id.is_empty() || !ids.insert((&item.kind, &item.id)) {
            bail!("invalid or duplicate hook evidence id `{}`", item.id);
        }
        validate_sha256(&item.output_sha256, "hook evidence checksum")?;
        if item.required && !item.success {
            bail!("required hook `{}` did not succeed", item.id);
        }
    }
    Ok(())
}

fn validate_candidate_hook_definitions(
    verify: &[HookConfig],
    sidecar: &[HookConfig],
    notify: &[HookConfig],
    registry_credential_env: &str,
) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    for hook in verify.iter().chain(sidecar).chain(notify) {
        validate_hook_config(hook)?;
        if hook
            .env
            .iter()
            .any(|name| crate::config::protected_hook_environment(name, registry_credential_env))
        {
            bail!(
                "sealed hook `{}` may not receive release-glz authorization or registry credentials",
                hook.id
            );
        }
        if !ids.insert(&hook.id) {
            bail!("duplicate sealed hook id `{}`", hook.id);
        }
    }
    Ok(())
}

fn validate_evidenced_hooks(
    verify: &[HookConfig],
    sidecar: &[HookConfig],
    evidence: &[HookEvidence],
    sidecars: &[SealedSidecarArtifact],
) -> Result<()> {
    if evidence.len() != verify.len() + sidecar.len() {
        bail!("sealed hook evidence does not match the configured verify and sidecar hooks");
    }
    for (index, hook) in verify.iter().enumerate() {
        validate_hook_evidence_binding(&evidence[index], hook, HookKind::Verify)?;
    }
    for (index, hook) in sidecar.iter().enumerate() {
        validate_hook_evidence_binding(&evidence[verify.len() + index], hook, HookKind::Sidecar)?;
    }
    let sidecar_ids = sidecar
        .iter()
        .map(|hook| hook.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if sidecars.iter().any(|artifact| {
        artifact.hook_id != "release-glz" && !sidecar_ids.contains(artifact.hook_id.as_str())
    }) {
        bail!("candidate sidecar artifact was produced by an undeclared hook");
    }
    Ok(())
}

fn validate_hook_evidence_binding(
    evidence: &HookEvidence,
    hook: &HookConfig,
    kind: HookKind,
) -> Result<()> {
    if evidence.id != hook.id || evidence.kind != kind || evidence.required != hook.required {
        bail!(
            "sealed hook evidence does not match hook definition `{}`",
            hook.id
        );
    }
    Ok(())
}

fn validate_sidecars(sidecars: &[SealedSidecarArtifact]) -> Result<()> {
    if sidecars.len() > MAX_SIDECAR_COUNT {
        bail!("candidate contains too many sidecar artifacts");
    }
    let mut paths = std::collections::BTreeSet::new();
    let mut total = 0_u64;
    for sidecar in sidecars {
        validate_sidecar_identity(&sidecar.hook_id, &sidecar.name, &sidecar.media_type)?;
        let expected_path = format!("sidecars/{}/{}", sidecar.hook_id, sidecar.name);
        if sidecar.path != expected_path || !paths.insert(&sidecar.path) {
            bail!("candidate sidecar path is invalid or duplicated");
        }
        validate_sha256(&sidecar.sha256, "sidecar checksum")?;
        total = total
            .checked_add(sidecar.size)
            .context("candidate sidecar total size overflow")?;
        if sidecar.size > MAX_SIDECAR_BYTES || total > MAX_TOTAL_SIDECAR_BYTES {
            bail!("candidate sidecar artifacts exceed their size limit");
        }
    }
    Ok(())
}

fn validate_sidecar_output_policy(
    private: bool,
    outputs: &OutputConfig,
    sidecars: &[SealedSidecarArtifact],
) -> Result<()> {
    let public = sidecars.iter().filter(|artifact| artifact.public);
    let public_count = public.clone().count();
    if public_count > 0 && !outputs.github_release {
        bail!("public sidecar artifacts require outputs.github_release");
    }
    if public_count > 0 && private && !outputs.allow_private_evidence_upload {
        bail!(
            "public sidecar artifacts for a private package require outputs.allow_private_evidence_upload"
        );
    }
    let mut names = std::collections::BTreeSet::new();
    for artifact in public {
        if !names.insert(&artifact.name) {
            bail!(
                "duplicate public GitHub Release asset name `{}`",
                artifact.name
            );
        }
    }
    Ok(())
}

fn validate_standard_output_artifacts(
    package: &str,
    version: &Version,
    outputs: &OutputConfig,
    sidecars: &[SealedSidecarArtifact],
) -> Result<()> {
    let built_in = sidecars
        .iter()
        .filter(|artifact| artifact.hook_id == "release-glz")
        .collect::<Vec<_>>();
    let sbom_name = format!("{package}-{version}.cdx.json");
    let provenance_name = format!("{package}-{version}.intoto.jsonl");
    let sbom = built_in.iter().filter(|artifact| {
        artifact.name == sbom_name && artifact.media_type == "application/vnd.cyclonedx+json"
    });
    let provenance = built_in.iter().filter(|artifact| {
        artifact.name == provenance_name && artifact.media_type == "application/vnd.in-toto+json"
    });
    if sbom.count() != usize::from(outputs.sbom) {
        bail!("Candidate SBOM artifacts do not match outputs.sbom policy");
    }
    if provenance.count() != usize::from(outputs.provenance) {
        bail!("Candidate provenance artifacts do not match outputs.provenance policy");
    }
    let expected_builtin = usize::from(outputs.sbom) + usize::from(outputs.provenance);
    if built_in.len() != expected_builtin {
        bail!("Candidate contains an unsupported built-in evidence artifact");
    }
    if outputs.signature
        && !sidecars.iter().any(|artifact| {
            artifact.media_type == "application/pgp-signature"
                || artifact.media_type == "application/vnd.dev.sigstore.bundle+json"
        })
    {
        bail!("outputs.signature requires a sealed signature sidecar artifact");
    }
    Ok(())
}

fn validate_sidecar_identity(hook_id: &str, name: &str, media_type: &str) -> Result<()> {
    validate_sidecar_hook_id(hook_id)?;
    validate_sidecar_name(name)?;
    validate_sidecar_media_type(media_type)?;
    Ok(())
}

fn validate_notify_hooks(hooks: &[String]) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    for id in hooks {
        if id.is_empty() || !ids.insert(id) {
            bail!("invalid or duplicate notify hook id `{id}`");
        }
    }
    Ok(())
}

fn validate_notify_hook_definitions(ids: &[String], hooks: &[HookConfig]) -> Result<()> {
    if ids.len() != hooks.len()
        || ids
            .iter()
            .zip(hooks)
            .any(|(expected, hook)| expected != &hook.id)
    {
        bail!("sealed notify hook definitions do not match the ordered hook ids");
    }
    for hook in hooks {
        validate_hook_config(hook)?;
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{field} is not a lowercase SHA-256 digest");
    }
    Ok(())
}
