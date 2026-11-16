//! A finished plan that a job which compiled hands to a job that writes the Release PR.
//!
//! The writing job never runs the compiler, so it reads the plan as untrusted input and keeps only what it can check against its own checkout.

use std::fmt;

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use semver::Version;
use serde_json::Value;

use crate::config::Manifest;
use crate::git::GitRepo;
use crate::model::ReleasePlan;
use crate::units::MIB;

/// Size a handed-off plan file may reach.
pub const MAX_PLAN_BYTES: u64 = 4 * MIB;

/// Why a [`Refusal::NotAPlan`] refuses a file that reads as a plan only through a spelling that `plan --out` never writes, such as a struct given as a list.
pub const UNWRITTEN_SPELLING: &str = "it spells a value in a form that `plan --out` never writes";

/// Why a handed-off plan cannot describe the Release PR that this checkout would write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The file, or the file that `plan --out` would write, is larger than [`MAX_PLAN_BYTES`].
    TooLarge,
    /// The file is not a `plan/v1` document, it carries a field the format lacks, or it spells a value in a form that `plan --out` never writes.
    NotAPlan(String),
    /// The document names another schema.
    Schema(String),
    /// The plan already names a Release PR, which only `release-pr` fills in.
    ReleasePrNamed,
    /// The plan describes another package or manifest version than the checkout declares.
    OtherManifest {
        /// Package the plan names.
        package: String,
        /// Manifest version the plan names.
        version: Version,
    },
    /// The plan's baseline is not a full commit id in the history of `HEAD`.
    BaselineOutsideHistory(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(
                formatter,
                "the plan file is larger than {MAX_PLAN_BYTES} bytes"
            ),
            Self::NotAPlan(reason) => write!(
                formatter,
                "the plan file is not a {} document: {reason}",
                ReleasePlan::SCHEMA
            ),
            Self::Schema(schema) => write!(formatter, "the plan file has schema `{schema}`"),
            Self::ReleasePrNamed => formatter.write_str(
                "the plan file already names a Release PR, so `plan --out` did not write it",
            ),
            Self::OtherManifest { package, version } => {
                write!(
                    formatter,
                    "the plan describes {package} {version}, which the checked-out manifest does not declare"
                )
            }
            Self::BaselineOutsideHistory(baseline) => write!(
                formatter,
                "the plan baseline `{baseline}` is not in the checked-out history; a shallow clone needs the full history"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// Write `plan` to a file that must not exist yet, so a handed-off plan is never replaced.
///
/// A plan whose file would be larger than [`read`] accepts is refused with [`Refusal::TooLarge`] before any file exists.
pub fn write_new(path: &Path, plan: &ReleasePlan) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(plan)?;
    if exceeds_limit(&bytes) {
        return Err(Refusal::TooLarge.into());
    }
    crate::fs::write_new(path, &bytes)
        .with_context(|| format!("failed to create plan `{}`", path.display()))
}

/// Whether a plan file of `bytes` is larger than [`MAX_PLAN_BYTES`], as a length that doesn't fit a `u64` is.
fn exceeds_limit(bytes: &[u8]) -> bool {
    !u64::try_from(bytes.len()).is_ok_and(|length| length <= MAX_PLAN_BYTES)
}

/// Read a plan file that `plan --out` wrote, refusing anything that `plan --out` could not have written.
pub fn read(path: &Path) -> Result<ReleasePlan> {
    let mut bytes = Vec::new();
    crate::fs::open(path)
        .map_err(anyhow::Error::from)
        .and_then(|file| Ok(file.take(MAX_PLAN_BYTES + 1).read_to_end(&mut bytes)?))
        .with_context(|| format!("failed to read plan `{}`", path.display()))?;
    parse(&bytes)
}

/// Read the bytes of a plan file that `plan --out` wrote, refusing anything that `plan --out` could not have written.
pub fn parse(bytes: &[u8]) -> Result<ReleasePlan> {
    if exceeds_limit(bytes) {
        return Err(Refusal::TooLarge.into());
    }
    let plan: ReleasePlan =
        serde_json::from_slice(bytes).map_err(|error| Refusal::NotAPlan(error.to_string()))?;
    let file: Value =
        serde_json::from_slice(bytes).map_err(|error| Refusal::NotAPlan(error.to_string()))?;
    if !spelled_as_written(&file, &serde_json::to_value(&plan)?) {
        return Err(Refusal::NotAPlan(UNWRITTEN_SPELLING.to_owned()).into());
    }
    if plan.schema != ReleasePlan::SCHEMA {
        return Err(Refusal::Schema(plan.schema).into());
    }
    if plan.pr_url.is_some() || plan.release_pr_head.is_some() {
        return Err(Refusal::ReleasePrNamed.into());
    }
    Ok(plan)
}

/// Whether every member of `file` is a member of `written` with the same value at every depth, so `file` differs from what `plan --out` writes only by members that take their default.
fn spelled_as_written(file: &Value, written: &Value) -> bool {
    match (file, written) {
        (Value::Object(file), Value::Object(written)) => file.iter().all(|(name, value)| {
            written
                .get(name)
                .is_some_and(|written| spelled_as_written(value, written))
        }),
        (Value::Array(file), Value::Array(written)) => {
            file.len() == written.len()
                && file
                    .iter()
                    .zip(written)
                    .all(|(file, written)| spelled_as_written(file, written))
        }
        _ => file == written,
    }
}

/// Refuse a plan that does not describe `manifest` and the history of `repo`.
pub fn check_checkout(plan: &ReleasePlan, manifest: &Manifest, repo: &GitRepo) -> Result<()> {
    if plan.package != manifest.package || plan.manifest_version != manifest.version {
        return Err(Refusal::OtherManifest {
            package: plan.package.clone(),
            version: plan.manifest_version.clone(),
        }
        .into());
    }
    if let Some(baseline) = plan.baseline.sha.as_deref()
        && !repo.history_contains(baseline)?
    {
        return Err(Refusal::BaselineOutsideHistory(baseline.to_owned()).into());
    }
    Ok(())
}
