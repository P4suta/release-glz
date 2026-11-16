//! Properties of the readers of a hook's `hook/v1` report and of the artifacts that a sidecar hook's evidence lists.
//!
//! An accepted report is a JSON object with exactly the members of `hook/v1`, a non-blank summary, and object evidence, and its rendering reads back as the same report.
//! Every refused report names the reason of invalid hook output.
//! The evidence of an accepted report is also read as a sidecar hook's artifacts, which are refused with their own typed reasons or are JSON objects with safe names, valid media types, and the bytes that their base64 content spells.

use std::collections::BTreeSet;

use base64::Engine;
use release_glz::failure::{RefusalReason, refusal_reason};
use release_glz::hooks::{HookReport, SidecarArtifact, parse_hook_output, parse_sidecar_artifacts};
use serde_json::{Map, Value, json};

const HOOK_ID: &str = "evidence";
const MEMBERS: [&str; 4] = ["evidence", "schema", "success", "summary"];
const MAX_NAME_BYTES: usize = 256;
const MAX_MEDIA_TYPE_BYTES: usize = 128;

/// A reader that accepted an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reached {
    Report,
    Artifacts,
}

pub fn check(data: &[u8]) -> Vec<Reached> {
    let report = match parse_hook_output(HOOK_ID, data) {
        Ok(report) => report,
        Err(error) => {
            assert_eq!(
                refusal_reason(&error),
                Some(RefusalReason::HookOutputInvalid),
                "{error:#}"
            );
            return Vec::new();
        }
    };
    let file: Value = serde_json::from_slice(data).expect("an accepted report is JSON");
    let members: BTreeSet<_> = file
        .as_object()
        .unwrap_or_else(|| panic!("an accepted report isn't a JSON object: {file}"))
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(members, BTreeSet::from(MEMBERS));
    assert_eq!(file["schema"], "hook/v1");
    assert!(!report.summary.trim().is_empty());
    assert_eq!(file["success"], report.success);
    assert_eq!(file["summary"], report.summary.as_str());
    assert_eq!(file["evidence"], Value::Object(report.evidence.clone()));
    assert_eq!(
        parse_hook_output(HOOK_ID, &render_report(&report)).expect("a rendered report reads back"),
        report
    );
    let mut reached = vec![Reached::Report];
    if artifacts(report.evidence) {
        reached.push(Reached::Artifacts);
    }
    reached
}

fn render_report(report: &HookReport) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "hook/v1",
        "success": report.success,
        "summary": report.summary,
        "evidence": report.evidence,
    }))
    .expect("a report serializes")
}

/// Whether GitHub keeps `name` as an asset name: 1 to 256 ASCII letters, digits, `.`, `-`, and `_`, with no `.` at either end.
fn asset_name(name: &str) -> bool {
    (1..=MAX_NAME_BYTES).contains(&name.len())
        && !name.starts_with('.')
        && !name.ends_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
}

/// Whether `media_type` is 1 to 128 visible ASCII characters with a `/` and without `"` or `\`.
fn media_type(media_type: &str) -> bool {
    (1..=MAX_MEDIA_TYPE_BYTES).contains(&media_type.len())
        && media_type.contains('/')
        && media_type
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
}

fn artifacts(evidence: Map<String, Value>) -> bool {
    let listed = evidence.get("artifacts").cloned();
    let artifacts = match parse_sidecar_artifacts(HOOK_ID, evidence) {
        Ok(artifacts) => artifacts,
        Err(error) => {
            let reason = refusal_reason(&error);
            assert!(
                matches!(
                    reason,
                    Some(
                        RefusalReason::SidecarArtifactsInvalid
                            | RefusalReason::SidecarNameUnsafe
                            | RefusalReason::SidecarMediaTypeInvalid
                    )
                ),
                "{error:#}"
            );
            return false;
        }
    };
    let entries = listed
        .as_ref()
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    assert_eq!(artifacts.len(), entries.len());
    let mut names = BTreeSet::new();
    for (artifact, entry) in artifacts.iter().zip(entries) {
        assert_eq!(artifact.hook_id, HOOK_ID);
        assert!(asset_name(&artifact.name), "{:?}", artifact.name);
        assert!(
            media_type(&artifact.media_type),
            "{:?}",
            artifact.media_type
        );
        assert!(names.insert(artifact.name.as_str()), "{:?}", artifact.name);
        let entry = entry
            .as_object()
            .unwrap_or_else(|| panic!("an accepted artifact isn't a JSON object: {entry}"));
        let content = entry["content_base64"]
            .as_str()
            .expect("accepted content is a string");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(content)
                .ok(),
            Some(artifact.bytes.clone())
        );
        assert_eq!(
            artifact.public,
            entry.get("public").and_then(Value::as_bool) == Some(true)
        );
    }
    assert_eq!(
        parse_sidecar_artifacts(HOOK_ID, render_artifacts(&artifacts))
            .expect("rendered artifacts read back"),
        artifacts
    );
    true
}

fn render_artifacts(artifacts: &[SidecarArtifact]) -> Map<String, Value> {
    let listed: Vec<_> = artifacts
        .iter()
        .map(|artifact| {
            json!({
                "name": artifact.name,
                "media_type": artifact.media_type,
                "content_base64": base64::engine::general_purpose::STANDARD.encode(&artifact.bytes),
                "public": artifact.public,
            })
        })
        .collect();
    Map::from_iter([("artifacts".to_owned(), Value::Array(listed))])
}
