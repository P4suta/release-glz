//! Properties of the reader of a sealed Candidate's `candidate.json`.
//!
//! An accepted manifest is the canonical JSON of its own value, so any other spelling of the same value is refused.
//! Its identity, tag, artifact paths, and hook evidence stay in the domain that sealing writes.
//! Every refusal names a typed reason, and bytes that aren't a manifest's JSON name the reason of an invalid manifest.

use release_glz::candidate::CandidateManifest;
use release_glz::canonical::canonical_json_bytes;
use release_glz::failure::{RefusalReason, refusal_reason};
use release_glz::forge::GitHubRepository;

const SCHEMA: &str = "candidate/v1";
const PACKAGE_FILE: &str = "artifacts/package.tar";
const DOCS_FILE: &str = "artifacts/docs.tar.gz";
const INTERFACE_FILE: &str = "artifacts/package-interface.json";
const COMMIT_DIGITS: usize = 40;
const DIGEST_DIGITS: usize = 64;
const MAX_RELEASE_NOTES_BYTES: usize = 1024 * 1024;

/// A verdict that accepted an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reached {
    Manifest,
}

pub fn check(data: &[u8]) -> Vec<Reached> {
    let manifest = match CandidateManifest::parse(data) {
        Ok(manifest) => manifest,
        Err(error) => {
            let reason = refusal_reason(&error);
            assert!(reason.is_some(), "an untyped refusal: {error:#}");
            if serde_json::from_slice::<CandidateManifest>(data).is_err() {
                assert_eq!(
                    reason,
                    Some(RefusalReason::CandidateManifestInvalid),
                    "{error:#}"
                );
            }
            return Vec::new();
        }
    };
    assert_eq!(
        canonical_json_bytes(&manifest).expect("an accepted manifest renders"),
        data
    );
    let mut respelled = b" ".to_vec();
    respelled.extend_from_slice(data);
    let error = CandidateManifest::parse(&respelled)
        .expect_err("a manifest that isn't canonical JSON is refused");
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::CandidateManifestInvalid),
        "{error:#}"
    );
    assert_domain(&manifest);
    vec![Reached::Manifest]
}

/// Whether `text` holds exactly `digits` lowercase hexadecimal digits.
fn lowercase_hex(text: &str, digits: usize) -> bool {
    text.len() == digits
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn assert_domain(manifest: &CandidateManifest) {
    assert_eq!(manifest.schema, SCHEMA);
    assert!(lowercase_hex(&manifest.source.commit_sha, COMMIT_DIGITS));
    assert!(!manifest.tag.starts_with("refs/") && !manifest.tag.ends_with("^{}"));
    assert!(manifest.tag.ends_with(&format!("v{}", manifest.version)));
    assert_eq!(
        GitHubRepository::parse(&manifest.github_repository)
            .expect("an accepted manifest names a valid repository")
            .full_name(),
        manifest.github_repository
    );
    assert!(manifest.release_notes.len() <= MAX_RELEASE_NOTES_BYTES);
    assert!(!manifest.release_notes.contains('\0'));
    let artifacts = &manifest.artifacts;
    assert_eq!(artifacts.package.path, PACKAGE_FILE);
    assert_eq!(artifacts.package_interface.path, INTERFACE_FILE);
    assert_eq!(artifacts.docs.is_some(), manifest.outputs.docs);
    for artifact in [&artifacts.package, &artifacts.package_interface]
        .into_iter()
        .chain(&artifacts.docs)
    {
        assert!(
            lowercase_hex(&artifact.sha256, DIGEST_DIGITS),
            "{artifact:?}"
        );
        assert!(
            lowercase_hex(&artifact.semantic_sha256, DIGEST_DIGITS),
            "{artifact:?}"
        );
    }
    if let Some(docs) = &artifacts.docs {
        assert_eq!(docs.path, DOCS_FILE);
    }
    for evidence in &manifest.hook_evidence {
        assert_eq!(evidence.schema, "hook/v1");
        assert!(!evidence.id.is_empty());
    }
    assert_eq!(
        manifest.notify_hooks.len(),
        manifest.notify_hook_definitions.len()
    );
    for (id, definition) in manifest
        .notify_hooks
        .iter()
        .zip(&manifest.notify_hook_definitions)
    {
        assert_eq!(id, &definition.id);
    }
}
