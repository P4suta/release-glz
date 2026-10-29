//! Properties of the Hex package and documentation archive validators.
//!
//! An accepted archive must stay within every limit, and each limit must refuse it one unit below its accepted size.

use release_glz::artifact::{
    ArchiveLimits, HexTarballValidation, fingerprint_hex_tarball, fingerprint_tar_gz,
    validate_and_fingerprint_docs_tarball, validate_and_fingerprint_hex_tarball,
    validate_docs_tarball, validate_hex_tarball,
};
use sha2::{Digest, Sha256};

const MAX_ENTRIES: usize = 128;
const MAX_ENTRY_BYTES: u64 = 256 * 1024;
const MAX_TOTAL_BYTES: u64 = 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024;
const LIMITS: ArchiveLimits = ArchiveLimits {
    max_entries: MAX_ENTRIES,
    max_entry_bytes: MAX_ENTRY_BYTES,
    max_total_bytes: MAX_TOTAL_BYTES,
    max_archive_bytes: MAX_ARCHIVE_BYTES,
};
const SHA256_HEX_LENGTH: usize = 64;

/// A validator that accepted an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reached {
    HexPackage,
    DocsArchive,
}

pub fn check(data: &[u8]) -> Vec<Reached> {
    [
        (hex(data), Reached::HexPackage),
        (docs(data), Reached::DocsArchive),
    ]
    .into_iter()
    .filter_map(|(accepted, validator)| accepted.then_some(validator))
    .collect()
}

fn lowercase_hex(text: &str) -> bool {
    text.len() == SHA256_HEX_LENGTH
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The largest archive size that refuses an accepted input.
fn one_byte_short(data: &[u8]) -> u64 {
    u64::try_from(data.len())
        .expect("an input length fits in u64")
        .checked_sub(1)
        .expect("an accepted archive has bytes")
}

fn outcome<T: Clone>(result: &anyhow::Result<T>) -> Result<T, String> {
    match result {
        Ok(value) => Ok(value.clone()),
        Err(error) => Err(format!("{error:#}")),
    }
}

fn hex(data: &[u8]) -> bool {
    let validated = validate_hex_tarball(data, LIMITS);
    assert_eq!(
        outcome(&validated),
        outcome(&validate_hex_tarball(data, LIMITS))
    );
    let combined = validate_and_fingerprint_hex_tarball(data, LIMITS);
    assert_eq!(validated.is_ok(), combined.is_ok());
    let Ok(validation) = validated else {
        return false;
    };
    let (combined_validation, fingerprint) = combined.expect("the combined validation agrees");
    assert_eq!(combined_validation, validation);
    assert_eq!(
        fingerprint_hex_tarball(data).expect("an accepted package fingerprints"),
        fingerprint
    );
    let digest: String = Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(validation.outer_checksum, digest);
    assert!(lowercase_hex(&validation.inner_checksum));
    assert!(validation.content_entries <= LIMITS.max_entries);
    assert!(validation.expanded_bytes <= LIMITS.max_total_bytes);
    assert_eq!(
        validate_hex_tarball(data, ArchiveLimits::default()).ok(),
        Some(validation.clone())
    );
    assert_limits_refuse_below(data, &validation);
    true
}

fn assert_limits_refuse_below(data: &[u8], validation: &HexTarballValidation) {
    assert!(
        validate_hex_tarball(
            data,
            ArchiveLimits {
                max_archive_bytes: one_byte_short(data),
                ..LIMITS
            }
        )
        .is_err()
    );
    if let Some(entries) = validation.content_entries.checked_sub(1) {
        assert!(
            validate_hex_tarball(
                data,
                ArchiveLimits {
                    max_entries: entries,
                    ..LIMITS
                }
            )
            .is_err()
        );
    }
    if let Some(total) = validation.expanded_bytes.checked_sub(1) {
        assert!(
            validate_hex_tarball(
                data,
                ArchiveLimits {
                    max_total_bytes: total,
                    ..LIMITS
                }
            )
            .is_err()
        );
    }
}

fn docs(data: &[u8]) -> bool {
    let validated = validate_docs_tarball(data, LIMITS);
    let combined = validate_and_fingerprint_docs_tarball(data, LIMITS);
    assert_eq!(validated.is_ok(), combined.is_ok());
    let Ok(fingerprint) = combined else {
        return false;
    };
    assert!(lowercase_hex(&fingerprint));
    assert_eq!(
        fingerprint_tar_gz(data).expect("an accepted archive fingerprints"),
        fingerprint
    );
    assert!(validate_docs_tarball(data, ArchiveLimits::default()).is_ok());
    assert!(
        validate_docs_tarball(
            data,
            ArchiveLimits {
                max_archive_bytes: one_byte_short(data),
                ..LIMITS
            }
        )
        .is_err()
    );
    true
}
