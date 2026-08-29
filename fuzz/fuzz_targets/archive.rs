#![no_main]

use libfuzzer_sys::fuzz_target;
use release_glz::artifact::{ArchiveLimits, validate_docs_tarball, validate_hex_tarball};

fuzz_target!(|data: &[u8]| {
    let limits = ArchiveLimits {
        max_entries: 128,
        max_entry_bytes: 256 * 1024,
        max_total_bytes: 1024 * 1024,
        max_archive_bytes: 1024 * 1024,
    };
    let _ = validate_hex_tarball(data, limits);
    let _ = validate_docs_tarball(data, limits);
});
