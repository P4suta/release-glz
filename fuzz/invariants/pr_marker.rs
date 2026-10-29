//! Properties of the managed Release PR marker parser.
//!
//! A managed body ends in exactly one complete marker, so text after it or a second marker leaves the body unmanaged.

use release_glz::forge::is_managed_release_pr;
use sha2::{Digest, Sha256};

const MARKER_PREFIX: &str = "<!-- release-glz:managed ";
const MARKER_SUFFIX: &str = " -->";
const OBJECT_HEX_LENGTH: usize = 40;
const BRANCH_SUFFIX_LENGTH: usize = 8;

/// A verdict that accepted an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reached {
    Managed,
}

pub fn check(data: &[u8]) -> Vec<Reached> {
    let Ok(body) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    let managed = is_managed_release_pr(body);
    if managed {
        assert_eq!(body.matches(MARKER_PREFIX).count(), 1, "{body:?}");
        assert!(body.trim_end().ends_with(MARKER_SUFFIX), "{body:?}");
    }
    if !body.contains(MARKER_PREFIX) {
        assert!(!managed, "{body:?}");
        let marker = complete_marker(body);
        assert!(is_managed_release_pr(&marker), "{marker:?}");
        assert!(is_managed_release_pr(&format!("{body}\n{marker}")));
        assert!(!is_managed_release_pr(&format!("{marker}\n{marker}")));
        if !body.trim().is_empty() {
            assert!(!is_managed_release_pr(&format!("{marker}\n{body}")));
        }
    }
    if managed {
        vec![Reached::Managed]
    } else {
        Vec::new()
    }
}

/// A marker whose field values derive from the input and satisfy every marker rule.
fn complete_marker(body: &str) -> String {
    let digest: String = Sha256::digest(body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!(
        "{MARKER_PREFIX}package=widget branch=release-glz/{} head={} digest={digest} version=1.2.3 intent=pending{MARKER_SUFFIX}",
        &digest[..BRANCH_SUFFIX_LENGTH],
        &digest[..OBJECT_HEX_LENGTH],
    )
}
