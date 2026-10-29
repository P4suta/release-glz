//! Properties of the managed Release PR marker parser.
//!
//! A body is managed only through the marker, and a complete marker makes any body without one managed.

use release_glz::forge::is_managed_release_pr;

const MARKER_PREFIX: &str = "<!-- release-glz:managed ";

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
    if !body.contains(MARKER_PREFIX) {
        assert!(!managed, "{body:?}");
        let value: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let marker = complete_marker(&value);
        assert!(is_managed_release_pr(&marker), "{marker:?}");
        assert!(is_managed_release_pr(&format!("{body}\n{marker}")));
    }
    if managed {
        vec![Reached::Managed]
    } else {
        Vec::new()
    }
}

/// A marker that carries every required field, each set to one whitespace-free value.
fn complete_marker(value: &str) -> String {
    format!(
        "{MARKER_PREFIX}package={value} branch={value} head={value} digest={value} version={value} intent=pending -->"
    )
}
