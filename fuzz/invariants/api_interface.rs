//! Properties of the package interface comparison that decides the API part of a release bump.
//!
//! An input holds the baseline interface, a NUL byte, and the local interface.
//! An input without a NUL byte compares one interface with itself.

use release_glz::api::compare;
use release_glz::model::{ApiChangeKind, ApiDiff, ApiStatus, Bump};

const SEPARATOR: u8 = 0;

/// A comparison outcome that an input reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reached {
    Compared,
    Changed,
}

pub fn check(data: &[u8]) -> Vec<Reached> {
    let (old, new) = match data.iter().position(|byte| *byte == SEPARATOR) {
        Some(index) => (&data[..index], &data[index + 1..]),
        None => (data, data),
    };
    for interface in [old, new] {
        if let Ok(diff) = compare(interface, interface) {
            assert!(diff.changes.is_empty(), "{diff:?}");
            assert_eq!(diff.status, ApiStatus::Compatible);
            assert_eq!(diff.impact, Bump::None);
        }
    }
    let Ok(forward) = compare(old, new) else {
        return Vec::new();
    };
    let backward = compare(new, old).expect("a comparison succeeds in both directions");
    assert_derived_fields(&forward);
    assert_derived_fields(&backward);
    assert_eq!(removals(&forward), additions(&backward));
    assert_eq!(additions(&forward), removals(&backward));
    assert_eq!(
        paths(&forward, ApiChangeKind::Changed),
        paths(&backward, ApiChangeKind::Changed)
    );
    if forward.changes.is_empty() {
        vec![Reached::Compared]
    } else {
        vec![Reached::Compared, Reached::Changed]
    }
}

/// The status, the impact, and each breaking flag follow from the list of changes.
fn assert_derived_fields(diff: &ApiDiff) {
    for change in &diff.changes {
        let breaking = !matches!(change.kind, ApiChangeKind::Added);
        assert_eq!(change.breaking, breaking, "{change:?}");
    }
    let expected_impact = if diff.changes.iter().any(|change| change.breaking) {
        Bump::Major
    } else if diff.changes.is_empty() {
        Bump::None
    } else {
        Bump::Minor
    };
    assert_eq!(diff.impact, expected_impact);
    let expected_status = if diff.changes.is_empty() {
        ApiStatus::Compatible
    } else {
        ApiStatus::Changed
    };
    assert_eq!(diff.status, expected_status);
    assert!(
        diff.changes
            .windows(2)
            .all(|pair| (&pair[0].path, &pair[0].summary) <= (&pair[1].path, &pair[1].summary))
    );
}

fn paths(diff: &ApiDiff, kind: ApiChangeKind) -> Vec<&str> {
    let mut paths: Vec<_> = diff
        .changes
        .iter()
        .filter(|change| change.kind == kind)
        .map(|change| change.path.as_str())
        .collect();
    paths.sort_unstable();
    paths
}

fn removals(diff: &ApiDiff) -> Vec<&str> {
    paths(diff, ApiChangeKind::Removed)
}

/// A constructor added to an existing type is the inverse of a removed constructor.
fn additions(diff: &ApiDiff) -> Vec<&str> {
    let mut added = paths(diff, ApiChangeKind::Added);
    added.extend(paths(diff, ApiChangeKind::ConstructorAdded));
    added.sort_unstable();
    added
}
