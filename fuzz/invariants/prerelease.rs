//! Properties of the core's prerelease reading and precedence.
//!
//! The core must accept exactly the prereleases that the `semver` crate accepts, spell each one back unchanged, and order versions as the `semver` crate does.

use release_glz_core::{Pre, Version, VersionCore, compare};

/// A path through the checks that an input reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reached {
    /// A valid prerelease that the core reads as a train.
    Train,
    /// A valid prerelease that the core keeps as text.
    Text,
    /// Two valid prereleases that the core orders as the `semver` crate does.
    Compared,
}

/// Check the prereleases on the first line of `data` and on the rest of it.
pub fn check(data: &[u8]) -> Vec<Reached> {
    let mut reached = Vec::new();
    let mut texts = data.splitn(2, |byte| *byte == b'\n');
    let left = read(texts.next().unwrap_or_default(), &mut reached);
    let right = read(texts.next().unwrap_or_default(), &mut reached);
    if let (Some((left, left_semver)), Some((right, right_semver))) = (left, right) {
        let core = VersionCore {
            major: 1,
            minor: 2,
            patch: 3,
        };
        let at = |pre| semver::Version {
            pre,
            ..semver::Version::new(core.major, core.minor, core.patch)
        };
        assert_eq!(
            compare(&Version { core, pre: left }, &Version { core, pre: right }),
            at(left_semver.clone()).cmp(&at(right_semver.clone())),
            "{left_semver} against {right_semver}"
        );
        reached.push(Reached::Compared);
    }
    reached
}

/// The prerelease that `text` spells, when the `semver` crate accepts it.
fn read<'a>(text: &'a [u8], reached: &mut Vec<Reached>) -> Option<(Pre<'a>, semver::Prerelease)> {
    let expected = std::str::from_utf8(text)
        .ok()
        .and_then(|text| semver::Prerelease::new(text).ok());
    let pre = Pre::parse(text);
    assert_eq!(pre.is_valid(), expected.is_some(), "{text:?}");
    let expected = expected?;
    assert_eq!(spelled(pre), text, "{expected}");
    match pre {
        Pre::Stable => {}
        Pre::Train(..) => reached.push(Reached::Train),
        Pre::Other(_) => reached.push(Reached::Text),
    }
    Some((pre, expected))
}

/// The text that spells `pre`.
fn spelled(pre: Pre<'_>) -> Vec<u8> {
    match pre {
        Pre::Stable => Vec::new(),
        Pre::Train(channel, number) => format!("{}.{number}", channel.label()).into_bytes(),
        Pre::Other(text) => text.to_vec(),
    }
}
