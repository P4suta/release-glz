//! The core crate's precedence and prerelease grammar agree with the `semver` crate, which the registry and the planner read versions with.
//!
//! The Kani proofs of the version decisions rely on that precedence and assume that grammar, so these tests tie both to an independent implementation.

use release_glz::version::view;
use release_glz_core::{Channel, Pre, VersionCore, compare};
use semver::{BuildMetadata, Prerelease, Version};

const PRERELEASES: [&str; 31] = [
    "",
    "0",
    "1",
    "10",
    "99999999999999999999",
    "100000000000000000000",
    "-",
    "A",
    "a-1",
    "x",
    "x-y",
    "Z.9",
    "1.2",
    "a.b.c",
    "alpha",
    "alpha.0",
    "alpha.1",
    "alpha.2",
    "alpha.10",
    "alpha.18446744073709551615",
    "alpha.18446744073709551616",
    "alpha.beta",
    "alpha.preview",
    "alpha.1.beta",
    "beta",
    "beta.2",
    "beta.11",
    "preview.4",
    "rc.1",
    "rc.1.1",
    "rc",
];

fn versions() -> Vec<Version> {
    let mut versions = Vec::new();
    for major in 0..3 {
        for minor in 0..3 {
            for patch in 0..3 {
                for pre in PRERELEASES {
                    let mut version = Version::new(major, minor, patch);
                    version.pre = Prerelease::new(pre).unwrap();
                    versions.push(version);
                }
            }
        }
    }
    versions
}

#[test]
fn core_precedence_agrees_with_semver_on_every_pair() {
    let versions = versions();
    for left in &versions {
        for right in &versions {
            assert_eq!(
                compare(&view(left), &view(right)),
                left.cmp(right),
                "{left} against {right}"
            );
        }
    }
}

#[test]
fn a_train_compares_like_the_prerelease_that_spells_it() {
    let core = Version::new(1, 1, 1);
    let mut trains = Vec::new();
    for channel in [Channel::Alpha, Channel::Beta, Channel::Rc] {
        for number in [0, 1, 2, 10, 11, u64::MAX] {
            trains.push((channel, number));
        }
    }
    let train = |(channel, number)| release_glz_core::Version {
        core: VersionCore {
            major: core.major,
            minor: core.minor,
            patch: core.patch,
        },
        pre: Pre::Train(channel, number),
    };
    let spelled = |(channel, number): (Channel, u64)| {
        let mut version = core.clone();
        version.pre = Prerelease::new(&format!("{}.{number}", channel.label())).unwrap();
        version
    };
    let versions = versions();
    for &left in &trains {
        for version in &versions {
            assert_eq!(
                compare(&train(left), &view(version)),
                spelled(left).cmp(version),
                "{} against {version}",
                spelled(left)
            );
            assert_eq!(
                compare(&view(version), &train(left)),
                version.cmp(&spelled(left)),
                "{version} against {}",
                spelled(left)
            );
        }
        for &right in &trains {
            assert_eq!(
                compare(&train(left), &train(right)),
                spelled(left).cmp(&spelled(right)),
                "{} against {}",
                spelled(left),
                spelled(right)
            );
        }
    }
}

/// The selection proofs cover published versions that are stable or on a train, so every train spelling has to parse as its train.
#[test]
fn parse_reads_every_train_spelling_as_its_train() {
    for (text, channel, number) in [
        ("alpha.0", Channel::Alpha, 0),
        ("beta.11", Channel::Beta, 11),
        ("rc.18446744073709551615", Channel::Rc, u64::MAX),
    ] {
        assert!(
            matches!(Pre::parse(text.as_bytes()), Pre::Train(parsed, value) if parsed == channel && value == number),
            "{text}"
        );
    }
    for text in [
        "rc.18446744073709551616",
        "rc",
        "rc.1.1",
        "rc.x",
        "preview.4",
        "alpha.beta",
        "1.2",
        "alpha.01",
    ] {
        assert!(
            matches!(Pre::parse(text.as_bytes()), Pre::Other(other) if other == text.as_bytes()),
            "{text}"
        );
    }
    assert!(matches!(Pre::parse(b""), Pre::Stable));
}

#[test]
fn build_metadata_never_changes_precedence() {
    for version in versions() {
        let mut built = version.clone();
        built.build = BuildMetadata::new("build.7").unwrap();
        assert_eq!(
            compare(&view(&built), &view(&version)),
            std::cmp::Ordering::Equal,
            "{built}"
        );
    }
}

#[test]
fn the_prerelease_grammar_agrees_with_semver_on_every_short_text() {
    let alphabet = [b'0', b'1', b'a', b'Z', b'-', b'.', b'+', b'_'];
    let mut level = vec![Vec::new()];
    let mut texts = Vec::new();
    for _ in 0..4 {
        level = level
            .iter()
            .flat_map(|text: &Vec<u8>| {
                alphabet.iter().map(move |byte| {
                    let mut next = text.clone();
                    next.push(*byte);
                    next
                })
            })
            .collect();
        texts.extend(level.iter().cloned());
    }
    for text in &texts {
        let spelled = std::str::from_utf8(text).unwrap();
        assert_eq!(
            Pre::parse(text).is_valid(),
            Prerelease::new(spelled).is_ok(),
            "{spelled:?}"
        );
    }
}
