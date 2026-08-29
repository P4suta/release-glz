use anyhow::{Result, bail};
use semver::{Prerelease, Version};

use crate::model::{Bump, PrereleaseChannel};

pub fn core(version: &Version) -> Version {
    Version::new(version.major, version.minor, version.patch)
}

pub fn apply_bump(version: &Version, bump: Bump) -> Version {
    let mut next = core(version);
    match bump {
        Bump::None => {}
        Bump::Patch => next.patch += 1,
        Bump::Minor => {
            next.minor += 1;
            next.patch = 0;
        }
        Bump::Major => {
            next.major += 1;
            next.minor = 0;
            next.patch = 0;
        }
    }
    next
}

/// Apply Hex's pre-1.0 compatibility rule to a semantic release signal.
/// Breaking and additive API changes are both minor releases while the
/// current public major version is zero.
pub fn effective_bump(current: &Version, required: Bump) -> Bump {
    if current.major == 0 && required == Bump::Major {
        Bump::Minor
    } else {
        required
    }
}

/// Advance a prerelease train while enforcing alpha -> beta -> rc -> stable.
/// A backwards channel transition is permitted only when the caller has
/// supplied an explicitly higher core version.
pub fn next_prerelease_with_core(
    published: &Version,
    target_core: &Version,
    channel: PrereleaseChannel,
    explicitly_higher_core: bool,
) -> Result<Version> {
    let published_core = core(published);
    let target_core = core(target_core);
    if target_core < published_core {
        bail!("prerelease core {target_core} is behind published {published_core}");
    }

    if let Some((current, _)) = prerelease_parts(published)
        && channel_rank(channel.as_str()) < channel_rank(current)
    {
        if target_core == published_core {
            bail!(
                "cannot move prerelease channel backwards from {current} to {}; choose an explicitly higher core version",
                channel.as_str()
            );
        }
        if !explicitly_higher_core {
            bail!(
                "moving prerelease channel backwards from {current} to {} requires an explicitly higher core version",
                channel.as_str()
            );
        }
    }

    let number = if target_core == published_core {
        prerelease_parts(published)
            .filter(|(current, _)| *current == channel.as_str())
            .map(|(_, number)| number + 1)
            .unwrap_or(1)
    } else {
        1
    };
    let mut next = target_core;
    next.pre = Prerelease::new(&format!("{}.{number}", channel.as_str()))?;
    Ok(next)
}

fn channel_rank(channel: &str) -> u8 {
    match channel {
        "alpha" => 0,
        "beta" => 1,
        "rc" => 2,
        _ => u8::MAX,
    }
}

/// Select a release version from the latest published release, latest stable
/// release, required bump, optional explicit manifest version, and train.
pub fn select_version(
    published: &Version,
    latest_stable: Option<&Version>,
    required: Bump,
    explicit: Option<&Version>,
    channel: Option<PrereleaseChannel>,
) -> Result<Version> {
    let stable_base = latest_stable.map(core).unwrap_or_else(|| core(published));
    let required_core = apply_bump(&stable_base, required);
    let explicit_override = explicit.filter(|version| *version > published);
    let explicit_higher_core =
        explicit_override.is_some_and(|version| core(version) > core(published));
    let target_core = explicit_override
        .map(core)
        .map(|version| std::cmp::max(version, required_core.clone()))
        .unwrap_or_else(|| required_core.clone());

    let mut selected = match channel {
        Some(channel) => {
            next_prerelease_with_core(published, &target_core, channel, explicit_higher_core)?
        }
        None => std::cmp::max(core(published), required_core),
    };

    if let Some(explicit) = explicit {
        let explicit = match channel {
            Some(channel) if explicit.pre.is_empty() => {
                next_prerelease_with_core(published, explicit, channel, explicit_higher_core)?
            }
            Some(channel) if !explicit.pre.as_str().starts_with(channel.as_str()) => {
                bail!(
                    "explicit version {explicit} does not belong to the configured {} prerelease train",
                    channel.as_str()
                )
            }
            _ => explicit.clone(),
        };
        if &explicit <= published {
            // An unchanged manifest is not an explicit override.
        } else if explicit < selected {
            bail!("explicit manifest version {explicit} is below the required version {selected}");
        } else {
            selected = explicit;
        }
    }
    Ok(selected)
}

fn prerelease_parts(version: &Version) -> Option<(&str, u64)> {
    let (label, number) = version.pre.as_str().split_once('.')?;
    Some((label, number.parse().ok()?))
}

pub fn bump_between(from: &Version, to: &Version) -> Bump {
    if to.major != from.major {
        Bump::Major
    } else if to.minor != from.minor {
        Bump::Minor
    } else if to != from {
        Bump::Patch
    } else {
        Bump::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(input: &str) -> Version {
        input.parse().unwrap()
    }

    #[test]
    fn bump_lattice_is_semver_ordered() {
        let cases = [
            ("1.2.3", Bump::None, "1.2.3"),
            ("1.2.3", Bump::Patch, "1.2.4"),
            ("1.2.3", Bump::Minor, "1.3.0"),
            ("1.2.3", Bump::Major, "2.0.0"),
            ("0.4.2", Bump::Major, "1.0.0"),
        ];
        for (input, bump, expected) in cases {
            assert_eq!(apply_bump(&v(input), bump), v(expected));
        }
    }

    #[test]
    fn prerelease_train_transitions_and_promotes() {
        let cases = [
            (
                "1.2.0-alpha.1",
                "1.1.0",
                Bump::Minor,
                Some(PrereleaseChannel::Alpha),
                "1.2.0-alpha.2",
            ),
            (
                "1.2.0-alpha.2",
                "1.1.0",
                Bump::Minor,
                Some(PrereleaseChannel::Beta),
                "1.2.0-beta.1",
            ),
            (
                "1.2.0-beta.1",
                "1.1.0",
                Bump::Major,
                Some(PrereleaseChannel::Rc),
                "2.0.0-rc.1",
            ),
            ("1.2.0-rc.3", "1.1.0", Bump::Minor, None, "1.2.0"),
        ];
        for (published, stable, bump, channel, expected) in cases {
            assert_eq!(
                select_version(&v(published), Some(&v(stable)), bump, None, channel).unwrap(),
                v(expected)
            );
        }
    }

    #[test]
    fn explicit_version_can_only_raise_the_minimum() {
        assert_eq!(
            select_version(
                &v("1.0.0"),
                Some(&v("1.0.0")),
                Bump::Minor,
                Some(&v("2.0.0")),
                None
            )
            .unwrap(),
            v("2.0.0")
        );
        assert!(
            select_version(
                &v("1.0.0"),
                Some(&v("1.0.0")),
                Bump::Major,
                Some(&v("1.2.0")),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn explicit_core_version_stays_on_the_configured_train() {
        assert_eq!(
            select_version(
                &v("1.0.0"),
                Some(&v("1.0.0")),
                Bump::Minor,
                Some(&v("2.0.0")),
                Some(PrereleaseChannel::Beta),
            )
            .unwrap(),
            v("2.0.0-beta.1")
        );
    }

    #[test]
    fn backward_channel_moves_require_an_explicitly_higher_core() {
        assert!(
            select_version(
                &v("1.2.0-rc.2"),
                Some(&v("1.1.0")),
                Bump::Major,
                None,
                Some(PrereleaseChannel::Alpha),
            )
            .is_err()
        );
        assert_eq!(
            select_version(
                &v("1.2.0-rc.2"),
                Some(&v("1.1.0")),
                Bump::Patch,
                Some(&v("2.0.0")),
                Some(PrereleaseChannel::Alpha),
            )
            .unwrap(),
            v("2.0.0-alpha.1")
        );
    }

    #[test]
    fn effective_bump_property_matches_hex_zero_major_rules() {
        for major in 0..=2 {
            for required in [Bump::None, Bump::Patch, Bump::Minor, Bump::Major] {
                let current = Version::new(major, 7, 9);
                let expected = if major == 0 && required == Bump::Major {
                    Bump::Minor
                } else {
                    required
                };
                assert_eq!(effective_bump(&current, required), expected);
            }
        }
    }

    #[test]
    fn every_forward_train_transition_and_same_channel_increment_is_defined() {
        let cases = [
            ("1.2.0", PrereleaseChannel::Alpha, "1.2.0-alpha.1"),
            ("1.2.0-alpha.7", PrereleaseChannel::Alpha, "1.2.0-alpha.8"),
            ("1.2.0-alpha.7", PrereleaseChannel::Beta, "1.2.0-beta.1"),
            ("1.2.0-alpha.7", PrereleaseChannel::Rc, "1.2.0-rc.1"),
            ("1.2.0-beta.3", PrereleaseChannel::Beta, "1.2.0-beta.4"),
            ("1.2.0-beta.3", PrereleaseChannel::Rc, "1.2.0-rc.1"),
            ("1.2.0-rc.2", PrereleaseChannel::Rc, "1.2.0-rc.3"),
            (
                "1.2.0-alpha.preview",
                PrereleaseChannel::Alpha,
                "1.2.0-alpha.1",
            ),
        ];
        for (published, channel, expected) in cases {
            assert_eq!(
                next_prerelease_with_core(&v(published), &v("1.2.0"), channel, false).unwrap(),
                v(expected),
                "{published} -> {channel:?}"
            );
        }
    }

    #[test]
    fn prerelease_core_and_backward_transition_guards_are_fail_closed() {
        assert!(
            next_prerelease_with_core(
                &v("2.0.0-alpha.1"),
                &v("1.9.9"),
                PrereleaseChannel::Alpha,
                true,
            )
            .unwrap_err()
            .to_string()
            .contains("behind")
        );
        assert!(
            next_prerelease_with_core(
                &v("1.2.0-preview.4"),
                &v("1.2.0"),
                PrereleaseChannel::Alpha,
                false,
            )
            .unwrap_err()
            .to_string()
            .contains("backwards")
        );
        for (published, backwards) in [
            ("1.2.0-beta.1", PrereleaseChannel::Alpha),
            ("1.2.0-rc.1", PrereleaseChannel::Alpha),
            ("1.2.0-rc.1", PrereleaseChannel::Beta),
        ] {
            assert!(
                next_prerelease_with_core(&v(published), &v("1.2.0"), backwards, false,).is_err(),
                "{published} -> {backwards:?}"
            );
            assert!(
                next_prerelease_with_core(&v(published), &v("2.0.0"), backwards, false,).is_err(),
                "higher but non-explicit {published} -> {backwards:?}"
            );
            assert_eq!(
                next_prerelease_with_core(&v(published), &v("2.0.0"), backwards, true,).unwrap(),
                v(&format!("2.0.0-{}.1", backwards.as_str()))
            );
        }
    }

    #[test]
    fn a_higher_automatic_core_can_continue_the_same_prerelease_channel() {
        assert_eq!(
            next_prerelease_with_core(
                &v("1.2.0-alpha.7"),
                &v("1.3.0"),
                PrereleaseChannel::Alpha,
                false,
            )
            .unwrap(),
            v("1.3.0-alpha.1")
        );
    }

    #[test]
    fn channel_ranks_and_explicit_core_authority_have_exact_boundaries() {
        assert_eq!(channel_rank("alpha"), 0);
        assert_eq!(channel_rank("beta"), 1);
        assert_eq!(channel_rank("rc"), 2);
        assert_eq!(channel_rank("preview"), u8::MAX);

        let unchanged = select_version(
            &v("1.2.0-alpha.1"),
            Some(&v("1.1.0")),
            Bump::None,
            Some(&v("1.2.0-alpha.1")),
            Some(PrereleaseChannel::Alpha),
        )
        .unwrap_err()
        .to_string();
        assert!(unchanged.contains("behind published"), "{unchanged}");

        let same_core = select_version(
            &v("1.2.0-preview.1"),
            Some(&v("1.2.0")),
            Bump::Minor,
            Some(&v("1.2.0-rc.1")),
            Some(PrereleaseChannel::Rc),
        )
        .unwrap_err()
        .to_string();
        assert!(
            same_core.contains("requires an explicitly higher core version"),
            "{same_core}"
        );
    }

    #[test]
    fn version_selection_never_moves_below_the_published_core() {
        for published in ["1.2.3", "1.2.3-rc.4"] {
            assert_eq!(
                select_version(&v(published), Some(&v("1.1.0")), Bump::None, None, None,).unwrap(),
                v("1.2.3"),
                "stale stable observation lowered {published}"
            );
        }
    }

    #[test]
    fn select_version_covers_stable_prerelease_and_explicit_boundaries() {
        let cases = [
            ("1.2.0-alpha.1", None, Bump::None, None, None, "1.2.0"),
            ("1.2.3", None, Bump::Patch, None, None, "1.2.4"),
            (
                "1.2.3",
                Some("1.2.3"),
                Bump::None,
                Some("1.2.3"),
                None,
                "1.2.3",
            ),
            (
                "1.2.0-alpha.1",
                Some("1.1.0"),
                Bump::Minor,
                Some("1.2.0-alpha.3"),
                Some(PrereleaseChannel::Alpha),
                "1.2.0-alpha.3",
            ),
            (
                "1.2.0-alpha.1",
                Some("1.1.0"),
                Bump::Minor,
                Some("2.0.0-beta.4"),
                Some(PrereleaseChannel::Beta),
                "2.0.0-beta.4",
            ),
        ];
        for (published, stable, bump, explicit, channel, expected) in cases {
            let stable = stable.map(v);
            let explicit = explicit.map(v);
            assert_eq!(
                select_version(
                    &v(published),
                    stable.as_ref(),
                    bump,
                    explicit.as_ref(),
                    channel,
                )
                .unwrap(),
                v(expected)
            );
        }

        let wrong_train = select_version(
            &v("1.2.0-alpha.1"),
            Some(&v("1.1.0")),
            Bump::Minor,
            Some(&v("1.2.0-rc.3")),
            Some(PrereleaseChannel::Beta),
        )
        .unwrap_err();
        assert!(wrong_train.to_string().contains("does not belong"));
    }

    #[test]
    fn bump_between_property_classifies_the_highest_changed_core_component() {
        let from = v("1.2.3");
        for (to, expected) in [
            ("1.2.3", Bump::None),
            ("1.2.3-rc.1", Bump::Patch),
            ("1.2.4", Bump::Patch),
            ("1.3.0", Bump::Minor),
            ("2.0.0", Bump::Major),
            ("0.2.3", Bump::Major),
        ] {
            assert_eq!(bump_between(&from, &v(to)), expected, "{to}");
        }
    }
}
