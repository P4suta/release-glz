//! Version arithmetic for the planner: core versions, release steps, and prerelease trains.
//!
//! The decisions live in `release-glz-core`, where Kani proves them, and this module adapts `semver` versions to them and words their refusals.
//! Precedence there ignores build metadata, as semantic versioning does.

use anyhow::{Result, anyhow, bail};
use release_glz_core::{Computed, Initial, Pre, Refusal, Selection, VersionCore};
use semver::{Prerelease, Version};

use crate::model::{Bump, PrereleaseChannel, bump_name};

/// Drop the prerelease and build metadata, leaving `major.minor.patch`.
pub fn core(version: &Version) -> Version {
    Version::new(version.major, version.minor, version.patch)
}

/// The version as the core crate compares it, without build metadata.
pub fn view(version: &Version) -> release_glz_core::Version<'_> {
    release_glz_core::Version {
        core: version_core(version),
        pre: Pre::parse(version.pre.as_str().as_bytes()),
    }
}

fn version_core(version: &Version) -> VersionCore {
    VersionCore {
        major: version.major,
        minor: version.minor,
        patch: version.patch,
    }
}

/// Whether `version` has a higher precedence than `other`, which build metadata never decides.
pub fn follows(version: &Version, other: &Version) -> bool {
    view(version).follows(&view(other))
}

/// Raise a version by one release step.
///
/// The result is always a stable core version; a prerelease train is started separately by [`next_prerelease_with_core`].
/// A step that would carry a component past `u64::MAX` is refused rather than wrapped.
pub fn apply_bump(version: &Version, bump: Bump) -> Result<Version> {
    let Some(next) = version_core(version).bumped(bump) else {
        let bump = bump_name(bump);
        bail!("{version} has the largest {bump} number, so no {bump} release can follow it");
    };
    Ok(Version::new(next.major, next.minor, next.patch))
}

/// Apply Hex's pre-1.0 compatibility rule to a semantic release signal.
/// Breaking and additive API changes are both minor releases while the current public major version is zero.
pub fn effective_bump(current: &Version, required: Bump) -> Bump {
    release_glz_core::effective_bump(current.major, required)
}

/// Advance a prerelease train while enforcing alpha -> beta -> rc -> stable.
/// A backwards channel transition is permitted only when the caller has supplied an explicitly higher core version.
pub fn next_prerelease_with_core(
    published: &Version,
    target_core: &Version,
    channel: PrereleaseChannel,
    explicitly_higher_core: bool,
) -> Result<Version> {
    match release_glz_core::next_prerelease(
        &view(published),
        version_core(target_core),
        channel.into(),
        explicitly_higher_core,
    ) {
        Ok(next) => render(next),
        Err(refusal) => Err(refused(refusal, published, None)),
    }
}

/// Select a release version from the latest published release, latest stable release, required bump, optional explicit manifest version, and train.
///
/// The selection always follows the published version, so it never names a version that is already published.
pub fn select_version(
    published: &Version,
    latest_stable: Option<&Version>,
    required: Bump,
    explicit: Option<&Version>,
    channel: Option<PrereleaseChannel>,
) -> Result<Version> {
    let explicit_view = explicit.map(view);
    match release_glz_core::select_version(
        &view(published),
        latest_stable.map(version_core),
        required,
        explicit_view.as_ref(),
        channel.map(Into::into),
    ) {
        Ok(Selection::Computed(computed)) => render(computed),
        Ok(Selection::Explicit) => explicit
            .cloned()
            .ok_or_else(|| anyhow!("the selection took an explicit version that wasn't given")),
        Err(refusal) => Err(refused(refusal, published, explicit)),
    }
}

/// The version of a package's first release, from the manifest's `version`.
///
/// A configured train puts a stable version on its first prerelease and refuses a prerelease of another train.
/// Without a train, `stable` drops the prerelease of a version that the caller asked to release as stable.
pub fn initial_version(
    version: &Version,
    channel: Option<PrereleaseChannel>,
    stable: bool,
) -> Result<Version> {
    match release_glz_core::initial_version(&view(version), channel.map(Into::into), stable) {
        Ok(Initial::Unchanged) => Ok(version.clone()),
        Ok(Initial::Computed(computed)) => {
            let mut initial = render(computed)?;
            initial.build = version.build.clone();
            Ok(initial)
        }
        Err(Refusal::ExplicitOffTrain { channel }) => bail!(
            "initial version {version} does not belong to the configured {} prerelease train",
            channel.label()
        ),
        Err(refusal) => Err(refused(refusal, version, Some(version))),
    }
}

/// Report the release step that separates two versions.
///
/// `set-version` uses this to check that an explicitly requested version is at least as large as the automatically required one.
pub fn bump_between(from: &Version, to: &Version) -> Bump {
    release_glz_core::bump_between(&view(from), &view(to))
}

/// The `semver` version that a computed selection names.
fn render(computed: Computed) -> Result<Version> {
    let mut version = Version::new(
        computed.core.major,
        computed.core.minor,
        computed.core.patch,
    );
    if let Some((channel, number)) = computed.train {
        version.pre = Prerelease::new(&format!("{}.{number}", channel.label()))?;
    }
    Ok(version)
}

/// A computed version as text, for a message.
fn text(computed: Computed) -> String {
    let core = computed.core;
    match computed.train {
        Some((channel, number)) => format!(
            "{}.{}.{}-{}.{number}",
            core.major,
            core.minor,
            core.patch,
            channel.label()
        ),
        None => format!("{}.{}.{}", core.major, core.minor, core.patch),
    }
}

/// The error that explains a refusal of the core crate.
fn refused(refusal: Refusal, published: &Version, explicit: Option<&Version>) -> anyhow::Error {
    let current = published.pre.as_str().split('.').next().unwrap_or_default();
    let core_text = |core: VersionCore| format!("{}.{}.{}", core.major, core.minor, core.patch);
    let explicit = explicit.map_or_else(String::new, ToString::to_string);
    anyhow!(match refusal {
        Refusal::StepOverflow { core, bump } => format!(
            "{} has the largest {bump} number, so no {bump} release can follow it",
            core_text(core),
            bump = bump_name(bump)
        ),
        Refusal::BehindPublishedCore { target } => format!(
            "prerelease core {} is behind published {}",
            core_text(target),
            core(published)
        ),
        Refusal::BackwardOnPublishedCore { channel } => format!(
            "cannot move prerelease channel backwards from {current} to {}; choose an explicitly higher core version",
            channel.label()
        ),
        Refusal::BackwardWithoutExplicitCore { channel } => format!(
            "moving prerelease channel backwards from {current} to {} requires an explicitly higher core version",
            channel.label()
        ),
        Refusal::TrainExhausted => format!(
            "{published} has the largest {current} number, so choose an explicitly higher core version"
        ),
        Refusal::TrainNotAfterPublished { next } => format!(
            "selected prerelease {} does not sort after published {published}; choose an explicitly higher core version",
            text(next)
        ),
        Refusal::ExplicitOffTrain { channel } => format!(
            "explicit version {explicit} does not belong to the configured {} prerelease train",
            channel.label()
        ),
        Refusal::ExplicitBelowRequired {
            candidate,
            required,
        } => format!(
            "explicit manifest version {} is below the required version {}",
            candidate.map_or(explicit, text),
            text(required)
        ),
        Refusal::NotAfterPublished { selected } => format!(
            "the selected version {} doesn't follow the published version {published}, so there is nothing new to release",
            text(selected)
        ),
    })
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
            assert_eq!(apply_bump(&v(input), bump).unwrap(), v(expected));
        }
    }

    #[test]
    fn a_step_past_the_largest_component_is_refused() {
        let max = u64::MAX;
        for (input, bump) in [
            (format!("1.2.{max}"), Bump::Patch),
            (format!("1.{max}.3"), Bump::Minor),
            (format!("{max}.2.3"), Bump::Major),
        ] {
            assert!(apply_bump(&v(&input), bump).is_err(), "{input} {bump:?}");
        }
        assert_eq!(
            apply_bump(&v(&format!("1.2.{max}")), Bump::Minor).unwrap(),
            v("1.3.0")
        );

        let published = v(&format!("1.2.0-alpha.{max}"));
        let error =
            next_prerelease_with_core(&published, &v("1.2.0"), PrereleaseChannel::Alpha, false)
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "1.2.0-alpha.{max} has the largest alpha number, so choose an explicitly higher core version"
            )
        );
        let error =
            select_version(&v(&format!("{max}.0.0")), None, Bump::Major, None, None).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("{max}.0.0 has the largest major number, so no major release can follow it")
        );
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
        let below = select_version(
            &v("1.0.0"),
            Some(&v("1.0.0")),
            Bump::Major,
            Some(&v("1.2.0")),
            None,
        )
        .unwrap_err();
        assert_eq!(
            below.to_string(),
            "explicit manifest version 1.2.0 is below the required version 2.0.0"
        );
        let train_below = select_version(
            &v("1.0.0"),
            Some(&v("1.0.0")),
            Bump::Major,
            Some(&v("1.2.0")),
            Some(PrereleaseChannel::Beta),
        )
        .unwrap_err();
        assert_eq!(
            train_below.to_string(),
            "explicit manifest version 1.2.0-beta.1 is below the required version 2.0.0-beta.1"
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
    fn an_explicit_version_keeps_its_build_metadata_but_build_metadata_alone_is_no_override() {
        assert_eq!(
            select_version(
                &v("1.0.0"),
                Some(&v("1.0.0")),
                Bump::Minor,
                Some(&v("2.0.0+build.7")),
                None,
            )
            .unwrap()
            .to_string(),
            "2.0.0+build.7"
        );
        assert!(!follows(&v("1.0.0+build.7"), &v("1.0.0")));
        assert!(follows(&v("1.0.1+build.7"), &v("1.0.0")));
        let unchanged = select_version(
            &v("1.0.0"),
            Some(&v("1.0.0")),
            Bump::None,
            Some(&v("1.0.0+build.7")),
            None,
        )
        .unwrap_err();
        assert_eq!(
            unchanged.to_string(),
            "the selected version 1.0.0 doesn't follow the published version 1.0.0, so there is nothing new to release"
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
            ("1.2.0-alpha.7", PrereleaseChannel::Alpha, "1.2.0-alpha.8"),
            ("1.2.0-alpha.7", PrereleaseChannel::Beta, "1.2.0-beta.1"),
            ("1.2.0-alpha.7", PrereleaseChannel::Rc, "1.2.0-rc.1"),
            ("1.2.0-beta.3", PrereleaseChannel::Beta, "1.2.0-beta.4"),
            ("1.2.0-beta.3", PrereleaseChannel::Rc, "1.2.0-rc.1"),
            ("1.2.0-rc.2", PrereleaseChannel::Rc, "1.2.0-rc.3"),
        ];
        for (published, channel, expected) in cases {
            assert_eq!(
                next_prerelease_with_core(&v(published), &v("1.2.0"), channel, false).unwrap(),
                v(expected),
                "{published} -> {channel:?}"
            );
        }

        let non_numeric = next_prerelease_with_core(
            &v("1.2.0-alpha.preview"),
            &v("1.2.0"),
            PrereleaseChannel::Alpha,
            false,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            non_numeric,
            "selected prerelease 1.2.0-alpha.1 does not sort after published 1.2.0-alpha.preview; choose an explicitly higher core version"
        );
        let stable_core_reuse =
            next_prerelease_with_core(&v("1.2.0"), &v("1.2.0"), PrereleaseChannel::Alpha, false)
                .unwrap_err()
                .to_string();
        assert!(stable_core_reuse.contains("does not sort after"));
        assert_eq!(
            next_prerelease_with_core(&v("1.2.0"), &v("1.2.1"), PrereleaseChannel::Alpha, false,)
                .unwrap(),
            v("1.2.1-alpha.1")
        );
    }

    #[test]
    fn prerelease_core_and_backward_transition_guards_are_fail_closed() {
        assert_eq!(
            next_prerelease_with_core(
                &v("2.0.0-alpha.1"),
                &v("1.9.9"),
                PrereleaseChannel::Alpha,
                true,
            )
            .unwrap_err()
            .to_string(),
            "prerelease core 1.9.9 is behind published 2.0.0"
        );
        assert_eq!(
            next_prerelease_with_core(
                &v("1.2.0-preview.4"),
                &v("1.2.0"),
                PrereleaseChannel::Alpha,
                false,
            )
            .unwrap_err()
            .to_string(),
            "cannot move prerelease channel backwards from preview to alpha; choose an explicitly higher core version"
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
    fn explicit_core_authority_has_exact_boundaries() {
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
        assert_eq!(
            same_core,
            "moving prerelease channel backwards from preview to rc requires an explicitly higher core version"
        );
    }

    #[test]
    fn version_selection_never_moves_below_or_onto_the_published_version() {
        assert_eq!(
            select_version(&v("1.2.3-rc.4"), Some(&v("1.1.0")), Bump::None, None, None).unwrap(),
            v("1.2.3"),
            "a stale stable observation lowered the selection"
        );
        let unchanged = select_version(&v("1.2.3"), Some(&v("1.1.0")), Bump::None, None, None)
            .unwrap_err()
            .to_string();
        assert!(unchanged.contains("doesn't follow"), "{unchanged}");
    }

    #[test]
    fn select_version_covers_stable_prerelease_and_explicit_boundaries() {
        let cases = [
            ("1.2.0-alpha.1", None, Bump::None, None, None, "1.2.0"),
            ("1.2.3", None, Bump::Patch, None, None, "1.2.4"),
            (
                "1.2.3",
                Some("1.2.3"),
                Bump::Patch,
                Some("1.2.3"),
                None,
                "1.2.4",
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
        assert_eq!(
            wrong_train.to_string(),
            "explicit version 1.2.0-rc.3 does not belong to the configured beta prerelease train"
        );

        let prefixed_train = select_version(
            &v("1.2.0-alpha.1"),
            Some(&v("1.1.0")),
            Bump::Minor,
            Some(&v("1.3.0-alphax.1")),
            Some(PrereleaseChannel::Alpha),
        )
        .unwrap_err();
        assert!(prefixed_train.to_string().contains("does not belong"));
    }

    #[test]
    fn a_first_release_joins_the_configured_train_and_keeps_its_build_metadata() {
        let cases = [
            (
                "1.0.0",
                Some(PrereleaseChannel::Alpha),
                false,
                "1.0.0-alpha.1",
            ),
            (
                "1.0.0+b.1",
                Some(PrereleaseChannel::Rc),
                false,
                "1.0.0-rc.1+b.1",
            ),
            (
                "1.0.0-beta.3",
                Some(PrereleaseChannel::Beta),
                false,
                "1.0.0-beta.3",
            ),
            ("1.0.0-beta.3", None, true, "1.0.0"),
            ("1.0.0-beta.3", None, false, "1.0.0-beta.3"),
            ("1.0.0", None, true, "1.0.0"),
        ];
        for (version, channel, stable, expected) in cases {
            assert_eq!(
                initial_version(&v(version), channel, stable)
                    .unwrap()
                    .to_string(),
                expected,
                "{version} {channel:?} {stable}"
            );
        }
        assert_eq!(
            initial_version(&v("1.0.0-beta.3"), Some(PrereleaseChannel::Alpha), false)
                .unwrap_err()
                .to_string(),
            "initial version 1.0.0-beta.3 does not belong to the configured alpha prerelease train"
        );
    }

    #[test]
    fn bump_between_property_classifies_the_highest_changed_core_component() {
        let from = v("1.2.3");
        for (to, expected) in [
            ("1.2.3", Bump::None),
            ("1.2.3+build", Bump::None),
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
