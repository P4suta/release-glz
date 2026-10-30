//! The version that a release takes.
//!
//! The planner decides it from the latest published version, the latest stable one, the required step, an explicit version, and the configured train.

use core::cmp::{Ordering, max};

use crate::precedence::{Channel, Label, Pre, Version, compare};
use crate::{Bump, VersionCore, increment};

/// A version that the selection computed rather than took from the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Computed {
    /// The numeric core.
    pub core: VersionCore,
    /// The train and its number, for a prerelease.
    pub train: Option<(Channel, u64)>,
}

impl Computed {
    /// The version this computation names.
    pub const fn version(self) -> Version<'static> {
        Version {
            core: self.core,
            pre: match self.train {
                Some((channel, number)) => Pre::Train(channel, number),
                None => Pre::Stable,
            },
        }
    }
}

/// The version selected for a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// A version that the selection computed.
    Computed(Computed),
    /// The explicit version, exactly as the manifest spells it.
    Explicit,
}

/// Why no version can be selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The required step would carry a component of `core` past the largest number.
    StepOverflow {
        /// The core the step starts from.
        core: VersionCore,
        /// The step.
        bump: Bump,
    },
    /// The train's core is behind the published one.
    BehindPublishedCore {
        /// The train's core.
        target: VersionCore,
    },
    /// The train would move back to an earlier channel on the published core.
    BackwardOnPublishedCore {
        /// The channel it would move to.
        channel: Channel,
    },
    /// The train would move back to an earlier channel without an explicitly higher core.
    BackwardWithoutExplicitCore {
        /// The channel it would move to.
        channel: Channel,
    },
    /// The published train number is already the largest one.
    TrainExhausted,
    /// The next train version wouldn't sort after the published one.
    TrainNotAfterPublished {
        /// The next train version.
        next: Computed,
    },
    /// The explicit version belongs to another train than the configured one.
    ExplicitOffTrain {
        /// The configured channel.
        channel: Channel,
    },
    /// The explicit version is below the required one.
    ExplicitBelowRequired {
        /// The train version the explicit core became, when the manifest named a core on a train.
        candidate: Option<Computed>,
        /// The version the release requires at least.
        required: Computed,
    },
    /// The selection wouldn't follow the published version.
    NotAfterPublished {
        /// The selection.
        selected: Computed,
    },
}

/// The next version on `channel`'s train after `published`, on the core `target`.
///
/// A train moves through alpha, beta, and rc, or counts up within one channel.
/// A move back to an earlier channel needs a core above the published one that the manifest named explicitly.
pub fn next_prerelease(
    published: &Version<'_>,
    target: VersionCore,
    channel: Channel,
    explicitly_higher_core: bool,
) -> Result<Computed, Refusal> {
    if target < published.core {
        return Err(Refusal::BehindPublishedCore { target });
    }
    let current = published.pre.numbered_label();
    if let Some((label, _)) = current
        && moves_back(label, channel)
    {
        if target == published.core {
            return Err(Refusal::BackwardOnPublishedCore { channel });
        }
        if !explicitly_higher_core {
            return Err(Refusal::BackwardWithoutExplicitCore { channel });
        }
    }
    let number = match current {
        Some((Label::Channel(current), number))
            if target == published.core && current == channel =>
        {
            increment(number).ok_or(Refusal::TrainExhausted)?
        }
        _ => 1,
    };
    let next = Computed {
        core: target,
        train: Some((channel, number)),
    };
    if !next.version().follows(published) {
        return Err(Refusal::TrainNotAfterPublished { next });
    }
    Ok(next)
}

/// Whether moving from a prerelease labeled `current` to `channel` goes back along the train.
fn moves_back(current: Label, channel: Channel) -> bool {
    #[cfg(feature = "negative-control-backward-train")]
    return Label::Channel(channel).rank() > current.rank();
    #[cfg(not(feature = "negative-control-backward-train"))]
    return Label::Channel(channel).rank() < current.rank();
}

/// Select the version of a release that follows `published`.
///
/// The step starts from `latest_stable`, or from the published core when nothing stable is published.
/// An explicit version that follows the published one overrides the computed version only when it isn't lower, and with a train it has to belong to that train.
pub fn select_version(
    published: &Version<'_>,
    latest_stable: Option<VersionCore>,
    required: Bump,
    explicit: Option<&Version<'_>>,
    channel: Option<Channel>,
) -> Result<Selection, Refusal> {
    let base = latest_stable.unwrap_or(published.core);
    let required_core = base.bumped(required).ok_or(Refusal::StepOverflow {
        core: base,
        bump: required,
    })?;
    let explicit_override = explicit.filter(|explicit| explicit.follows(published));
    let explicitly_higher_core =
        explicit_override.is_some_and(|explicit| explicit.core > published.core);
    let target =
        explicit_override.map_or(required_core, |explicit| max(explicit.core, required_core));
    let computed = match channel {
        Some(channel) => next_prerelease(published, target, channel, explicitly_higher_core)?,
        None => Computed {
            core: stable_core(published.core, required_core),
            train: None,
        },
    };
    let mut selected = Selection::Computed(computed);
    if let Some(explicit) = explicit {
        let (candidate, version) = match channel {
            Some(channel) if matches!(explicit.pre, Pre::Stable) => {
                let train =
                    next_prerelease(published, explicit.core, channel, explicitly_higher_core)?;
                (Selection::Computed(train), train.version())
            }
            Some(channel) if !explicit.pre.starts_with(channel) => {
                return Err(Refusal::ExplicitOffTrain { channel });
            }
            _ => (Selection::Explicit, *explicit),
        };
        if !version.follows(published) {
            // An unchanged manifest is no explicit override.
        } else if below_required(&version, &computed.version()) {
            return Err(Refusal::ExplicitBelowRequired {
                candidate: match candidate {
                    Selection::Computed(train) => Some(train),
                    Selection::Explicit => None,
                },
                required: computed,
            });
        } else {
            selected = candidate;
        }
    }
    if let Selection::Computed(selected) = selected
        && !after_published(&selected.version(), published)
    {
        return Err(Refusal::NotAfterPublished { selected });
    }
    Ok(selected)
}

/// The core of a stable selection, which never falls below the published core.
fn stable_core(published: VersionCore, required: VersionCore) -> VersionCore {
    #[cfg(feature = "negative-control-understep")]
    let _ = required;
    #[cfg(feature = "negative-control-understep")]
    return published;
    #[cfg(not(feature = "negative-control-understep"))]
    return max(published, required);
}

/// Whether an explicit version is lower than the version the release requires.
fn below_required(explicit: &Version<'_>, required: &Version<'_>) -> bool {
    #[cfg(feature = "negative-control-override-floor")]
    return compare(explicit, required) == Ordering::Greater;
    #[cfg(not(feature = "negative-control-override-floor"))]
    return compare(explicit, required) == Ordering::Less;
}

/// Whether a computed selection follows the published version, which is the last guard before a version leaves the planner.
fn after_published(selected: &Version<'_>, published: &Version<'_>) -> bool {
    #[cfg(feature = "negative-control-reselect")]
    return !published.follows(selected);
    #[cfg(not(feature = "negative-control-reselect"))]
    return selected.follows(published);
}

/// How the version of a first release relates to the manifest's version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Initial {
    /// The manifest's version, unchanged.
    Unchanged,
    /// The manifest's core, put on a train or made stable.
    Computed(Computed),
}

/// The version of a package's first release, from the manifest's `version`.
///
/// A configured train puts a stable version on its first prerelease and refuses a prerelease of another train.
/// Without a train, `stable` drops the prerelease of a version that the caller asked to release as stable.
pub fn initial_version(
    version: &Version<'_>,
    channel: Option<Channel>,
    stable: bool,
) -> Result<Initial, Refusal> {
    match channel {
        Some(channel) if matches!(version.pre, Pre::Stable) => Ok(Initial::Computed(Computed {
            core: version.core,
            train: Some((channel, 1)),
        })),
        Some(channel) if !joins_train(version.pre, channel) => {
            Err(Refusal::ExplicitOffTrain { channel })
        }
        Some(_) => Ok(Initial::Unchanged),
        None if stable && !matches!(version.pre, Pre::Stable) => Ok(Initial::Computed(Computed {
            core: version.core,
            train: None,
        })),
        None => Ok(Initial::Unchanged),
    }
}

/// Whether a prerelease belongs to `channel`'s train.
fn joins_train(pre: Pre<'_>, channel: Channel) -> bool {
    #[cfg(feature = "negative-control-initial-train")]
    let _ = (pre, channel);
    #[cfg(feature = "negative-control-initial-train")]
    return true;
    #[cfg(not(feature = "negative-control-initial-train"))]
    return pre.starts_with(channel);
}

/// The step a release needs once Hex's rule for versions below 1.0 applies.
///
/// While the published major version is zero, a breaking change is a minor release.
pub fn effective_bump(major: u64, required: Bump) -> Bump {
    if below_one(major) && required == Bump::Major {
        Bump::Minor
    } else {
        required
    }
}

fn below_one(major: u64) -> bool {
    #[cfg(feature = "negative-control-zero-major")]
    let _ = major;
    #[cfg(feature = "negative-control-zero-major")]
    return false;
    #[cfg(not(feature = "negative-control-zero-major"))]
    return major == 0;
}

/// The step that separates two versions, named by the highest component that changed.
///
/// A change in the prerelease alone is a patch step.
pub fn bump_between(from: &Version<'_>, to: &Version<'_>) -> Bump {
    if to.core.major != from.core.major {
        Bump::Major
    } else if to.core.minor != from.core.minor {
        Bump::Minor
    } else if differ_below_minor(from, to) {
        Bump::Patch
    } else {
        Bump::None
    }
}

/// Whether two versions with the same major and minor numbers differ in their patch number or prerelease.
fn differ_below_minor(from: &Version<'_>, to: &Version<'_>) -> bool {
    #[cfg(feature = "negative-control-bump-between")]
    return to.core.patch != from.core.patch;
    #[cfg(not(feature = "negative-control-bump-between"))]
    return compare(to, from) != Ordering::Equal;
}

/// Whether a release of a version with `major` needs an acknowledgement that the owner hasn't given.
///
/// Gleam warns against versions below 1.0, so a 0.x release needs `allow_version_zero`.
pub fn version_zero_refused(major: u64, acknowledged: bool) -> bool {
    #[cfg(feature = "negative-control-version-zero")]
    let _ = (major, acknowledged);
    #[cfg(feature = "negative-control-version-zero")]
    return false;
    #[cfg(not(feature = "negative-control-version-zero"))]
    return major == 0 && !acknowledged;
}

#[cfg(kani)]
mod proofs {
    use core::cmp::Ordering;

    use super::{
        Computed, Initial, Refusal, Selection, bump_between, effective_bump, initial_version,
        select_version, version_zero_refused,
    };
    use crate::precedence::symbolic::{self, TEXT};
    use crate::precedence::{Channel, Label, Pre, Version, compare};
    use crate::{Bump, VersionCore};

    /// The version a selection names, given the explicit version the selection could take.
    fn named<'a>(selection: Selection, explicit: Option<&Version<'a>>) -> Version<'a> {
        match selection {
            Selection::Computed(computed) => computed.version(),
            Selection::Explicit => *explicit.unwrap(),
        }
    }

    /// A selection never names a version that doesn't follow the published one, so it never names a version Hex already holds.
    ///
    /// Every core and train number is symbolic, and prerelease text has at most four bytes.
    #[kani::proof]
    #[kani::unwind(6)]
    fn a_selected_version_follows_the_published_one() {
        let published_bytes: [u8; TEXT] = kani::any();
        let explicit_bytes: [u8; TEXT] = kani::any();
        let published = symbolic::version(&published_bytes);
        let explicit = symbolic::version(&explicit_bytes);
        let explicit = if kani::any() { Some(&explicit) } else { None };
        let channel: Option<Channel> = kani::any();
        let result = select_version(&published, kani::any(), kani::any(), explicit, channel);
        if let Ok(selection) = result {
            kani::assert(
                named(selection, explicit).follows(&published),
                "a selected version must follow the published one",
            );
        }
        kani::cover!(matches!(result, Ok(Selection::Explicit)));
        kani::cover!(matches!(
            result,
            Ok(Selection::Computed(Computed { train: Some(_), .. }))
        ));
        kani::cover!(matches!(
            result,
            Ok(Selection::Computed(Computed { train: None, .. }))
        ));
        kani::cover!(matches!(result, Err(Refusal::NotAfterPublished { .. })));
    }

    /// A selection reaches the core that the required step demands from the latest stable release.
    ///
    /// Every core and train number is symbolic, and prerelease text has at most four bytes.
    #[kani::proof]
    #[kani::unwind(6)]
    fn a_selection_reaches_the_core_the_required_step_demands() {
        let published_bytes: [u8; TEXT] = kani::any();
        let explicit_bytes: [u8; TEXT] = kani::any();
        let published = symbolic::version(&published_bytes);
        let explicit = symbolic::version(&explicit_bytes);
        let explicit = if kani::any() { Some(&explicit) } else { None };
        let latest_stable: Option<VersionCore> = kani::any();
        let required: Bump = kani::any();
        let base = latest_stable.unwrap_or(published.core);
        match select_version(&published, latest_stable, required, explicit, kani::any()) {
            Ok(selection) => kani::assert(
                base.bumped(required)
                    .is_some_and(|required| named(selection, explicit).core >= required),
                "a selection must reach the core of the required step",
            ),
            Err(Refusal::StepOverflow { core, bump }) => {
                assert!(core == base && bump == required && base.bumped(required).is_none());
            }
            Err(_) => {}
        }
        kani::cover!(required == Bump::Major && published.core.major == base.major);
    }

    /// A train moves forward through its channels or counts up within one, and a move back needs an explicitly higher core.
    ///
    /// Every core and train number is symbolic, and prerelease text has at most four bytes.
    #[kani::proof]
    #[kani::unwind(6)]
    fn a_train_moves_forward_or_counts_up_within_its_channel() {
        let published_bytes: [u8; TEXT] = kani::any();
        let explicit_bytes: [u8; TEXT] = kani::any();
        let published = symbolic::version(&published_bytes);
        let explicit = symbolic::version(&explicit_bytes);
        let explicit = if kani::any() { Some(&explicit) } else { None };
        let channel: Channel = kani::any();
        let result = select_version(
            &published,
            kani::any(),
            kani::any(),
            explicit,
            Some(channel),
        );
        let current = published.pre.numbered_label();
        let backward =
            current.is_some_and(|(label, _)| Label::Channel(channel).rank() < label.rank());
        let explicitly_higher = explicit
            .is_some_and(|explicit| explicit.follows(&published) && explicit.core > published.core);
        if backward && !explicitly_higher {
            kani::assert(
                result.is_err(),
                "a train must not move back without an explicitly higher core",
            );
        }
        match result {
            Ok(Selection::Computed(Computed { core, train })) => {
                let Some((on, number)) = train else {
                    panic!("a selection with a train is a prerelease");
                };
                assert!(on == channel);
                if backward {
                    assert!(core > published.core);
                }
                match current {
                    Some((Label::Channel(current), previous))
                        if current == channel && core == published.core =>
                    {
                        assert!(u128::from(number) == u128::from(previous) + 1);
                    }
                    _ => assert!(number == 1),
                }
            }
            Ok(Selection::Explicit) => {
                assert!(explicit.is_some_and(|explicit| explicit.pre.starts_with(channel)));
            }
            Err(_) => {}
        }
        kani::cover!(backward && result.is_ok());
        kani::cover!(matches!(
            (current, result),
            (Some((Label::Channel(current), _)), Ok(Selection::Computed(Computed { train: Some((on, number)), .. })))
                if current == on && number > 1
        ));
    }

    /// An explicit version that follows the published one but stays below the required core is refused, and an explicit version is taken only when it follows the published one.
    ///
    /// Every core and train number is symbolic, and prerelease text has at most four bytes.
    #[kani::proof]
    #[kani::unwind(6)]
    fn an_explicit_version_below_the_required_one_is_refused() {
        let published_bytes: [u8; TEXT] = kani::any();
        let explicit_bytes: [u8; TEXT] = kani::any();
        let published = symbolic::version(&published_bytes);
        let explicit = symbolic::version(&explicit_bytes);
        let latest_stable: Option<VersionCore> = kani::any();
        let required: Bump = kani::any();
        let channel: Option<Channel> = kani::any();
        let result = select_version(
            &published,
            latest_stable,
            required,
            Some(&explicit),
            channel,
        );
        let base = latest_stable.unwrap_or(published.core);
        if explicit.follows(&published)
            && base
                .bumped(required)
                .is_some_and(|required| explicit.core < required)
        {
            kani::assert(
                result.is_err(),
                "an explicit version below the required one must be refused",
            );
        }
        if let Ok(Selection::Explicit) = result {
            assert!(explicit.follows(&published));
        }
        kani::cover!(matches!(result, Err(Refusal::ExplicitBelowRequired { .. })));
        kani::cover!(matches!(result, Ok(Selection::Explicit)));
    }

    /// A first release joins the configured train, starting at its first number, or keeps a prerelease that belongs to it.
    ///
    /// The core is symbolic, and prerelease text has at most four bytes.
    #[kani::proof]
    #[kani::unwind(6)]
    fn the_first_release_joins_the_configured_train() {
        let bytes: [u8; TEXT] = kani::any();
        let version = symbolic::version(&bytes);
        let channel: Option<Channel> = kani::any();
        let stable: bool = kani::any();
        match initial_version(&version, channel, stable) {
            Ok(Initial::Unchanged) => {
                if let Some(channel) = channel {
                    kani::assert(
                        version.pre.starts_with(channel),
                        "a first release must join the configured train",
                    );
                } else {
                    assert!(!stable || matches!(version.pre, Pre::Stable));
                }
            }
            Ok(Initial::Computed(Computed { core, train })) => {
                assert!(core == version.core);
                match channel {
                    Some(channel) => {
                        assert!(train == Some((channel, 1)) && matches!(version.pre, Pre::Stable));
                    }
                    None => assert!(train.is_none() && stable),
                }
            }
            Err(Refusal::ExplicitOffTrain { channel: refused }) => {
                assert!(channel == Some(refused) && !version.pre.starts_with(refused));
                assert!(!matches!(version.pre, Pre::Stable));
            }
            Err(_) => panic!("a first release refuses only a prerelease of another train"),
        }
        kani::cover!(channel.is_some() && !matches!(version.pre, Pre::Stable));
    }

    #[kani::proof]
    fn a_breaking_change_below_one_is_a_minor_release() {
        let major: u64 = kani::any();
        let required: Bump = kani::any();
        let effective = effective_bump(major, required);
        if major == 0 && required == Bump::Major {
            kani::assert(
                effective == Bump::Minor,
                "a breaking change below 1.0 must be a minor release",
            );
        } else {
            assert!(effective == required);
        }
        kani::cover!(major == 0 && required == Bump::Major);
    }

    /// The step between two versions names the highest component that changed, and a change of the prerelease alone is a patch step.
    ///
    /// Every core is symbolic, and prerelease text has at most four bytes.
    #[kani::proof]
    #[kani::unwind(6)]
    fn the_step_between_versions_names_the_highest_changed_component() {
        let from_bytes: [u8; TEXT] = kani::any();
        let to_bytes: [u8; TEXT] = kani::any();
        let from = symbolic::version(&from_bytes);
        let to = symbolic::version(&to_bytes);
        let step = bump_between(&from, &to);
        if from.core == to.core && compare(&from, &to) != Ordering::Equal {
            kani::assert(
                step == Bump::Patch,
                "a change of the prerelease alone must be a patch step",
            );
        }
        assert!((step == Bump::Major) == (from.core.major != to.core.major));
        assert!(
            (step == Bump::Minor)
                == (from.core.major == to.core.major && from.core.minor != to.core.minor)
        );
        assert!((step == Bump::None) == (compare(&from, &to) == Ordering::Equal));
        kani::cover!(step == Bump::Patch && from.core == to.core);
    }

    #[kani::proof]
    fn a_zero_major_release_needs_its_acknowledgement() {
        let major: u64 = kani::any();
        let acknowledged: bool = kani::any();
        kani::assert(
            version_zero_refused(major, acknowledged) == (major == 0 && !acknowledged),
            "a release below 1.0 must need its acknowledgement",
        );
        kani::cover!(version_zero_refused(major, acknowledged));
    }
}
