//! The release requirement lattice and the version arithmetic it drives.

use core::fmt;

/// The ordered SemVer release requirement lattice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Bump {
    /// No release is required.
    #[default]
    None,
    /// A backwards-compatible fix.
    Patch,
    /// A backwards-compatible feature or an API addition.
    Minor,
    /// A breaking API change.
    Major,
}

impl Bump {
    /// The stronger of two requirements.
    ///
    /// Signals combine by maximum, so no single signal can lower what another one already requires.
    pub fn max(self, other: Self) -> Self {
        #[cfg(feature = "negative-control-join")]
        if let Some(joined) = negative_control_join(self, other) {
            return joined;
        }
        core::cmp::max(self, other)
    }
}

/// Joins two bumps into the smaller one.
#[cfg(feature = "negative-control-join")]
fn negative_control_join(bump: Bump, other: Bump) -> Option<Bump> {
    Some(core::cmp::min(bump, other))
}

impl fmt::Display for Bump {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::None => "none",
            Self::Patch => "patch",
            Self::Minor => "minor",
            Self::Major => "major",
        })
    }
}

/// The numeric part of a semantic version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct VersionCore {
    /// Major component.
    pub major: u64,
    /// Minor component.
    pub minor: u64,
    /// Patch component.
    pub patch: u64,
}

impl VersionCore {
    /// The smallest version core that `bump` requires after this one, or `None` when the bumped component is `u64::MAX`.
    pub fn bumped(self, bump: Bump) -> Option<Self> {
        match bump {
            Bump::None => Some(self),
            Bump::Patch => Some(Self {
                patch: increment(self.patch)?,
                ..self
            }),
            Bump::Minor => Some(Self {
                minor: increment(self.minor)?,
                patch: 0,
                ..self
            }),
            Bump::Major => Some(Self {
                major: increment(self.major)?,
                minor: 0,
                patch: 0,
            }),
        }
    }
}

/// One more than `value`, or `None` when `value` is `u64::MAX`.
pub fn increment(value: u64) -> Option<u64> {
    #[cfg(feature = "negative-control-increment")]
    if let Some(next) = negative_control_increment(value) {
        return next;
    }
    value.checked_add(1)
}

/// Wraps around instead of reporting the largest value.
#[cfg(feature = "negative-control-increment")]
fn negative_control_increment(value: u64) -> Option<Option<u64>> {
    Some(Some(value.wrapping_add(1)))
}

#[cfg(kani)]
mod proofs {
    use super::{Bump, VersionCore, increment};

    #[kani::proof]
    fn the_join_of_two_bumps_is_the_larger_one() {
        let a: Bump = kani::any();
        let b: Bump = kani::any();
        let joined = a.max(b);
        kani::assert(
            joined >= a && joined >= b && (joined == a || joined == b) && joined == b.max(a),
            "the join of two bumps must be the larger one",
        );
        kani::cover!(a != b);
    }

    #[kani::proof]
    fn an_increment_adds_one_or_reports_the_largest_value() {
        let value: u64 = kani::any();
        match increment(value) {
            Some(next) => kani::assert(
                u128::from(next) == u128::from(value) + 1,
                "an increment must add exactly one",
            ),
            None => kani::assert(
                value == u64::MAX,
                "only the largest value may fail to increment",
            ),
        }
        kani::cover!(increment(value).is_none());
        kani::cover!(increment(value).is_some());
    }

    /// A bump raises exactly the component it names, resets the smaller ones, and never wraps.
    #[kani::proof]
    fn a_bump_raises_the_core_or_reports_an_overflow() {
        let version: VersionCore = kani::any();
        let bump: Bump = kani::any();
        match version.bumped(bump) {
            Some(next) => {
                if bump == Bump::None {
                    assert!(next == version);
                } else {
                    kani::assert(next > version, "a bump must raise the version core");
                }
                let raised = |before: u64, after: u64| u128::from(after) == u128::from(before) + 1;
                match bump {
                    Bump::None => {}
                    Bump::Patch => assert!(
                        next.major == version.major
                            && next.minor == version.minor
                            && raised(version.patch, next.patch)
                    ),
                    Bump::Minor => assert!(
                        next.major == version.major
                            && raised(version.minor, next.minor)
                            && next.patch == 0
                    ),
                    Bump::Major => assert!(
                        raised(version.major, next.major) && next.minor == 0 && next.patch == 0
                    ),
                }
            }
            None => assert!(match bump {
                Bump::None => false,
                Bump::Patch => version.patch == u64::MAX,
                Bump::Minor => version.minor == u64::MAX,
                Bump::Major => version.major == u64::MAX,
            }),
        }
        kani::cover!(version.bumped(bump).is_none());
        kani::cover!(bump == Bump::Major && version.bumped(bump).is_some());
    }
}
