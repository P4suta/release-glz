//! Semantic version precedence without build metadata.
//!
//! The order is the one [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html#spec-item-11) defines.
//! Cores compare numerically, a stable version follows every prerelease of its core, and prereleases compare identifier by identifier.

use core::cmp::Ordering;

use crate::VersionCore;

/// A prerelease channel, in the order that a release train moves through them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Channel {
    /// `alpha`, the first channel.
    Alpha,
    /// `beta`.
    Beta,
    /// `rc`, the last channel before a stable release.
    Rc,
}

impl Channel {
    /// The label that names this channel in a version.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Alpha => "alpha",
            Self::Beta => "beta",
            Self::Rc => "rc",
        }
    }
}

/// The prerelease of a version.
#[derive(Debug, Clone, Copy)]
pub enum Pre<'a> {
    /// No prerelease, so the version is stable.
    Stable,
    /// The prerelease `<channel>.<number>` of a release train.
    Train(Channel, u64),
    /// Any other prerelease, as the bytes of its dot-separated identifiers.
    Other(&'a [u8]),
}

impl<'a> Pre<'a> {
    /// The prerelease that `text` spells, which is stable when `text` is empty.
    pub const fn parse(text: &'a [u8]) -> Self {
        if text.is_empty() {
            Self::Stable
        } else {
            Self::Other(text)
        }
    }

    /// Whether the prerelease follows the grammar of semantic versioning.
    ///
    /// Every identifier is a non-empty run of ASCII letters, digits, and hyphens, and a numeric identifier has no leading zero.
    pub fn is_valid(self) -> bool {
        match self {
            Self::Stable | Self::Train(..) => true,
            Self::Other(text) => !text.is_empty() && segments(text).all(valid_identifier),
        }
    }

    /// Whether the first identifier is the label of `channel`.
    pub fn starts_with(self, channel: Channel) -> bool {
        match self {
            Self::Stable => false,
            Self::Train(own, _) => own == channel,
            Self::Other(text) => segments(text).next() == Some(channel.label().as_bytes()),
        }
    }

    /// The label and number of a prerelease that is exactly `<label>.<number>`, which is how a release train reads it.
    pub(crate) fn numbered_label(self) -> Option<(Label, u64)> {
        match self {
            Self::Stable => None,
            Self::Train(channel, number) => Some((Label::Channel(channel), number)),
            Self::Other(text) => {
                let dot = text.iter().position(|byte| *byte == DOT)?;
                let number = parse_number(text.get(dot + 1..)?)?;
                Some((Label::of(text.get(..dot)?), number))
            }
        }
    }

    fn identifiers(self) -> Identifiers<'a> {
        match self {
            Self::Stable => Identifiers::End,
            Self::Train(channel, number) => Identifiers::Label(channel, number),
            Self::Other(text) => Identifiers::Text(segments(text)),
        }
    }
}

/// The byte that separates prerelease identifiers.
const DOT: u8 = b'.';

/// The dot-separated identifiers of a prerelease's text, in order.
struct Segments<'a> {
    text: &'a [u8],
    start: usize,
}

fn segments(text: &[u8]) -> Segments<'_> {
    Segments { text, start: 0 }
}

impl<'a> Iterator for Segments<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let rest = self.text.get(self.start..)?;
        let length = rest
            .iter()
            .position(|byte| *byte == DOT)
            .unwrap_or(rest.len());
        self.start += length + 1;
        rest.get(..length)
    }
}

/// The first identifier of a numbered prerelease, as a release train ranks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Label {
    /// The label of a channel.
    Channel(Channel),
    /// A label that names no channel, which a train treats as later than every channel.
    Unknown,
}

impl Label {
    fn of(text: &[u8]) -> Self {
        match text {
            b"alpha" => Self::Channel(Channel::Alpha),
            b"beta" => Self::Channel(Channel::Beta),
            b"rc" => Self::Channel(Channel::Rc),
            _ => Self::Unknown,
        }
    }

    /// The position of the label in the order a train moves through.
    pub(crate) const fn rank(self) -> u8 {
        match self {
            Self::Channel(Channel::Alpha) => 0,
            Self::Channel(Channel::Beta) => 1,
            Self::Channel(Channel::Rc) => 2,
            Self::Unknown => u8::MAX,
        }
    }
}

/// A version without build metadata, which precedence ignores.
#[derive(Debug, Clone, Copy)]
pub struct Version<'a> {
    /// The numeric core.
    pub core: VersionCore,
    /// The prerelease.
    pub pre: Pre<'a>,
}

impl Version<'_> {
    /// The stable version with `core`.
    pub const fn stable(core: VersionCore) -> Self {
        Self {
            core,
            pre: Pre::Stable,
        }
    }

    /// Whether this version has a higher precedence than `other`.
    pub fn follows(&self, other: &Version<'_>) -> bool {
        compare(self, other) == Ordering::Greater
    }
}

/// The precedence of `left` relative to `right`.
pub fn compare(left: &Version<'_>, right: &Version<'_>) -> Ordering {
    #[cfg(feature = "negative-control-prerelease-first")]
    return negative_control_prerelease_first(left, right);
    #[cfg(not(feature = "negative-control-prerelease-first"))]
    return left
        .core
        .cmp(&right.core)
        .then_with(|| compare_prereleases(left.pre, right.pre));
}

#[cfg(feature = "negative-control-prerelease-first")]
fn negative_control_prerelease_first(left: &Version<'_>, right: &Version<'_>) -> Ordering {
    compare_prereleases(left.pre, right.pre).then_with(|| left.core.cmp(&right.core))
}

fn compare_prereleases(left: Pre<'_>, right: Pre<'_>) -> Ordering {
    match (left, right) {
        (Pre::Stable, Pre::Stable) => Ordering::Equal,
        (Pre::Stable, _) => stable_after_prerelease(),
        (_, Pre::Stable) => stable_after_prerelease().reverse(),
        _ => {
            let mut left = left.identifiers();
            let mut right = right.identifiers();
            loop {
                match (left.next(), right.next()) {
                    (None, None) => return same_identifiers(),
                    (None, Some(_)) => return Ordering::Less,
                    (Some(_), None) => return Ordering::Greater,
                    (Some(left), Some(right)) => match compare_identifiers(left, right) {
                        Ordering::Equal => {}
                        decided => return decided,
                    },
                }
            }
        }
    }
}

/// A stable version's precedence relative to a prerelease of its core.
fn stable_after_prerelease() -> Ordering {
    #[cfg(feature = "negative-control-stable-before-prerelease")]
    return negative_control_stable_first();
    #[cfg(not(feature = "negative-control-stable-before-prerelease"))]
    return Ordering::Greater;
}

#[cfg(feature = "negative-control-stable-before-prerelease")]
fn negative_control_stable_first() -> Ordering {
    Ordering::Less
}

/// The precedence of two prereleases with the same identifiers.
fn same_identifiers() -> Ordering {
    #[cfg(feature = "negative-control-equal-prereleases")]
    return negative_control_unequal();
    #[cfg(not(feature = "negative-control-equal-prereleases"))]
    return Ordering::Equal;
}

#[cfg(feature = "negative-control-equal-prereleases")]
fn negative_control_unequal() -> Ordering {
    Ordering::Less
}

/// One dot-separated identifier of a prerelease.
#[derive(Debug, Clone, Copy)]
enum Identifier<'a> {
    /// A numeric identifier that fits in 64 bits.
    Number(u64),
    /// A numeric identifier too large for 64 bits, as its digits.
    LargeNumber(&'a [u8]),
    /// An identifier with a letter or a hyphen.
    Text(&'a [u8]),
}

impl<'a> Identifier<'a> {
    fn classify(text: &'a [u8]) -> Self {
        if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
            return Self::Text(text);
        }
        parse_number(text).map_or(Self::LargeNumber(text), Self::Number)
    }
}

/// Numeric identifiers compare by value and come before text, which compares by ASCII bytes.
///
/// Two numbers too large for 64 bits compare by length first, which is their value order because a valid one has no leading zero.
fn compare_identifiers(left: Identifier<'_>, right: Identifier<'_>) -> Ordering {
    match (left, right) {
        (Identifier::Number(left), Identifier::Number(right)) => compare_numbers(left, right),
        (Identifier::Number(_), Identifier::LargeNumber(_)) => Ordering::Less,
        (Identifier::LargeNumber(_), Identifier::Number(_)) => Ordering::Greater,
        (Identifier::LargeNumber(left), Identifier::LargeNumber(right)) => {
            left.len().cmp(&right.len()).then_with(|| left.cmp(right))
        }
        (Identifier::Number(_) | Identifier::LargeNumber(_), Identifier::Text(_)) => Ordering::Less,
        (Identifier::Text(_), Identifier::Number(_) | Identifier::LargeNumber(_)) => {
            Ordering::Greater
        }
        (Identifier::Text(left), Identifier::Text(right)) => left.cmp(right),
    }
}

fn compare_numbers(left: u64, right: u64) -> Ordering {
    #[cfg(feature = "negative-control-reverse-numbers")]
    return negative_control_reversed(left, right);
    #[cfg(not(feature = "negative-control-reverse-numbers"))]
    return left.cmp(&right);
}

#[cfg(feature = "negative-control-reverse-numbers")]
fn negative_control_reversed(left: u64, right: u64) -> Ordering {
    right.cmp(&left)
}

/// The identifiers of a prerelease, in order.
enum Identifiers<'a> {
    /// A train whose label comes next.
    Label(Channel, u64),
    /// A train whose number comes next.
    Number(u64),
    /// The identifiers of an arbitrary prerelease.
    Text(Segments<'a>),
    /// No identifier is left.
    End,
}

impl<'a> Iterator for Identifiers<'a> {
    type Item = Identifier<'a>;

    fn next(&mut self) -> Option<Identifier<'a>> {
        match self {
            Self::Label(channel, number) => {
                let label = channel.label().as_bytes();
                *self = Self::Number(*number);
                Some(Identifier::Text(label))
            }
            Self::Number(number) => {
                let number = *number;
                *self = Self::End;
                Some(Identifier::Number(number))
            }
            Self::Text(identifiers) => identifiers.next().map(Identifier::classify),
            Self::End => None,
        }
    }
}

fn valid_identifier(identifier: &[u8]) -> bool {
    let numeric = identifier.iter().all(u8::is_ascii_digit);
    !identifier.is_empty()
        && identifier
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        && !(numeric && identifier.len() > 1 && identifier.first() == Some(&b'0'))
}

/// The base that numeric identifiers are written in.
const DECIMAL: u32 = 10;

/// The value of a non-empty run of ASCII digits, or `None` when it has another byte or exceeds 64 bits.
fn parse_number(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0_u64, |value, digit| {
        let digit = char::from(*digit).to_digit(DECIMAL)?;
        value
            .checked_mul(u64::from(DECIMAL))?
            .checked_add(u64::from(digit))
    })
}

/// Symbolic versions for the proofs of this crate.
///
/// A prerelease is stable, a train with any channel and any number, or valid text of at most [`TEXT`] bytes.
#[cfg(kani)]
pub(crate) mod symbolic {
    use super::{Pre, Version};

    /// The longest prerelease text that the proofs cover.
    pub(crate) const TEXT: usize = 4;

    pub(crate) fn pre(bytes: &[u8; TEXT]) -> Pre<'_> {
        match kani::any::<u8>() {
            0 => Pre::Stable,
            1 => Pre::Train(kani::any(), kani::any()),
            _ => {
                let length: usize = kani::any();
                kani::assume(length >= 1 && length <= TEXT);
                let pre = Pre::Other(&bytes[..length]);
                kani::assume(pre.is_valid());
                pre
            }
        }
    }

    pub(crate) fn version(bytes: &[u8; TEXT]) -> Version<'_> {
        Version {
            core: kani::any(),
            pre: pre(bytes),
        }
    }
}

#[cfg(kani)]
mod proofs {
    use core::cmp::Ordering;

    use super::symbolic::{self, TEXT};
    use super::{Channel, Pre, Version, compare};

    #[kani::proof]
    #[kani::unwind(8)]
    fn a_version_equals_itself_and_order_flips_with_its_operands() {
        let left_bytes: [u8; TEXT] = kani::any();
        let right_bytes: [u8; TEXT] = kani::any();
        let left = symbolic::version(&left_bytes);
        let right = symbolic::version(&right_bytes);
        kani::assert(
            compare(&left, &left) == Ordering::Equal,
            "a version must equal itself",
        );
        assert!(compare(&left, &right) == compare(&right, &left).reverse());
        kani::cover!(matches!(left.pre, Pre::Other(_)) && compare(&left, &right) == Ordering::Less);
        kani::cover!(
            matches!(left.pre, Pre::Train(..))
                && compare(&left, &right) == Ordering::Equal
                && matches!(right.pre, Pre::Other(_))
        );
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn a_stable_release_follows_every_prerelease_of_its_core() {
        let bytes: [u8; TEXT] = kani::any();
        let prerelease = symbolic::version(&bytes);
        kani::assume(!matches!(prerelease.pre, Pre::Stable));
        kani::assert(
            Version::stable(prerelease.core).follows(&prerelease),
            "a stable release must follow every prerelease of its core",
        );
        kani::cover!(matches!(prerelease.pre, Pre::Other(_)));
    }

    #[kani::proof]
    #[kani::unwind(8)]
    fn the_core_decides_before_the_prerelease() {
        let left_bytes: [u8; TEXT] = kani::any();
        let right_bytes: [u8; TEXT] = kani::any();
        let left = symbolic::version(&left_bytes);
        let right = symbolic::version(&right_bytes);
        kani::assume(left.core != right.core);
        kani::assert(
            compare(&left, &right) == left.core.cmp(&right.core),
            "the core must decide before the prerelease",
        );
        kani::cover!(
            left.core < right.core
                && matches!(left.pre, Pre::Stable)
                && !matches!(right.pre, Pre::Stable)
        );
    }

    /// A train's next number follows it, a later channel follows an earlier one, and a stable release follows the whole train.
    #[kani::proof]
    #[kani::unwind(8)]
    fn a_train_counts_up_and_moves_through_its_channels_in_precedence() {
        let core = kani::any();
        let channel: Channel = kani::any();
        let number: u64 = kani::any();
        kani::assume(number < u64::MAX);
        let on = |channel, number| Version {
            core,
            pre: Pre::Train(channel, number),
        };
        kani::assert(
            on(channel, number + 1).follows(&on(channel, number)),
            "a train's next number must follow it",
        );
        let later: Channel = kani::any();
        let any_number: u64 = kani::any();
        if later > channel {
            assert!(on(later, any_number).follows(&on(channel, number)));
        }
        assert!(Version::stable(core).follows(&on(channel, number)));
        kani::cover!(later > channel && any_number < number);
    }
}
