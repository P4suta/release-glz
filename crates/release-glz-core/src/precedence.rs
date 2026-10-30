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
    /// The prerelease that `text` spells.
    ///
    /// Empty text is stable, and valid text that is exactly `<channel>.<number>` is that train.
    pub fn parse(text: &'a [u8]) -> Self {
        if text.is_empty() {
            return Self::Stable;
        }
        let other = Self::Other(text);
        match other.numbered_label() {
            Some((Label::Channel(channel), number)) if other.is_valid() => {
                Self::Train(channel, number)
            }
            _ => other,
        }
    }

    /// Whether the prerelease follows the grammar of semantic versioning.
    ///
    /// Every identifier is a non-empty run of ASCII letters, digits, and hyphens, and a numeric identifier has no leading zero.
    pub fn is_valid(self) -> bool {
        match self {
            Self::Stable | Self::Train(..) => true,
            Self::Other(text) => !text.is_empty() && segments(text).all(Segment::is_valid),
        }
    }

    /// Whether the first identifier is the label of `channel`.
    pub fn starts_with(self, channel: Channel) -> bool {
        match self {
            Self::Stable => false,
            Self::Train(own, _) => own == channel,
            Self::Other(text) => segments(text).next().is_some_and(|first| {
                compare_bytes(first.bytes, channel.label().as_bytes()).is_eq()
            }),
        }
    }

    /// The label and number of a prerelease that is exactly `<label>.<number>`, which is how a release train reads it.
    pub(crate) fn numbered_label(self) -> Option<(Label, u64)> {
        match self {
            Self::Stable => None,
            Self::Train(channel, number) => Some((Label::Channel(channel), number)),
            Self::Other(text) => {
                let mut segments = segments(text);
                let label = segments.next()?;
                let number = parse_number(segments.next()?.bytes)?;
                segments
                    .next()
                    .is_none()
                    .then(|| (Label::of(label.bytes), number))
            }
        }
    }
}

/// The byte that separates prerelease identifiers.
const DOT: u8 = b'.';

/// One dot-separated identifier of a prerelease's text.
#[derive(Debug, Clone, Copy)]
struct Segment<'a> {
    bytes: &'a [u8],
    /// Whether the identifier is a non-empty run of ASCII digits.
    numeric: bool,
}

impl Segment<'_> {
    /// Whether a numeric identifier has no leading zero, or another identifier is a non-empty run of ASCII letters, digits, and hyphens.
    fn is_valid(self) -> bool {
        if self.numeric {
            return self.bytes.len() == 1 || self.bytes.first() != Some(&b'0');
        }
        let mut index = 0;
        while let Some(byte) = self.bytes.get(index) {
            if !(byte.is_ascii_alphanumeric() || *byte == b'-') {
                return false;
            }
            index += 1;
        }
        index > 0
    }
}

/// The dot-separated identifiers of a prerelease's text, in order.
///
/// Each identifier takes one indexed scan, which a proof unwinds once per byte.
struct Segments<'a> {
    text: &'a [u8],
    start: usize,
}

fn segments(text: &[u8]) -> Segments<'_> {
    Segments { text, start: 0 }
}

impl<'a> Iterator for Segments<'a> {
    type Item = Segment<'a>;

    fn next(&mut self) -> Option<Segment<'a>> {
        let start = self.start;
        if start > self.text.len() {
            return None;
        }
        let mut end = start;
        let mut numeric = true;
        while let Some(&byte) = self.text.get(end)
            && byte != DOT
        {
            numeric &= byte.is_ascii_digit();
            end += 1;
        }
        self.start = end + 1;
        Some(Segment {
            bytes: self.text.get(start..end)?,
            numeric: numeric && end > start,
        })
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
    if let Some(ordering) = negative_control_prerelease_first(left, right) {
        return ordering;
    }
    left.core
        .cmp(&right.core)
        .then_with(|| compare_prereleases(left.pre, right.pre))
}

/// Compares the prereleases before the cores.
#[cfg(feature = "negative-control-prerelease-first")]
fn negative_control_prerelease_first(left: &Version<'_>, right: &Version<'_>) -> Option<Ordering> {
    Some(compare_prereleases(left.pre, right.pre).then_with(|| left.core.cmp(&right.core)))
}

fn compare_prereleases(left: Pre<'_>, right: Pre<'_>) -> Ordering {
    match (left, right) {
        (Pre::Stable, Pre::Stable) => Ordering::Equal,
        (Pre::Stable, _) => stable_after_prerelease(),
        (_, Pre::Stable) => stable_after_prerelease().reverse(),
        (Pre::Train(left_channel, left_number), Pre::Train(right_channel, right_number)) => {
            left_channel
                .cmp(&right_channel)
                .then_with(|| compare_numbers(left_number, right_number))
        }
        (Pre::Train(channel, number), Pre::Other(text))
        | (Pre::Other(text), Pre::Train(channel, number)) => {
            let ordering = train_against_text(channel, number, text);
            if matches!(left, Pre::Train(..)) {
                ordering
            } else {
                ordering.reverse()
            }
        }
        (Pre::Other(left), Pre::Other(right)) => compare_texts(left, right),
    }
}

/// A stable version's precedence relative to a prerelease of its core.
fn stable_after_prerelease() -> Ordering {
    #[cfg(feature = "negative-control-stable-before-prerelease")]
    if let Some(ordering) = negative_control_stable_first() {
        return ordering;
    }
    Ordering::Greater
}

/// Orders a stable version before the prereleases of its core.
#[cfg(feature = "negative-control-stable-before-prerelease")]
fn negative_control_stable_first() -> Option<Ordering> {
    Some(Ordering::Less)
}

/// The precedence of two prereleases with the same identifiers.
fn same_identifiers() -> Ordering {
    #[cfg(feature = "negative-control-equal-prereleases")]
    if let Some(ordering) = negative_control_unequal() {
        return ordering;
    }
    Ordering::Equal
}

/// Orders two prereleases with the same identifiers as unequal.
#[cfg(feature = "negative-control-equal-prereleases")]
fn negative_control_unequal() -> Option<Ordering> {
    Some(Ordering::Less)
}

/// A train's prerelease relative to prerelease text, compared as the identifiers `<label>.<number>` that spell the train.
fn train_against_text(channel: Channel, number: u64, text: &[u8]) -> Ordering {
    let mut segments = segments(text);
    let by_label = match segments.next() {
        Some(first) if !first.numeric => compare_bytes(channel.label().as_bytes(), first.bytes),
        _ => Ordering::Greater,
    };
    if by_label.is_ne() {
        return by_label;
    }
    let by_number = match segments.next() {
        Some(second) if second.numeric => number_against_digits(number, second.bytes),
        Some(_) => Ordering::Less,
        None => Ordering::Greater,
    };
    if by_number.is_ne() {
        return by_number;
    }
    if segments.next().is_some() {
        Ordering::Less
    } else {
        same_identifiers()
    }
}

/// Two prerelease texts, compared identifier by identifier, where the text that runs out of identifiers first comes first.
fn compare_texts(left: &[u8], right: &[u8]) -> Ordering {
    let mut left = segments(left);
    let mut right = segments(right);
    loop {
        match (left.next(), right.next()) {
            (None, None) => return same_identifiers(),
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(left), Some(right)) => match compare_segments(left, right) {
                Ordering::Equal => {}
                decided => return decided,
            },
        }
    }
}

/// Numeric identifiers compare by value and come before text, which compares by ASCII bytes.
///
/// Two numeric identifiers compare by length first, which is their value order because a valid one has no leading zero.
fn compare_segments(left: Segment<'_>, right: Segment<'_>) -> Ordering {
    match (left.numeric, right.numeric) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (numeric, _) => {
            let by_length = if numeric {
                left.bytes.len().cmp(&right.bytes.len())
            } else {
                Ordering::Equal
            };
            by_length.then_with(|| compare_bytes(left.bytes, right.bytes))
        }
    }
}

/// The lexicographic order of two byte strings, as `<[u8]>::cmp` orders them.
///
/// One indexed loop compares them, which a proof unwinds once per byte.
fn compare_bytes(left: &[u8], right: &[u8]) -> Ordering {
    let mut index = 0;
    while let (Some(left_byte), Some(right_byte)) = (left.get(index), right.get(index)) {
        if left_byte != right_byte {
            return left_byte.cmp(right_byte);
        }
        index += 1;
    }
    left.len().cmp(&right.len())
}

/// A train's number relative to a numeric identifier, which follows every train number when it exceeds 64 bits.
fn number_against_digits(number: u64, digits: &[u8]) -> Ordering {
    parse_number(digits).map_or(Ordering::Less, |value| compare_numbers(number, value))
}

fn compare_numbers(left: u64, right: u64) -> Ordering {
    #[cfg(feature = "negative-control-reverse-numbers")]
    if let Some(ordering) = negative_control_reversed(left, right) {
        return ordering;
    }
    left.cmp(&right)
}

/// Orders numbers backward.
#[cfg(feature = "negative-control-reverse-numbers")]
fn negative_control_reversed(left: u64, right: u64) -> Option<Ordering> {
    Some(right.cmp(&left))
}

/// The base that numeric identifiers are written in.
const DECIMAL: u32 = 10;

/// The value of a non-empty run of ASCII digits, or `None` when it has another byte or exceeds 64 bits.
fn parse_number(digits: &[u8]) -> Option<u64> {
    let mut value = 0_u64;
    let mut index = 0;
    while let Some(digit) = digits.get(index) {
        let digit = char::from(*digit).to_digit(DECIMAL)?;
        value = value
            .checked_mul(u64::from(DECIMAL))?
            .checked_add(u64::from(digit))?;
        index += 1;
    }
    (index > 0).then_some(value)
}

/// Symbolic versions for the proofs of this crate.
#[cfg(kani)]
pub(crate) mod symbolic {
    use super::{Pre, Version};

    /// A prerelease that is stable, a train with any channel and number, or valid text of at most `N` bytes.
    ///
    /// Comparing two such texts takes one step more than they have identifiers, and no other loop runs longer than `N` bytes, so a harness over it unwinds `N + 2` times.
    pub(crate) fn pre<const N: usize>(bytes: &[u8; N]) -> Pre<'_> {
        match kani::any::<u8>() {
            0 => Pre::Stable,
            1 => Pre::Train(kani::any(), kani::any()),
            _ => {
                let length: usize = kani::any();
                kani::assume(length >= 1 && length <= N);
                let pre = Pre::Other(&bytes[..length]);
                kani::assume(pre.is_valid());
                pre
            }
        }
    }

    pub(crate) fn version<const N: usize>(bytes: &[u8; N]) -> Version<'_> {
        Version {
            core: kani::any(),
            pre: pre(bytes),
        }
    }

    /// A version that is stable or on a train with any channel and number, which is how [`Pre::parse`] reads every `<channel>.<number>`.
    ///
    /// No loop runs over it, so a harness over it unwinds once.
    pub(crate) fn release() -> Version<'static> {
        Version {
            core: kani::any(),
            pre: if kani::any() {
                Pre::Stable
            } else {
                Pre::Train(kani::any(), kani::any())
            },
        }
    }
}

#[cfg(kani)]
mod proofs {
    use core::cmp::Ordering;

    use super::symbolic;
    use super::{Channel, Pre, Version, compare};

    /// The longest prerelease text that these proofs cover for one version.
    const TEXT: usize = 3;
    /// The longest prerelease text of each version when a proof compares two of them.
    const PAIRED_TEXT: usize = 2;

    /// A version equals itself, and swapping two versions reverses their order.
    ///
    /// Every core and train number is symbolic, and prerelease text has at most two bytes.
    #[kani::proof]
    #[kani::unwind(4)]
    fn a_version_equals_itself_and_order_flips_with_its_operands() {
        let left_bytes: [u8; PAIRED_TEXT] = kani::any();
        let right_bytes: [u8; PAIRED_TEXT] = kani::any();
        let left = symbolic::version(&left_bytes);
        let right = symbolic::version(&right_bytes);
        kani::assert(
            compare(&left, &left) == Ordering::Equal,
            "a version must equal itself",
        );
        let ordering = compare(&left, &right);
        assert!(ordering == compare(&right, &left).reverse());
        kani::cover!(
            matches!((left.pre, right.pre), (Pre::Other(_), Pre::Other(_)))
                && ordering == Ordering::Less
        );
        kani::cover!(
            left.core == right.core
                && matches!((left.pre, right.pre), (Pre::Train(..), Pre::Other(_)))
                && ordering == Ordering::Less
        );
    }

    /// A stable release follows every prerelease of its core.
    ///
    /// The core and train number are symbolic, and prerelease text has at most three bytes.
    #[kani::proof]
    #[kani::unwind(5)]
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

    /// Two versions with different cores compare by their cores, whatever their prereleases.
    ///
    /// Every core and train number is symbolic, and prerelease text has at most two bytes.
    #[kani::proof]
    #[kani::unwind(4)]
    fn the_core_decides_before_the_prerelease() {
        let left_bytes: [u8; PAIRED_TEXT] = kani::any();
        let right_bytes: [u8; PAIRED_TEXT] = kani::any();
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
    ///
    /// The core, channels, and train numbers are symbolic.
    #[kani::proof]
    #[kani::unwind(1)]
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
