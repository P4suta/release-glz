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
            Some((Label::Channel(channel), number)) if spells_a_train(other) => {
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

/// Whether `<label>.<number>` text is valid, so that it reads as a train.
fn spells_a_train(pre: Pre<'_>) -> bool {
    #[cfg(feature = "negative-control-unchecked-train")]
    if let Some(valid) = negative_control_unchecked_train() {
        return valid;
    }
    pre.is_valid()
}

/// Reads `<label>.<number>` text as a train without checking its grammar, so a number with a leading zero passes.
#[cfg(feature = "negative-control-unchecked-train")]
fn negative_control_unchecked_train() -> Option<bool> {
    Some(true)
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
            #[cfg(feature = "negative-control-leading-zero")]
            if let Some(valid) = negative_control_leading_zero() {
                return valid;
            }
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

/// Admits a numeric identifier with a leading zero.
#[cfg(feature = "negative-control-leading-zero")]
fn negative_control_leading_zero() -> Option<bool> {
    Some(true)
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
        Some(first) if !first.numeric => compare_bytes(train_label(channel), first.bytes),
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

/// The label that spells a train of `channel` when it meets prerelease text.
fn train_label(channel: Channel) -> &'static [u8] {
    #[cfg(feature = "negative-control-one-label")]
    if let Some(label) = negative_control_one_label() {
        return label;
    }
    channel.label().as_bytes()
}

/// Spells every train with the first channel's label.
#[cfg(feature = "negative-control-one-label")]
fn negative_control_one_label() -> Option<&'static [u8]> {
    Some(Channel::Alpha.label().as_bytes())
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
    /// For `N` of at least two, no loop over such text, and no comparison of two such texts, takes more than `N` steps, so a harness over it unwinds `N + 1` times.
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
    #[kani::unwind(3)]
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
    #[kani::unwind(4)]
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
    #[kani::unwind(3)]
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

    /// The longest text that the proofs over spelled trains and parsing cover, which holds `alpha.99`.
    const SPELLED: usize = 8;

    /// The longest text that the proof of the grammar covers.
    const GRAMMAR: usize = 4;

    /// The label of `channel` as semantic versioning text spells it, written out here instead of read from `Channel::label`.
    fn spelled_label(channel: Channel) -> &'static [u8] {
        match channel {
            Channel::Alpha => b"alpha",
            Channel::Beta => b"beta",
            Channel::Rc => b"rc",
        }
    }

    /// The train that `text` spells as `<label>.<number>` by the rules of semantic versioning: a channel's label, a dot, and digits without a leading zero.
    fn spelled_train(text: &[u8]) -> Option<(Channel, u64)> {
        let channel = if text.starts_with(b"alpha.") {
            Channel::Alpha
        } else if text.starts_with(b"beta.") {
            Channel::Beta
        } else if text.starts_with(b"rc.") {
            Channel::Rc
        } else {
            return None;
        };
        let digits = &text[spelled_label(channel).len() + 1..];
        if digits.is_empty() || (digits.len() > 1 && digits[0] == b'0') {
            return None;
        }
        let mut value = 0_u64;
        let mut index = 0;
        while index < digits.len() {
            if !digits[index].is_ascii_digit() {
                return None;
            }
            value = value * 10 + u64::from(digits[index] - b'0');
            index += 1;
        }
        Some((channel, value))
    }

    /// Whether the bytes of `text` before its first dot are `label`.
    fn first_identifier_is(text: &[u8], label: &[u8]) -> bool {
        let mut end = 0;
        while end < text.len() && text[end] != b'.' {
            end += 1;
        }
        &text[..end] == label
    }

    /// Whether `text` follows the grammar of semantic versioning, stated byte by byte in one pass instead of identifier by identifier.
    fn valid_by_statement(text: &[u8]) -> bool {
        let mut length = 0_usize;
        let mut digits_only = true;
        let mut leading_zero = false;
        let mut index = 0;
        while index < text.len() {
            let byte = text[index];
            if byte == b'.' {
                if length == 0 || (digits_only && leading_zero && length > 1) {
                    return false;
                }
                length = 0;
                digits_only = true;
                leading_zero = false;
            } else if byte.is_ascii_alphanumeric() || byte == b'-' {
                if length == 0 {
                    leading_zero = byte == b'0';
                }
                digits_only &= byte.is_ascii_digit();
                length += 1;
            } else {
                return false;
            }
            index += 1;
        }
        length > 0 && !(digits_only && leading_zero && length > 1)
    }

    /// A train compares with prerelease text exactly as the text `<label>.<number>` that spells it does, which is where a train's label decides its order.
    ///
    /// The core and the channel are symbolic, the train number has one digit, and the other prerelease is any valid text of at most two bytes.
    /// The proof of parsing shows that the same text parses back into the train and names its channel.
    #[kani::proof]
    #[kani::unwind(8)]
    fn a_train_compares_like_the_text_that_spells_it() {
        let channel: Channel = kani::any();
        let number: u64 = kani::any();
        kani::assume(number < 10);
        let digit = b'0' + number as u8;
        let (mut alpha, mut beta, mut rc) = (*b"alpha.0", *b"beta.0", *b"rc.0");
        let text: &[u8] = match channel {
            Channel::Alpha => {
                alpha[6] = digit;
                &alpha
            }
            Channel::Beta => {
                beta[5] = digit;
                &beta
            }
            Channel::Rc => {
                rc[3] = digit;
                &rc
            }
        };
        let other_bytes: [u8; PAIRED_TEXT] = kani::any();
        let other_length: usize = kani::any();
        kani::assume(other_length >= 1 && other_length <= PAIRED_TEXT);
        let other = Pre::Other(&other_bytes[..other_length]);
        kani::assume(other.is_valid());
        let core = kani::any();
        let against = Version { core, pre: other };
        let train = Version {
            core,
            pre: Pre::Train(channel, number),
        };
        let spelled = Version {
            core,
            pre: Pre::Other(text),
        };
        let ordering = compare(&train, &against);
        kani::assert(
            ordering == compare(&spelled, &against),
            "a train must compare like the text that spells it",
        );
        kani::cover!(ordering == Ordering::Greater);
        kani::cover!(ordering == Ordering::Less);
    }

    /// Against text with its own label and one more identifier, a train compares by its number when that identifier is numeric, and ranks below it otherwise.
    ///
    /// The core, the channel, and the train number are symbolic, and the second identifier is any valid one-byte identifier.
    #[kani::proof]
    #[kani::unwind(8)]
    fn a_train_meets_its_own_label_by_its_number() {
        let channel: Channel = kani::any();
        let number: u64 = kani::any();
        let second: u8 = kani::any();
        kani::assume(second.is_ascii_alphanumeric() || second == b'-');
        let (mut alpha, mut beta, mut rc) = (*b"alpha.0", *b"beta.0", *b"rc.0");
        let text: &[u8] = match channel {
            Channel::Alpha => {
                alpha[6] = second;
                &alpha
            }
            Channel::Beta => {
                beta[5] = second;
                &beta
            }
            Channel::Rc => {
                rc[3] = second;
                &rc
            }
        };
        let core = kani::any();
        let train = Version {
            core,
            pre: Pre::Train(channel, number),
        };
        let against = Version {
            core,
            pre: Pre::Other(text),
        };
        let expected = if second.is_ascii_digit() {
            number.cmp(&u64::from(second - b'0'))
        } else {
            Ordering::Less
        };
        let ordering = compare(&train, &against);
        kani::assert(
            ordering == expected,
            "a train must meet its own label by its number",
        );
        kani::cover!(ordering == Ordering::Greater);
        kani::cover!(ordering == Ordering::Less && !second.is_ascii_digit());
    }

    /// Text parses as a train exactly when it spells `<label>.<number>` with a number that has no leading zero, any other text keeps its bytes, and its first identifier decides the channel it names.
    ///
    /// The text is any eight bytes or fewer.
    #[kani::proof]
    #[kani::unwind(10)]
    fn text_parses_as_a_train_exactly_when_it_spells_one() {
        let bytes: [u8; SPELLED] = kani::any();
        let length: usize = kani::any();
        kani::assume(length <= SPELLED);
        let text = &bytes[..length];
        let expected = spelled_train(text);
        let parsed = Pre::parse(text);
        kani::assert(
            match (parsed, expected) {
                (Pre::Train(channel, number), Some((spelled, value))) => {
                    channel == spelled && number == value
                }
                (Pre::Other(kept), None) => !text.is_empty() && kept == text,
                (Pre::Stable, None) => text.is_empty(),
                _ => false,
            },
            "text must parse as a train exactly when it spells one",
        );
        let channel: Channel = kani::any();
        let names = first_identifier_is(text, spelled_label(channel));
        assert!(Pre::Other(text).starts_with(channel) == names);
        kani::assert(
            parsed.starts_with(channel) == names,
            "a parsed prerelease must name the channel that its first identifier spells",
        );
        kani::cover!(expected.is_some());
        kani::cover!(expected.is_none() && text.starts_with(b"rc.0") && length > 4);
    }

    /// The prerelease grammar accepts exactly the texts whose identifiers are non-empty runs of ASCII letters, digits, and hyphens, without a leading zero in a numeric identifier.
    ///
    /// The text is any four bytes or fewer.
    #[kani::proof]
    #[kani::unwind(6)]
    fn the_prerelease_grammar_is_the_one_semantic_versioning_states() {
        let bytes: [u8; GRAMMAR] = kani::any();
        let length: usize = kani::any();
        kani::assume(length <= GRAMMAR);
        let text = &bytes[..length];
        let valid = valid_by_statement(text);
        kani::assert(
            Pre::Other(text).is_valid() == valid,
            "the prerelease grammar must be the one semantic versioning states",
        );
        kani::cover!(valid && text.contains(&b'.'));
        kani::cover!(!valid && text.starts_with(b"01"));
    }
}
