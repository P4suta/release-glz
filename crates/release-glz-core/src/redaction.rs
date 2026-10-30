//! Which bytes of a text redaction removes before the text leaves the process.
//!
//! A byte is covered when some occurrence of a non-empty secret spans it, and redaction replaces each maximal run of covered bytes once.
//! `coverage` decides each byte in one pass, and `Runs` groups the decisions into maximal runs.

use core::iter::Peekable;
use core::ops::Range;

/// One stretch of a text that redaction keeps or replaces.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Segment {
    /// Bytes that no occurrence of a secret covers, kept as they are.
    Kept(Range<usize>),
    /// A maximal run of bytes that occurrences of secrets cover, replaced as a whole.
    Redacted(Range<usize>),
}

/// The segments of `text` in order, which together cover every byte once.
///
/// An empty secret covers nothing, and occurrences of one secret may overlap.
/// When the text and every secret are UTF-8, every segment starts and ends on a character boundary.
pub fn redaction_segments<'a>(
    text: &'a [u8],
    secrets: &'a [&'a [u8]],
) -> impl Iterator<Item = Segment> + 'a {
    Runs::new(coverage(text, secrets))
}

/// Whether each byte of `text` is covered, in order, decided in one pass that carries the end of the furthest occurrence so far.
fn coverage<'a>(text: &'a [u8], secrets: &'a [&'a [u8]]) -> impl Iterator<Item = bool> + 'a {
    (0..text.len()).scan(0, move |reach, at| {
        *reach = extend_reach(text, secrets, at, *reach);
        Some(*reach > at)
    })
}

/// The end of the furthest occurrence that starts at or before `at`, given `reach`, the end of the furthest one that starts before it.
fn extend_reach(text: &[u8], secrets: &[&[u8]], at: usize, reach: usize) -> usize {
    let mut reach = reach;
    for secret in secrets {
        if let Some(end) = occurrence_end(text, secret, at) {
            reach = reach.max(end);
        }
    }
    reach
}

/// The end of the occurrence of `secret` that starts at `at`, if a non-empty secret occurs there.
fn occurrence_end(text: &[u8], secret: &[u8], at: usize) -> Option<usize> {
    if secret.is_empty() || !occurs_at(text, secret, at) {
        return None;
    }
    #[cfg(feature = "negative-control-redaction-partial")]
    if let Some(end) = negative_control_redaction_partial(secret, at) {
        return end;
    }
    #[cfg(feature = "negative-control-redaction-overreach")]
    if let Some(end) = negative_control_redaction_overreach(secret, at) {
        return end;
    }
    #[cfg(feature = "negative-control-redaction-midchar")]
    if let Some(end) = negative_control_redaction_midchar(at) {
        return end;
    }
    at.checked_add(secret.len())
}

/// Whether `secret` occurs in `text` at `at`.
fn occurs_at(text: &[u8], secret: &[u8], at: usize) -> bool {
    secret.iter().enumerate().all(|(offset, byte)| {
        at.checked_add(offset)
            .and_then(|index| text.get(index))
            .is_some_and(|found| found == byte)
    })
}

/// Leaves the last byte of each secret occurrence unredacted.
#[cfg(feature = "negative-control-redaction-partial")]
fn negative_control_redaction_partial(secret: &[u8], at: usize) -> Option<Option<usize>> {
    Some(at.checked_add(secret.len() - 1))
}

/// Redacts the byte after each secret occurrence too.
#[cfg(feature = "negative-control-redaction-overreach")]
fn negative_control_redaction_overreach(secret: &[u8], at: usize) -> Option<Option<usize>> {
    Some(at.checked_add(secret.len() + 1))
}

/// Redacts only the first byte of each secret occurrence, which can end inside a character.
#[cfg(feature = "negative-control-redaction-midchar")]
fn negative_control_redaction_midchar(at: usize) -> Option<Option<usize>> {
    Some(at.checked_add(1))
}

/// The maximal runs of equal decisions, as kept and redacted segments.
struct Runs<I: Iterator<Item = bool>> {
    decisions: Peekable<I>,
    /// Where the next run starts.
    position: usize,
}

impl<I: Iterator<Item = bool>> Runs<I> {
    fn new(decisions: I) -> Self {
        Self {
            decisions: decisions.peekable(),
            position: 0,
        }
    }
}

impl<I: Iterator<Item = bool>> Iterator for Runs<I> {
    type Item = Segment;

    fn next(&mut self) -> Option<Segment> {
        let redacted = self.decisions.next()?;
        let start = self.position;
        let end = run_end(&mut self.decisions, redacted, start);
        self.position = end;
        Some(if redacted {
            Segment::Redacted(start..end)
        } else {
            Segment::Kept(start..end)
        })
    }
}

/// The end of the run that starts at `start` with `redacted`, after taking every equal decision that follows it.
fn run_end<I: Iterator<Item = bool>>(
    decisions: &mut Peekable<I>,
    redacted: bool,
    start: usize,
) -> usize {
    #[cfg(feature = "negative-control-redaction-split")]
    if let Some(end) = negative_control_redaction_split(start) {
        return end;
    }
    let mut end = start + 1;
    while decisions.next_if_eq(&redacted).is_some() {
        end += 1;
    }
    end
}

/// Ends every run after one decision, so one covered run becomes several segments.
#[cfg(feature = "negative-control-redaction-split")]
fn negative_control_redaction_split(start: usize) -> Option<usize> {
    Some(start + 1)
}

#[cfg(kani)]
mod proofs {
    use super::{Runs, Segment, coverage, extend_reach};

    /// The longest text the coverage proofs cover.
    const TEXT: usize = 3;
    /// The longest secret the proofs cover, two of which they check together.
    const SECRET: usize = 2;
    /// The longest stream of decisions the run proof covers.
    const DECISIONS: usize = 6;

    /// A symbolic prefix of `buffer`, of any length up to its size.
    fn prefix<const N: usize>(buffer: &[u8; N]) -> &[u8] {
        let length: usize = kani::any();
        kani::assume(length <= N);
        &buffer[..length]
    }

    /// Whether `secret` is non-empty and occurs in `text` at `start`, straight from the definition.
    fn occurs(text: &[u8], secret: &[u8], start: usize) -> bool {
        if secret.is_empty() || start + secret.len() > text.len() {
            return false;
        }
        let mut offset = 0;
        while offset < secret.len() {
            if text[start + offset] != secret[offset] {
                return false;
            }
            offset += 1;
        }
        true
    }

    /// Each step adds exactly the occurrences that start at its byte to the furthest end so far.
    ///
    /// The proof covers texts of at most four bytes, two secrets of at most two bytes, and any byte and earlier reach.
    #[kani::proof]
    #[kani::unwind(5)]
    fn each_step_reaches_exactly_the_occurrences_that_start_there() {
        let text_buffer: [u8; 4] = kani::any();
        let first: [u8; SECRET] = kani::any();
        let second: [u8; SECRET] = kani::any();
        let text = prefix(&text_buffer);
        let secrets = [prefix(&first), prefix(&second)];
        let at: usize = kani::any();
        let reach: usize = kani::any();
        kani::assume(at < text.len());
        let mut expected = reach;
        for secret in secrets {
            if occurs(text, secret, at) {
                expected = expected.max(at + secret.len());
            }
        }
        kani::assert(
            extend_reach(text, &secrets, at, reach) == expected,
            "a step must reach exactly the occurrences that start at its byte",
        );
        kani::cover!(expected > reach && secrets[0].len() == SECRET);
    }

    /// The decision for every byte is whether some occurrence of a non-empty secret spans it.
    ///
    /// The proof covers texts of at most three bytes and two secrets of at most two bytes, all of any value.
    #[kani::proof]
    #[kani::unwind(4)]
    fn redaction_covers_exactly_the_bytes_of_secret_occurrences() {
        let text_buffer: [u8; TEXT] = kani::any();
        let first: [u8; SECRET] = kani::any();
        let second: [u8; SECRET] = kani::any();
        let text = prefix(&text_buffer);
        let secrets = [prefix(&first), prefix(&second)];
        let mut expected = [false; TEXT];
        let mut start = 0;
        while start < text.len() {
            for secret in secrets {
                if occurs(text, secret, start) {
                    let mut index = start;
                    while index < start + secret.len() {
                        expected[index] = true;
                        index += 1;
                    }
                }
            }
            start += 1;
        }
        let mut index = 0;
        for decided in coverage(text, &secrets) {
            kani::assert(
                decided == expected[index],
                "every byte of every secret occurrence must be redacted, and no other",
            );
            index += 1;
        }
        assert!(index == text.len());
        kani::cover!(text.len() == TEXT && expected[0] && !expected[1] && expected[2]);
    }

    /// The first `length` of `values`, one at a time.
    struct Decisions {
        values: [bool; DECISIONS],
        length: usize,
        next: usize,
    }

    impl Iterator for Decisions {
        type Item = bool;

        fn next(&mut self) -> Option<bool> {
            if self.next >= self.length {
                return None;
            }
            let value = self.values[self.next];
            self.next += 1;
            Some(value)
        }
    }

    /// The segments of a stream of decisions cover it once and in order, each with the decision at both its ends, and neighbors differ.
    ///
    /// Every boundary between two segments is then a change of decision, and as many segments as changes plus one leave no change inside a segment, so each segment is a maximal run.
    /// The proof covers streams of at most six decisions of any value.
    #[kani::proof]
    #[kani::unwind(7)]
    fn redaction_replaces_each_maximal_covered_run_once() {
        let values: [bool; DECISIONS] = kani::any();
        let length: usize = kani::any();
        kani::assume(length <= DECISIONS);
        let mut next = 0;
        let mut previous = None;
        let mut segments = 0;
        for segment in Runs::new(Decisions {
            values,
            length,
            next: 0,
        }) {
            let (range, redacted) = match segment {
                Segment::Kept(range) => (range, false),
                Segment::Redacted(range) => (range, true),
            };
            assert!(range.start == next && range.start < range.end && range.end <= length);
            assert!(values[range.start] == redacted && values[range.end - 1] == redacted);
            kani::assert(
                previous != Some(redacted),
                "each maximal covered run must be one segment",
            );
            previous = Some(redacted);
            next = range.end;
            segments += 1;
        }
        assert!(next == length);
        let mut changes = 0;
        let mut index = 1;
        while index < length {
            if values[index] != values[index - 1] {
                changes += 1;
            }
            index += 1;
        }
        assert!(segments == if length == 0 { 0 } else { changes + 1 });
        kani::cover!(length == DECISIONS && segments == 3);
    }

    /// Whether `bytes` is a sequence of characters, each a lead byte followed by as many continuation bytes as the lead byte announces.
    ///
    /// Every UTF-8 string has this shape, and the decisions below depend on nothing else.
    fn well_formed(bytes: &[u8]) -> bool {
        let mut index = 0;
        while index < bytes.len() {
            let width = match bytes[index] {
                0x00..=0x7F => 1,
                0xC0..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF7 => 4,
                _ => return false,
            };
            if index + width > bytes.len() {
                return false;
            }
            let mut offset = 1;
            while offset < width {
                if bytes[index + offset] & 0xC0 != 0x80 {
                    return false;
                }
                offset += 1;
            }
            index += width;
        }
        true
    }

    /// When the text and the secrets are UTF-8, every byte of a character gets the decision of the character's first byte.
    ///
    /// A segment ends only where the decision changes, which the run proof above shows, so no segment ends inside a character and the kept text stays UTF-8.
    /// The proof covers texts of at most three bytes and two secrets of at most two bytes, all of any value with the shape of UTF-8, which includes every UTF-8 string of those lengths.
    #[kani::proof]
    #[kani::unwind(4)]
    fn redaction_never_splits_a_character() {
        let text_buffer: [u8; TEXT] = kani::any();
        let first: [u8; SECRET] = kani::any();
        let second: [u8; SECRET] = kani::any();
        let text = prefix(&text_buffer);
        let secrets = [prefix(&first), prefix(&second)];
        kani::assume(well_formed(text) && well_formed(secrets[0]) && well_formed(secrets[1]));
        let mut index = 0;
        let mut previous = false;
        let mut redacted = false;
        for decided in coverage(text, &secrets) {
            if text[index] & 0xC0 == 0x80 {
                kani::assert(
                    decided == previous,
                    "a character must be redacted or kept as a whole",
                );
            }
            previous = decided;
            redacted |= decided;
            index += 1;
        }
        kani::cover!(
            text.len() == TEXT && first[0] >= 0xC0 && secrets[0].len() == SECRET && redacted
        );
    }
}
