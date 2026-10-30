//! The managed marker that ends the body of every Release PR that release-glz writes.
//!
//! release-glz trusts a body only when one marker ends it and no other marker starts before it.
//! Text from commits and package interfaces enters a body only in inert form, which holds no `<`, so it can't open a marker.
//! The functions work on bytes and split only at ASCII bytes, so every slice they return of UTF-8 input is UTF-8.
//! The adapter trims trailing whitespace from a body and splits its fields at whitespace before it calls them.

/// The text that opens a marker.
pub const MARKER_PREFIX: &str = "<!-- release-glz:managed ";

/// The text that closes a marker.
pub const MARKER_SUFFIX: &str = " -->";

/// The fields of a marker, in the order release-glz writes them.
pub const MARKER_KEYS: [&str; 6] = ["package", "branch", "head", "digest", "version", "intent"];

/// Feed `sink` the marker whose fields hold `values`, in the order of [`MARKER_KEYS`].
///
/// The fields of the marker give the values back when none of them holds whitespace.
pub fn write_marker(values: [&[u8]; 6], mut sink: impl FnMut(&[u8])) {
    sink(MARKER_PREFIX.as_bytes());
    for (index, (key, value)) in MARKER_KEYS.iter().zip(values).enumerate() {
        if index > 0 {
            sink(b" ");
        }
        sink(key.as_bytes());
        sink(b"=");
        sink(value);
    }
    sink(MARKER_SUFFIX.as_bytes());
}

/// Feed `sink` `text` with every `<` written as `&lt;`, so the text can't open an HTML comment, a tag, or a marker.
pub fn write_inert(text: &[u8], mut sink: impl FnMut(&[u8])) {
    #[cfg(feature = "negative-control-inert-less-than")]
    if let Some(()) = negative_control_inert_less_than(text, &mut sink) {
        return;
    }
    let mut start = 0;
    for (index, byte) in text.iter().enumerate() {
        if *byte == b'<' {
            sink(&text[start..index]);
            sink(b"&lt;");
            start = index + 1;
        }
    }
    sink(&text[start..]);
}

/// Writes the text as it is, `<` included.
#[cfg(feature = "negative-control-inert-less-than")]
fn negative_control_inert_less_than(text: &[u8], sink: &mut impl FnMut(&[u8])) -> Option<()> {
    sink(text);
    Some(())
}

/// The offset of the marker that ends `body`, whose trailing whitespace the caller removed, when no other marker starts before it.
pub fn marker_start(body: &[u8]) -> Option<usize> {
    let start = last_occurrence(body, MARKER_PREFIX.as_bytes())?;
    let marker_end = first_occurrence(&body[start..], MARKER_SUFFIX.as_bytes())?
        .checked_add(start)?
        .checked_add(MARKER_SUFFIX.len())?;
    let alone = first_occurrence(&body[..start], MARKER_PREFIX.as_bytes()).is_none();
    (alone && marker_end == body.len()).then_some(start)
}

/// The values of a marker whose fields are `fields`, in the order of [`MARKER_KEYS`], when they name each key exactly once and nothing else.
///
/// A field is a key, `=`, and the value, which may itself hold `=`.
pub fn marker_values<'a>(fields: impl Iterator<Item = &'a [u8]>) -> Option<[&'a [u8]; 6]> {
    let mut values: [Option<&[u8]>; 6] = [None; 6];
    for field in fields {
        record(&mut values, field)?;
    }
    let [package, branch, head, digest, version, intent] = values;
    Some([package?, branch?, head?, digest?, version?, intent?])
}

/// Record the value of `field` under its key, refusing a field without `=`, an unknown key, and a key seen before.
fn record<'a>(values: &mut [Option<&'a [u8]>; 6], field: &'a [u8]) -> Option<()> {
    let separator = field.iter().position(|byte| *byte == b'=')?;
    let (key, value) = (&field[..separator], &field[separator + 1..]);
    let slot = MARKER_KEYS
        .iter()
        .position(|known| known.as_bytes() == key)?;
    #[cfg(feature = "negative-control-duplicate-keys")]
    if let Some(recorded) = negative_control_duplicate_keys(&mut values[slot], value) {
        return recorded;
    }
    match values[slot].replace(value) {
        None => Some(()),
        Some(_) => None,
    }
}

/// Lets a later field replace an earlier one with the same key.
#[cfg(feature = "negative-control-duplicate-keys")]
fn negative_control_duplicate_keys<'a>(
    slot: &mut Option<&'a [u8]>,
    value: &'a [u8],
) -> Option<Option<()>> {
    *slot = Some(value);
    Some(Some(()))
}

/// The first offset at which `needle` occurs in `haystack`.
fn first_occurrence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    #[cfg(feature = "negative-control-search-skips-start")]
    if let Some(found) = negative_control_search_skips_start(haystack, needle) {
        return found;
    }
    let last = haystack.len().checked_sub(needle.len())?;
    (0..=last).find(|&at| haystack[at..at + needle.len()] == *needle)
}

/// Starts the search for a first occurrence one byte late.
#[cfg(feature = "negative-control-search-skips-start")]
fn negative_control_search_skips_start(haystack: &[u8], needle: &[u8]) -> Option<Option<usize>> {
    let last = haystack.len().checked_sub(needle.len());
    Some(last.and_then(|last| (1..=last).find(|&at| haystack[at..at + needle.len()] == *needle)))
}

/// The last offset at which `needle` occurs in `haystack`.
fn last_occurrence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    #[cfg(feature = "negative-control-search-stops-short")]
    if let Some(found) = negative_control_search_stops_short(haystack, needle) {
        return found;
    }
    let last = haystack.len().checked_sub(needle.len())?;
    (0..=last)
        .rev()
        .find(|&at| haystack[at..at + needle.len()] == *needle)
}

/// Stops the search for a last occurrence before the last offset.
#[cfg(feature = "negative-control-search-stops-short")]
fn negative_control_search_stops_short(haystack: &[u8], needle: &[u8]) -> Option<Option<usize>> {
    let last = haystack.len().checked_sub(needle.len());
    Some(last.and_then(|last| {
        (0..last)
            .rev()
            .find(|&at| haystack[at..at + needle.len()] == *needle)
    }))
}

#[cfg(kani)]
mod proofs {
    use super::{MARKER_KEYS, first_occurrence, last_occurrence, record, write_inert};

    /// The longest text the inert proof covers.
    const TEXT: usize = 3;
    /// The longest haystack the search proofs cover.
    const HAYSTACK: usize = 4;
    /// The longest needle the search proofs cover.
    const NEEDLE: usize = 2;
    /// The longest field the field proof covers: the longest key, `=`, and one byte of value.
    const FIELD: usize = 9;

    /// A symbolic prefix of `buffer`, of any length up to its size.
    fn prefix<const N: usize>(buffer: &[u8; N]) -> &[u8] {
        let length: usize = kani::any();
        kani::assume(length <= N);
        &buffer[..length]
    }

    /// Bytes written in order into a buffer of `N`, with zeros after the last one.
    struct Written<const N: usize> {
        bytes: [u8; N],
        length: usize,
    }

    impl<const N: usize> Written<N> {
        fn new() -> Self {
            Self {
                bytes: [0; N],
                length: 0,
            }
        }

        fn push(&mut self, part: &[u8]) {
            for byte in part {
                self.bytes[self.length] = *byte;
                self.length += 1;
            }
        }
    }

    /// Inert text replaces each `<` with `&lt;` and keeps every other byte, so it holds no `<`.
    ///
    /// The proof covers texts of at most three bytes of any value.
    #[kani::proof]
    #[kani::unwind(13)]
    fn inert_text_replaces_each_less_than_sign() {
        let text: [u8; TEXT] = kani::any();
        for length in 0..=TEXT {
            let mut inert = Written::<12>::new();
            write_inert(&text[..length], |part| inert.push(part));
            let mut expected = Written::<12>::new();
            for byte in &text[..length] {
                if *byte == b'<' {
                    expected.push(b"&lt;");
                } else {
                    expected.push(&[*byte]);
                }
            }
            kani::assert(
                inert.length == expected.length && inert.bytes == expected.bytes,
                "inert text must replace each less-than sign and keep every other byte",
            );
        }
        kani::cover!(text[1] == b'<');
    }

    /// Whether `needle` occurs in `haystack` at `at`, straight from the definition.
    fn occurs(haystack: &[u8], needle: &[u8], at: usize) -> bool {
        if at + needle.len() > haystack.len() {
            return false;
        }
        let mut offset = 0;
        while offset < needle.len() {
            if haystack[at + offset] != needle[offset] {
                return false;
            }
            offset += 1;
        }
        true
    }

    /// The first occurrence is the earliest offset at which the needle occurs.
    ///
    /// The proof covers haystacks of at most four bytes and needles of at most two bytes, all of any value.
    #[kani::proof]
    #[kani::unwind(6)]
    fn the_first_occurrence_is_the_earliest_match() {
        let haystack_buffer: [u8; HAYSTACK] = kani::any();
        let needle_buffer: [u8; NEEDLE] = kani::any();
        let haystack = prefix(&haystack_buffer);
        let needle = prefix(&needle_buffer);
        let mut expected = None;
        let mut at = HAYSTACK + 1;
        while at > 0 {
            at -= 1;
            if occurs(haystack, needle, at) {
                expected = Some(at);
            }
        }
        kani::assert(
            first_occurrence(haystack, needle) == expected,
            "the first occurrence must be the earliest match",
        );
        kani::cover!(expected == Some(0) && occurs(haystack, needle, 2));
    }

    /// The last occurrence is the latest offset at which the needle occurs.
    ///
    /// The proof covers haystacks of at most four bytes and needles of at most two bytes, all of any value.
    #[kani::proof]
    #[kani::unwind(6)]
    fn the_last_occurrence_is_the_latest_match() {
        let haystack_buffer: [u8; HAYSTACK] = kani::any();
        let needle_buffer: [u8; NEEDLE] = kani::any();
        let haystack = prefix(&haystack_buffer);
        let needle = prefix(&needle_buffer);
        let mut expected = None;
        let mut at = 0;
        while at <= HAYSTACK {
            if occurs(haystack, needle, at) {
                expected = Some(at);
            }
            at += 1;
        }
        kani::assert(
            last_occurrence(haystack, needle) == expected,
            "the last occurrence must be the latest match",
        );
        kani::cover!(
            expected.is_some()
                && expected == haystack.len().checked_sub(needle.len())
                && occurs(haystack, needle, 0)
        );
    }

    /// Reading a field records the value after its first `=` under its key, and refuses a field without `=`, an unknown key, and a key that already holds a value.
    ///
    /// Reading a marker reads each of its fields so and then requires every key, which the Lean model and its refinement check for fields of every length.
    /// The proof covers fields of at most nine bytes of any value and every set of keys that already hold a value.
    #[kani::proof]
    #[kani::unwind(10)]
    fn a_field_is_recorded_only_under_a_new_known_key() {
        let field_buffer: [u8; FIELD] = kani::any();
        let field = prefix(&field_buffer);
        let held: [bool; 6] = kani::any();
        let mut values = held.map(|holds| holds.then_some(b"held".as_slice()));
        let recorded = record(&mut values, field);
        let mut separator = field.len();
        let mut index = field.len();
        while index > 0 {
            index -= 1;
            if field[index] == b'=' {
                separator = index;
            }
        }
        let mut slot = MARKER_KEYS.len();
        if separator < field.len() {
            let mut known = 0;
            while known < MARKER_KEYS.len() {
                if MARKER_KEYS[known].as_bytes() == &field[..separator] {
                    slot = known;
                }
                known += 1;
            }
        }
        let accepted = slot < MARKER_KEYS.len() && !held[slot];
        kani::assert(
            recorded.is_some() == accepted
                && (!accepted || values[slot] == Some(&field[separator + 1..])),
            "a field must be recorded only under a new known key",
        );
        kani::cover!(accepted && slot == 4 && field.len() == FIELD);
    }
}
