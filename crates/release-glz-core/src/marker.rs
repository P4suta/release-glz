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
            sink(field_separator());
        }
        sink(key.as_bytes());
        sink(b"=");
        sink(value);
    }
    sink(MARKER_SUFFIX.as_bytes());
}

/// The bytes between two fields of a marker.
fn field_separator() -> &'static [u8] {
    #[cfg(feature = "negative-control-fields-run-together")]
    if let Some(separator) = negative_control_fields_run_together() {
        return separator;
    }
    b" "
}

/// Writes the fields of a marker with nothing between them.
#[cfg(feature = "negative-control-fields-run-together")]
fn negative_control_fields_run_together() -> Option<&'static [u8]> {
    Some(b"")
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
    #[cfg(feature = "negative-control-marker-at-start")]
    if let Some(start) = negative_control_marker_at_start() {
        return start;
    }
    block_at_end(body, MARKER_PREFIX.as_bytes(), MARKER_SUFFIX.as_bytes())
}

/// Finds a marker at the start of every body, an empty one too.
#[cfg(feature = "negative-control-marker-at-start")]
fn negative_control_marker_at_start() -> Option<Option<usize>> {
    Some(Some(0))
}

/// The offset of the block that `open` starts and `close` ends at the end of `body`, when no other `open` starts before it.
fn block_at_end(body: &[u8], open: &[u8], close: &[u8]) -> Option<usize> {
    let start = last_occurrence(body, open)?;
    let block_end = first_occurrence(&body[start..], close)?
        .checked_add(start)?
        .checked_add(close.len())?;
    let alone = first_occurrence(&body[..start], open).is_none();
    (alone && block_end == body.len()).then_some(start)
}

/// The values of a marker whose fields are `fields`, in the order of [`MARKER_KEYS`], when they name each key exactly once and nothing else.
///
/// A field is a key, `=`, and the value, which may itself hold `=`.
pub fn marker_values<'a>(fields: impl Iterator<Item = &'a [u8]>) -> Option<[&'a [u8]; 6]> {
    let mut values: [Option<&[u8]>; 6] = [None; 6];
    for field in fields {
        record(&mut values, field)?;
    }
    #[cfg(feature = "negative-control-missing-key")]
    if let Some(values) = negative_control_missing_key(values) {
        return values;
    }
    let [package, branch, head, digest, version, intent] = values;
    Some([package?, branch?, head?, digest?, version?, intent?])
}

/// Gives back an empty value for a key that no field named.
#[cfg(feature = "negative-control-missing-key")]
fn negative_control_missing_key(values: [Option<&[u8]>; 6]) -> Option<Option<[&[u8]; 6]>> {
    Some(Some(values.map(|value| value.unwrap_or(b""))))
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
    use super::{
        MARKER_KEYS, block_at_end, first_occurrence, last_occurrence, marker_start, marker_values,
        record, write_inert, write_marker,
    };

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

    /// Whether `write_marker` feeds its sink exactly `expected`, part by part, for `values`.
    fn writes(values: [&[u8]; 6], expected: &[&[u8]; 25]) -> bool {
        let mut parts = 0;
        let mut matched = true;
        write_marker(values, |part| {
            matched &= expected.get(parts).is_some_and(|wanted| *wanted == part);
            parts += 1;
        });
        matched && parts == expected.len()
    }

    /// A marker is the prefix, each key with `=` and its value in the order release-glz writes them, one space between two fields, and the suffix.
    ///
    /// Every value is one byte of any value, or every value is empty, and the expected parts are written out here instead of read from the keys.
    #[kani::proof]
    #[kani::unwind(30)]
    fn a_marker_writes_each_key_and_value_in_order() {
        let bytes: [u8; 6] = kani::any();
        let [package, branch, head, digest, version, intent]: [&[u8]; 6] =
            core::array::from_fn(|index| &bytes[index..=index]);
        let filled = writes(
            [package, branch, head, digest, version, intent],
            &[
                b"<!-- release-glz:managed ",
                b"package",
                b"=",
                package,
                b" ",
                b"branch",
                b"=",
                branch,
                b" ",
                b"head",
                b"=",
                head,
                b" ",
                b"digest",
                b"=",
                digest,
                b" ",
                b"version",
                b"=",
                version,
                b" ",
                b"intent",
                b"=",
                intent,
                b" -->",
            ],
        );
        let empty = writes(
            [b""; 6],
            &[
                b"<!-- release-glz:managed ",
                b"package",
                b"=",
                b"",
                b" ",
                b"branch",
                b"=",
                b"",
                b" ",
                b"head",
                b"=",
                b"",
                b" ",
                b"digest",
                b"=",
                b"",
                b" ",
                b"version",
                b"=",
                b"",
                b" ",
                b"intent",
                b"=",
                b"",
                b" -->",
            ],
        );
        kani::assert(
            filled && empty,
            "a marker must write each key and value in order",
        );
        kani::cover!(bytes[0] == b'=');
    }

    /// `marker_start` finds the block that the marker's own texts open and close, which the harness below decides for short texts.
    ///
    /// The marker's texts are long, and a search over a body that holds them exhausts the solver, so the harness pins an empty body and the shortest marker.
    #[kani::proof]
    #[kani::unwind(31)]
    fn the_marker_is_found_with_its_own_texts() {
        let found = marker_start(b"<!-- release-glz:managed  -->");
        kani::assert(
            marker_start(b"").is_none() && found == Some(0),
            "the marker must be found with its own texts",
        );
        kani::cover!(found.is_some());
    }

    /// A body has the block that ends it exactly when that block's opening text occurs nowhere earlier and its closing text first follows the opening at the end.
    ///
    /// Every body of up to five arbitrary bytes, with a one-byte opening and closing text, against the definitions of occurrence.
    #[kani::proof]
    #[kani::unwind(7)]
    fn the_marker_that_ends_a_body_is_found_after_inert_text() {
        let bytes: [u8; 5] = kani::any();
        let length: usize = kani::any_where(|length| *length <= bytes.len());
        let body = &bytes[..length];
        let (open, close): (&[u8], &[u8]) = (b"<", b">");
        let mut last_open = None;
        let mut opens = 0;
        for at in 0..length {
            if occurs(body, open, at) {
                last_open = Some(at);
                opens += 1;
            }
        }
        let expected = last_open.filter(|&start| {
            let mut first_close = None;
            for at in start..length {
                if first_close.is_none() && occurs(body, close, at) {
                    first_close = Some(at);
                }
            }
            opens == 1 && first_close == Some(length - 1)
        });
        let found = block_at_end(body, open, close);
        kani::assert(
            found == expected,
            "the marker that ends a body must be found after inert text",
        );
        kani::cover!(found.is_some_and(|start| start > 0));
    }

    /// The fields of a marker give back each value in the order of the keys, in any order of the fields, and fields that miss a key give back nothing.
    ///
    /// Fixed fields in two orders, and the same fields without their last one.
    #[kani::proof]
    #[kani::unwind(10)]
    fn the_fields_of_a_marker_give_back_each_value() {
        let fields: [&[u8]; 6] = [
            b"package=p",
            b"branch=b",
            b"head=h",
            b"digest=d",
            b"version=v",
            b"intent=i",
        ];
        let values: [&[u8]; 6] = [b"p", b"b", b"h", b"d", b"v", b"i"];
        kani::assert(
            marker_values(fields.iter().copied()) == Some(values)
                && marker_values(fields.iter().rev().copied()) == Some(values)
                && marker_values(fields[..5].iter().copied()).is_none(),
            "the fields of a marker must give back each value",
        );
        kani::cover!(marker_values(fields.iter().copied()).is_some());
    }
}
