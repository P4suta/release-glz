//! The order of member names in canonical JSON.

use core::cmp::Ordering;

/// Compare two member names by their UTF-16 code units, the order in which RFC 8785 sorts object members.
///
/// The order differs from Rust's order of strings, which compares UTF-8 bytes: a character above U+FFFF sorts before U+E000 through U+FFFF here.
pub fn utf16_cmp(left: &str, right: &str) -> Ordering {
    #[cfg(feature = "negative-control-utf8-key-order")]
    if let Some(order) = negative_control_utf8_key_order(left, right) {
        return order;
    }
    #[cfg(feature = "negative-control-first-unit-key-order")]
    if let Some(order) = negative_control_first_unit_key_order(left, right) {
        return order;
    }
    left.encode_utf16().cmp(right.encode_utf16())
}

/// Sorts member names by their UTF-8 bytes instead.
#[cfg(feature = "negative-control-utf8-key-order")]
fn negative_control_utf8_key_order(left: &str, right: &str) -> Option<Ordering> {
    Some(left.cmp(right))
}

/// Compares member names by their first UTF-16 code unit only.
#[cfg(feature = "negative-control-first-unit-key-order")]
fn negative_control_first_unit_key_order(left: &str, right: &str) -> Option<Ordering> {
    Some(
        left.encode_utf16()
            .take(1)
            .cmp(right.encode_utf16().take(1)),
    )
}

#[cfg(kani)]
mod proofs {
    use core::cmp::Ordering;

    use super::utf16_cmp;

    /// A symbolic name of at most one character of any value, written into `buffer`.
    fn name(buffer: &mut [u8; 4]) -> &str {
        let character: char = kani::any();
        if kani::any() {
            character.encode_utf8(buffer)
        } else {
            ""
        }
    }

    /// The UTF-16 code units of `name`, from the encoding's definition: one unit below U+10000 and a surrogate pair above.
    fn units(name: &str) -> ([u16; 2], usize) {
        let Some(character) = name.chars().next() else {
            return ([0, 0], 0);
        };
        let value = u32::from(character);
        if value < 0x1_0000 {
            ([value as u16, 0], 1)
        } else {
            let offset = value - 0x1_0000;
            (
                [
                    0xD800 + (offset >> 10) as u16,
                    0xDC00 + (offset & 0x3FF) as u16,
                ],
                2,
            )
        }
    }

    /// The order of two names of at most one character is the order of their UTF-16 code units.
    ///
    /// The proof covers names of at most one character of any value.
    /// Longer names compare by the first character in which they differ, because the code units of one character are never a proper prefix of another character's, which this harness also proves.
    #[kani::proof]
    #[kani::unwind(6)]
    fn member_names_sort_by_utf16_code_units() {
        let mut left_buffer = [0; 4];
        let mut right_buffer = [0; 4];
        let left = name(&mut left_buffer);
        let right = name(&mut right_buffer);
        let (left_units, left_count) = units(left);
        let (right_units, right_count) = units(right);
        kani::assert(
            utf16_cmp(left, right) == left_units[..left_count].cmp(&right_units[..right_count]),
            "member names must sort by UTF-16 code units",
        );
        if left != right && left_count > 0 && right_count > 0 {
            let shorter = left_count.min(right_count);
            assert!(left_units[..shorter] != right_units[..shorter]);
        }
        kani::cover!(utf16_cmp(left, right) != left.cmp(right));
    }

    /// The order ties exactly the equal names and reverses with its arguments, so sorting gives one result.
    ///
    /// The order is also transitive, because the harness above shows that it is the order of code unit slices, which `core` orders lexicographically.
    /// The proof covers names of at most one character of any value.
    #[kani::proof]
    #[kani::unwind(6)]
    fn member_names_have_a_strict_total_order() {
        let mut left_buffer = [0; 4];
        let mut right_buffer = [0; 4];
        let left = name(&mut left_buffer);
        let right = name(&mut right_buffer);
        kani::assert(
            (utf16_cmp(left, right) == Ordering::Equal) == (left == right),
            "member names must compare equal only when they are equal",
        );
        assert!(utf16_cmp(left, right) == utf16_cmp(right, left).reverse());
        kani::cover!(left != right && u32::from(left.chars().next().unwrap_or('a')) > 0xFFFF);
    }
}
