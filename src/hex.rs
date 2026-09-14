//! Hexadecimal rendering for digests.
//!
//! Every digest that crosses the public boundary is written here rather than
//! through a formatting trait, so the rendering is one function rather than a
//! trait implementation a dependency may withdraw.

/// Nibbles in one byte.
const NIBBLES_PER_BYTE: usize = 2;

/// Mask selecting the low nibble of a byte.
const LOW_NIBBLE: u8 = 0x0f;

/// Bits to shift a byte right by to reach its high nibble.
const HIGH_NIBBLE_SHIFT: u32 = 4;

const LOWERCASE: &[u8; 16] = b"0123456789abcdef";
const UPPERCASE: &[u8; 16] = b"0123456789ABCDEF";

/// Render bytes as lowercase hexadecimal.
pub(crate) fn lower(bytes: &[u8]) -> String {
    encode(bytes, LOWERCASE)
}

/// Render bytes as uppercase hexadecimal.
pub(crate) fn upper(bytes: &[u8]) -> String {
    encode(bytes, UPPERCASE)
}

fn encode(bytes: &[u8], alphabet: &[u8; 16]) -> String {
    let mut rendered = String::with_capacity(bytes.len() * NIBBLES_PER_BYTE);
    for byte in bytes {
        rendered.push(char::from(alphabet[usize::from(byte >> HIGH_NIBBLE_SHIFT)]));
        rendered.push(char::from(alphabet[usize::from(byte & LOW_NIBBLE)]));
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendering_matches_the_formatting_traits_it_replaces() {
        for bytes in [
            vec![],
            vec![0x00],
            vec![0xff],
            vec![0x0a, 0xb0, 0x5f, 0x10],
            (0..=255_u8).collect::<Vec<_>>(),
        ] {
            let expected_lower: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            let expected_upper: String = bytes.iter().map(|byte| format!("{byte:02X}")).collect();
            assert_eq!(lower(&bytes), expected_lower);
            assert_eq!(upper(&bytes), expected_upper);
            assert_eq!(lower(&bytes).len(), bytes.len() * NIBBLES_PER_BYTE);
        }
    }
}
