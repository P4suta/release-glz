//! Hexadecimal identities: SHA-256 digests and git object ids.

/// Lowercase hexadecimal digits in a SHA-256 digest.
pub const SHA256_HEX_LEN: usize = 64;

/// Lowercase hexadecimal digits in a SHA-1 git object id.
pub const OBJECT_HEX_LEN: usize = 40;

/// Whether `value` is exactly `length` lowercase hexadecimal digits.
pub fn lowercase_hex(value: &[u8], length: usize) -> bool {
    has_length(value, length) && every_byte_is_a_digit(value)
}

fn has_length(value: &[u8], length: usize) -> bool {
    #[cfg(feature = "negative-control-hex-length")]
    if let Some(has) = negative_control_hex_length(value, length) {
        return has;
    }
    value.len() == length
}

/// Whether `value` is a SHA-256 digest in lowercase hexadecimal.
pub fn is_sha256_hex(value: &[u8]) -> bool {
    lowercase_hex(value, SHA256_HEX_LEN)
}

/// Whether `value` is a full SHA-1 git object id in lowercase hexadecimal.
pub fn is_object_id(value: &[u8]) -> bool {
    lowercase_hex(value, OBJECT_HEX_LEN)
}

/// Whether `value` is a full commit id of a SHA-1 or a SHA-256 git repository, in lowercase hexadecimal.
pub fn is_commit_id(value: &[u8]) -> bool {
    is_object_id(value) || is_sha256_hex(value)
}

fn every_byte_is_a_digit(value: &[u8]) -> bool {
    #[cfg(feature = "negative-control-hex-any-byte")]
    if let Some(digits) = negative_control_hex_any_byte(value) {
        return digits;
    }
    let mut digits = true;
    for &byte in value {
        digits &= lowercase_hex_digit(byte);
    }
    digits
}

fn lowercase_hex_digit(byte: u8) -> bool {
    #[cfg(feature = "negative-control-hex-case")]
    if let Some(digit) = negative_control_hex_case(byte) {
        return digit;
    }
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

/// Accepts a value longer than its length.
#[cfg(feature = "negative-control-hex-length")]
fn negative_control_hex_length(value: &[u8], length: usize) -> Option<bool> {
    Some(value.len() >= length)
}

/// Accepts a value when any one byte is a digit.
#[cfg(feature = "negative-control-hex-any-byte")]
fn negative_control_hex_any_byte(value: &[u8]) -> Option<bool> {
    Some(value.iter().any(|byte| lowercase_hex_digit(*byte)))
}

/// Accepts an uppercase hexadecimal digit.
#[cfg(feature = "negative-control-hex-case")]
fn negative_control_hex_case(byte: u8) -> Option<bool> {
    byte.is_ascii_hexdigit().then_some(true)
}

#[cfg(kani)]
mod proofs {
    use super::{
        OBJECT_HEX_LEN, SHA256_HEX_LEN, is_commit_id, is_object_id, is_sha256_hex, lowercase_hex,
        lowercase_hex_digit,
    };

    /// The digit check accepts exactly `0` to `9` and `a` to `f`, for every byte.
    #[kani::proof]
    fn a_hex_digit_is_exactly_a_lowercase_hexadecimal_digit() {
        let byte: u8 = kani::any();
        kani::assert(
            lowercase_hex_digit(byte) == (byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "a hex digit must be a lowercase hexadecimal digit",
        );
        kani::cover!(lowercase_hex_digit(byte) && byte.is_ascii_alphabetic());
        kani::cover!(!lowercase_hex_digit(byte) && byte.is_ascii_hexdigit());
    }

    /// A digest accepts exactly the 64-byte values whose every byte is a digit, and an object id exactly such 40-byte values.
    ///
    /// Every byte string of 64 bytes, and its first 40 bytes.
    #[kani::proof]
    #[kani::unwind(66)]
    fn hex_identities_check_every_byte() {
        let value: [u8; SHA256_HEX_LEN] = kani::any();
        let object = &value[..OBJECT_HEX_LEN];
        let mut digest_digits = true;
        let mut object_digits = true;
        for (index, byte) in value.iter().enumerate() {
            let digit = lowercase_hex_digit(*byte);
            digest_digits &= digit;
            object_digits &= digit || index >= OBJECT_HEX_LEN;
        }
        kani::assert(
            is_sha256_hex(&value) == digest_digits && is_object_id(object) == object_digits,
            "a hex identity must check every byte",
        );
        kani::assert(
            is_commit_id(&value) == digest_digits && is_commit_id(object) == object_digits,
            "a commit id must be a full digest or object id",
        );
        kani::cover!(digest_digits);
        kani::cover!(object_digits && !digest_digits);
    }

    /// No identity accepts a value of another length, whatever its bytes.
    ///
    /// Every required length, for values of up to three bytes, and each identity length for values one byte too short or too long.
    #[kani::proof]
    #[kani::unwind(67)]
    fn hex_identities_refuse_every_other_length() {
        let length: usize = kani::any();
        let one: [u8; 1] = kani::any();
        let two: [u8; 2] = kani::any();
        let three: [u8; 3] = kani::any();
        let short_refused = (length == 0 || !lowercase_hex(&[], length))
            && (length == 1 || !lowercase_hex(&one, length))
            && (length == 2 || !lowercase_hex(&two, length))
            && (length == 3 || !lowercase_hex(&three, length));
        let digits = [b'0'; SHA256_HEX_LEN + 1];
        kani::assert(
            short_refused
                && !is_sha256_hex(&digits)
                && !is_sha256_hex(&digits[..SHA256_HEX_LEN - 1])
                && !is_object_id(&digits[..OBJECT_HEX_LEN + 1])
                && !is_object_id(&digits[..OBJECT_HEX_LEN - 1])
                && !is_commit_id(&digits)
                && !is_commit_id(&digits[..OBJECT_HEX_LEN + 1]),
            "a hex identity must refuse every other length",
        );
        kani::cover!(length == 3 && lowercase_hex(&three, length));
        kani::cover!(length != 3 && lowercase_hex(&three, 3));
    }
}
