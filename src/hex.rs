//! The spelling of a digest in the `CHECKSUM` entry of a Hex package.
//!
//! Hex writes that entry in uppercase hexadecimal, and every other digest keeps the lowercase spelling of [`Sha256Digest`].

use release_glz_domain::Sha256Digest;

/// The uppercase spelling of `digest` that the `CHECKSUM` entry of a Hex package records.
pub fn upper(digest: &Sha256Digest) -> String {
    digest.as_str().to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use release_glz_domain::Sha256Digest;

    use super::upper;

    #[test]
    fn the_checksum_spelling_is_the_digest_in_uppercase() {
        let digest = Sha256Digest::parse(&"0123456789abcdef".repeat(4)).unwrap();
        assert_eq!(upper(&digest), "0123456789ABCDEF".repeat(4));
        assert_eq!(Sha256Digest::from_wire(&upper(&digest)).unwrap(), digest);
    }
}
