//! Owned checked types of release-glz.
//!
//! Each type keeps its value private, and each of its constructors yields only a value for which a predicate of `release-glz-core` holds.
//! Serde reads and writes each type as the plain string it wraps, so wire bytes stay unchanged.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A commit ID that GitHub serves: exactly 40 lowercase hexadecimal digits.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CommitId(String);

impl CommitId {
    /// The number of lowercase hexadecimal digits in a commit ID.
    pub const LEN: usize = release_glz_core::OBJECT_HEX_LEN;

    /// The commit ID that `value` spells.
    ///
    /// # Errors
    ///
    /// Returns the refusal that names why `value` isn't 40 lowercase hexadecimal digits.
    pub fn parse(value: &str) -> Result<Self, CommitIdRefusal> {
        let bytes = value.as_bytes();
        if release_glz_core::is_object_id(bytes) {
            Ok(Self(value.to_owned()))
        } else if release_glz_core::is_sha256_hex(bytes) {
            Err(CommitIdRefusal::Sha256ObjectId)
        } else if bytes.len() == Self::LEN {
            Err(CommitIdRefusal::NotLowercaseHex)
        } else {
            Err(CommitIdRefusal::Length { found: bytes.len() })
        }
    }

    /// The 40 digits.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl AsRef<str> for CommitId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for CommitId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<String> for CommitId {
    type Error = CommitIdRefusal;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<CommitId> for String {
    fn from(id: CommitId) -> Self {
        id.0
    }
}

/// Why a value isn't a [`CommitId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitIdRefusal {
    /// The value is a SHA-256 object ID, which GitHub doesn't serve.
    Sha256ObjectId,
    /// The value has a length other than 40 bytes.
    Length {
        /// The value's length in bytes.
        found: usize,
    },
    /// The value has 40 bytes, and one of them isn't a lowercase hexadecimal digit.
    NotLowercaseHex,
}

impl fmt::Display for CommitIdRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digits = CommitId::LEN;
        match self {
            Self::Sha256ObjectId => write!(
                formatter,
                "a SHA-256 object ID isn't a GitHub commit ID, which has {digits} lowercase hexadecimal digits"
            ),
            Self::Length { found } => write!(
                formatter,
                "a commit ID has {digits} lowercase hexadecimal digits, and this value has {found} bytes"
            ),
            Self::NotLowercaseHex => write!(
                formatter,
                "a commit ID holds only the lowercase hexadecimal digits `0` to `9` and `a` to `f`"
            ),
        }
    }
}

impl std::error::Error for CommitIdRefusal {}

/// A SHA-256 digest in its one sealed spelling: exactly 64 lowercase hexadecimal digits.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// The number of hexadecimal digits in a SHA-256 digest.
    pub const LEN: usize = release_glz_core::SHA256_HEX_LEN;

    /// The digest that `value` spells in its sealed spelling.
    ///
    /// # Errors
    ///
    /// Returns the refusal that names why `value` isn't 64 lowercase hexadecimal digits.
    pub fn parse(value: &str) -> Result<Self, Sha256DigestRefusal> {
        if release_glz_core::is_sha256_hex(value.as_bytes()) {
            Ok(Self(value.to_owned()))
        } else if value.len() != Self::LEN {
            Err(Sha256DigestRefusal::Length { found: value.len() })
        } else if release_glz_core::is_sha256_hex(value.to_ascii_lowercase().as_bytes()) {
            Err(Sha256DigestRefusal::Uppercase)
        } else {
            Err(Sha256DigestRefusal::NotHex)
        }
    }

    /// The digest that an external format may spell in hexadecimal digits of either case, such as the release checksum of a Hex registry.
    ///
    /// # Errors
    ///
    /// Returns the refusal that names why `value` isn't 64 hexadecimal digits.
    pub fn from_wire(value: &str) -> Result<Self, Sha256DigestRefusal> {
        Self::parse(&value.to_ascii_lowercase())
    }

    /// The digest whose 32 bytes are `digest`, spelled in lowercase.
    #[must_use]
    pub fn from_bytes(digest: [u8; 32]) -> Self {
        Self(
            digest
                .iter()
                .flat_map(|byte| [byte >> 4, byte & 0x0f])
                .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
                .collect(),
        )
    }

    /// The 64 digits.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl AsRef<str> for Sha256Digest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = Sha256DigestRefusal;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Sha256Digest> for String {
    fn from(digest: Sha256Digest) -> Self {
        digest.0
    }
}

/// Why a value isn't a [`Sha256Digest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha256DigestRefusal {
    /// The value has a length other than 64 bytes.
    Length {
        /// The value's length in bytes.
        found: usize,
    },
    /// The value is 64 hexadecimal digits, and one of them is uppercase, which only [`Sha256Digest::from_wire`] reads.
    Uppercase,
    /// The value has 64 bytes, and one of them isn't a hexadecimal digit in either case.
    NotHex,
}

impl fmt::Display for Sha256DigestRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digits = Sha256Digest::LEN;
        match self {
            Self::Length { found } => write!(
                formatter,
                "a SHA-256 digest has {digits} hexadecimal digits, and this value has {found} bytes"
            ),
            Self::Uppercase => {
                formatter.write_str("a sealed SHA-256 digest has only lowercase hexadecimal digits")
            }
            Self::NotHex => formatter.write_str(
                "a SHA-256 digest holds only the hexadecimal digits `0` to `9` and `a` to `f`",
            ),
        }
    }
}

impl std::error::Error for Sha256DigestRefusal {}

/// A Git object ID of a SHA-1 repository, such as a blob ID: exactly 40 lowercase hexadecimal digits.
///
/// It has the spelling of a [`CommitId`], and it stays a distinct type because a blob ID names no commit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ObjectId(String);

impl ObjectId {
    /// The number of lowercase hexadecimal digits in an object ID.
    pub const LEN: usize = release_glz_core::OBJECT_HEX_LEN;

    /// The object ID that `value` spells.
    ///
    /// # Errors
    ///
    /// Returns the refusal that names why `value` isn't 40 lowercase hexadecimal digits.
    pub fn parse(value: &str) -> Result<Self, ObjectIdRefusal> {
        if release_glz_core::is_object_id(value.as_bytes()) {
            Ok(Self(value.to_owned()))
        } else if value.len() == Self::LEN {
            Err(ObjectIdRefusal::NotLowercaseHex)
        } else {
            Err(ObjectIdRefusal::Length { found: value.len() })
        }
    }

    /// The 40 digits.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl AsRef<str> for ObjectId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<String> for ObjectId {
    type Error = ObjectIdRefusal;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ObjectId> for String {
    fn from(id: ObjectId) -> Self {
        id.0
    }
}

/// Why a value isn't an [`ObjectId`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectIdRefusal {
    /// The value has a length other than 40 bytes.
    Length {
        /// The value's length in bytes.
        found: usize,
    },
    /// The value has 40 bytes, and one of them isn't a lowercase hexadecimal digit.
    NotLowercaseHex,
}

impl fmt::Display for ObjectIdRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digits = ObjectId::LEN;
        match self {
            Self::Length { found } => write!(
                formatter,
                "an object ID has {digits} lowercase hexadecimal digits, and this value has {found} bytes"
            ),
            Self::NotLowercaseHex => formatter.write_str(
                "an object ID holds only the lowercase hexadecimal digits `0` to `9` and `a` to `f`",
            ),
        }
    }
}

impl std::error::Error for ObjectIdRefusal {}

#[cfg(test)]
mod tests {
    use super::{CommitId, CommitIdRefusal};

    #[test]
    fn a_commit_id_is_exactly_forty_lowercase_hexadecimal_digits() {
        let id = "0123456789abcdef0123456789abcdef01234567";
        let parsed = CommitId::parse(id).unwrap();
        assert_eq!(parsed.as_str(), id);
        assert_eq!(parsed.to_string(), id);
        assert_eq!(AsRef::<str>::as_ref(&parsed), id);
        assert_eq!(String::from(parsed), id);
        assert_eq!(CommitId::LEN, 40);
    }

    #[test]
    fn every_other_length_is_refused_with_the_length_it_has() {
        for found in [0, 1, 39, 41, 63, 65] {
            assert_eq!(
                CommitId::parse(&"a".repeat(found)),
                Err(CommitIdRefusal::Length { found }),
                "{found}"
            );
        }
        assert_eq!(
            CommitId::parse(&"a".repeat(39)).unwrap_err().to_string(),
            "a commit ID has 40 lowercase hexadecimal digits, and this value has 39 bytes"
        );
    }

    #[test]
    fn a_sha256_object_id_is_refused_as_one_that_github_does_not_serve() {
        let refusal = CommitId::parse(&"b".repeat(64)).unwrap_err();
        assert_eq!(refusal, CommitIdRefusal::Sha256ObjectId);
        assert_eq!(
            refusal.to_string(),
            "a SHA-256 object ID isn't a GitHub commit ID, which has 40 lowercase hexadecimal digits"
        );
        assert_eq!(
            CommitId::parse(&"G".repeat(64)),
            Err(CommitIdRefusal::Length { found: 64 })
        );
    }

    #[test]
    fn an_uppercase_or_other_character_is_refused() {
        for value in [
            "A".repeat(40),
            format!("{}F", "a".repeat(39)),
            format!("{}g", "a".repeat(39)),
            format!("{} ", "a".repeat(39)),
            format!("{}\0", "a".repeat(39)),
        ] {
            assert_eq!(
                CommitId::parse(&value),
                Err(CommitIdRefusal::NotLowercaseHex),
                "{value:?}"
            );
        }
        assert_eq!(
            CommitId::parse(&format!("{}é", "a".repeat(38))),
            Err(CommitIdRefusal::NotLowercaseHex)
        );
        assert_eq!(
            CommitIdRefusal::NotLowercaseHex.to_string(),
            "a commit ID holds only the lowercase hexadecimal digits `0` to `9` and `a` to `f`"
        );
    }

    #[test]
    fn serde_writes_and_reads_the_plain_string() {
        let id = CommitId::parse(&"c".repeat(40)).unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", "c".repeat(40)));
        assert_eq!(serde_json::from_str::<CommitId>(&json).unwrap(), id);
    }

    #[test]
    fn serde_refuses_what_parse_refuses() {
        for (value, refusal) in [
            ("d".repeat(64), CommitIdRefusal::Sha256ObjectId),
            ("d".repeat(41), CommitIdRefusal::Length { found: 41 }),
            ("D".repeat(40), CommitIdRefusal::NotLowercaseHex),
        ] {
            let error = serde_json::from_str::<CommitId>(&format!("\"{value}\"")).unwrap_err();
            assert!(
                error.to_string().starts_with(&refusal.to_string()),
                "{value}: {error}"
            );
        }
        serde_json::from_str::<CommitId>("40").unwrap_err();
    }
}

#[cfg(test)]
mod sha256_digest_tests {
    use std::fmt::Write;

    use super::{Sha256Digest, Sha256DigestRefusal};

    #[test]
    fn a_digest_is_exactly_sixty_four_lowercase_hexadecimal_digits() {
        let digest = "0123456789abcdef".repeat(4);
        let parsed = Sha256Digest::parse(&digest).unwrap();
        assert_eq!(parsed.as_str(), digest);
        assert_eq!(parsed.to_string(), digest);
        assert_eq!(AsRef::<str>::as_ref(&parsed), digest);
        assert_eq!(String::from(parsed), digest);
        assert_eq!(Sha256Digest::LEN, 64);
    }

    #[test]
    fn every_other_length_is_refused_with_the_length_it_has() {
        for found in [0, 1, 40, 63, 65] {
            for value in ["a".repeat(found), "A".repeat(found), "g".repeat(found)] {
                assert_eq!(
                    Sha256Digest::parse(&value),
                    Err(Sha256DigestRefusal::Length { found }),
                    "{value}"
                );
                assert_eq!(
                    Sha256Digest::from_wire(&value),
                    Err(Sha256DigestRefusal::Length { found }),
                    "{value}"
                );
            }
        }
        assert_eq!(
            Sha256Digest::parse(&"a".repeat(63))
                .unwrap_err()
                .to_string(),
            "a SHA-256 digest has 64 hexadecimal digits, and this value has 63 bytes"
        );
    }

    #[test]
    fn parse_refuses_an_uppercase_digit_that_from_wire_reads() {
        for value in [
            "A".repeat(64),
            format!("{}F", "a".repeat(63)),
            format!("A{}", "0".repeat(63)),
            "0123456789ABCDEFabcdef"
                .repeat(3)
                .chars()
                .take(64)
                .collect::<String>(),
        ] {
            assert_eq!(
                Sha256Digest::parse(&value),
                Err(Sha256DigestRefusal::Uppercase),
                "{value}"
            );
            let read = Sha256Digest::from_wire(&value).unwrap();
            assert_eq!(read.as_str(), value.to_ascii_lowercase());
            assert_eq!(Sha256Digest::parse(read.as_str()), Ok(read));
        }
        assert_eq!(
            Sha256DigestRefusal::Uppercase.to_string(),
            "a sealed SHA-256 digest has only lowercase hexadecimal digits"
        );
    }

    #[test]
    fn from_wire_keeps_a_lowercase_digest_as_it_is() {
        let digest = "c".repeat(64);
        assert_eq!(
            Sha256Digest::from_wire(&digest),
            Sha256Digest::parse(&digest)
        );
    }

    #[test]
    fn a_character_that_is_no_hexadecimal_digit_in_either_case_is_refused() {
        for value in [
            "g".repeat(64),
            "G".repeat(64),
            format!("{} ", "a".repeat(63)),
            format!("{}\0", "a".repeat(63)),
            format!("{}é", "a".repeat(62)),
            format!("{}É", "A".repeat(62)),
        ] {
            assert_eq!(
                Sha256Digest::parse(&value),
                Err(Sha256DigestRefusal::NotHex),
                "{value:?}"
            );
            assert_eq!(
                Sha256Digest::from_wire(&value),
                Err(Sha256DigestRefusal::NotHex),
                "{value:?}"
            );
        }
        assert_eq!(
            Sha256DigestRefusal::NotHex.to_string(),
            "a SHA-256 digest holds only the hexadecimal digits `0` to `9` and `a` to `f`"
        );
    }

    #[test]
    fn from_bytes_spells_every_byte_as_two_lowercase_digits() {
        for start in (0..=u8::MAX).step_by(32) {
            let bytes: [u8; 32] = std::array::from_fn(|offset| {
                start.checked_add(u8::try_from(offset).unwrap()).unwrap()
            });
            let expected = bytes.iter().fold(String::new(), |mut expected, byte| {
                write!(expected, "{byte:02x}").unwrap();
                expected
            });
            let digest = Sha256Digest::from_bytes(bytes);
            assert_eq!(digest.as_str(), expected);
            assert_eq!(Sha256Digest::parse(&expected), Ok(digest));
        }
    }

    #[test]
    fn serde_writes_and_reads_only_the_lowercase_string() {
        let digest = Sha256Digest::parse(&"e".repeat(64)).unwrap();
        let json = serde_json::to_string(&digest).unwrap();
        assert_eq!(json, format!("\"{}\"", "e".repeat(64)));
        assert_eq!(serde_json::from_str::<Sha256Digest>(&json).unwrap(), digest);
        for (value, refusal) in [
            ("E".repeat(64), Sha256DigestRefusal::Uppercase),
            ("e".repeat(65), Sha256DigestRefusal::Length { found: 65 }),
            ("x".repeat(64), Sha256DigestRefusal::NotHex),
        ] {
            let error = serde_json::from_str::<Sha256Digest>(&format!("\"{value}\"")).unwrap_err();
            assert!(
                error.to_string().starts_with(&refusal.to_string()),
                "{value}: {error}"
            );
        }
        serde_json::from_str::<Sha256Digest>("64").unwrap_err();
    }
}

#[cfg(test)]
mod object_id_tests {
    use super::{CommitId, ObjectId, ObjectIdRefusal};

    #[test]
    fn an_object_id_is_exactly_forty_lowercase_hexadecimal_digits() {
        let id = "0123456789abcdef0123456789abcdef01234567";
        let parsed = ObjectId::parse(id).unwrap();
        assert_eq!(parsed.as_str(), id);
        assert_eq!(parsed.to_string(), id);
        assert_eq!(AsRef::<str>::as_ref(&parsed), id);
        assert_eq!(String::from(parsed), id);
        assert_eq!(ObjectId::LEN, CommitId::LEN);
    }

    #[test]
    fn every_other_length_is_refused_with_the_length_it_has() {
        for found in [0, 1, 39, 41, 64] {
            assert_eq!(
                ObjectId::parse(&"a".repeat(found)),
                Err(ObjectIdRefusal::Length { found }),
                "{found}"
            );
        }
        assert_eq!(
            ObjectId::parse(&"a".repeat(41)).unwrap_err().to_string(),
            "an object ID has 40 lowercase hexadecimal digits, and this value has 41 bytes"
        );
    }

    #[test]
    fn an_uppercase_or_other_character_is_refused() {
        for value in [
            "A".repeat(40),
            format!("{}F", "a".repeat(39)),
            format!("{}g", "a".repeat(39)),
            format!("{} ", "a".repeat(39)),
            format!("{}\0", "a".repeat(39)),
            format!("{}é", "a".repeat(38)),
        ] {
            assert_eq!(
                ObjectId::parse(&value),
                Err(ObjectIdRefusal::NotLowercaseHex),
                "{value:?}"
            );
        }
        assert_eq!(
            ObjectIdRefusal::NotLowercaseHex.to_string(),
            "an object ID holds only the lowercase hexadecimal digits `0` to `9` and `a` to `f`"
        );
    }

    #[test]
    fn serde_writes_and_reads_the_plain_string() {
        let id = ObjectId::parse(&"c".repeat(40)).unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", "c".repeat(40)));
        assert_eq!(serde_json::from_str::<ObjectId>(&json).unwrap(), id);
        for (value, refusal) in [
            ("d".repeat(41), ObjectIdRefusal::Length { found: 41 }),
            ("D".repeat(40), ObjectIdRefusal::NotLowercaseHex),
        ] {
            let error = serde_json::from_str::<ObjectId>(&format!("\"{value}\"")).unwrap_err();
            assert!(
                error.to_string().starts_with(&refusal.to_string()),
                "{value}: {error}"
            );
        }
        serde_json::from_str::<ObjectId>("40").unwrap_err();
    }
}
