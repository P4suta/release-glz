//! Owned checked types of release-glz.
//!
//! Each type keeps its value private and has one constructor, which accepts a value only when a predicate of `release-glz-core` holds for it.
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
