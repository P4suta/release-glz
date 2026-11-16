//! Canonical JSON bytes, and the SHA-256 digests that the public contract records.
//!
//! A digest of a value is taken over its canonical JSON rather than serde's default output, so two runs on different platforms and two independent implementations agree byte for byte.
//! Every digest ends here as a [`Sha256Digest`], so it has the one lowercase spelling of that type.

use std::fmt;

use anyhow::{Context, Result};
use release_glz_domain::Sha256Digest;
use serde::Serialize;
use serde::ser::{
    SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant, Serializer,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::refuse;

/// Serialize a value using the JSON Canonicalization Scheme from RFC 8785.
///
/// A non-finite number is refused before `serde_json::to_value` can write it as `null`.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    if value.serialize(FiniteNumbers) == Err(Stop::NonFinite) {
        refuse!(
            CanonicalNumberNonFinite,
            "RFC 8785 does not permit non-finite JSON numbers"
        );
    }
    let value = serde_json::to_value(value).context("value cannot be represented as JSON")?;
    let mut output = Vec::new();
    write_value(&value, &mut output)?;
    Ok(output)
}

/// Hash the canonical JSON bytes of a value with SHA-256.
///
/// The result is what the public contract calls an intent or candidate digest.
pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<Sha256Digest> {
    Ok(sha256(canonical_json_bytes(value)?))
}

/// The SHA-256 digest of `bytes`.
pub fn sha256(bytes: impl AsRef<[u8]>) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

/// The SHA-256 digest of every byte that `hasher` took in.
pub fn finalize_sha256(hasher: Sha256) -> Sha256Digest {
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn write_value(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::String(value) => serde_json::to_writer(output, value)?,
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                output.extend_from_slice(value.to_string().as_bytes());
            } else if let Some(value) = number.as_u64() {
                output.extend_from_slice(value.to_string().as_bytes());
            } else if let Some(value) = number.as_f64() {
                output.extend_from_slice(ecmascript_number(value)?.as_bytes());
            } else {
                refuse!(
                    CanonicalNumberNonFinite,
                    "JSON number is outside the RFC 8785 I-JSON domain"
                );
            }
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_value(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| release_glz_core::utf16_cmp(left, right));
            output.push(b'{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)?;
                output.push(b':');
                write_value(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn ecmascript_number(value: f64) -> Result<String> {
    if !value.is_finite() {
        refuse!(
            CanonicalNumberNonFinite,
            "RFC 8785 does not permit non-finite JSON numbers"
        );
    }
    let mut buffer = ryu_js::Buffer::new();
    Ok(buffer.format(value).to_owned())
}

/// What stopped [`FiniteNumbers`] before the end of a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// An `f32` or `f64` that is NaN or an infinity.
    NonFinite,
    /// An error of the value's own `Serialize` implementation, which `serde_json::to_value` meets and reports in turn.
    Custom,
}

impl fmt::Display for Stop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonFinite => "a non-finite number",
            Self::Custom => "an error of the value's own serializer",
        })
    }
}

impl std::error::Error for Stop {}

impl serde::ser::Error for Stop {
    fn custom<T: fmt::Display>(_: T) -> Self {
        Self::Custom
    }
}

/// A serializer that writes nothing and stops at the first non-finite number, at any depth and in map keys too.
#[derive(Debug, Clone, Copy)]
struct FiniteNumbers;

/// Accept a scalar of each listed type, none of which can be non-finite.
macro_rules! accept_scalars {
    ($($method:ident: $scalar:ty),+ $(,)?) => {
        $(fn $method(self, _: $scalar) -> Result<(), Stop> {
            Ok(())
        })+
    };
}

impl Serializer for FiniteNumbers {
    type Ok = ();
    type Error = Stop;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    accept_scalars! {
        serialize_bool: bool,
        serialize_i8: i8,
        serialize_i16: i16,
        serialize_i32: i32,
        serialize_i64: i64,
        serialize_i128: i128,
        serialize_u8: u8,
        serialize_u16: u16,
        serialize_u32: u32,
        serialize_u64: u64,
        serialize_u128: u128,
        serialize_char: char,
        serialize_str: &str,
        serialize_bytes: &[u8],
        serialize_unit_struct: &'static str,
    }

    fn serialize_f32(self, value: f32) -> Result<(), Stop> {
        if value.is_finite() {
            Ok(())
        } else {
            Err(Stop::NonFinite)
        }
    }

    fn serialize_f64(self, value: f64) -> Result<(), Stop> {
        if value.is_finite() {
            Ok(())
        } else {
            Err(Stop::NonFinite)
        }
    }

    fn serialize_none(self) -> Result<(), Stop> {
        Ok(())
    }

    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), Stop> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<(), Stop> {
        Ok(())
    }

    fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<(), Stop> {
        Ok(())
    }

    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<(), Stop> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        value: &T,
    ) -> Result<(), Stop> {
        value.serialize(self)
    }

    fn serialize_seq(self, _: Option<usize>) -> Result<Self, Stop> {
        Ok(self)
    }

    fn serialize_tuple(self, _: usize) -> Result<Self, Stop> {
        Ok(self)
    }

    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Self, Stop> {
        Ok(self)
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self, Stop> {
        Ok(self)
    }

    fn serialize_map(self, _: Option<usize>) -> Result<Self, Stop> {
        Ok(self)
    }

    fn serialize_struct(self, _: &'static str, _: usize) -> Result<Self, Stop> {
        Ok(self)
    }

    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        _: usize,
    ) -> Result<Self, Stop> {
        Ok(self)
    }
}

impl SerializeSeq for FiniteNumbers {
    type Ok = ();
    type Error = Stop;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Stop> {
        value.serialize(Self)
    }

    fn end(self) -> Result<(), Stop> {
        Ok(())
    }
}

impl SerializeTuple for FiniteNumbers {
    type Ok = ();
    type Error = Stop;

    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Stop> {
        value.serialize(Self)
    }

    fn end(self) -> Result<(), Stop> {
        Ok(())
    }
}

impl SerializeTupleStruct for FiniteNumbers {
    type Ok = ();
    type Error = Stop;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Stop> {
        value.serialize(Self)
    }

    fn end(self) -> Result<(), Stop> {
        Ok(())
    }
}

impl SerializeTupleVariant for FiniteNumbers {
    type Ok = ();
    type Error = Stop;

    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Stop> {
        value.serialize(Self)
    }

    fn end(self) -> Result<(), Stop> {
        Ok(())
    }
}

impl SerializeMap for FiniteNumbers {
    type Ok = ();
    type Error = Stop;

    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Stop> {
        key.serialize(Self)
    }

    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Stop> {
        value.serialize(Self)
    }

    fn end(self) -> Result<(), Stop> {
        Ok(())
    }
}

impl SerializeStruct for FiniteNumbers {
    type Ok = ();
    type Error = Stop;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _: &'static str,
        value: &T,
    ) -> Result<(), Stop> {
        value.serialize(Self)
    }

    fn end(self) -> Result<(), Stop> {
        Ok(())
    }
}

impl SerializeStructVariant for FiniteNumbers {
    type Ok = ();
    type Error = Stop;

    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        _: &'static str,
        value: &T,
    ) -> Result<(), Stop> {
        value.serialize(Self)
    }

    fn end(self) -> Result<(), Stop> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failure::{RefusalReason, refusal_reason};

    #[test]
    fn ecmascript_formatter_rejects_every_non_finite_number() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let error = ecmascript_number(value).unwrap_err();
            assert_eq!(
                refusal_reason(&error),
                Some(RefusalReason::CanonicalNumberNonFinite),
                "{error:#}"
            );
        }
    }

    /// The vectors are the SHA-256 examples of FIPS 180-2 and the digest of no bytes.
    #[test]
    fn digests_match_the_published_vectors_in_lowercase() {
        for (bytes, expected) in [
            (
                &b""[..],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            assert_eq!(sha256(bytes).as_str(), expected);
            let mut hasher = Sha256::new();
            for chunk in bytes.chunks(7) {
                hasher.update(chunk);
            }
            assert_eq!(finalize_sha256(hasher), sha256(bytes));
        }
    }
}
