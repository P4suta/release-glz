//! Canonical JSON bytes, and the SHA-256 digests that the public contract records.
//!
//! A digest of a value is taken over its canonical JSON rather than serde's default output, so two runs on different platforms and two independent implementations agree byte for byte.
//! Every digest ends here as a [`Sha256Digest`], so it has the one lowercase spelling of that type.

use anyhow::{Context, Result, bail};
use release_glz_domain::Sha256Digest;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Serialize a value using the JSON Canonicalization Scheme from RFC 8785.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
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
                bail!("JSON number is outside the RFC 8785 I-JSON domain");
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
        bail!("RFC 8785 does not permit non-finite JSON numbers");
    }
    let mut buffer = ryu_js::Buffer::new();
    Ok(buffer.format(value).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecmascript_formatter_rejects_every_non_finite_number() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let error = ecmascript_number(value).unwrap_err().to_string();
            assert!(error.contains("non-finite"), "{error}");
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
