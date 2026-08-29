use std::cmp::Ordering;

use anyhow::{Context, Result, bail};
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

pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(canonical_json_bytes(value)?)
    ))
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
            entries.sort_by(|(left, _), (right, _)| utf16_cmp(left, right));
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

fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
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
}
