use std::path::Path;

use anyhow::{Result, bail};

use crate::units::MIB;

/// Sidecar artifacts one Candidate may carry.
pub(crate) const MAX_COUNT: usize = 64;

/// Size one sidecar artifact may reach.
pub(crate) const MAX_ARTIFACT_BYTES: u64 = 64 * MIB;

/// Size every sidecar artifact may reach together.
pub(crate) const MAX_TOTAL_BYTES: u64 = 128 * MIB;

/// Characters a sidecar artifact name may use.
pub(crate) const MAX_NAME_LEN: usize = 256;

/// Characters a sidecar media type may use.
pub(crate) const MAX_MEDIA_TYPE_LEN: usize = 128;

pub(crate) fn validate_hook_id(hook_id: &str) -> Result<()> {
    let valid = !hook_id.is_empty()
        && hook_id.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'A'..=b'Z' => true,
            b'0'..=b'9' | b'_' | b'-' | b'.' => index > 0,
            _ => false,
        });
    if !valid {
        bail!("sidecar artifact hook id is unsafe");
    }
    Ok(())
}

pub(crate) fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > MAX_NAME_LEN
        || name.contains(['/', '\\', '\n', '\r', '\0'])
        || Path::new(name).is_absolute()
        || Path::new(name)
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("sidecar artifact name `{name}` is not a safe asset name");
    }
    Ok(())
}

pub(crate) fn validate_media_type(media_type: &str) -> Result<()> {
    if media_type.is_empty()
        || media_type.len() > MAX_MEDIA_TYPE_LEN
        || !media_type.contains('/')
        || !media_type
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
    {
        bail!("sidecar artifact media type is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_identifiers_reject_every_path_and_character_boundary() {
        assert!(validate_hook_id("Upper.case-1").is_ok());
        assert!(validate_hook_id("bad id").is_err());

        for name in ["/absolute", ".."] {
            assert!(validate_name(name).is_err(), "accepted {name:?}");
        }

        assert!(validate_media_type(&format!("application/{}", "x".repeat(128))).is_err());
        assert!(validate_media_type("application/\u{7f}json").is_err());
    }
}
