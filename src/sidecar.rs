use std::path::Path;

use anyhow::{Result, bail};

pub(crate) const MAX_COUNT: usize = 64;
pub(crate) const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;

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
        || name.len() > 256
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
        || media_type.len() > 128
        || !media_type.contains('/')
        || !media_type
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
    {
        bail!("sidecar artifact media type is invalid");
    }
    Ok(())
}
