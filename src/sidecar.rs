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

/// Refuse a name that GitHub would change when it receives the asset.
///
/// GitHub renames an asset whose name has special characters or a leading or trailing `.`, and the upload then fails after the package is public.
/// The rule also keeps the name a single filename in the Candidate directory.
pub(crate) fn validate_name(name: &str) -> Result<()> {
    let kept = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && !name.starts_with('.')
        && !name.ends_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    if !kept {
        bail!(
            "sidecar artifact name {name:?} is not a safe asset name, which GitHub keeps as it is: use 1 to {MAX_NAME_LEN} ASCII letters, digits, `.`, `-`, and `_`, with no `.` at either end"
        );
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

    /// GitHub keeps these names, so an upload comes back under the name the Candidate seals.
    #[test]
    fn an_asset_name_github_keeps_is_admitted() {
        let longest = "x".repeat(MAX_NAME_LEN);
        for name in [
            "sbom.cdx.json",
            "release-glz.intoto.jsonl",
            "widget-1.2.3-rc.1.cdx.json",
            "Widget_1.2.3.tar.gz",
            "SHA256SUMS",
            "a",
            "a..b",
            longest.as_str(),
        ] {
            assert!(validate_name(name).is_ok(), "refused {name:?}");
        }
    }

    /// Each class of name that GitHub would rename, or that names no single file, fails with the rule it breaks.
    #[test]
    fn an_asset_name_github_would_rename_is_refused() {
        let too_long = "x".repeat(MAX_NAME_LEN + 1);
        for name in [
            "",
            too_long.as_str(),
            ".",
            "..",
            ".sbom.json",
            "sbom.json.",
            "my sbom.json",
            "widget-1.0.0+build.1.cdx.json",
            "widget~1.json",
            "widget(1).json",
            "widget:1.json",
            "widget@1.json",
            "nested/evidence.json",
            "nested\\evidence.json",
            "/absolute",
            "bad\nname",
            "bad\0name",
            "sböm.json",
        ] {
            let error = validate_name(name).unwrap_err().to_string();
            assert!(error.contains("safe asset name"), "{name:?}: {error}");
            assert!(
                error.contains("ASCII letters, digits, `.`, `-`, and `_`"),
                "{name:?}: {error}"
            );
        }
    }

    /// The rule refuses every character outside ASCII letters, digits, `.`, `-`, and `_` in every position, and `.` at either end.
    #[test]
    fn every_character_github_renames_is_refused_in_every_position() {
        let samples =
            (0..=0x2ff_u32)
                .filter_map(char::from_u32)
                .chain(['€', '日', '\u{feff}', '\u{10ffff}']);
        for character in samples {
            let kept = character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_');
            let kept_at_an_end = kept && character != '.';
            assert_eq!(
                validate_name(&format!("a{character}b")).is_ok(),
                kept,
                "{character:?} inside a name"
            );
            assert_eq!(
                validate_name(&format!("{character}b")).is_ok(),
                kept_at_an_end,
                "{character:?} at the start of a name"
            );
            assert_eq!(
                validate_name(&format!("a{character}")).is_ok(),
                kept_at_an_end,
                "{character:?} at the end of a name"
            );
        }
    }
}
