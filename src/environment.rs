//! The environment variables that release-glz reads as settings, each either unset or Unicode.

use std::ffi::OsString;

use anyhow::Result;

use crate::failure::{RefusalReason, refused};

/// The value of the environment variable `name`, or `None` when it isn't set.
///
/// # Errors
///
/// Refuses a value that isn't Unicode, which no setting that release-glz reads can hold.
pub fn variable(name: &str) -> Result<Option<String>> {
    setting(name, std::env::var_os(name))
}

/// The setting that `value` of the variable `name` holds, without echoing a value that isn't Unicode, since it may be a credential.
fn setting(name: &str, value: Option<OsString>) -> Result<Option<String>> {
    value
        .map(|value| {
            value.into_string().map_err(|_| {
                refused(
                    RefusalReason::EnvironmentValueNotUnicode,
                    format_args!(
                        "the environment variable `{name}` holds a value that isn't Unicode"
                    ),
                )
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::setting;
    use crate::failure::{RefusalReason, refusal_reason};
    use std::ffi::OsString;

    #[cfg(unix)]
    fn not_unicode() -> OsString {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(vec![b'x', 0xff])
    }

    #[cfg(windows)]
    fn not_unicode() -> OsString {
        use std::os::windows::ffi::OsStringExt;
        OsString::from_wide(&[u16::from(b'x'), 0xd800])
    }

    #[test]
    fn only_an_unset_variable_reads_as_absent_and_a_value_that_isnt_unicode_is_refused() {
        assert_eq!(setting("NAME", None).unwrap(), None);
        assert_eq!(
            setting("NAME", Some("value".into())).unwrap().as_deref(),
            Some("value")
        );
        let error = setting("NAME", Some(not_unicode())).unwrap_err();
        assert_eq!(
            (refusal_reason(&error), error.to_string()),
            (
                Some(RefusalReason::EnvironmentValueNotUnicode),
                "the environment variable `NAME` holds a value that isn't Unicode".to_owned()
            )
        );
    }
}
