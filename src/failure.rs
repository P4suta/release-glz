use std::fmt;

use anyhow::Error;
use serde::{Deserialize, Serialize};

/// Stable classes shared by the CLI exit status and machine-readable error code.
///
/// Classification is deliberately carried by the error type. Error message text
/// is presentation only and can never change the exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    Internal,
    UsageOrConfig,
    PolicyOrApproval,
    ImmutableStateConflict,
    TemporaryExternal,
    Hook,
    PartialRelease,
}

impl FailureClass {
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Internal => 1,
            Self::UsageOrConfig => 2,
            Self::PolicyOrApproval => 3,
            Self::ImmutableStateConflict => 4,
            Self::TemporaryExternal => 5,
            Self::Hook => 6,
            Self::PartialRelease => 7,
        }
    }

    pub const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::Internal => "internal_failure",
            Self::UsageOrConfig => "usage_or_config",
            Self::PolicyOrApproval => "policy_or_approval",
            Self::ImmutableStateConflict => "immutable_state_conflict",
            Self::TemporaryExternal => "temporary_external_failure",
            Self::Hook => "hook_failure",
            Self::PartialRelease => "partial_release",
        }
    }
}

#[derive(Debug)]
pub struct ClassifiedFailure {
    class: FailureClass,
    message: String,
}

impl ClassifiedFailure {
    pub fn new(class: FailureClass, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
        }
    }

    pub const fn class(&self) -> FailureClass {
        self.class
    }
}

impl fmt::Display for ClassifiedFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ClassifiedFailure {}

pub fn classified(class: FailureClass, error: impl fmt::Display) -> Error {
    Error::new(ClassifiedFailure::new(class, error.to_string()))
}

/// Attach a boundary-specific class without replacing a more precise class
/// already carried by the source error.
pub fn with_default_class(error: Error, fallback: FailureClass) -> Error {
    if classify(&error) == FailureClass::Internal
        && error.downcast_ref::<ClassifiedFailure>().is_none()
    {
        classified(fallback, error)
    } else {
        error
    }
}

pub fn classify(error: &Error) -> FailureClass {
    if let Some(classified) = error.downcast_ref::<ClassifiedFailure>() {
        return classified.class();
    }
    if let Some(release) = error.downcast_ref::<crate::release::ReleaseRunError>() {
        return release.failure_class();
    }
    if let Some(error) = error.downcast_ref::<reqwest::Error>()
        && (error.is_timeout() || error.is_connect())
    {
        return FailureClass::TemporaryExternal;
    }
    FailureClass::Internal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_failure_class_has_a_stable_machine_contract() {
        let cases = [
            (FailureClass::Internal, 1, "internal_failure"),
            (FailureClass::UsageOrConfig, 2, "usage_or_config"),
            (FailureClass::PolicyOrApproval, 3, "policy_or_approval"),
            (
                FailureClass::ImmutableStateConflict,
                4,
                "immutable_state_conflict",
            ),
            (
                FailureClass::TemporaryExternal,
                5,
                "temporary_external_failure",
            ),
            (FailureClass::Hook, 6, "hook_failure"),
            (FailureClass::PartialRelease, 7, "partial_release"),
        ];

        for (class, exit_code, diagnostic_code) in cases {
            assert_eq!(class.exit_code(), exit_code);
            assert_eq!(class.diagnostic_code(), diagnostic_code);
        }
    }

    #[test]
    fn message_words_never_select_a_failure_class() {
        for message in [
            "hook approval conflict timed out invalid TOML",
            "connection policy checksum mismatch",
        ] {
            assert_eq!(classify(&anyhow::anyhow!(message)), FailureClass::Internal);
        }
        let failure = classified(FailureClass::UsageOrConfig, "an unrelated message");
        assert_eq!(classify(&failure), FailureClass::UsageOrConfig);
        let preserved = with_default_class(failure, FailureClass::TemporaryExternal);
        assert_eq!(classify(&preserved), FailureClass::UsageOrConfig);
        let defaulted = with_default_class(
            anyhow::anyhow!("untyped boundary error"),
            FailureClass::TemporaryExternal,
        );
        assert_eq!(classify(&defaulted), FailureClass::TemporaryExternal);
    }
}
