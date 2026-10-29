//! Redaction of the credentials that GitHub and Hex put in the environment.
//!
//! The test runs itself again as a child with those variables set, because changing this process's environment would race the other tests.

use std::process::Command;

use release_glz::secrets::{redact, redact_with};

/// Set only in the child run, whose environment carries the credentials.
const CHILD_RUN: &str = "RELEASE_GLZ_TEST_REDACTION_CHILD";

/// The credentials that every redaction removes without being told about them.
const STANDARD_CREDENTIALS: [&str; 5] = [
    "HEXPM_API_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
];

#[test]
fn every_standard_credential_in_the_environment_is_redacted() {
    if std::env::var_os(CHILD_RUN).is_some() {
        for name in STANDARD_CREDENTIALS {
            let value = std::env::var(name).unwrap();
            let text = format!("before {value} after");
            assert_eq!(redact(&text), "before [REDACTED] after", "{name}");
            assert_eq!(
                redact_with(&text, ["after"]),
                "before [REDACTED] [REDACTED]",
                "{name}"
            );
        }
        return;
    }
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "every_standard_credential_in_the_environment_is_redacted",
            "--nocapture",
        ])
        .env(CHILD_RUN, "1");
    for (index, name) in STANDARD_CREDENTIALS.into_iter().enumerate() {
        child.env(name, format!("credential-{index}-value"));
    }
    let output = child.output().unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}
