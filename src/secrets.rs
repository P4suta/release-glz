const STANDARD_SECRET_ENV_NAMES: [&str; 5] = [
    "HEXPM_API_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
];

pub fn redact(input: &str) -> String {
    redact_values(
        input,
        STANDARD_SECRET_ENV_NAMES
            .into_iter()
            .filter_map(|name| std::env::var(name).ok()),
    )
}

pub fn redact_with<S>(input: &str, secrets: impl IntoIterator<Item = S>) -> String
where
    S: AsRef<str>,
{
    redact_values(&redact(input), secrets)
}

fn redact_values<S>(input: &str, secrets: impl IntoIterator<Item = S>) -> String
where
    S: AsRef<str>,
{
    let mut output = input.to_owned();
    for secret in secrets {
        let secret = secret.as_ref();
        if !secret.is_empty() {
            output = output.replace(secret, "[REDACTED]");
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_tokens_from_arbitrary_output() {
        let text = "request Authorization: super-secret; JSON=super-secret";
        let redacted = redact_values(text, ["super-secret"]);
        assert_eq!(
            redacted,
            "request Authorization: [REDACTED]; JSON=[REDACTED]"
        );
        assert!(!redacted.contains("super-secret"));
    }

    #[test]
    fn empty_credentials_are_ignored_instead_of_redacting_every_boundary() {
        let text = "registry request failed";
        assert_eq!(redact_values(text, [""]), text);
    }

    #[test]
    fn configured_credentials_are_redacted_in_addition_to_standard_names() {
        let text = "custom-value and custom-value again";
        let redacted = redact_with(text, ["custom-value"]);
        assert_eq!(redacted, "[REDACTED] and [REDACTED] again");
    }

    #[test]
    fn github_oidc_and_actions_runtime_tokens_are_standard_secrets() {
        assert!(STANDARD_SECRET_ENV_NAMES.contains(&"ACTIONS_ID_TOKEN_REQUEST_TOKEN"));
        assert!(STANDARD_SECRET_ENV_NAMES.contains(&"ACTIONS_RUNTIME_TOKEN"));
    }
}
