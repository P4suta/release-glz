pub fn redact(input: &str) -> String {
    redact_values(
        input,
        ["HEXPM_API_KEY", "GITHUB_TOKEN", "GH_TOKEN"]
            .into_iter()
            .filter_map(|name| std::env::var(name).ok()),
    )
}

fn redact_values(input: &str, secrets: impl IntoIterator<Item = String>) -> String {
    let mut output = input.to_owned();
    for secret in secrets {
        if !secret.is_empty() {
            output = output.replace(&secret, "[REDACTED]");
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
        let redacted = redact_values(text, ["super-secret".to_owned()]);
        assert_eq!(
            redacted,
            "request Authorization: [REDACTED]; JSON=[REDACTED]"
        );
        assert!(!redacted.contains("super-secret"));
    }

    #[test]
    fn empty_credentials_are_ignored_instead_of_redacting_every_boundary() {
        let text = "registry request failed";
        assert_eq!(redact_values(text, [String::new()]), text);
    }
}
