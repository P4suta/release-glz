//! Redaction applied to text that can leave the process.
//!
//! Standard credential environment variables are redacted unconditionally;
//! a manifest also names its own `credential_env`, which the caller adds.

use release_glz_core::Segment;

const STANDARD_SECRET_ENV_NAMES: [&str; 5] = [
    "HEXPM_API_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
];

/// Replace every standard credential value found in the environment with `[REDACTED]`.
///
/// Error and log text passes through here before it is shown, so a credential that was read into memory cannot reach a transcript.
pub fn redact(input: &str) -> String {
    redact_values(input, standard_secrets())
}

/// Redact the standard credentials and the caller's additional secrets.
///
/// A manifest names its registry credential through `credential_env`, so only the caller knows which extra value has to disappear.
pub fn redact_with<S>(input: &str, secrets: impl IntoIterator<Item = S>) -> String
where
    S: AsRef<str>,
{
    let secrets = secrets
        .into_iter()
        .map(|secret| secret.as_ref().to_owned())
        .collect::<Vec<_>>();
    redact_values(input, standard_secrets().chain(secrets))
}

fn standard_secrets() -> impl Iterator<Item = String> {
    STANDARD_SECRET_ENV_NAMES
        .into_iter()
        .filter_map(|name| std::env::var(name).ok())
}

/// Replace each run of text that some occurrence of a secret covers with one `[REDACTED]`.
///
/// The core decides the runs from every occurrence in the original text, so no secret can hide part of another, whatever their order.
/// Its runs end on character boundaries, so the kept text stays UTF-8.
fn redact_values<S>(input: &str, secrets: impl IntoIterator<Item = S>) -> String
where
    S: AsRef<str>,
{
    let secrets = secrets
        .into_iter()
        .map(|secret| secret.as_ref().to_owned())
        .collect::<Vec<_>>();
    let secrets = secrets.iter().map(String::as_bytes).collect::<Vec<_>>();
    let text = input.as_bytes();
    let mut output = Vec::with_capacity(text.len());
    for segment in release_glz_core::redaction_segments(text, &secrets) {
        match segment {
            Segment::Kept(range) => output.extend_from_slice(&text[range]),
            Segment::Redacted(_) => output.extend_from_slice(b"[REDACTED]"),
        }
    }
    String::from_utf8_lossy(&output).into_owned()
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

    #[test]
    fn a_secret_inside_another_leaves_no_part_of_either() {
        for secrets in [["abc", "abcdef"], ["abcdef", "abc"]] {
            assert_eq!(
                redact_values("x abcdef y", secrets),
                "x [REDACTED] y",
                "{secrets:?}"
            );
        }
    }

    #[test]
    fn secrets_that_overlap_in_the_text_become_one_redaction() {
        for secrets in [["abcd", "cdef"], ["cdef", "abcd"]] {
            assert_eq!(
                redact_values("abcdef", secrets),
                "[REDACTED]",
                "{secrets:?}"
            );
        }
        assert_eq!(redact_values("aaaa", ["aaa"]), "[REDACTED]");
    }

    #[test]
    fn redaction_keeps_multibyte_characters_whole() {
        assert_eq!(
            redact_values("ééé-秘密-é", ["秘密", "é-秘"]),
            "éé[REDACTED]-é"
        );
    }

    /// The redaction that replaces each maximal run of characters that some secret occurrence covers.
    fn covered_runs_redacted(text: &str, secrets: &[&str]) -> String {
        let mut covered = vec![false; text.len()];
        for secret in secrets.iter().filter(|secret| !secret.is_empty()) {
            for (start, _) in text.char_indices() {
                if text[start..].starts_with(secret) {
                    covered[start..start + secret.len()].fill(true);
                }
            }
        }
        let mut output = String::new();
        let mut redacting = false;
        for (index, character) in text.char_indices() {
            if !covered[index] {
                output.push(character);
            } else if !redacting {
                output.push_str("[REDACTED]");
            }
            redacting = covered[index];
        }
        output
    }

    /// Every word over `ab` whose length is at most `max`, including the empty word.
    fn words(max: usize) -> Vec<String> {
        let mut words = vec![String::new()];
        let mut previous = vec![String::new()];
        for _ in 0..max {
            previous = previous
                .iter()
                .flat_map(|word| [format!("{word}a"), format!("{word}b")])
                .collect();
            words.extend(previous.iter().cloned());
        }
        words
    }

    #[test]
    fn every_short_text_loses_exactly_the_characters_its_secrets_cover() {
        let secrets = words(3);
        for text in words(7) {
            for first in &secrets {
                for second in &secrets {
                    let pair = [first.as_str(), second.as_str()];
                    assert_eq!(
                        redact_values(&text, pair),
                        covered_runs_redacted(&text, &pair),
                        "{text:?} with {pair:?}"
                    );
                }
            }
        }
    }
}
