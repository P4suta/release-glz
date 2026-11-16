//! The commit message gate: a Conventional Commit type, and a fix that stages the test it needs.

use crate::container::Failure;
use crate::tool::{Tool, capture};
use std::path::Path;

/// The commit types that `committed.toml` allows.
const TYPES: [&str; 11] = [
    "feat", "fix", "docs", "style", "refactor", "perf", "test", "build", "ci", "chore", "revert",
];

/// The Conventional Commit type of a subject line, if it has one.
fn kind(subject: &str) -> Option<&str> {
    let (head, _) = subject.split_once(':')?;
    let name = head.split(['(', '!']).next()?.trim();
    TYPES.contains(&name).then_some(name)
}

/// Whether a staged change carries a test: a file under a test directory, a fuzz target or seed, or an added test or harness.
fn carries_test(paths: &[&str], diff: &str) -> bool {
    let test_path = paths.iter().any(|path| {
        path.starts_with("tests/")
            || path.contains("/tests/")
            || path.starts_with("fuzz/")
            || path.ends_with(".test.js")
    });
    let added_test = diff.lines().any(|line| {
        line.starts_with('+')
            && (line.contains("#[test]")
                || line.contains("#[tokio::test")
                || line.contains("#[kani::proof]")
                || line.contains("fuzz_target!"))
    });
    test_path || added_test
}

/// The first line of a message that isn't blank or a Git comment.
fn subject(message: &str) -> Option<&str> {
    message
        .lines()
        .map(str::trim_end)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
}

/// Refuses a commit message without a known type, or a fix without a staged test.
///
/// # Errors
///
/// Returns a failure when the message is unreadable or empty, names no Conventional Commit type, or is a fix without a staged test.
/// Returns a failure when Git can't show the staged changes of a fix.
pub fn check(root: &Path, message: &Path) -> Result<(), Failure> {
    let text = crate::fs::read_to_string(message).map_err(|error| {
        Failure::new(format!(
            "the commit message {} is unreadable: {error}",
            message.display()
        ))
    })?;
    let Some(subject) = subject(&text) else {
        return Err(Failure::new("the commit message is empty"));
    };
    if subject.starts_with("Merge ") {
        return Ok(());
    }
    let Some(kind) = kind(subject) else {
        return Err(Failure::new(format!(
            "`{subject}` names no Conventional Commit type; start with one of {}",
            TYPES.join(", ")
        )));
    };
    if kind != "fix" {
        return Ok(());
    }
    let staged = capture(
        Tool::Git
            .command(root)
            .args(["diff", "--cached", "--name-only", "--diff-filter=ACMR"]),
        "git diff --cached --name-only",
    )?;
    let diff = capture(
        Tool::Git.command(root).args(["diff", "--cached", "-U0"]),
        "git diff --cached",
    )?;
    let paths = staged.lines().collect::<Vec<_>>();
    if carries_test(&paths, &diff) {
        Ok(())
    } else {
        Err(Failure::new(
            "a fix lands with a test that fails without it; stage the test with the fix",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{carries_test, kind, subject};

    #[test]
    fn the_type_is_read_before_scope_bang_and_colon() {
        assert_eq!(kind("feat(core)!: add a rule"), Some("feat"));
        assert_eq!(kind("fix: keep the primary error"), Some("fix"));
        assert_eq!(kind("wip: nothing"), None);
        assert_eq!(kind("no colon here"), None);
    }

    #[test]
    fn the_subject_skips_blank_lines_and_git_comments() {
        assert_eq!(subject("\n# Please enter\nfix: x\n"), Some("fix: x"));
        assert_eq!(subject("# only a comment\n\n"), None);
    }

    #[test]
    fn a_fix_needs_a_staged_test() {
        assert!(carries_test(&["tests/registry_contract.rs"], ""));
        assert!(carries_test(&["crates/test-support/tests/x.rs"], ""));
        assert!(carries_test(&["fuzz/fuzz_targets/config.rs"], ""));
        assert!(carries_test(&["action/index.test.js"], ""));
        assert!(carries_test(&["src/config.rs"], "+    #[test]\n"));
        assert!(carries_test(&["src/forge.rs"], "+    #[tokio::test]\n"));
        assert!(carries_test(
            &["crates/release-glz-core/src/run.rs"],
            "+    #[kani::proof]\n"
        ));
        assert!(!carries_test(
            &["src/config.rs"],
            "-    #[test]\n+ fn x() {}\n"
        ));
        assert!(!carries_test(&["src/config.rs"], "+ fn x() {}\n"));
    }
}
