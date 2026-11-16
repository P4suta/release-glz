//! Properties of the reader of the records that `git log` prints for release notes and intent.
//!
//! Each accepted commit has a commit ID of 40 lowercase hexadecimal digits, fields without NUL, and a body without surrounding whitespace.
//! The records that `git log` would print for the accepted commits read back as the same commits.
//! A refusal is the documented error of a record that lacks its commit ID or a field.

use release_glz::git::{Commit, parse_commit_log};

const COMMIT_DIGITS: usize = 40;
const MISSING: &str = "git log record has no ";

/// A verdict that accepted an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reached {
    Commits,
}

pub fn check(data: &[u8]) -> Vec<Reached> {
    let Ok(raw) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    let commits = match parse_commit_log(raw) {
        Ok(commits) => commits,
        Err(error) => {
            assert!(error.to_string().starts_with(MISSING), "{error:#}");
            return Vec::new();
        }
    };
    for commit in &commits {
        assert_eq!(commit.sha.len(), COMMIT_DIGITS, "{commit:?}");
        assert!(
            commit
                .sha
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "{commit:?}"
        );
        for field in [
            &commit.author_name,
            &commit.author_email,
            &commit.subject,
            &commit.body,
        ] {
            assert!(!field.contains('\0'), "{commit:?}");
        }
        assert_eq!(commit.body.trim(), commit.body);
        commit.conventional_bump();
    }
    assert_eq!(
        parse_commit_log(&render(&commits)).expect("rendered records read back"),
        commits
    );
    vec![Reached::Commits]
}

/// The records that `git log` prints for `commits`, each field followed by NUL and each record by a newline.
fn render(commits: &[Commit]) -> String {
    commits
        .iter()
        .map(|commit| {
            format!(
                "{}\0{}\0{}\0{}\0{}\0\n",
                commit.sha, commit.author_name, commit.author_email, commit.subject, commit.body
            )
        })
        .collect()
}
