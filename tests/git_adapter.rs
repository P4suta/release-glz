use std::fs;
use std::path::{Path, PathBuf};

use release_glz::git::GitRepo;
use release_glz_test_support::{git, init_repository};

fn commit(repository: &Path, message: &str) -> String {
    git(
        repository,
        &["commit", "--quiet", "--allow-empty", "--message", message],
    );
    git(repository, &["rev-parse", "HEAD"]).trim().to_owned()
}

/// A working repository with an `origin` bare remote beside it.
fn repository_with_remote(root: &Path) -> (PathBuf, PathBuf) {
    let remote = root.join("remote.git");
    let work = root.join("work");
    fs::create_dir(&work).unwrap();
    git(
        root,
        &["init", "--quiet", "--bare", remote.to_str().unwrap()],
    );
    init_repository(&work);
    git(
        &work,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    (work, remote)
}

#[test]
fn a_remote_tag_lookup_ignores_tags_whose_names_only_end_in_the_release_tag() {
    let temp = tempfile::tempdir().unwrap();
    let (work, _remote) = repository_with_remote(temp.path());
    let release = commit(&work, "release");
    git(&work, &["tag", "v1.0.0"]);
    let shadow = commit(&work, "shadow");
    git(&work, &["tag", "z/refs/tags/v1.0.0"]);
    git(&work, &["push", "--quiet", "origin", "--tags"]);

    let repo = GitRepo::discover(&work).unwrap();
    let state = repo.remote_tag_state("v1.0.0").unwrap().unwrap();
    assert_eq!(state.target_sha, release);
    assert_ne!(state.target_sha, shadow);
    assert!(!state.annotated);
    assert_eq!(repo.remote_tag_sha("v2.0.0").unwrap(), None);
}

#[test]
fn an_annotated_remote_tag_reports_the_commit_it_peels_to() {
    let temp = tempfile::tempdir().unwrap();
    let (work, _remote) = repository_with_remote(temp.path());
    let release = commit(&work, "release");
    git(
        &work,
        &["tag", "--annotate", "v1.0.0", "--message", "v1.0.0"],
    );
    commit(&work, "shadow");
    git(
        &work,
        &[
            "tag",
            "--annotate",
            "z/refs/tags/v1.0.0",
            "--message",
            "shadow",
        ],
    );
    git(&work, &["push", "--quiet", "origin", "--tags"]);

    let state = GitRepo::discover(&work)
        .unwrap()
        .remote_tag_state("v1.0.0")
        .unwrap()
        .unwrap();
    assert_eq!(state.target_sha, release);
    assert!(state.annotated);
}

#[test]
fn commit_messages_carrying_control_separators_round_trip() {
    let temp = tempfile::tempdir().unwrap();
    init_repository(temp.path());
    let subject = "feat: one\u{1f}two\u{1e}three";
    let body = "body\u{1e}with\u{1f}separators\n\nand a second paragraph";
    let sha = commit(temp.path(), &format!("{subject}\n\n{body}"));
    let earlier = commit(temp.path(), "fix: an ordinary commit");

    let commits = GitRepo::discover(temp.path())
        .unwrap()
        .commits_since(None)
        .unwrap();
    assert_eq!(commits.len(), 2);
    assert_eq!(commits[0].sha, earlier);
    assert_eq!(commits[0].subject, "fix: an ordinary commit");
    assert_eq!(commits[0].body, "");
    assert_eq!(commits[1].sha, sha);
    assert_eq!(commits[1].subject, subject);
    assert_eq!(commits[1].body, body);
    assert_eq!(commits[1].author_name, "release-glz test");
    assert_eq!(commits[1].author_email, "release-glz-test@example.invalid");
}

#[test]
fn a_ref_that_looks_like_an_option_resolves_to_nothing() {
    let temp = tempfile::tempdir().unwrap();
    init_repository(temp.path());
    commit(temp.path(), "first");
    let repo = GitRepo::discover(temp.path()).unwrap();
    assert_eq!(repo.resolve("--all").unwrap(), None);
    assert_eq!(repo.resolve("-h").unwrap(), None);
}

#[test]
fn history_contains_only_full_ids_of_head_and_its_ancestors() {
    let temp = tempfile::tempdir().unwrap();
    init_repository(temp.path());
    let first = commit(temp.path(), "first");
    git(temp.path(), &["switch", "--quiet", "--create", "side"]);
    let side = commit(temp.path(), "side");
    git(temp.path(), &["switch", "--quiet", "-"]);
    let head = commit(temp.path(), "second");
    let repo = GitRepo::discover(temp.path()).unwrap();

    assert!(repo.history_contains(&first).unwrap());
    assert!(repo.history_contains(&head).unwrap());
    for outside in [
        side.clone(),
        "f".repeat(40),
        "f".repeat(64),
        first.to_ascii_uppercase(),
        first[..7].to_owned(),
        "HEAD".to_owned(),
        "HEAD~1".to_owned(),
        "side".to_owned(),
        "--all".to_owned(),
        String::new(),
    ] {
        assert!(
            !repo.history_contains(&outside).unwrap(),
            "`{outside}` counted as history"
        );
    }
}
