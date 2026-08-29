use std::fs;
use std::process::Command;

use release_glz::git::GitRepo;

#[test]
fn release_tags_are_annotated_and_observable_after_push() {
    let temp = tempfile::tempdir().unwrap();
    let remote = temp.path().join("remote.git");
    let work = temp.path().join("work");
    git(temp.path(), &["init", "--bare", remote.to_str().unwrap()]);
    git(temp.path(), &["init", work.to_str().unwrap()]);
    git(&work, &["config", "user.name", "Test"]);
    git(&work, &["config", "user.email", "test@example.invalid"]);
    git(&work, &["config", "commit.gpgsign", "false"]);
    git(&work, &["config", "tag.gpgsign", "false"]);
    fs::write(work.join("README.md"), "fixture").unwrap();
    git(&work, &["add", "README.md"]);
    let tree = git_output(&work, &["write-tree"]);
    let commit = git_output(&work, &["commit-tree", &tree, "-m", "initial"]);
    git(&work, &["update-ref", "HEAD", &commit]);
    git(
        &work,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );

    let repo = GitRepo::discover(&work).unwrap();
    let head = repo.head().unwrap();
    repo.create_annotated_tag("v1.2.3", &head, "release widget 1.2.3")
        .unwrap();
    let local = repo.tag_state("v1.2.3").unwrap().unwrap();
    assert_eq!(local.target_sha, head);
    assert!(local.annotated);

    let pushed = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(&work)
        .args(["push", "--no-verify", "origin", "refs/tags/v1.2.3"])
        .output()
        .unwrap();
    assert!(
        pushed.status.success(),
        "{}",
        String::from_utf8_lossy(&pushed.stderr)
    );
    let remote = repo.remote_tag_state("v1.2.3").unwrap().unwrap();
    assert_eq!(remote.target_sha, head);
    assert!(remote.annotated);
}

fn git(directory: &std::path::Path, args: &[&str]) {
    let _ = git_output(directory, args);
}

fn git_output(directory: &std::path::Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
