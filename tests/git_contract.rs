use std::fs;
use std::path::Path;
use std::process::Command;

use release_glz::git::GitRepo;

#[test]
fn default_branch_prefers_remote_then_current_then_main_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let work = temp.path().join("work");
    init_repo(&work, "trunk");
    let repo = GitRepo::discover(&work).unwrap();
    assert_eq!(repo.default_branch().unwrap(), "trunk");

    run_git(&work, &["update-ref", "refs/remotes/origin/stable", "HEAD"]);
    run_git(
        &work,
        &[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/stable",
        ],
    );
    assert_eq!(repo.default_branch().unwrap(), "stable");

    run_git(
        &work,
        &["symbolic-ref", "--delete", "refs/remotes/origin/HEAD"],
    );
    run_git(&work, &["checkout", "--detach", "HEAD"]);
    assert_eq!(repo.default_branch().unwrap(), "main");
}

#[test]
fn commits_resolution_and_bounded_history_have_exact_edges() {
    let temp = tempfile::tempdir().unwrap();
    let work = temp.path().join("work");
    init_repo(&work, "main");
    let first = git_stdout(&work, &["rev-parse", "HEAD"]);
    fs::write(work.join("file.txt"), "second").unwrap();
    run_git(&work, &["add", "file.txt"]);
    commit_index(
        &work,
        "feat: second",
        Some("BREAKING-CHANGE: documented body"),
    );
    let repo = GitRepo::discover(&work).unwrap();

    assert_eq!(repo.head().unwrap().len(), 40);
    assert_eq!(repo.resolve("HEAD").unwrap(), Some(repo.head().unwrap()));
    assert_eq!(repo.resolve("refs/heads/missing").unwrap(), None);
    let all = repo.commits_since(None).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].subject, "feat: second");
    assert!(all[0].body.contains("BREAKING-CHANGE"));
    assert_eq!(repo.commits_since(Some(&first)).unwrap().len(), 1);

    assert!(repo.rev_list_bounded(0).is_err());
    let (one, truncated) = repo.rev_list_bounded(1).unwrap();
    assert_eq!(one.len(), 1);
    assert!(truncated);
    let (all, truncated) = repo.rev_list_bounded(10).unwrap();
    assert_eq!(all.len(), 2);
    assert!(!truncated);
}

#[test]
fn local_and_remote_tag_state_never_conflates_lightweight_and_annotated_tags() {
    let temp = tempfile::tempdir().unwrap();
    let work = temp.path().join("work");
    let bare = temp.path().join("remote.git");
    init_repo(&work, "main");
    run_command(Command::new("git").args(["init", "--bare"]).arg(&bare));
    run_git(&work, &["remote", "add", "origin", bare.to_str().unwrap()]);
    let repo = GitRepo::discover(&work).unwrap();
    let head = repo.head().unwrap();

    assert_eq!(repo.tag_state("missing").unwrap(), None);
    assert_eq!(repo.remote_tag_state("missing").unwrap(), None);

    repo.create_tag("v1.0.0", &head).unwrap();
    let local = repo.tag_state("v1.0.0").unwrap().unwrap();
    assert_eq!(local.target_sha, head);
    assert!(!local.annotated);
    run_git(
        &bare,
        &[
            "fetch",
            work.to_str().unwrap(),
            "refs/tags/v1.0.0:refs/tags/v1.0.0",
        ],
    );
    let remote = repo.remote_tag_state("v1.0.0").unwrap().unwrap();
    assert_eq!(remote.target_sha, head);
    assert!(!remote.annotated);
    assert_eq!(repo.remote_tag_sha("v1.0.0").unwrap(), Some(head.clone()));

    repo.create_annotated_tag("v1.0.1", &head, "release 1.0.1")
        .unwrap();
    run_git(
        &bare,
        &[
            "fetch",
            work.to_str().unwrap(),
            "refs/tags/v1.0.1:refs/tags/v1.0.1",
        ],
    );
    let annotated = repo.remote_tag_state("v1.0.1").unwrap().unwrap();
    assert_eq!(annotated.target_sha, head);
    assert!(annotated.annotated);
}

#[test]
fn git_effect_failures_are_errors_and_never_report_success() {
    let temp = tempfile::tempdir().unwrap();
    let work = temp.path().join("work");
    init_repo(&work, "main");
    let repo = GitRepo::discover(&work).unwrap();
    let head = repo.head().unwrap();
    repo.create_tag("v1.0.0", &head).unwrap();
    assert!(repo.create_tag("v1.0.0", &head).is_err());
    assert!(
        repo.create_annotated_tag("v1.0.0", &head, "duplicate")
            .is_err()
    );
    assert!(repo.push_tag("v1.0.0").is_err());
    assert!(
        repo.archive("refs/heads/missing", &temp.path().join("archive"))
            .is_err()
    );
    assert!(repo.run(["not-a-real-git-subcommand"]).is_err());
    assert!(GitRepo::discover(Path::new("/definitely/not/a/repository")).is_err());
}

#[test]
fn git_snapshot_resolves_safe_long_paths_from_the_committed_tree() {
    let temp = tempfile::tempdir().unwrap();
    let work = temp.path().join("work");
    init_repo(&work, "main");
    let relative = Path::new("src").join("a".repeat(120)).join("module.gleam");
    fs::create_dir_all(work.join(relative.parent().unwrap())).unwrap();
    fs::write(work.join(&relative), "pub fn value() { 1 }\n").unwrap();
    run_git(&work, &["add", relative.to_str().unwrap()]);
    commit_index(&work, "feat: add deeply nested module", None);
    fs::write(work.join(&relative), "dirty working tree").unwrap();

    let repo = GitRepo::discover(&work).unwrap();
    let destination = temp.path().join("snapshot");
    repo.archive(&repo.head().unwrap(), &destination).unwrap();

    assert_eq!(
        fs::read_to_string(destination.join(relative)).unwrap(),
        "pub fn value() { 1 }\n"
    );
}

fn init_repo(path: &Path, branch: &str) {
    fs::create_dir_all(path).unwrap();
    run_command(Command::new("git").args(["init", "-b", branch]).arg(path));
    run_git(path, &["config", "user.name", "Release Test"]);
    run_git(path, &["config", "user.email", "release@example.com"]);
    run_git(path, &["config", "commit.gpgsign", "false"]);
    run_git(path, &["config", "tag.gpgSign", "false"]);
    fs::write(path.join("file.txt"), "first").unwrap();
    run_git(path, &["add", "file.txt"]);
    commit_index(path, "fix: first", None);
}

fn commit_index(path: &Path, subject: &str, body: Option<&str>) {
    let tree = git_stdout(path, &["write-tree"]);
    let parent = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .unwrap();
    let mut command = Command::new("git");
    command.arg("-C").arg(path).args(["commit-tree", &tree]);
    if parent.status.success() {
        command
            .arg("-p")
            .arg(String::from_utf8(parent.stdout).unwrap().trim());
    }
    command.args(["-m", subject]);
    if let Some(body) = body {
        command.args(["-m", body]);
    }
    let commit = command_output(&mut command);
    run_git(path, &["update-ref", "HEAD", &commit]);
}

fn run_git(path: &Path, args: &[&str]) {
    run_command(Command::new("git").arg("-C").arg(path).args(args));
}

fn git_stdout(path: &Path, args: &[&str]) -> String {
    command_output(Command::new("git").arg("-C").arg(path).args(args))
}

fn run_command(command: &mut Command) {
    let _ = command_output(command);
}

fn command_output(command: &mut Command) -> String {
    command
        .env("GIT_AUTHOR_NAME", "Release Test")
        .env("GIT_AUTHOR_EMAIL", "release@example.com")
        .env("GIT_COMMITTER_NAME", "Release Test")
        .env("GIT_COMMITTER_EMAIL", "release@example.com");
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}
