use std::path::Path;
use std::process::Command;

use release_glz_test_support::{git, isolated_command};

#[test]
fn tests_read_git_configuration_only_from_the_isolated_fixture() {
    let global = std::env::var_os("GIT_CONFIG_GLOBAL").expect("GIT_CONFIG_GLOBAL is set by Cargo");
    assert!(
        Path::new(&global).ends_with(Path::new("tests/fixtures/git/isolated.gitconfig")),
        "{global:?}"
    );
    assert_eq!(
        std::env::var("GIT_CONFIG_NOSYSTEM").as_deref(),
        Ok("1"),
        "system Git configuration must be skipped"
    );
    assert_eq!(
        std::env::var("GIT_TERMINAL_PROMPT").as_deref(),
        Ok("0"),
        "Git must never prompt for credentials"
    );

    let temp = tempfile::tempdir().unwrap();
    let effective = git(temp.path(), &["config", "--global", "--list"]);
    assert_eq!(
        effective.lines().collect::<Vec<_>>(),
        [
            "user.name=release-glz test",
            "user.email=release-glz-test@example.invalid",
            "commit.gpgsign=false",
            "tag.gpgsign=false",
        ]
    );
    let hooks = Command::new("git")
        .arg("-C")
        .arg(temp.path())
        .args(["config", "--get", "core.hooksPath"])
        .output()
        .unwrap();
    assert!(
        !hooks.status.success(),
        "a hooks path leaked into tests: {}",
        String::from_utf8_lossy(&hooks.stdout)
    );
}

#[test]
fn the_binary_under_test_receives_no_ambient_credentials() {
    let mut probe = if cfg!(windows) {
        let mut command = isolated_command("cmd");
        command.args(["/C", "set"]);
        command
    } else {
        isolated_command("env")
    };
    let probe = probe.env("RELEASE_GLZ_PROBE", "visible").output().unwrap();
    assert!(probe.status.success());
    let names = String::from_utf8(probe.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name.to_owned()))
        .collect::<Vec<_>>();
    assert!(names.iter().any(|name| name == "RELEASE_GLZ_PROBE"));
    assert!(names.iter().any(|name| name == "GIT_CONFIG_GLOBAL"));
    for credential in [
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "HEXPM_API_KEY",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "HOME",
    ] {
        assert!(
            !names.iter().any(|name| name == credential),
            "{credential} reached the binary under test"
        );
    }
}
