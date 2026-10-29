#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use release_glz_test_support::isolated_command;

/// One variable from every family that dependency build code must never read.
const WITHHELD: [(&str, &str); 15] = [
    ("GITHUB_TOKEN", "job-token-value"),
    ("GH_TOKEN", "cli-token-value"),
    ("ACTIONS_RUNTIME_TOKEN", "runtime-token-value"),
    ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "oidc-token-value"),
    (
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "https://oidc.example.invalid",
    ),
    ("ACTIONS_CACHE_URL", "https://cache.example.invalid"),
    ("ACTIONS_RESULTS_URL", "https://results.example.invalid"),
    ("INPUT_GITHUB-TOKEN", "input-token-value"),
    ("GITHUB_ENV", "/runner/command-env"),
    ("GITHUB_OUTPUT", "/runner/command-output"),
    ("GITHUB_PATH", "/runner/command-path"),
    ("GITHUB_STATE", "/runner/command-state"),
    ("GITHUB_STEP_SUMMARY", "/runner/command-summary"),
    ("HEXPM_API_KEY", "registry-key-value"),
    ("PRIVATE_HEX_TOKEN", "configured-registry-key-value"),
];

#[test]
fn the_compiler_runs_without_tokens_inputs_runner_files_or_registry_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let record = temp.path().join("environment");
    let gleam = temp.path().join("fake-gleam");
    fs::write(
        &gleam,
        format!(
            "#!/bin/sh\nenv > '{}'\nprintf '%s\\n' 'gleam 1.19.2'\n",
            record.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&gleam, fs::Permissions::from_mode(0o755)).unwrap();
    fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/dogfood/gleam-mutants/gleam.toml"
        ),
        temp.path().join("gleam.toml"),
    )
    .unwrap();

    let mut command = isolated_command(env!("CARGO_BIN_EXE_release-glz"));
    command
        .current_dir(temp.path())
        .args(["--output", "json", "doctor"])
        .env("RELEASE_GLZ_GLEAM", &gleam)
        .env("HOME", temp.path());
    for (name, value) in WITHHELD {
        command.env(name, value);
    }
    let output = command.output().unwrap();

    let recorded = fs::read_to_string(&record).unwrap_or_else(|error| {
        panic!(
            "the fake compiler never ran ({error}): {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let names: Vec<_> = recorded
        .lines()
        .filter_map(|line| line.split_once('=').map(|(name, _)| name))
        .collect();
    for (name, value) in WITHHELD {
        assert!(!names.contains(&name), "{name} reached the compiler");
        assert!(
            !recorded.contains(value),
            "the value of {name} reached the compiler"
        );
    }
    assert!(names.contains(&"PATH"), "{recorded}");
    assert!(names.contains(&"HOME"), "{recorded}");
}
