use std::collections::BTreeMap;
use std::fs;

use release_glz_test_support::fake_tool::{self, Action, Behavior};
use release_glz_test_support::isolated_command;

/// One variable from every family that dependency build code must never read.
const WITHHELD: [(&str, &str); 16] = [
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
    ("RELEASE_GLZ_MANUAL_REASON", "release-glz-value"),
];

/// The prefix of the variables that release-glz defines for itself.
const RELEASE_GLZ_PREFIX: &str = "RELEASE_GLZ_";

#[test]
fn the_compiler_runs_without_tokens_inputs_runner_files_or_registry_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let record = temp.path().join("environment.json");
    let gleam = fake_tool::gleam_on_path(
        &temp.path().join("fake-compiler"),
        &Behavior::always(vec![
            Action::RecordEnvironment(record.clone()),
            Action::Stdout("gleam 1.19.2\n".into()),
        ]),
    );
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
        .env("PATH", gleam)
        .env("HOME", temp.path());
    for (name, value) in WITHHELD {
        command.env(name, value);
    }
    let output = command.output().unwrap();

    let recorded = fs::read(&record).unwrap_or_else(|error| {
        panic!(
            "the gleam that PATH finds first never ran ({error}): {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let recorded: BTreeMap<String, String> = serde_json::from_slice(&recorded).unwrap();
    for (name, value) in WITHHELD {
        assert!(!recorded.contains_key(name), "{name} reached the compiler");
        assert!(
            recorded.values().all(|seen| !seen.contains(value)),
            "the value of {name} reached the compiler"
        );
    }
    assert!(
        recorded
            .keys()
            .all(|name| !name.starts_with(RELEASE_GLZ_PREFIX)),
        "a release-glz variable reached the compiler: {recorded:?}"
    );
    assert!(recorded.contains_key("PATH"), "{recorded:?}");
    assert!(recorded.contains_key("HOME"), "{recorded:?}");
}
