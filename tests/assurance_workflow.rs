use std::fs;
use std::path::Path;

/// The one compiler release whose Windows Hex export the compatibility fallback recovers from, which shipping assurance keeps running natively.
const WINDOWS_HEX_TARBALL_REGRESSION: &str = "1.18.1";

fn pinned_tool(tool: &str) -> String {
    fs::read_to_string("mise.toml")
        .unwrap()
        .parse::<toml_edit::DocumentMut>()
        .unwrap()["tools"][tool]
        .as_str()
        .unwrap_or_else(|| panic!("mise.toml pins no {tool}"))
        .to_owned()
}

#[test]
fn routine_ci_uses_one_selected_linux_gate_without_shipping_campaigns() {
    let yaml = fs::read_to_string(".github/workflows/ci.yml").unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    let triggers = parsed["on"].as_mapping().unwrap();
    assert!(triggers.contains_key("pull_request"));
    assert!(triggers.contains_key("merge_group"));
    assert!(!triggers.contains_key("push"));
    assert!(!triggers.contains_key("schedule"));
    assert_eq!(
        parsed["concurrency"]["cancel-in-progress"].as_bool(),
        Some(true)
    );
    assert_eq!(
        parsed["jobs"]["checks"]["runs-on"].as_str(),
        Some("ubuntu-24.04")
    );
    assert!(parsed["jobs"]["checks"]["strategy"].is_null());
    for campaign in ["cargo mutants", "cargo fuzz", "cargo llvm-cov"] {
        assert!(!yaml.contains(campaign), "routine CI starts {campaign}");
    }
}

#[test]
fn assurance_workflow_has_fixed_fail_closed_shipping_gates() {
    let yaml = fs::read_to_string(".github/workflows/assurance.yml").unwrap();
    serde_yaml::from_str::<serde_yaml::Value>(&yaml).unwrap();
    for required in [
        "cargo-deny --version 0.20.2",
        "cargo-audit --version 0.22.2",
        "cargo-machete --version 0.9.2",
        "cargo-mutants --version 27.1.0",
        "cargo-nextest-0.9.140-x86_64-unknown-linux-gnu.tar.gz",
        "4ee9aaa0d0171a985a5d0eb735b87355894c1c455972e9674fb9fdbd1387c9a3",
        "cargo-llvm-cov --version 0.9.0",
        "cargo-fuzz --version 0.13.2",
        "cargo deny check -D warnings",
        "cargo audit -D warnings",
        "cargo machete",
        "cargo llvm-cov",
        "--branch --json",
        "scripts/check-coverage.js --lines 90 --branches 85",
        "cargo mutants --in-place --test-tool nextest",
        "src/version.rs",
        "src/registry.rs",
        "src/artifact.rs",
        "src/reconciler.rs",
        "actionlint",
        "zizmor",
        "rustup toolchain install 1.97.0 --profile minimal",
        "cargo +1.97.0 install --locked zizmor --version",
        "scripts/verify-workflows.js",
        "scripts/de-shell.js",
        "tests/fixtures/workflow/gleam.toml",
        "GENERATED_WORKFLOW",
        "init --update",
    ] {
        assert!(
            yaml.contains(required),
            "missing assurance gate: {required}"
        );
    }
    assert!(yaml.contains("nightly-2026-08-22"));
    assert!(!yaml.contains("nightly-2026-07-15"));
    assert!(yaml.contains("permissions: {}"));
    assert!(!yaml.contains("cargo mutants --jobs"));
    assert!(!yaml.contains("RELEASE_GLZ_ACTION_SHA"));
    assert!(!yaml.contains("cargo install --locked zizmor --version"));
    assert!(!yaml.contains("continue-on-error: true"));
    assert!(Path::new("tests/fixtures/workflow/gleam.toml").is_file());

    let triggers = yaml
        .split_once("permissions:")
        .expect("assurance workflow must declare permissions")
        .0;
    assert!(triggers.contains("workflow_dispatch:"));
    assert!(triggers.contains("workflow_call:"));
    assert!(!triggers.contains("push:"));
    assert!(!triggers.contains("schedule:"));
    assert!(
        !triggers.contains("pull_request:"),
        "expensive assurance must run on demand or for a release candidate"
    );

    for line in yaml.lines().filter(|line| {
        line.trim_start()
            .trim_start_matches("- ")
            .starts_with("uses:")
    }) {
        let reference = line
            .split_once('@')
            .unwrap_or_else(|| panic!("missing immutable pin: {line}"))
            .1
            .split_whitespace()
            .next()
            .unwrap();
        assert_eq!(reference.len(), 40, "mutable action reference: {line}");
        assert!(reference.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}

#[test]
fn mutation_gate_uses_four_explicit_fail_closed_shards() {
    let yaml = fs::read_to_string(".github/workflows/assurance.yml").unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    let mutation = &parsed["jobs"]["mutation"];
    let shards = mutation["strategy"]["matrix"]["shard"]
        .as_sequence()
        .expect("mutation gate must declare an explicit shard matrix")
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(shards, ["0/4", "1/4", "2/4", "3/4"]);
    assert_eq!(mutation["strategy"]["fail-fast"].as_bool(), Some(false));
    assert!(
        mutation["name"]
            .as_str()
            .is_some_and(|name| name.contains("matrix.shard"))
    );

    let command = mutation["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|step| step["run"].as_str())
        .find(|run| run.contains("cargo mutants"))
        .expect("mutation command is missing");
    assert!(command.contains("--in-place --test-tool nextest"));
    assert_eq!(
        mutation["env"]["MUTATION_SHARD"].as_str(),
        Some("${{ matrix.shard }}")
    );
    assert!(command.contains("--shard \"$MUTATION_SHARD\""));
    assert!(!command.contains("continue-on-error"));
}

fn fuzz_targets() -> Vec<String> {
    fs::read_to_string("fuzz/Cargo.toml")
        .unwrap()
        .parse::<toml_edit::DocumentMut>()
        .unwrap()["bin"]
        .as_array_of_tables()
        .expect("the fuzz manifest declares its targets")
        .iter()
        .map(|target| target["name"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn routine_ci_refuses_an_unformatted_fuzz_workspace_or_a_stale_fuzz_lockfile() {
    let parsed: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(".github/workflows/ci.yml").unwrap()).unwrap();
    let commands: Vec<_> = parsed["jobs"]["checks"]["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|step| step["run"].as_str())
        .collect();
    for command in [
        "cargo fmt --manifest-path fuzz/Cargo.toml -- --check",
        "cargo fetch --locked --manifest-path fuzz/Cargo.toml",
    ] {
        assert!(commands.contains(&command), "routine CI omits `{command}`");
    }
}

#[test]
fn every_required_parser_has_a_bounded_fuzz_target() {
    let targets = fuzz_targets();
    for target in [
        "archive",
        "config",
        "pr_marker",
        "api_interface",
        "identifiers",
    ] {
        assert!(
            targets.iter().any(|name| name == target),
            "missing {target}"
        );
    }
    for target in &targets {
        let source = format!("fuzz/fuzz_targets/{target}.rs");
        assert!(Path::new(&source).is_file(), "missing {source}");
    }
}

#[test]
fn fuzz_smoke_uses_fixed_run_counts_and_seeds() {
    let yaml = fs::read_to_string(".github/workflows/assurance.yml").unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    let steps = parsed["jobs"]["fuzz"]["steps"].as_sequence().unwrap();
    for target in fuzz_targets() {
        let prefix = format!("cargo fuzz run {target} -- ");
        let command = steps
            .iter()
            .filter_map(|step| step["run"].as_str())
            .find(|run| run.starts_with(&prefix))
            .unwrap_or_else(|| panic!("missing fuzz command for {target}"));
        for flag in ["-runs=", "-seed="] {
            let value = command
                .split_whitespace()
                .find_map(|word| word.strip_prefix(flag))
                .and_then(|value| value.parse::<u32>().ok());
            assert!(
                value.is_some_and(|value| value > 0),
                "{target} requires a fixed positive {flag}"
            );
        }
        assert!(!command.contains("-max_total_time="));
    }
}

#[test]
fn dependency_policy_is_explicit_and_deny_by_default() {
    let policy = fs::read_to_string("deny.toml").unwrap();
    assert!(policy.contains("unknown-registry = \"deny\""));
    assert!(policy.contains("unknown-git = \"deny\""));
    assert!(policy.contains("wildcards = \"deny\""));
    assert!(policy.contains("confidence-threshold = 0.8"));
}

#[test]
fn release_assurance_covers_native_platforms_and_gleam_versions() {
    let yaml = fs::read_to_string(".github/workflows/ci.yml").unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    let assurance = fs::read_to_string(".github/workflows/assurance.yml").unwrap();
    let shipping: serde_yaml::Value = serde_yaml::from_str(&assurance).unwrap();
    let current = parsed["jobs"]["checks"]["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .find_map(|step| step["with"]["gleam-version"].as_str())
        .expect("the fast gate must use a fixed Gleam version");
    let matrix = shipping["jobs"]["compatibility"]["strategy"]["matrix"]["include"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|value| {
            (
                value["os"].as_str().unwrap(),
                value["gleam"].as_str().unwrap(),
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        matrix,
        std::collections::BTreeSet::from([
            ("ubuntu-24.04", "1.9.0"),
            ("ubuntu-24.04", "1.12.0"),
            ("ubuntu-24.04", current),
            ("macos-15", current),
            ("windows-2025", current),
            ("windows-2025", WINDOWS_HEX_TARBALL_REGRESSION),
        ])
    );
    assert!(assurance.contains("gleam-version: ${{ matrix.gleam }}"));
    assert!(
        shipping["jobs"]["compatibility"]["steps"]
            .as_sequence()
            .unwrap()
            .iter()
            .any(|step| step["run"].as_str()
                == Some("cargo test --workspace --all-targets --locked"))
    );
    assert!(
        parsed["env"]["RUST_TEST_THREADS"].is_null(),
        "the fast gate runs tests in parallel, as developers do"
    );
    let required = &parsed["jobs"]["required"];
    assert_eq!(required["name"].as_str(), Some("required"));
    assert_eq!(required["if"].as_str(), Some("always()"));
    assert_eq!(
        required["needs"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>(),
        ["changes", "checks"]
    );
    let required_run = required["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .find_map(|step| step["run"].as_str())
        .unwrap();
    assert!(required_run.contains("'include \"required\"; required($full)'"));
    assert!(yaml.contains("node --test scripts/*.test.js"));
    assert!(yaml.contains(".github/check-required.jq"));
    assert!(
        shipping["env"]["RUST_TEST_THREADS"].is_null(),
        "shipping assurance runs tests in parallel, as developers do"
    );
}

#[test]
fn every_job_that_runs_compiler_tests_installs_the_pinned_gleam() {
    let yaml = fs::read_to_string(".github/workflows/assurance.yml").unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    for job in ["coverage", "mutation"] {
        let steps = parsed["jobs"][job]["steps"].as_sequence().unwrap();
        let setup = steps
            .iter()
            .find(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("erlef/setup-beam@"))
            })
            .unwrap_or_else(|| {
                panic!("the {job} job must install Gleam, because compiler tests fail without it")
            });

        let reference = setup["uses"].as_str().unwrap().split_once('@').unwrap().1;
        assert_eq!(reference.len(), 40, "Gleam setup action must be immutable");
        assert_eq!(
            setup["with"]["otp-version"].as_str(),
            Some(pinned_tool("erlang").as_str())
        );
        assert_eq!(
            setup["with"]["gleam-version"].as_str(),
            Some(pinned_tool("gleam").as_str())
        );
    }
}

#[test]
fn ci_selects_the_rust_job_for_every_file_a_test_reads() {
    let filters: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(".github/filters/ci.yml").unwrap()).unwrap();
    let runtime = filters["runtime"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|pattern| pattern.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let mut read = Vec::new();
    for entry in fs::read_dir("tests").unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            let source = fs::read_to_string(&path).unwrap();
            for opening in ["include_str!(\"../", "read_to_string(\"", "read_dir(\""] {
                for (index, _) in source.match_indices(opening) {
                    let rest = &source[index + opening.len()..];
                    read.push(rest[..rest.find('"').unwrap()].to_owned());
                }
            }
        }
    }
    assert!(read.len() > 10, "found too few test inputs: {read:?}");
    for input in read {
        assert!(
            runtime.iter().any(|pattern| glob_matches(pattern, &input))
                || runtime
                    .iter()
                    .any(|pattern| glob_matches(pattern, &format!("{input}/file"))),
            "CI skips the Rust job when `{input}` changes, although a test reads it"
        );
    }
}

fn glob_matches(pattern: &str, path: &str) -> bool {
    fn segments(pattern: &[&str], path: &[&str]) -> bool {
        match (pattern.split_first(), path.split_first()) {
            (None, None) => true,
            (Some((&"**", rest)), _) => {
                segments(rest, path) || (!path.is_empty() && segments(pattern, &path[1..]))
            }
            (Some((first, rest)), Some((name, remaining))) => {
                segment(first, name) && segments(rest, remaining)
            }
            _ => false,
        }
    }
    fn segment(pattern: &str, name: &str) -> bool {
        match pattern.split_once('*') {
            None => pattern == name,
            Some((prefix, suffix)) => {
                name.len() >= prefix.len() + suffix.len()
                    && name.starts_with(prefix)
                    && name.ends_with(suffix)
            }
        }
    }
    let pattern = pattern.split('/').collect::<Vec<_>>();
    let path = path.split('/').collect::<Vec<_>>();
    segments(&pattern, &path)
}

#[test]
fn local_tool_pins_match_the_versions_ci_installs() {
    let pin = pinned_tool;
    let ci = fs::read_to_string(".github/workflows/ci.yml").unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&ci).unwrap();
    let steps = |job: &str| parsed["jobs"][job]["steps"].as_sequence().unwrap().clone();
    let with = |job: &str, action: &str, input: &str| {
        steps(job)
            .iter()
            .find(|step| {
                step["uses"]
                    .as_str()
                    .is_some_and(|value| value.starts_with(action))
            })
            .and_then(|step| step["with"][input].as_str().map(str::to_owned))
            .unwrap_or_else(|| panic!("{job} sets no {action} {input}"))
    };

    let rust = pin("rust");
    assert!(
        steps("checks").iter().any(|step| step["run"]
            .as_str()
            .is_some_and(|run| run.contains(&format!("rustup default {rust}")))),
        "the fast gate must use the pinned Rust {rust}"
    );
    let manifest = fs::read_to_string("Cargo.toml")
        .unwrap()
        .parse::<toml_edit::DocumentMut>()
        .unwrap();
    let minimum = manifest["package"]["rust-version"].as_str().unwrap();
    assert!(
        rust.starts_with(&format!("{minimum}.")),
        "Rust {rust} is not the declared minimum {minimum}"
    );
    assert_eq!(
        with("checks", "erlef/setup-beam@", "gleam-version"),
        pin("gleam")
    );
    assert_eq!(
        with("checks", "erlef/setup-beam@", "otp-version"),
        pin("erlang")
    );
    assert_eq!(
        with("changes", "actions/setup-node@", "node-version"),
        pin("node")
    );
    assert!(
        ci.contains(&format!(
            "actionlint/releases/download/v{0}/actionlint_{0}_",
            pin("actionlint")
        )),
        "CI must install the pinned actionlint"
    );
    let assurance = fs::read_to_string(".github/workflows/assurance.yml").unwrap();
    assert!(
        assurance.contains(&format!(
            "install --locked zizmor --version {}",
            pin("aqua:zizmorcore/zizmor")
        )),
        "shipping assurance must install the pinned zizmor"
    );
}

#[test]
fn every_repository_workflow_is_valid_yaml_and_includes_assurance() {
    let paths = fs::read_dir(".github/workflows")
        .unwrap()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    let mut names = Vec::new();
    for entry in paths {
        let path = entry.path();
        if path.extension().is_some_and(|extension| extension == "yml") {
            let source = fs::read_to_string(&path).unwrap();
            serde_yaml::from_str::<serde_yaml::Value>(&source)
                .unwrap_or_else(|error| panic!("invalid {}: {error}", path.display()));
            names.push(path.file_name().unwrap().to_string_lossy().into_owned());
        }
    }
    names.sort();
    assert_eq!(names, ["assurance.yml", "ci.yml", "distribute.yml"]);
}

#[test]
fn local_assurance_outputs_cannot_be_committed_accidentally() {
    let ignore = fs::read_to_string(".gitignore").unwrap();
    let patterns = ignore.lines().collect::<std::collections::HashSet<_>>();

    for required in ["/coverage.json", "/mutants.out*/"] {
        assert!(
            patterns.contains(required),
            "missing assurance output ignore: {required}"
        );
    }
}
