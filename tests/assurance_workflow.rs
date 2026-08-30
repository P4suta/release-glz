use std::fs;
use std::path::Path;

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
        "cargo +1.97.0 install --locked zizmor --version 1.29.0",
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
    assert!(!yaml.contains("cargo install --locked zizmor --version 1.29.0"));
    assert!(!yaml.contains("continue-on-error: true"));
    assert!(Path::new("tests/fixtures/workflow/gleam.toml").is_file());

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
fn mutation_gate_uses_two_explicit_fail_closed_shards() {
    let yaml = fs::read_to_string(".github/workflows/assurance.yml").unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    let mutation = &parsed["jobs"]["mutation"];
    let shards = mutation["strategy"]["matrix"]["shard"]
        .as_sequence()
        .expect("mutation gate must declare an explicit shard matrix")
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(shards, ["0/2", "1/2"]);
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

#[test]
fn every_required_parser_has_a_bounded_fuzz_target() {
    let manifest = fs::read_to_string("fuzz/Cargo.toml").unwrap();
    for target in ["archive", "config", "pr_marker", "api_interface"] {
        assert!(manifest.contains(&format!("name = \"{target}\"")));
        let source = format!("fuzz/fuzz_targets/{target}.rs");
        assert!(Path::new(&source).is_file(), "missing {source}");
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
fn ci_exercises_minimum_configured_and_current_gleam_versions() {
    let yaml = fs::read_to_string(".github/workflows/ci.yml").unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    let matrix = parsed["jobs"]["test"]["strategy"]["matrix"]["gleam"]
        .as_sequence()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    for version in ["1.9.0", "1.12.0", "1.18.1"] {
        assert!(
            matrix.contains(&version),
            "Gleam compatibility matrix is missing {version}"
        );
    }
    assert!(
        !matrix.contains(&"1.12.3"),
        "matrix must contain published releases"
    );
    assert!(yaml.contains("gleam-version: ${{ matrix.gleam }}"));
    assert!(yaml.contains("matrix.gleam"));
    assert!(yaml.contains("RUST_TEST_THREADS: 1"));
    for test in [
        "scripts/check-coverage.test.js",
        "scripts/generate-action-checksums.test.js",
        "scripts/generate-provenance.test.js",
        "scripts/generate-sbom.test.js",
        "scripts/package-windows.test.js",
        "scripts/verify-release-assets.test.js",
        "scripts/workflow-tools.test.js",
    ] {
        assert!(yaml.contains(test), "CI does not execute {test}");
    }

    let assurance = fs::read_to_string(".github/workflows/assurance.yml").unwrap();
    assert!(assurance.contains("RUST_TEST_THREADS: 1"));
}

#[test]
fn coverage_job_installs_current_gleam_before_measuring() {
    let yaml = fs::read_to_string(".github/workflows/assurance.yml").unwrap();
    let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    let steps = parsed["jobs"]["coverage"]["steps"].as_sequence().unwrap();
    let setup = steps
        .iter()
        .find(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|value| value.starts_with("erlef/setup-beam@"))
        })
        .expect("coverage job must install Gleam so compiler smoke tests are measured");

    let reference = setup["uses"].as_str().unwrap().split_once('@').unwrap().1;
    assert_eq!(reference.len(), 40, "Gleam setup action must be immutable");
    assert_eq!(setup["with"]["otp-version"].as_str(), Some("28.0"));
    assert_eq!(setup["with"]["gleam-version"].as_str(), Some("1.18.1"));
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
