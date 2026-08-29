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
        "cargo-llvm-cov --version 0.9.0",
        "cargo-fuzz --version 0.13.2",
        "cargo deny check -D warnings",
        "cargo audit -D warnings",
        "cargo machete",
        "cargo llvm-cov",
        "--branch --json",
        "scripts/check-coverage.js --lines 90 --branches 85",
        "cargo mutants --jobs 1",
        "src/version.rs",
        "src/registry.rs",
        "src/artifact.rs",
        "src/reconciler.rs",
        "actionlint",
        "zizmor",
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
    assert!(!yaml.contains("cargo mutants --jobs 2"));
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
    for version in ["1.9.0", "1.12.3", "1.18.1"] {
        assert!(
            yaml.contains(version),
            "Gleam compatibility matrix is missing {version}"
        );
    }
    assert!(yaml.contains("gleam-version: ${{ matrix.gleam }}"));
    assert!(yaml.contains("matrix.gleam"));
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
