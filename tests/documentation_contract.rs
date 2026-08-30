use std::fs;

#[test]
fn readme_documents_the_v1_candidate_first_contract() {
    let readme = fs::read_to_string("README.md").unwrap();
    for required in [
        "ReleasePlan",
        "Candidate",
        "ReleaseState",
        "schema = 2",
        "rehearse --ref",
        "verify --candidate",
        "release --candidate",
        "status",
        "doctor",
        "migrate --update",
        "command/v2",
        "candidate_digest",
        "intent_digest",
        "Hex.pm Organization",
        "hex-compatible",
        "Exit code",
        "partially_released",
        "GitHub Release",
        "gh attestation verify",
        "To update",
        "To uninstall",
        "--profile public",
        "--profile organization",
        "--profile private",
        "doctor --online",
        "doctor --candidate-build",
        "next-action-argv",
        "prepare",
        "promote",
    ] {
        assert!(readme.contains(required), "README is missing `{required}`");
    }
    assert!(!readme.contains("merged Release PR is the only publication approval"));
    assert!(!readme.contains("run `gleam publish --yes`"));
}

#[test]
fn registry_guides_and_release_checklist_preserve_the_v1_operational_boundary() {
    let organization = fs::read_to_string("docs/quickstart-organization.md").unwrap();
    for required in [
        "--profile organization",
        "api_url = \"https://hex.pm/api\"",
        "repository_url = \"https://repo.hex.pm/repos/acme\"",
        "GitHub applies it only to the publish job",
    ] {
        assert!(
            organization.contains(required),
            "Organization guide misses {required}"
        );
    }

    let private = fs::read_to_string("docs/quickstart-private.md").unwrap();
    for required in [
        "--profile private",
        "doctor --candidate-build",
        "private dependencies",
        "are not",
        "Candidate digest",
        "artifact digest",
        "source SHA",
    ] {
        assert!(
            private.contains(required),
            "private guide misses {required}"
        );
    }

    let readiness = fs::read_to_string("docs/release-readiness.md").unwrap();
    for required in [
        "all six",
        "checksum-only commit",
        "CycloneDX",
        "provenance",
        "attestations",
        "annotated",
        "Re-download every asset",
    ] {
        assert!(
            readiness.contains(required),
            "release checklist misses {required}"
        );
    }
}

#[test]
fn operations_and_migration_guides_cover_every_supported_registry_path() {
    for path in [
        "docs/quickstart-public.md",
        "docs/quickstart-organization.md",
        "docs/quickstart-private.md",
        "docs/migration-v1.md",
        "docs/recovery.md",
        "docs/threat-model.md",
    ] {
        let source = fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("missing required guide {path}: {error}"));
        assert!(source.starts_with('#'), "{path} has no title");
    }

    let migration = fs::read_to_string("docs/migration-v1.md").unwrap();
    for required in [
        "schema 1",
        "schema 2",
        "migrate --check",
        "migrate --diff",
        "migrate --update",
        "legacy-gleam.toml",
        "legacy-unreleased",
        "JSON schema v1",
    ] {
        assert!(
            migration.contains(required),
            "migration guide misses {required}"
        );
    }

    let recovery = fs::read_to_string("docs/recovery.md").unwrap();
    for stage in [
        "verify_hooks",
        "prepare_git_tag",
        "prepare_github_draft",
        "publish_package",
        "publish_docs",
        "finalize_github_release",
        "notify_hooks",
    ] {
        assert!(recovery.contains(stage), "recovery guide misses {stage}");
    }
    assert!(recovery.contains("same Candidate"));
    assert!(recovery.contains("never re-POST"));

    let threat = fs::read_to_string("docs/threat-model.md").unwrap();
    for required in [
        "working tree",
        "cross-origin",
        "path traversal",
        "OIDC",
        "fork",
        "secret",
        "immutable",
    ] {
        assert!(threat.contains(required), "threat model misses {required}");
    }
}

#[test]
fn threat_model_documents_the_narrow_gleam_windows_packaging_fallback() {
    let threat = fs::read_to_string("docs/threat-model.md").unwrap();
    for required in [
        "Gleam 1.18.1",
        "gleam-lang/gleam/issues/6184",
        "Windows",
        "export hex-tarball",
        "export package-information",
        "compiler validations",
        "Hex v3",
        "All other errors fail closed",
    ] {
        assert!(
            threat.contains(required),
            "threat model misses Windows fallback contract `{required}`"
        );
    }
}
