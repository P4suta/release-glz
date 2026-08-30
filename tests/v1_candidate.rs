use std::fs;
use std::io::Write;

use flate2::{Compression, write::GzEncoder};
use release_glz::artifact::{ArchiveLimits, validate_hex_tarball};
use release_glz::candidate::{
    Candidate, CandidateInput, CandidateSource, HookEvidence, HookKind, RegistryIdentity,
};
use release_glz::config::{
    ApprovalConfig, ApprovalMode, AuthKind, HookConfig, OutputConfig, RegistryProvider,
};
use release_glz::hooks::SidecarArtifact;
use semver::Version;
use sha2::{Digest, Sha256};

#[test]
fn candidate_seals_and_verifies_the_exact_publish_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("candidate");
    let package = hex_package(&[
        ("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n"),
        ("src/widget.gleam", b"pub fn main() { Nil }\n"),
    ]);
    let docs = tar_gz(&[("index.html", b"<h1>Widget</h1>"), ("search.js", b"[]")]);
    let interface = br#"{"modules":{}}"#.to_vec();
    let input = candidate_input(package.clone(), Some(docs), interface);

    let sealed = Candidate::seal(&directory, input).unwrap();
    assert_eq!(sealed.schema, "candidate/v1");
    assert_eq!(sealed.artifacts.package.sha256, hex_sha256(&package));
    assert_eq!(sealed.intent_digest.len(), 64);
    assert_eq!(sealed.candidate_digest.len(), 64);
    assert_ne!(sealed.intent_digest, sealed.candidate_digest);
    assert_eq!(sealed.registry.credential_env, "HEXPM_API_KEY");
    assert_eq!(sealed.registry.auth, AuthKind::HexToken);
    assert_eq!(sealed.github_repository, "owner/widget");
    assert_eq!(sealed.release_notes, "Widget release notes.");
    assert_eq!(sealed.approval.environment, "release");

    let verified = Candidate::verify(&directory).unwrap();
    assert_eq!(verified, sealed);
    assert!(
        Candidate::seal(
            &directory,
            candidate_input(package, None, br#"{}"#.to_vec())
        )
        .is_err()
    );
}

#[test]
fn candidate_rejects_an_unsafe_tag_or_credential_environment_name() {
    let temp = tempfile::tempdir().unwrap();
    let package = hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]);
    let mut unsafe_tag = candidate_input(package.clone(), None, br#"{}"#.to_vec());
    unsafe_tag.tag = "refs/heads/main".into();
    assert!(Candidate::seal(&temp.path().join("tag"), unsafe_tag).is_err());

    let mut unsafe_env = candidate_input(package, None, br#"{}"#.to_vec());
    unsafe_env.registry.credential_env = "BAD=secret".into();
    assert!(Candidate::seal(&temp.path().join("env"), unsafe_env).is_err());

    let mut unsafe_branch = candidate_input(
        hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
        None,
        br#"{}"#.to_vec(),
    );
    unsafe_branch.release_branch_prefix = "refs/heads/main".into();
    assert!(Candidate::seal(&temp.path().join("branch"), unsafe_branch).is_err());

    let mut missing_hook_policy = candidate_input(
        hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
        None,
        br#"{}"#.to_vec(),
    );
    missing_hook_policy.notify_hooks.push("announce".into());
    assert!(Candidate::seal(&temp.path().join("hook"), missing_hook_policy).is_err());

    let mut unsafe_repository = candidate_input(
        hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
        None,
        br#"{}"#.to_vec(),
    );
    unsafe_repository.github_repository = "-owner/widget".into();
    let error = Candidate::seal(&temp.path().join("repository"), unsafe_repository)
        .unwrap_err()
        .to_string();
    assert!(error.contains("owner/name"), "{error}");
}

#[test]
fn candidate_registry_urls_reject_queries_and_fragments_at_the_sealed_boundary() {
    let temp = tempfile::tempdir().unwrap();
    let package = || hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]);

    for (name, url) in [
        ("query", "https://hex.pm/api?credential=secret"),
        ("fragment", "https://repo.hex.pm/docs#candidate"),
    ] {
        let mut input = candidate_input(package(), None, br#"{}"#.to_vec());
        if name == "query" {
            input.registry.api_url = url.into();
        } else {
            input.registry.docs_url = url.into();
        }
        let error = Candidate::seal(&temp.path().join(name), input)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("query or fragment"),
            "{name} unexpectedly passed the Candidate boundary: {error}"
        );
    }
}

#[test]
fn candidate_registry_urls_reject_opaque_credentials_and_unapproved_http_independently() {
    let temp = tempfile::tempdir().unwrap();
    for (name, url) in [
        ("opaque", "mailto:registry@example.test"),
        ("password", "https://user:password@hex.pm/api"),
        ("http-without-opt-in", "http://127.0.0.1:8080/api"),
    ] {
        let mut input = fresh_candidate_input();
        input.registry.api_url = url.into();
        input.registry.allow_http_loopback = false;
        assert!(
            Candidate::seal(&temp.path().join(name), input).is_err(),
            "accepted unsafe registry URL case {name}"
        );
    }
}

#[test]
fn candidate_rejects_an_unsafe_hex_organization_identity() {
    let temp = tempfile::tempdir().unwrap();
    for (index, repository) in ["", "../other", "acme/widgets", ".hidden", "acme org"]
        .into_iter()
        .enumerate()
    {
        let mut input = candidate_input(
            hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
            None,
            br#"{}"#.to_vec(),
        );
        input.registry.repository = Some(repository.into());
        assert!(
            Candidate::seal(&temp.path().join(index.to_string()), input).is_err(),
            "accepted unsafe Hex organization {repository:?}"
        );
    }
}

#[test]
fn candidate_identity_requires_a_gleam_package_name_and_matching_version_tag() {
    let temp = tempfile::tempdir().unwrap();
    for (index, package) in [
        "",
        "Widget",
        "../widget",
        "widget-name",
        "2widget",
        "_widget",
    ]
    .into_iter()
    .enumerate()
    {
        let mut input = candidate_input(
            hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
            None,
            br#"{}"#.to_vec(),
        );
        input.package = package.into();
        assert!(
            Candidate::seal(&temp.path().join(format!("package-{index}")), input).is_err(),
            "accepted unsafe package name {package:?}"
        );
    }

    let mut mismatched = candidate_input(
        hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
        None,
        br#"{}"#.to_vec(),
    );
    mismatched.tag = "v9.9.9".into();
    assert!(Candidate::seal(&temp.path().join("tag-mismatch"), mismatched).is_err());

    let mut prefixed = candidate_input(
        hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
        None,
        br#"{}"#.to_vec(),
    );
    prefixed.package = "widget_2".into();
    prefixed.tag = "packages/widget_2/v1.2.3".into();
    Candidate::seal(&temp.path().join("valid-prefixed"), prefixed).unwrap();
}

#[test]
fn candidate_source_registry_branch_notes_and_approval_policy_are_independently_sealed() {
    let temp = tempfile::tempdir().unwrap();
    for case in [
        "short-sha",
        "long-sha",
        "uppercase-sha",
        "nonhex-sha",
        "manifest-parent",
        "unsafe-custom-repository",
        "external-http",
        "credential-url",
        "empty-prefix",
        "refs-prefix",
        "spaced-prefix",
        "nul-notes",
        "empty-environment",
        "multiline-environment",
        "normal-mode",
        "manual-mode",
        "fallback",
        "empty-manual-refs",
        "partial-manual-ref",
        "duplicate-manual-ref",
    ] {
        let mut input = fresh_candidate_input();
        match case {
            "short-sha" => input.source.commit_sha = "a".repeat(39),
            "long-sha" => input.source.commit_sha = "a".repeat(65),
            "uppercase-sha" => input.source.commit_sha = "A".repeat(40),
            "nonhex-sha" => input.source.commit_sha = "g".repeat(40),
            "manifest-parent" => input.source.manifest_path = "../gleam.toml".into(),
            "unsafe-custom-repository" => {
                input.registry.provider = RegistryProvider::HexCompatible;
                input.registry.repository = Some("../acme".into());
            }
            "external-http" => {
                input.registry.api_url = "http://192.0.2.1/api".into();
                input.registry.allow_http_loopback = true;
            }
            "credential-url" => input.registry.api_url = "https://token@hex.pm/api".into(),
            "empty-prefix" => input.release_branch_prefix.clear(),
            "refs-prefix" => input.release_branch_prefix = "refs/heads/release/".into(),
            "spaced-prefix" => input.release_branch_prefix = "release branch/".into(),
            "nul-notes" => input.release_notes = "notes\0secret".into(),
            "empty-environment" => input.approval.environment.clear(),
            "multiline-environment" => input.approval.environment = "release\nprod".into(),
            "normal-mode" => input.approval.normal = ApprovalMode::Environment,
            "manual-mode" => {
                input.approval.manual = ApprovalMode::ReleasePrAndEnvironment;
            }
            "fallback" => {
                input.approval.private_repository_fallback = Some("weaken-gate".into());
            }
            "empty-manual-refs" => input.approval.manual_refs.clear(),
            "partial-manual-ref" => input.approval.manual_refs = vec!["main".into()],
            "duplicate-manual-ref" => {
                input.approval.manual_refs =
                    vec!["refs/heads/main".into(), "refs/heads/main".into()];
            }
            _ => unreachable!(),
        }
        assert!(
            Candidate::seal(&temp.path().join(case), input).is_err(),
            "accepted invalid Candidate policy case {case}"
        );
    }

    for (index, host) in ["localhost", "127.0.0.1", "[::1]"].into_iter().enumerate() {
        let mut input = fresh_candidate_input();
        let base = format!("http://{host}:8080");
        input.registry.api_url = format!("{base}/api");
        input.registry.repository_url = base.clone();
        input.registry.docs_url = format!("{base}/docs");
        input.registry.allow_http_loopback = true;
        input.source.commit_sha = "b".repeat(64);
        input.source.manifest_path = "gleam.toml".into();
        input.approval.private_repository_fallback = Some("workflow-dispatch-digest".into());
        input.approval.manual_refs = vec!["refs/tags/v1.2.3".into()];
        Candidate::seal(&temp.path().join(format!("valid-{index}")), input).unwrap();
    }
}

#[test]
fn candidate_release_notes_have_a_hard_one_mebibyte_limit() {
    let temp = tempfile::tempdir().unwrap();
    let mut at_limit = fresh_candidate_input();
    at_limit.release_notes = "x".repeat(1024 * 1024);
    Candidate::seal(&temp.path().join("at-limit"), at_limit).unwrap();

    let mut over_limit = fresh_candidate_input();
    over_limit.release_notes = "x".repeat(1024 * 1024 + 1);
    assert!(Candidate::seal(&temp.path().join("over-limit"), over_limit).is_err());
}

#[test]
fn candidate_verification_detects_any_raw_artifact_change() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("candidate");
    let package = hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]);
    Candidate::seal(
        &directory,
        candidate_input(
            package,
            Some(tar_gz(&[("index.html", b"ok")])),
            br#"{}"#.to_vec(),
        ),
    )
    .unwrap();
    fs::write(directory.join("artifacts/package.tar"), b"tampered").unwrap();
    let error = Candidate::verify(&directory).unwrap_err().to_string();
    assert!(error.contains("checksum"), "{error}");
}

#[test]
fn candidate_verification_rejects_unsealed_inventory_entries() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("candidate");
    let package = hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]);
    Candidate::seal(
        &directory,
        candidate_input(package, None, br#"{}"#.to_vec()),
    )
    .unwrap();
    fs::write(
        directory.join("unsealed-secret.txt"),
        b"must not be ignored",
    )
    .unwrap();
    let error = Candidate::verify(&directory).unwrap_err().to_string();
    assert!(error.contains("inventory"), "{error}");
}

#[test]
fn candidate_verification_rejects_every_manifest_identity_and_digest_tamper() {
    let temp = tempfile::tempdir().unwrap();
    for case in [
        "schema",
        "package",
        "tag",
        "source-sha",
        "source-path",
        "credential-env",
        "branch-prefix",
        "release-notes",
        "artifact-path",
        "artifact-size",
        "artifact-sha",
        "package-semantic",
        "interface-semantic",
        "intent-digest",
        "candidate-digest",
    ] {
        let directory = temp.path().join(case);
        Candidate::seal(&directory, fresh_candidate_input()).unwrap();
        mutate_candidate_json(&directory, |manifest| match case {
            "schema" => manifest["schema"] = "candidate/v2".into(),
            "package" => manifest["package"] = "Widget".into(),
            "tag" => manifest["tag"] = "v9.9.9".into(),
            "source-sha" => manifest["source"]["commit_sha"] = "A".repeat(40).into(),
            "source-path" => manifest["source"]["manifest_path"] = "../gleam.toml".into(),
            "credential-env" => manifest["registry"]["credential_env"] = "TOKEN=value".into(),
            "branch-prefix" => manifest["release_branch_prefix"] = "".into(),
            "release-notes" => manifest["release_notes"] = "bad\0notes".into(),
            "artifact-path" => {
                manifest["artifacts"]["package"]["path"] = "artifacts/other.tar".into()
            }
            "artifact-size" => manifest["artifacts"]["package"]["size"] = u64::MAX.into(),
            "artifact-sha" => manifest["artifacts"]["package"]["sha256"] = "g".repeat(64).into(),
            "package-semantic" => {
                manifest["artifacts"]["package"]["semantic_sha256"] = "0".repeat(64).into()
            }
            "interface-semantic" => {
                manifest["artifacts"]["package_interface"]["semantic_sha256"] =
                    "0".repeat(64).into()
            }
            "intent-digest" => manifest["intent_digest"] = "0".repeat(64).into(),
            "candidate-digest" => manifest["candidate_digest"] = "0".repeat(64).into(),
            _ => unreachable!(),
        });
        let error = Candidate::verify(&directory).unwrap_err().to_string();
        assert!(!error.is_empty(), "tamper {case} was not rejected");
    }
}

#[test]
fn candidate_manifest_is_bounded_strict_json_in_a_regular_file() {
    let temp = tempfile::tempdir().unwrap();

    let unknown = temp.path().join("unknown");
    Candidate::seal(&unknown, fresh_candidate_input()).unwrap();
    mutate_candidate_json(&unknown, |manifest| {
        manifest["unsealed"] = true.into();
    });
    assert!(Candidate::verify(&unknown).is_err());

    let oversized = temp.path().join("oversized");
    Candidate::seal(&oversized, fresh_candidate_input()).unwrap();
    fs::write(
        oversized.join("candidate.json"),
        vec![b' '; 1024 * 1024 + 1],
    )
    .unwrap();
    let error = Candidate::verify(&oversized).unwrap_err().to_string();
    assert!(error.contains("size limit"), "{error}");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let linked = temp.path().join("linked");
        Candidate::seal(&linked, fresh_candidate_input()).unwrap();
        fs::rename(
            linked.join("candidate.json"),
            linked.join("manifest-target"),
        )
        .unwrap();
        symlink("manifest-target", linked.join("candidate.json")).unwrap();
        let error = Candidate::verify(&linked).unwrap_err().to_string();
        assert!(error.contains("regular file"), "{error}");
    }
}

#[test]
fn semantic_intent_ignores_tar_order_but_candidate_digest_does_not() {
    let temp = tempfile::tempdir().unwrap();
    let first_dir = temp.path().join("first");
    let second_dir = temp.path().join("second");
    let first = hex_package(&[
        ("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n"),
        ("src/a.gleam", b"pub fn a() { 1 }\n"),
    ]);
    let second = hex_package(&[
        ("src/a.gleam", b"pub fn a() { 1 }\n"),
        ("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n"),
    ]);
    assert_ne!(first, second);
    let one = Candidate::seal(
        &first_dir,
        candidate_input(
            first,
            Some(tar_gz(&[("b", b"2"), ("a", b"1")])),
            br#"{}"#.to_vec(),
        ),
    )
    .unwrap();
    let two = Candidate::seal(
        &second_dir,
        candidate_input(
            second,
            Some(tar_gz(&[("a", b"1"), ("b", b"2")])),
            br#"{}"#.to_vec(),
        ),
    )
    .unwrap();
    assert_eq!(one.intent_digest, two.intent_digest);
    assert_ne!(one.candidate_digest, two.candidate_digest);
}

#[test]
fn hex_validation_rejects_bad_checksum_duplicate_and_link_entries() {
    let valid = hex_package(&[("gleam.toml", b"name = \"x\"\nversion = \"1.0.0\"\n")]);
    validate_hex_tarball(&valid, ArchiveLimits::default()).unwrap();

    let bad_checksum = outer_package(b"3", b"meta", &tar_gz(&[("x", b"ok")]), Some(b"BAD"));
    assert!(validate_hex_tarball(&bad_checksum, ArchiveLimits::default()).is_err());

    let duplicate = outer_package(
        b"3",
        b"meta",
        &tar_gz(&[("same", b"one"), ("same", b"two")]),
        None,
    );
    assert!(validate_hex_tarball(&duplicate, ArchiveLimits::default()).is_err());

    let linked_contents = malicious_link_tar_gz();
    let linked = outer_package(b"3", b"meta", &linked_contents, None);
    assert!(validate_hex_tarball(&linked, ArchiveLimits::default()).is_err());
}

#[test]
fn archive_expansion_limits_are_enforced_before_extraction() {
    let package = hex_package(&[("large", &[7_u8; 1024])]);
    let limits = ArchiveLimits {
        max_entries: 10,
        max_entry_bytes: 512,
        max_total_bytes: 512,
        max_archive_bytes: 1024 * 1024,
    };
    assert!(validate_hex_tarball(&package, limits).is_err());
}

#[test]
fn sidecars_are_sealed_beside_but_cannot_change_the_candidate_core_intent() {
    let temp = tempfile::tempdir().unwrap();
    let package = hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]);
    let mut with_sidecar = candidate_input(package.clone(), None, br#"{}"#.to_vec());
    let sidecar_hook = HookConfig {
        id: "sbom".into(),
        argv: vec!["./scripts/sbom".into()],
        timeout_seconds: 30,
        required: true,
        env: vec![],
    };
    let sidecar_evidence = HookEvidence {
        schema: "hook/v1".into(),
        id: "sbom".into(),
        kind: HookKind::Sidecar,
        required: true,
        success: true,
        output_sha256: "2".repeat(64),
    };
    with_sidecar.sidecar_hook_definitions = vec![sidecar_hook.clone()];
    with_sidecar.hook_evidence = vec![sidecar_evidence.clone()];
    with_sidecar.sidecars.push(SidecarArtifact {
        hook_id: "sbom".into(),
        name: "sbom.cdx.json".into(),
        media_type: "application/vnd.cyclonedx+json".into(),
        bytes: br#"{"bomFormat":"CycloneDX"}"#.to_vec(),
        public: true,
    });
    let sealed = Candidate::seal(&temp.path().join("with"), with_sidecar).unwrap();
    let mut without_sidecar = candidate_input(package, None, br#"{}"#.to_vec());
    without_sidecar.sidecar_hook_definitions = vec![sidecar_hook];
    without_sidecar.hook_evidence = vec![sidecar_evidence];
    let plain = Candidate::seal(&temp.path().join("plain"), without_sidecar).unwrap();

    assert_eq!(sealed.intent_digest, plain.intent_digest);
    assert_ne!(sealed.candidate_digest, plain.candidate_digest);
    assert_eq!(sealed.sidecars.len(), 1);
    assert_eq!(sealed.sidecars[0].path, "sidecars/sbom/sbom.cdx.json");
    assert_eq!(
        Candidate::sidecar_bytes(&temp.path().join("with"), &sealed).unwrap()[0].1,
        br#"{"bomFormat":"CycloneDX"}"#
    );

    fs::write(
        temp.path().join("with/sidecars/sbom/sbom.cdx.json"),
        b"tampered",
    )
    .unwrap();
    assert!(Candidate::verify(&temp.path().join("with")).is_err());
}

#[test]
fn output_policy_is_part_of_the_semantic_release_intent() {
    let temp = tempfile::tempdir().unwrap();
    let package = hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]);
    let normal = Candidate::seal(
        &temp.path().join("normal"),
        candidate_input(package.clone(), None, br#"{}"#.to_vec()),
    )
    .unwrap();
    let mut without_github = candidate_input(package, None, br#"{}"#.to_vec());
    without_github.outputs.github_release = false;
    let without_github = Candidate::seal(&temp.path().join("without"), without_github).unwrap();
    assert!(normal.outputs.github_release);
    assert!(!without_github.outputs.github_release);
    assert_ne!(normal.intent_digest, without_github.intent_digest);

    let mut inconsistent = candidate_input(
        hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
        None,
        br#"{}"#.to_vec(),
    );
    inconsistent.outputs.docs = true;
    assert!(Candidate::seal(&temp.path().join("inconsistent"), inconsistent).is_err());
}

#[test]
fn verify_and_sidecar_hook_definitions_are_sealed_into_the_intent() {
    let temp = tempfile::tempdir().unwrap();
    let package = hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]);
    let mut first = candidate_input(package.clone(), None, br#"{}"#.to_vec());
    first.verify_hook_definitions = vec![HookConfig {
        id: "policy".into(),
        argv: vec!["./scripts/policy".into(), "--strict".into()],
        timeout_seconds: 30,
        required: true,
        env: vec!["POLICY_MODE".into()],
    }];
    first.hook_evidence = vec![HookEvidence {
        schema: "hook/v1".into(),
        id: "policy".into(),
        kind: HookKind::Verify,
        required: true,
        success: true,
        output_sha256: "1".repeat(64),
    }];
    let sealed = Candidate::seal(&temp.path().join("first"), first).unwrap();
    assert_eq!(sealed.verify_hook_definitions[0].id, "policy");

    let mut changed = candidate_input(package, None, br#"{}"#.to_vec());
    changed.verify_hook_definitions = vec![HookConfig {
        id: "policy".into(),
        argv: vec!["./scripts/policy".into(), "--lenient".into()],
        timeout_seconds: 30,
        required: true,
        env: vec!["POLICY_MODE".into()],
    }];
    changed.hook_evidence = sealed.hook_evidence.clone();
    let changed = Candidate::seal(&temp.path().join("changed"), changed).unwrap();
    assert_ne!(sealed.intent_digest, changed.intent_digest);

    let mut missing_evidence = candidate_input(
        hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
        None,
        br#"{}"#.to_vec(),
    );
    missing_evidence.sidecar_hook_definitions = vec![HookConfig {
        id: "sbom".into(),
        argv: vec!["./scripts/sbom".into()],
        timeout_seconds: 30,
        required: true,
        env: vec![],
    }];
    assert!(Candidate::seal(&temp.path().join("missing"), missing_evidence).is_err());
}

#[test]
fn candidate_hook_evidence_is_strictly_bound_to_ordered_definitions() {
    let temp = tempfile::tempdir().unwrap();
    for case in [
        "schema",
        "empty-id",
        "checksum",
        "required-failure",
        "missing",
        "binding-id",
        "binding-kind",
        "binding-required",
        "duplicate-evidence",
        "duplicate-definition",
        "invalid-definition",
    ] {
        let mut input = input_with_verify_hook();
        match case {
            "schema" => input.hook_evidence[0].schema = "hook/v2".into(),
            "empty-id" => input.hook_evidence[0].id.clear(),
            "checksum" => input.hook_evidence[0].output_sha256 = "G".repeat(64),
            "required-failure" => input.hook_evidence[0].success = false,
            "missing" => input.hook_evidence.clear(),
            "binding-id" => input.hook_evidence[0].id = "other".into(),
            "binding-kind" => input.hook_evidence[0].kind = HookKind::Sidecar,
            "binding-required" => input.hook_evidence[0].required = false,
            "duplicate-evidence" => {
                input.verify_hook_definitions.push(HookConfig {
                    id: "other".into(),
                    argv: vec!["verify-other".into()],
                    timeout_seconds: 30,
                    required: true,
                    env: vec![],
                });
                input.hook_evidence.push(input.hook_evidence[0].clone());
            }
            "duplicate-definition" => {
                input
                    .sidecar_hook_definitions
                    .push(input.verify_hook_definitions[0].clone());
                input.hook_evidence.clear();
            }
            "invalid-definition" => input.verify_hook_definitions[0].argv.clear(),
            _ => unreachable!(),
        }
        assert!(
            Candidate::seal(&temp.path().join(case), input).is_err(),
            "accepted invalid hook binding {case}"
        );
    }
}

#[test]
fn candidate_sidecars_require_safe_identity_declared_producer_and_signature_policy() {
    let temp = tempfile::tempdir().unwrap();
    for (index, case) in [
        "empty-hook",
        "numeric-hook",
        "empty-name",
        "nested-name",
        "backslash-name",
        "long-name",
        "empty-media",
        "missing-media-slash",
        "quoted-media",
        "undeclared-producer",
    ]
    .into_iter()
    .enumerate()
    {
        let mut input = fresh_candidate_input();
        let mut artifact = SidecarArtifact {
            hook_id: "ghost".into(),
            name: "evidence.json".into(),
            media_type: "application/json".into(),
            bytes: b"{}".to_vec(),
            public: false,
        };
        match case {
            "empty-hook" => artifact.hook_id.clear(),
            "numeric-hook" => artifact.hook_id = "0hook".into(),
            "empty-name" => artifact.name.clear(),
            "nested-name" => artifact.name = "nested/evidence.json".into(),
            "backslash-name" => artifact.name = "nested\\evidence.json".into(),
            "long-name" => artifact.name = "x".repeat(257),
            "empty-media" => artifact.media_type.clear(),
            "missing-media-slash" => artifact.media_type = "json".into(),
            "quoted-media" => artifact.media_type = "application/\"json".into(),
            "undeclared-producer" => {}
            _ => unreachable!(),
        }
        input.sidecars.push(artifact);
        assert!(
            Candidate::seal(&temp.path().join(format!("invalid-{index}")), input).is_err(),
            "accepted invalid sidecar case {case}"
        );
    }

    let mut too_many = fresh_candidate_input();
    too_many.sidecars = (0..65)
        .map(|index| SidecarArtifact {
            hook_id: "release-glz".into(),
            name: format!("evidence-{index}.json"),
            media_type: "application/json".into(),
            bytes: b"{}".to_vec(),
            public: false,
        })
        .collect();
    assert!(Candidate::seal(&temp.path().join("too-many"), too_many).is_err());

    let mut missing_signature = fresh_candidate_input();
    missing_signature.outputs.signature = true;
    assert!(Candidate::seal(&temp.path().join("missing-signature"), missing_signature).is_err());

    let mut signed = fresh_candidate_input();
    signed.outputs.signature = true;
    signed.sidecar_hook_definitions.push(HookConfig {
        id: "sign".into(),
        argv: vec!["sign".into()],
        timeout_seconds: 30,
        required: true,
        env: vec![],
    });
    signed.hook_evidence.push(HookEvidence {
        schema: "hook/v1".into(),
        id: "sign".into(),
        kind: HookKind::Sidecar,
        required: true,
        success: true,
        output_sha256: "8".repeat(64),
    });
    signed.sidecars.push(SidecarArtifact {
        hook_id: "sign".into(),
        name: "widget-1.2.3.sig".into(),
        media_type: "application/pgp-signature".into(),
        bytes: b"signature".to_vec(),
        public: true,
    });
    let signed_dir = temp.path().join("signed");
    Candidate::seal(&signed_dir, signed).unwrap();

    for case in ["path", "checksum", "size"] {
        let directory = temp.path().join(format!("tampered-{case}"));
        let mut input = fresh_candidate_input();
        add_public_sidecar(&mut input, "evidence", "evidence.json");
        Candidate::seal(&directory, input).unwrap();
        mutate_candidate_json(&directory, |manifest| match case {
            "path" => manifest["sidecars"][0]["path"] = "sidecars/other/file".into(),
            "checksum" => manifest["sidecars"][0]["sha256"] = "g".repeat(64).into(),
            "size" => manifest["sidecars"][0]["size"] = u64::MAX.into(),
            _ => unreachable!(),
        });
        assert!(
            Candidate::verify(&directory).is_err(),
            "accepted {case} tamper"
        );
    }
}

#[test]
fn candidate_notify_hooks_are_an_ordered_idempotent_protocol() {
    let temp = tempfile::tempdir().unwrap();
    for case in [
        "empty-id",
        "duplicate-id",
        "missing-definition",
        "wrong-order",
    ] {
        let mut input = fresh_candidate_input();
        input.notify_hooks = vec!["announce".into(), "audit".into()];
        input.notify_hook_definitions = vec![notify_hook("announce"), notify_hook("audit")];
        match case {
            "empty-id" => input.notify_hooks = vec![String::new()],
            "duplicate-id" => input.notify_hooks = vec!["announce".into(), "announce".into()],
            "missing-definition" => {
                input.notify_hook_definitions.pop();
            }
            "wrong-order" => input.notify_hook_definitions.swap(0, 1),
            _ => unreachable!(),
        }
        assert!(
            Candidate::seal(&temp.path().join(case), input).is_err(),
            "accepted invalid notify protocol {case}"
        );
    }

    let mut valid = fresh_candidate_input();
    valid.notify_hooks = vec!["announce".into(), "audit".into()];
    valid.notify_hook_definitions = vec![notify_hook("announce"), notify_hook("audit")];
    Candidate::seal(&temp.path().join("valid"), valid).unwrap();
}

#[test]
fn public_sidecars_require_an_unambiguous_explicit_upload_policy() {
    let temp = tempfile::tempdir().unwrap();
    let package = || hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]);

    let mut no_release = candidate_input(package(), None, br#"{}"#.to_vec());
    add_public_sidecar(&mut no_release, "sbom", "evidence.json");
    no_release.outputs.github_release = false;
    assert!(Candidate::seal(&temp.path().join("no-release"), no_release).is_err());

    let mut private = candidate_input(package(), None, br#"{}"#.to_vec());
    add_public_sidecar(&mut private, "sbom", "evidence.json");
    private.private = true;
    assert!(!private.outputs.allow_private_evidence_upload);
    assert!(Candidate::seal(&temp.path().join("private"), private).is_err());

    let mut duplicate = candidate_input(package(), None, br#"{}"#.to_vec());
    add_public_sidecar(&mut duplicate, "sbom", "evidence.json");
    add_public_sidecar(&mut duplicate, "provenance", "evidence.json");
    assert!(Candidate::seal(&temp.path().join("duplicate"), duplicate).is_err());
}

#[test]
fn requested_sbom_and_provenance_are_built_in_deterministic_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let mut input = candidate_input(
        hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
        None,
        br#"{"modules":{}}"#.to_vec(),
    );
    input.outputs.sbom = true;
    input.outputs.provenance = true;
    let evidence = Candidate::built_in_evidence(&input).unwrap();
    assert_eq!(
        evidence
            .iter()
            .map(|artifact| artifact.name.as_str())
            .collect::<Vec<_>>(),
        ["widget-1.2.3.cdx.json", "widget-1.2.3.intoto.jsonl"]
    );
    let sbom: serde_json::Value = serde_json::from_slice(&evidence[0].bytes).unwrap();
    assert_eq!(sbom["bomFormat"], "CycloneDX");
    assert_eq!(sbom["metadata"]["component"]["name"], "widget");
    let provenance: serde_json::Value = serde_json::from_slice(&evidence[1].bytes).unwrap();
    assert_eq!(provenance["_type"], "https://in-toto.io/Statement/v1");
    assert_eq!(
        provenance["subject"][0]["digest"]["sha256"],
        format!("{:x}", Sha256::digest(&input.package_tarball))
    );
    input.sidecars = evidence;
    let sealed = Candidate::seal(&temp.path().join("complete"), input).unwrap();
    assert_eq!(sealed.sidecars.len(), 2);

    let mut missing = candidate_input(
        hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
        None,
        br#"{}"#.to_vec(),
    );
    missing.outputs.sbom = true;
    assert!(Candidate::seal(&temp.path().join("missing"), missing).is_err());
}

#[test]
fn built_in_evidence_is_private_when_github_release_upload_is_disabled() {
    let mut input = fresh_candidate_input();
    input.outputs.github_release = false;
    input.outputs.sbom = true;
    input.outputs.provenance = true;
    let evidence = Candidate::built_in_evidence(&input).unwrap();
    assert_eq!(evidence.len(), 2);
    assert!(evidence.iter().all(|artifact| !artifact.public));
}

fn add_public_sidecar(input: &mut CandidateInput, hook_id: &str, name: &str) {
    input.sidecar_hook_definitions.push(HookConfig {
        id: hook_id.into(),
        argv: vec![format!("./scripts/{hook_id}")],
        timeout_seconds: 30,
        required: true,
        env: vec![],
    });
    input.hook_evidence.push(HookEvidence {
        schema: "hook/v1".into(),
        id: hook_id.into(),
        kind: HookKind::Sidecar,
        required: true,
        success: true,
        output_sha256: "7".repeat(64),
    });
    input.sidecars.push(SidecarArtifact {
        hook_id: hook_id.into(),
        name: name.into(),
        media_type: "application/json".into(),
        bytes: format!("{{\"hook\":\"{hook_id}\"}}").into_bytes(),
        public: true,
    });
}

fn candidate_input(
    package_tarball: Vec<u8>,
    docs_tarball: Option<Vec<u8>>,
    package_interface: Vec<u8>,
) -> CandidateInput {
    let outputs = OutputConfig {
        docs: docs_tarball.is_some(),
        sbom: false,
        provenance: false,
        ..OutputConfig::default()
    };
    CandidateInput {
        package: "widget".into(),
        version: Version::new(1, 2, 3),
        tag: "v1.2.3".into(),
        source: CandidateSource {
            commit_sha: "a".repeat(40),
            manifest_path: "packages/widget/gleam.toml".into(),
        },
        compiler: Version::new(1, 18, 1),
        registry: RegistryIdentity {
            provider: RegistryProvider::HexPm,
            repository: None,
            api_url: "https://hex.pm/api".into(),
            repository_url: "https://repo.hex.pm".into(),
            docs_url: "https://repo.hex.pm/docs".into(),
            credential_env: "HEXPM_API_KEY".into(),
            auth: AuthKind::HexToken,
            allow_http_loopback: false,
        },
        private: false,
        github_repository: "owner/widget".into(),
        release_branch_prefix: "release-glz/".into(),
        release_notes: "Widget release notes.".into(),
        approval: ApprovalConfig::default(),
        outputs,
        package_tarball,
        docs_tarball,
        package_interface,
        hook_evidence: vec![],
        verify_hook_definitions: vec![],
        sidecar_hook_definitions: vec![],
        sidecars: vec![],
        notify_hooks: vec![],
        notify_hook_definitions: vec![],
    }
}

fn fresh_candidate_input() -> CandidateInput {
    candidate_input(
        hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
        None,
        br#"{}"#.to_vec(),
    )
}

fn input_with_verify_hook() -> CandidateInput {
    let mut input = fresh_candidate_input();
    input.verify_hook_definitions.push(HookConfig {
        id: "policy".into(),
        argv: vec!["verify-policy".into()],
        timeout_seconds: 30,
        required: true,
        env: vec![],
    });
    input.hook_evidence.push(HookEvidence {
        schema: "hook/v1".into(),
        id: "policy".into(),
        kind: HookKind::Verify,
        required: true,
        success: true,
        output_sha256: "9".repeat(64),
    });
    input
}

fn notify_hook(id: &str) -> HookConfig {
    HookConfig {
        id: id.into(),
        argv: vec![format!("notify-{id}")],
        timeout_seconds: 30,
        required: true,
        env: vec![],
    }
}

fn mutate_candidate_json(directory: &std::path::Path, mutate: impl FnOnce(&mut serde_json::Value)) {
    let path = directory.join("candidate.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    mutate(&mut manifest);
    fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
}

fn hex_package(files: &[(&str, &[u8])]) -> Vec<u8> {
    outer_package(b"3", b"metadata", &tar_gz(files), None)
}

fn outer_package(
    version: &[u8],
    metadata: &[u8],
    contents: &[u8],
    checksum: Option<&[u8]>,
) -> Vec<u8> {
    let expected = checksum.map(Vec::from).unwrap_or_else(|| {
        let mut digest = Sha256::new();
        digest.update(version);
        digest.update(metadata);
        digest.update(contents);
        format!("{:X}", digest.finalize()).into_bytes()
    });
    tar(&[
        ("VERSION", version),
        ("metadata.config", metadata),
        ("contents.tar.gz", contents),
        ("CHECKSUM", &expected),
    ])
}

fn tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let bytes = Vec::new();
    let encoder = GzEncoder::new(bytes, Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (path, contents) in files {
        append(&mut archive, path, contents);
    }
    let encoder = archive.into_inner().unwrap();
    encoder.finish().unwrap()
}

fn malicious_link_tar_gz() -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    header.set_link_name("outside").unwrap();
    header.set_cksum();
    archive
        .append_data(&mut header, "link", std::io::empty())
        .unwrap();
    let encoder = archive.into_inner().unwrap();
    encoder.finish().unwrap()
}

fn tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut archive = tar::Builder::new(&mut bytes);
        for (path, contents) in files {
            append(&mut archive, path, contents);
        }
        archive.finish().unwrap();
    }
    bytes
}

fn append<W: Write>(archive: &mut tar::Builder<W>, path: &str, contents: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(contents.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_cksum();
    archive.append_data(&mut header, path, contents).unwrap();
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
