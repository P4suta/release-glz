use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::ops::Range;

use flate2::{Compression, write::GzEncoder};
use proptest::prelude::*;
use proptest::sample::{Index, select};
use release_glz::artifact::{ArchiveLimits, build_hex_tarball, validate_hex_tarball};
use release_glz::candidate::{
    Candidate, CandidateInput, CandidateManifest, CandidateSource, HookEvidence, HookKind,
    RegistryIdentity, SealedPolicy,
};
use release_glz::config::{
    ApprovalConfig, ApprovalMode, AuthKind, HookConfig, Manifest, OutputConfig, RegistryProvider,
    SeparationMode,
};
use release_glz::failure::{FailureClass, RefusalReason, classify, refusal_reason};
use release_glz::hooks::SidecarArtifact;
use release_glz::release::{LiveReleaseTarget, SourceBoundCandidate};
use release_glz_test_support::property::{self, ByteChange};
use release_glz_test_support::schema::assert_published_envelope;
use release_glz_test_support::{git, init_repository, isolated_command};
use semver::{BuildMetadata, Prerelease, Version};
use sha2::{Digest, Sha256};

/// A package whose committed configuration states one complete publication policy.
const POLICY_SOURCE: &str = r#"name = "widget"
version = "1.2.3"
description = "A publication policy fixture"
licences = ["MIT"]

[repository]
type = "github"
user = "acme"
repo = "widget"

[tools.release-glz]
schema = 2
compiler = "1.18.1"

[tools.release-glz.registry]
provider = "hexpm"
api_url = "https://hex.pm/api"
repository_url = "https://repo.hex.pm"
docs_url = "https://repo.hex.pm/docs"
credential_env = "HEXPM_API_KEY"
auth = "hex-token"

[tools.release-glz.approval]
normal = "release-pr-and-environment"
manual = "environment"
environment = "release"
manual_refs = ["refs/heads/main"]

[tools.release-glz.outputs]
docs = false
github_release = true
sbom = false
provenance = false

[[tools.release-glz.hooks.notify]]
id = "announce"
argv = ["./scripts/announce"]
timeout_seconds = 30
required = false
"#;

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
    assert_eq!(
        seal_refusal(
            &directory,
            candidate_input(package, None, br#"{}"#.to_vec())
        ),
        Some(RefusalReason::CandidateDestinationExists)
    );
}

#[test]
fn candidate_rejects_an_unsafe_tag_or_credential_environment_name() {
    let temp = tempfile::tempdir().unwrap();
    let package = hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]);
    let mut unsafe_tag = candidate_input(package.clone(), None, br#"{}"#.to_vec());
    unsafe_tag.tag = "refs/heads/main".into();
    assert_eq!(
        seal_refusal(&temp.path().join("tag"), unsafe_tag),
        Some(RefusalReason::CandidateTagUnsafe)
    );

    let mut unsafe_env = candidate_input(package, None, br#"{}"#.to_vec());
    unsafe_env.registry.credential_env = "BAD=secret".into();
    assert_eq!(
        seal_refusal(&temp.path().join("env"), unsafe_env),
        Some(RefusalReason::CredentialEnvInvalid)
    );

    let mut unsafe_branch = candidate_input(
        hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
        None,
        br#"{}"#.to_vec(),
    );
    unsafe_branch.release_branch_prefix = "refs/heads/main".into();
    assert_eq!(
        seal_refusal(&temp.path().join("branch"), unsafe_branch),
        Some(RefusalReason::GitRefPrefixUnsafe)
    );

    let mut missing_hook_policy = candidate_input(
        hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
        None,
        br#"{}"#.to_vec(),
    );
    missing_hook_policy.notify_hooks.push("announce".into());
    assert_eq!(
        seal_refusal(&temp.path().join("hook"), missing_hook_policy),
        Some(RefusalReason::NotifyHooksMismatch)
    );

    let mut unsafe_repository = candidate_input(
        hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
        None,
        br#"{}"#.to_vec(),
    );
    unsafe_repository.github_repository = "-owner/widget".into();
    let error = Candidate::seal(&temp.path().join("repository"), unsafe_repository).unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::GithubRepositoryInvalid)
    );
    assert!(error.to_string().contains("owner/name"), "{error}");
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
        let error = Candidate::seal(&temp.path().join(name), input).unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::UrlQueryOrFragment),
            "{name}"
        );
        assert!(
            error.to_string().contains("query or fragment"),
            "{name} unexpectedly passed the Candidate boundary: {error}"
        );
    }
}

#[test]
fn candidate_registry_urls_reject_opaque_credentials_and_http_beyond_loopback_independently() {
    let temp = tempfile::tempdir().unwrap();
    for (name, url, reason) in [
        (
            "opaque",
            "mailto:registry@example.test",
            RefusalReason::UrlNotHierarchical,
        ),
        (
            "password",
            "https://user:password@hex.pm/api",
            RefusalReason::UrlCredentials,
        ),
        (
            "http-to-a-host-name",
            "http://registry.example.test/api",
            RefusalReason::UrlTransportUntrusted,
        ),
        (
            "http-to-localhost",
            "http://localhost:8080/api",
            RefusalReason::UrlTransportUntrusted,
        ),
        (
            "http-to-a-public-address",
            "http://192.0.2.1/api",
            RefusalReason::UrlTransportUntrusted,
        ),
        (
            "http-to-a-mapped-address",
            "http://[::ffff:127.0.0.1]/api",
            RefusalReason::UrlTransportUntrusted,
        ),
        (
            "no-scheme-separator",
            "https;//hex.pm/api",
            RefusalReason::UrlMalformed,
        ),
        (
            "percent-in-host",
            "https://h%x.pm/api",
            RefusalReason::UrlMalformed,
        ),
    ] {
        let mut input = fresh_candidate_input();
        input.registry.api_url = url.into();
        assert_eq!(
            seal_refusal(&temp.path().join(name), input),
            Some(reason),
            "{name}"
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
        assert_eq!(
            seal_refusal(&temp.path().join(index.to_string()), input),
            Some(RefusalReason::RegistryRepositoryInvalid),
            "{repository:?}"
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
        assert_eq!(
            seal_refusal(&temp.path().join(format!("package-{index}")), input),
            Some(RefusalReason::PackageNameInvalid),
            "{package:?}"
        );
    }

    let mut mismatched = candidate_input(
        hex_package(&[("gleam.toml", b"name = \"widget\"\nversion = \"1.2.3\"\n")]),
        None,
        br#"{}"#.to_vec(),
    );
    mismatched.tag = "v9.9.9".into();
    assert_eq!(
        seal_refusal(&temp.path().join("tag-mismatch"), mismatched),
        Some(RefusalReason::CandidateTagVersionMismatch)
    );

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
    for (case, reason) in [
        ("short-sha", RefusalReason::CandidateSourceCommitInvalid),
        ("long-sha", RefusalReason::CandidateSourceCommitInvalid),
        ("sha256-sha", RefusalReason::CandidateSourceCommitInvalid),
        ("uppercase-sha", RefusalReason::CandidateSourceCommitInvalid),
        ("nonhex-sha", RefusalReason::CandidateSourceCommitInvalid),
        ("manifest-parent", RefusalReason::PathOutsideRepository),
        (
            "unsafe-custom-repository",
            RefusalReason::RegistryRepositoryInvalid,
        ),
        ("external-http", RefusalReason::UrlTransportUntrusted),
        ("credential-url", RefusalReason::UrlCredentials),
        ("empty-prefix", RefusalReason::GitRefPrefixUnsafe),
        ("refs-prefix", RefusalReason::GitRefPrefixUnsafe),
        ("spaced-prefix", RefusalReason::GitRefPrefixUnsafe),
        ("nul-notes", RefusalReason::CandidateReleaseNotesInvalid),
        (
            "empty-environment",
            RefusalReason::ApprovalEnvironmentInvalid,
        ),
        (
            "multiline-environment",
            RefusalReason::ApprovalEnvironmentInvalid,
        ),
        ("normal-mode", RefusalReason::ApprovalModeFixed),
        ("manual-mode", RefusalReason::ApprovalModeFixed),
        ("fallback", RefusalReason::ApprovalFallbackUnsupported),
        ("empty-manual-refs", RefusalReason::ManualRefsEmpty),
        (
            "partial-manual-ref",
            RefusalReason::ManualRefKindUnsupported,
        ),
        ("duplicate-manual-ref", RefusalReason::ManualRefDuplicate),
    ] {
        let mut input = fresh_candidate_input();
        match case {
            "short-sha" => input.source.commit_sha = "a".repeat(39),
            "long-sha" => input.source.commit_sha = "a".repeat(65),
            "sha256-sha" => input.source.commit_sha = "b".repeat(64),
            "uppercase-sha" => input.source.commit_sha = "A".repeat(40),
            "nonhex-sha" => input.source.commit_sha = "g".repeat(40),
            "manifest-parent" => input.source.manifest_path = "../gleam.toml".into(),
            "unsafe-custom-repository" => {
                input.registry.provider = RegistryProvider::HexCompatible;
                input.registry.repository = Some("../acme".into());
            }
            "external-http" => input.registry.api_url = "http://192.0.2.1/api".into(),
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
            _ => panic!("unknown case {case}"),
        }
        assert_eq!(
            seal_refusal(&temp.path().join(case), input),
            Some(reason),
            "{case}"
        );
    }

    for (index, host) in ["127.0.0.1", "127.8.9.10", "[::1]"].into_iter().enumerate() {
        let mut input = fresh_candidate_input();
        let base = format!("http://{host}:8080");
        input.registry.api_url = format!("{base}/api");
        input.registry.repository_url = base.clone();
        input.registry.docs_url = format!("{base}/docs");
        input.source.commit_sha = "b".repeat(40);
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
    assert_eq!(
        seal_refusal(&temp.path().join("over-limit"), over_limit),
        Some(RefusalReason::CandidateReleaseNotesInvalid)
    );
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
    let error = Candidate::verify(&directory).unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::CandidateChecksumMismatch)
    );
    assert_eq!(
        error.to_string(),
        "candidate checksum mismatch for `artifacts/package.tar`"
    );
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
    let error = Candidate::verify(&directory).unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::CandidateInventoryMismatch)
    );
    assert_eq!(
        error.to_string(),
        "Candidate inventory differs from the sealed manifest"
    );
}

#[test]
fn candidate_verification_rejects_every_manifest_identity_and_digest_tamper() {
    let temp = tempfile::tempdir().unwrap();
    // Every tamper also breaks a digest that verification checks last, so each case names the refusal of its own field.
    for (case, reason, expected) in [
        (
            "schema",
            RefusalReason::CandidateSchemaUnsupported,
            "unsupported candidate schema `candidate/v2`",
        ),
        (
            "package",
            RefusalReason::PackageNameInvalid,
            "package name must start with a lowercase letter and contain only a-z, 0-9, or _",
        ),
        (
            "tag",
            RefusalReason::CandidateTagVersionMismatch,
            "candidate.tag must end with the Candidate version `v1.2.3`",
        ),
        (
            "tag-ref",
            RefusalReason::CandidateTagUnsafe,
            "candidate.tag contains a dangerous git ref form",
        ),
        (
            "source-sha",
            RefusalReason::CandidateSourceCommitInvalid,
            "candidate source commit must be a full lowercase SHA: a commit ID holds only the lowercase hexadecimal digits `0` to `9` and `a` to `f`",
        ),
        (
            "source-sha256",
            RefusalReason::CandidateSourceCommitInvalid,
            "candidate source commit must be a full lowercase SHA: a SHA-256 object ID isn't a GitHub commit ID, which has 40 lowercase hexadecimal digits",
        ),
        (
            "source-path",
            RefusalReason::PathOutsideRepository,
            "candidate source manifest_path must stay within the repository",
        ),
        (
            "credential-env",
            RefusalReason::CredentialEnvInvalid,
            "candidate registry credential_env is not a safe environment variable name",
        ),
        (
            "registry-url-without-host",
            RefusalReason::UrlNotHierarchical,
            "candidate registry api_url must be an absolute hierarchical URL",
        ),
        (
            "registry-url-malformed",
            RefusalReason::UrlMalformed,
            "candidate registry api_url is invalid",
        ),
        (
            "branch-prefix",
            RefusalReason::GitRefPrefixUnsafe,
            "candidate release branch prefix is unsafe",
        ),
        (
            "release-notes",
            RefusalReason::CandidateReleaseNotesInvalid,
            "candidate release notes are invalid or exceed 1 MiB",
        ),
        (
            "artifact-path",
            RefusalReason::CandidateArtifactPathUnexpected,
            "candidate artifact path `artifacts/other.tar` must be `artifacts/package.tar`",
        ),
        (
            "artifact-size",
            RefusalReason::CandidateFileTooLarge,
            "candidate artifact `artifacts/package.tar` exceeds its size limit",
        ),
        (
            "artifact-sha",
            RefusalReason::CandidateChecksumMalformed,
            "artifact checksum is not a lowercase SHA-256 digest",
        ),
        (
            "artifact-sha-uppercase",
            RefusalReason::CandidateChecksumMalformed,
            "artifact checksum is not a lowercase SHA-256 digest",
        ),
        (
            "semantic-sha-uppercase",
            RefusalReason::CandidateChecksumMalformed,
            "semantic checksum is not a lowercase SHA-256 digest",
        ),
        (
            "package-semantic",
            RefusalReason::CandidateSemanticChecksumMismatch,
            "candidate semantic checksum mismatch",
        ),
        (
            "interface-semantic",
            RefusalReason::CandidateSemanticChecksumMismatch,
            "candidate semantic checksum mismatch",
        ),
        (
            "intent-digest",
            RefusalReason::CandidateIntentDigestMismatch,
            "candidate intent digest mismatch",
        ),
        (
            "candidate-digest",
            RefusalReason::CandidateDigestMismatch,
            "candidate digest mismatch",
        ),
    ] {
        let directory = temp.path().join(case);
        Candidate::seal(&directory, fresh_candidate_input()).unwrap();
        mutate_candidate_json(&directory, |manifest| match case {
            "schema" => manifest["schema"] = "candidate/v2".into(),
            "package" => manifest["package"] = "Widget".into(),
            "tag" => manifest["tag"] = "v9.9.9".into(),
            "tag-ref" => manifest["tag"] = "refs/tags/v1.2.3".into(),
            "source-sha" => manifest["source"]["commit_sha"] = "A".repeat(40).into(),
            "source-sha256" => manifest["source"]["commit_sha"] = "b".repeat(64).into(),
            "source-path" => manifest["source"]["manifest_path"] = "../gleam.toml".into(),
            "credential-env" => manifest["registry"]["credential_env"] = "TOKEN=value".into(),
            "registry-url-without-host" => {
                manifest["registry"]["api_url"] = "file:///registry".into()
            }
            "registry-url-malformed" => {
                manifest["registry"]["api_url"] = "https;//hex.pm/api".into()
            }
            "branch-prefix" => manifest["release_branch_prefix"] = "".into(),
            "release-notes" => manifest["release_notes"] = "bad\0notes".into(),
            "artifact-path" => {
                manifest["artifacts"]["package"]["path"] = "artifacts/other.tar".into()
            }
            "artifact-size" => manifest["artifacts"]["package"]["size"] = u64::MAX.into(),
            "artifact-sha" => manifest["artifacts"]["package"]["sha256"] = "g".repeat(64).into(),
            "artifact-sha-uppercase" => {
                uppercase_first_letter(&mut manifest["artifacts"]["package"]["sha256"])
            }
            "semantic-sha-uppercase" => {
                uppercase_first_letter(&mut manifest["artifacts"]["package"]["semantic_sha256"])
            }
            "package-semantic" => {
                manifest["artifacts"]["package"]["semantic_sha256"] = "0".repeat(64).into()
            }
            "interface-semantic" => {
                manifest["artifacts"]["package_interface"]["semantic_sha256"] =
                    "0".repeat(64).into()
            }
            "intent-digest" => manifest["intent_digest"] = "0".repeat(64).into(),
            "candidate-digest" => manifest["candidate_digest"] = "0".repeat(64).into(),
            _ => panic!("unknown case {case}"),
        });
        let error = Candidate::verify(&directory).unwrap_err();
        assert_eq!(refusal_reason(&error), Some(reason), "tamper {case}");
        assert_eq!(error.to_string(), expected, "tamper {case}");
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
    assert_eq!(
        verify_refusal(&unknown),
        Some(RefusalReason::CandidateManifestInvalid)
    );

    let loosened = temp.path().join("loosened");
    Candidate::seal(&loosened, fresh_candidate_input()).unwrap();
    mutate_candidate_json(&loosened, |manifest| {
        manifest["registry"]["allow_http_loopback"] = false.into();
    });
    let error = Candidate::verify(&loosened).unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::CandidateManifestInvalid)
    );
    let error = format!("{error:#}");
    assert!(
        error.contains("unknown field `allow_http_loopback`"),
        "{error}"
    );

    let oversized = temp.path().join("oversized");
    Candidate::seal(&oversized, fresh_candidate_input()).unwrap();
    fs::write(
        oversized.join("candidate.json"),
        vec![b' '; 1024 * 1024 + 1],
    )
    .unwrap();
    let error = Candidate::verify(&oversized).unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::CandidateFileTooLarge)
    );
    assert!(error.to_string().contains("size limit"), "{error}");

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
        let error = Candidate::verify(&linked).unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::CandidateFileNotRegular)
        );
        assert!(error.to_string().contains("regular file"), "{error}");
    }
}

/// A sealed manifest has one spelling, so bytes that spell the same value another way are refused.
#[test]
fn a_manifest_respelled_without_changing_its_value_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("candidate");
    let mut input = fresh_candidate_input();
    input.release_notes = "Widget\u{1f}release notes.".into();
    Candidate::seal(&directory, input).unwrap();
    let path = directory.join("candidate.json");
    let sealed = fs::read(&path).unwrap();
    let escape = sealed
        .windows(6)
        .position(|window| window == br"\u001f")
        .unwrap();
    // The first two are the counterexamples that the property of changed sealed files found.
    for (case, respelled) in [
        ("an uppercase escape digit", flipped(&sealed, escape + 5, 5)),
        (
            "a trailing carriage return",
            [&sealed, b"\r".as_slice()].concat(),
        ),
        ("a leading space", [b" ".as_slice(), &sealed].concat()),
    ] {
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&respelled).unwrap(),
            serde_json::from_slice::<serde_json::Value>(&sealed).unwrap(),
            "{case} changes the value"
        );
        fs::write(&path, respelled).unwrap();
        assert_eq!(
            verify_refusal(&directory),
            Some(RefusalReason::CandidateManifestInvalid),
            "{case}"
        );
    }
    fs::write(&path, &sealed).unwrap();
    Candidate::verify(&directory).unwrap();
}

#[test]
fn candidate_verification_refuses_a_declared_artifact_size_over_the_archive_limit() {
    let temp = tempfile::tempdir().unwrap();
    let limit = ArchiveLimits::default().max_archive_bytes;
    for artifact in ["package", "package_interface"] {
        for (size, refused) in [(limit, false), (limit + 1, true)] {
            let directory = temp.path().join(format!("{artifact}-{size}"));
            Candidate::seal(&directory, fresh_candidate_input()).unwrap();
            mutate_candidate_json(&directory, |manifest| {
                manifest["artifacts"][artifact]["size"] = size.into();
            });
            let error = Candidate::verify(&directory).unwrap_err();
            assert_eq!(
                refusal_reason(&error) == Some(RefusalReason::CandidateFileTooLarge),
                refused,
                "{artifact} declared at {size} bytes: {error}"
            );
        }
    }
}

#[test]
fn sealing_refuses_a_package_interface_over_the_archive_limit() {
    let temp = tempfile::tempdir().unwrap();
    let limit = usize::try_from(ArchiveLimits::default().max_archive_bytes).unwrap();
    for (size, refused) in [(limit, false), (limit + 1, true)] {
        let mut input = fresh_candidate_input();
        input.package_interface = vec![b' '; size];
        let error = Candidate::seal(&temp.path().join(size.to_string()), input).unwrap_err();
        assert_eq!(
            refusal_reason(&error) == Some(RefusalReason::CandidateInterfaceTooLarge),
            refused,
            "{size} bytes: {error}"
        );
    }
}

#[test]
fn publication_binds_a_candidate_whose_policy_matches_its_source_commit() {
    let temp = tempfile::tempdir().unwrap();
    let (repository, sha) = policy_repository(temp.path());
    let sealed = Candidate::seal(
        &temp.path().join("candidate"),
        honest_policy_input(&repository, &sha),
    )
    .unwrap();
    let bound = SourceBoundCandidate::bind(sealed.clone(), &repository.join("gleam.toml")).unwrap();
    assert_eq!(bound.manifest(), &sealed);
}

#[test]
fn a_private_publication_needs_its_registry_credential_before_it_builds_a_target() {
    let unset = "RELEASE_GLZ_TEST_UNSET_CREDENTIAL";
    assert!(std::env::var_os(unset).is_none());
    let public = POLICY_SOURCE.replace("HEXPM_API_KEY", unset);
    let private = public.replace(
        concat!(
            "provider = \"hexpm\"\n",
            "api_url = \"https://hex.pm/api\"\n",
            "repository_url = \"https://repo.hex.pm\"\n",
            "docs_url = \"https://repo.hex.pm/docs\"\n",
        ),
        concat!(
            "provider = \"hexpm\"\n",
            "repository = \"acme\"\n",
            "api_url = \"https://hex.pm/api\"\n",
            "repository_url = \"https://repo.hex.pm/repos/acme\"\n",
            "docs_url = \"https://repo.hex.pm/repos/acme/docs\"\n",
        ),
    );
    assert_ne!(private, public);
    for (case, source, expected) in [
        ("public", public.as_str(), None),
        (
            "private",
            private.as_str(),
            Some(format!(
                "private registry credential environment `{unset}` is not set"
            )),
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let (repository, sha) = policy_repository_from(temp.path(), source);
        let sealed = Candidate::seal(
            &temp.path().join("candidate"),
            honest_policy_input(&repository, &sha),
        )
        .unwrap();
        let bound = SourceBoundCandidate::bind(sealed, &repository.join("gleam.toml")).unwrap();
        let error = LiveReleaseTarget::from_candidate(bound)
            .err()
            .map(|error| (refusal_reason(&error), error.to_string()));
        assert_eq!(
            error,
            expected.map(|message| (Some(RefusalReason::RegistryCredentialMissing), message)),
            "{case}"
        );
    }
}

#[test]
fn a_sealed_file_with_its_size_but_other_bytes_fails_its_checksum() {
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("candidate");
    Candidate::seal(&directory, fresh_candidate_input()).unwrap();
    let path = directory.join("artifacts/package.tar");
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(&path, bytes).unwrap();

    let error = Candidate::verify(&directory).unwrap_err();

    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::CandidateChecksumMismatch)
    );
    assert_eq!(
        error.to_string(),
        "candidate checksum mismatch for `artifacts/package.tar`"
    );
}

#[test]
fn publication_refuses_a_candidate_whose_policy_differs_from_its_source_commit() {
    let temp = tempfile::tempdir().unwrap();
    let (repository, sha) = policy_repository(temp.path());
    type Forgery = (&'static str, fn(&mut CandidateInput));
    let forgeries: [Forgery; 10] = [
        ("registry", |input| {
            input.registry.api_url = "https://attacker.example/api".into();
        }),
        ("registry", |input| {
            input.registry.credential_env = "OTHER_REGISTRY_KEY".into();
        }),
        ("notify_hook_definitions", |input| {
            input.notify_hook_definitions[0].argv = vec!["./scripts/exfiltrate".into()];
        }),
        ("approval", |input| {
            input
                .approval
                .manual_refs
                .push("refs/heads/attacker".into());
        }),
        ("manifest_path", |input| {
            input.source.manifest_path = "fixtures/gleam.toml".into();
        }),
        ("release_notes", |input| {
            input.release_notes = "Download it from https://attacker.example.".into();
        }),
        ("github_repository", |input| {
            input.github_repository = "attacker/widget".into();
        }),
        ("compiler", |input| input.compiler = Version::new(1, 19, 0)),
        ("outputs", |input| input.outputs.github_release = false),
        ("release_branch_prefix", |input| {
            input.release_branch_prefix = "attacker/".into();
        }),
    ];
    let honest = Candidate::seal(
        &temp.path().join("honest"),
        honest_policy_input(&repository, &sha),
    )
    .unwrap();
    let honest = SealedPolicy::of(&honest);
    for (index, (field, forge)) in forgeries.into_iter().enumerate() {
        let mut input = honest_policy_input(&repository, &sha);
        forge(&mut input);
        let sealed = Candidate::seal(&temp.path().join(format!("forged-{index}")), input).unwrap();
        assert_eq!(SealedPolicy::of(&sealed).differences(&honest), [field]);
        let error = SourceBoundCandidate::bind(sealed, &repository.join("gleam.toml")).unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::CandidatePolicyDiffers),
            "{field}"
        );
        assert!(
            error.to_string().ends_with(&format!(": {field}")),
            "{field}: {error}"
        );
    }
}

#[test]
fn publication_reads_the_source_policy_from_the_commit_instead_of_the_working_tree() {
    let temp = tempfile::tempdir().unwrap();
    let (repository, sha) = policy_repository(temp.path());
    fs::write(
        repository.join("gleam.toml"),
        POLICY_SOURCE.replace("https://hex.pm/api", "https://attacker.example/api"),
    )
    .unwrap();
    let sealed = Candidate::seal(
        &temp.path().join("candidate"),
        honest_policy_input(&repository, &sha),
    )
    .unwrap();
    assert_eq!(sealed.registry.api_url, "https://attacker.example/api");
    let error = SourceBoundCandidate::bind(sealed, &repository.join("gleam.toml")).unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::CandidatePolicyDiffers)
    );
    assert!(error.to_string().ends_with(": registry"), "{error}");
}

#[test]
fn publication_refuses_a_source_commit_without_release_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let (repository, sha) =
        policy_repository_from(temp.path(), "name = \"widget\"\nversion = \"1.2.3\"\n");
    fs::write(repository.join("gleam.toml"), POLICY_SOURCE).unwrap();
    let sealed = Candidate::seal(
        &temp.path().join("candidate"),
        honest_policy_input(&repository, &sha),
    )
    .unwrap();
    let error = SourceBoundCandidate::bind(sealed, &repository.join("gleam.toml")).unwrap_err();
    assert_eq!(refusal_reason(&error), Some(RefusalReason::ConfigMissing));
    assert_eq!(classify(&error), FailureClass::UsageOrConfig);
    let message = format!("{error:#}");
    assert!(
        message.contains("[tools.release-glz]") && message.contains("release-glz init"),
        "{message}"
    );

    let unconfigured = Manifest::parse(
        repository.join("gleam.toml"),
        "name = \"widget\"\nversion = \"1.2.3\"\n".into(),
    )
    .unwrap();
    let error = SealedPolicy::from_source(&unconfigured, &repository, "gleam.toml").unwrap_err();
    assert_eq!(refusal_reason(&error), Some(RefusalReason::ConfigMissing));
}

#[test]
fn candidate_commands_refuse_a_checkout_without_release_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let unconfigured = "name = \"widget\"\nversion = \"1.2.3\"\n";
    let (repository, sha) = policy_repository_from(temp.path(), unconfigured);
    fs::write(repository.join("gleam.toml"), POLICY_SOURCE).unwrap();
    let candidate = temp.path().join("candidate");
    Candidate::seal(&candidate, honest_policy_input(&repository, &sha)).unwrap();
    fs::write(repository.join("gleam.toml"), unconfigured).unwrap();
    for arguments in [
        vec!["release-pr", "--dry-run", "--candidate"],
        vec!["release", "--dry-run", "--candidate"],
        vec!["verify", "--online", "--candidate"],
    ] {
        let output = isolated_command(env!("CARGO_BIN_EXE_release-glz"))
            .current_dir(&repository)
            .args(["--output", "json"])
            .args(&arguments)
            .arg(&candidate)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_published_envelope(&envelope);
        assert_eq!(envelope["diagnostics"][0]["code"], "config_missing");
        let message = envelope["diagnostics"][0]["message"].as_str().unwrap();
        assert!(
            message.contains("[tools.release-glz]") && message.contains("release-glz init"),
            "{arguments:?}: {message}"
        );
    }
}

#[test]
fn publication_refuses_a_checkout_at_another_commit() {
    let temp = tempfile::tempdir().unwrap();
    let (repository, sha) = policy_repository(temp.path());
    let sealed = Candidate::seal(
        &temp.path().join("candidate"),
        honest_policy_input(&repository, &sha),
    )
    .unwrap();
    git(
        &repository,
        &["commit", "--allow-empty", "-m", "chore: later"],
    );
    let error = SourceBoundCandidate::bind(sealed, &repository.join("gleam.toml")).unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::CandidateSourceMismatch)
    );
    assert!(error.to_string().contains("source"), "{error}");
}

#[test]
fn a_candidate_path_that_is_not_a_directory_is_a_usage_error() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing");
    for arguments in [
        vec!["verify", "--candidate"],
        vec!["status", "--candidate"],
        vec!["release", "--dry-run", "--candidate"],
    ] {
        let output = isolated_command(env!("CARGO_BIN_EXE_release-glz"))
            .current_dir(temp.path())
            .args(["--output", "json"])
            .args(&arguments)
            .arg(&missing)
            .output()
            .unwrap();
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_published_envelope(&envelope);
        let message = envelope["diagnostics"][0]["message"].as_str().unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}: {message}");
        assert_eq!(
            envelope["diagnostics"][0]["code"],
            "candidate_not_directory"
        );
        assert!(
            message.contains(&missing.display().to_string()),
            "{arguments:?}: {message}"
        );
    }
}

#[test]
fn offline_candidate_commands_need_no_manifest_in_the_working_directory() {
    let temp = tempfile::tempdir().unwrap();
    let candidate = temp.path().join("candidate");
    Candidate::seal(&candidate, fresh_candidate_input()).unwrap();
    let elsewhere = temp.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    for command in ["verify", "status"] {
        let output = isolated_command(env!("CARGO_BIN_EXE_release-glz"))
            .current_dir(&elsewhere)
            .args(["--output", "json", command, "--candidate"])
            .arg(&candidate)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{command}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_published_envelope(&envelope);
        assert_eq!(envelope["ok"], true, "{command}");
    }
}

#[test]
fn offline_verify_and_status_print_a_populated_candidate_in_their_published_schemas() {
    let temp = tempfile::tempdir().unwrap();
    let candidate = temp.path().join("candidate");
    let mut input = input_with_verify_hook();
    input.docs_tarball = Some(tar_gz(&[("index.html", b"<h1>Widget</h1>")]));
    input.outputs.docs = true;
    input.package_interface = br#"{"modules":{}}"#.to_vec();
    add_public_sidecar(&mut input, "sbom", "sbom.cdx.json");
    input.notify_hooks = vec!["announce".into()];
    input.notify_hook_definitions = vec![notify_hook("announce")];
    Candidate::seal(&candidate, input).unwrap();

    let run = |command: &str| {
        let output = isolated_command(env!("CARGO_BIN_EXE_release-glz"))
            .current_dir(temp.path())
            .args(["--output", "json", command, "--candidate"])
            .arg(&candidate)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{command}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_published_envelope(&envelope);
        envelope
    };
    let verified = run("verify");
    let sealed = &verified["result"]["candidate"];
    for populated in [
        "verify_hook_definitions",
        "sidecar_hook_definitions",
        "hook_evidence",
        "sidecars",
        "notify_hooks",
        "notify_hook_definitions",
    ] {
        assert!(
            !sealed[populated].as_array().unwrap().is_empty(),
            "{populated}"
        );
    }
    assert!(sealed["artifacts"]["docs"].is_object());
    let status = run("status");
    assert_eq!(
        status["result"]["candidate_digest"],
        sealed["candidate_digest"]
    );
    assert_eq!(status["next_actions"][0]["argv"][1], "release");
}

#[test]
fn release_refuses_a_forged_candidate_before_it_needs_any_token() {
    let temp = tempfile::tempdir().unwrap();
    let (repository, sha) = policy_repository(temp.path());
    let mut input = honest_policy_input(&repository, &sha);
    input.registry.api_url = "https://attacker.example/api".into();
    let candidate = temp.path().join("forged");
    Candidate::seal(&candidate, input).unwrap();
    let output = isolated_command(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(&repository)
        .args(["--output", "json", "release", "--candidate"])
        .arg(&candidate)
        .output()
        .unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_published_envelope(&envelope);
    let message = envelope["diagnostics"][0]["message"].as_str().unwrap();
    assert_eq!(output.status.code(), Some(4), "{message}");
    assert_eq!(
        envelope["diagnostics"][0]["code"],
        "candidate_policy_differs"
    );
    assert!(message.ends_with(": registry"), "{message}");
}

/// The reason that sealing `input` into `directory` is refused with, which panics when sealing succeeds.
fn seal_refusal(directory: &std::path::Path, input: CandidateInput) -> Option<RefusalReason> {
    refusal_reason(&Candidate::seal(directory, input).unwrap_err())
}

/// The reason that verifying the Candidate in `directory` is refused with, which panics when verification succeeds.
fn verify_refusal(directory: &std::path::Path) -> Option<RefusalReason> {
    refusal_reason(&Candidate::verify(directory).unwrap_err())
}

/// A committed copy of [`POLICY_SOURCE`] and the SHA of its commit.
fn policy_repository(temp: &std::path::Path) -> (std::path::PathBuf, String) {
    policy_repository_from(temp, POLICY_SOURCE)
}

/// A committed copy of `source` and the SHA of its commit.
fn policy_repository_from(temp: &std::path::Path, source: &str) -> (std::path::PathBuf, String) {
    let repository = temp.join("repo");
    fs::create_dir_all(&repository).unwrap();
    fs::write(repository.join("gleam.toml"), source).unwrap();
    init_repository(&repository);
    for (name, value) in [
        ("core.hooksPath", ".git/no-hooks"),
        ("user.email", "fixture@example.test"),
        ("user.name", "Fixture"),
        ("commit.gpgsign", "false"),
    ] {
        git(&repository, &["config", name, value]);
    }
    git(&repository, &["add", "."]);
    git(
        &repository,
        &["commit", "-m", "feat: publication policy source"],
    );
    let sha = git(&repository, &["rev-parse", "HEAD"]).trim().to_owned();
    (repository, sha)
}

/// A Candidate input whose policy is what the working tree of `repository` states, sealed as the commit `sha`.
fn honest_policy_input(repository: &std::path::Path, sha: &str) -> CandidateInput {
    let manifest = Manifest::load(repository.join("gleam.toml")).unwrap();
    let SealedPolicy {
        package,
        version,
        tag,
        manifest_path,
        compiler,
        registry,
        private,
        github_repository,
        release_branch_prefix,
        release_notes,
        approval,
        outputs,
        verify_hook_definitions,
        sidecar_hook_definitions,
        notify_hooks,
        notify_hook_definitions,
    } = SealedPolicy::from_source(&manifest, repository, "gleam.toml").unwrap();
    CandidateInput {
        package,
        version,
        tag,
        source: CandidateSource {
            commit_sha: sha.to_owned(),
            manifest_path,
        },
        compiler,
        registry,
        private,
        github_repository,
        release_branch_prefix,
        release_notes,
        approval,
        outputs,
        verify_hook_definitions,
        sidecar_hook_definitions,
        notify_hooks,
        notify_hook_definitions,
        ..fresh_candidate_input()
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

    let refusal = |package: &[u8], limits| {
        let error = validate_hex_tarball(package, limits).unwrap_err();
        (refusal_reason(&error), format!("{error:#}"))
    };
    let bad_checksum = outer_package(b"3", b"meta", &tar_gz(&[("x", b"ok")]), Some(b"BAD"));
    assert_eq!(
        refusal(&bad_checksum, ArchiveLimits::default()),
        (
            Some(RefusalReason::HexInnerChecksumMismatch),
            "Hex package inner checksum mismatch".to_owned()
        )
    );

    let duplicate = outer_package(
        b"3",
        b"meta",
        &tar_gz(&[("same", b"one"), ("same", b"two")]),
        None,
    );
    assert_eq!(
        refusal(&duplicate, ArchiveLimits::default()),
        (
            Some(RefusalReason::ArchiveEntryDuplicate),
            "unsafe Hex contents archive: archive contains duplicate entry `same`".to_owned()
        )
    );

    let linked_contents = malicious_link_tar_gz();
    let linked = outer_package(b"3", b"meta", &linked_contents, None);
    assert_eq!(
        refusal(&linked, ArchiveLimits::default()),
        (
            Some(RefusalReason::ArchiveEntryNotRegular),
            "unsafe Hex contents archive: archive entry `link` is not a regular file".to_owned()
        )
    );
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
    let error = validate_hex_tarball(&package, limits).unwrap_err();
    assert_eq!(
        (refusal_reason(&error), format!("{error:#}")),
        (
            Some(RefusalReason::ArchiveLimitExceeded),
            "unsafe Hex contents archive: archive entry exceeds the per-file limit".to_owned()
        )
    );
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
    assert_eq!(
        verify_refusal(&temp.path().join("with")),
        Some(RefusalReason::CandidateChecksumMismatch)
    );
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
    assert_eq!(
        seal_refusal(&temp.path().join("inconsistent"), inconsistent),
        Some(RefusalReason::CandidateDocsPolicyMismatch)
    );
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
    assert_eq!(
        seal_refusal(&temp.path().join("missing"), missing_evidence),
        Some(RefusalReason::CandidateHookEvidenceMismatch)
    );
}

#[test]
fn candidate_boundary_rejects_core_and_configured_publication_credentials_in_hooks() {
    let temp = tempfile::tempdir().unwrap();
    for (case, credential_env, forwarded_env) in [
        ("github", "PRIVATE_REGISTRY_TOKEN", "GITHUB_TOKEN"),
        (
            "registry",
            "PRIVATE_REGISTRY_TOKEN",
            "PRIVATE_REGISTRY_TOKEN",
        ),
    ] {
        let mut input = input_with_verify_hook();
        input.registry.credential_env = credential_env.into();
        input.verify_hook_definitions[0].env = vec![forwarded_env.into()];
        let error = Candidate::seal(&temp.path().join(case), input).unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::HookEnvProtected),
            "{case}"
        );
        assert!(
            error.to_string().contains("may not receive"),
            "{case}: {error}"
        );
    }
}

#[test]
fn candidate_hook_evidence_is_strictly_bound_to_ordered_definitions() {
    let temp = tempfile::tempdir().unwrap();
    for (case, reason) in [
        ("schema", RefusalReason::CandidateHookEvidenceInvalid),
        ("empty-id", RefusalReason::CandidateHookEvidenceInvalid),
        ("checksum", RefusalReason::CandidateChecksumMalformed),
        ("required-failure", RefusalReason::CandidateHookFailed),
        ("missing", RefusalReason::CandidateHookEvidenceMismatch),
        ("binding-id", RefusalReason::CandidateHookEvidenceMismatch),
        ("binding-kind", RefusalReason::CandidateHookEvidenceMismatch),
        (
            "binding-required",
            RefusalReason::CandidateHookEvidenceMismatch,
        ),
        (
            "duplicate-evidence",
            RefusalReason::CandidateHookEvidenceInvalid,
        ),
        ("duplicate-definition", RefusalReason::HookIdDuplicate),
        ("invalid-definition", RefusalReason::HookArgvInvalid),
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
            _ => panic!("unknown case {case}"),
        }
        assert_eq!(
            seal_refusal(&temp.path().join(case), input),
            Some(reason),
            "{case}"
        );
    }
}

#[test]
fn candidate_sidecars_require_safe_identity_declared_producer_and_signature_policy() {
    let temp = tempfile::tempdir().unwrap();
    for (index, (case, reason)) in [
        ("empty-hook", RefusalReason::SidecarHookIdUnsafe),
        ("numeric-hook", RefusalReason::SidecarHookIdUnsafe),
        ("empty-name", RefusalReason::SidecarNameUnsafe),
        ("nested-name", RefusalReason::SidecarNameUnsafe),
        ("backslash-name", RefusalReason::SidecarNameUnsafe),
        ("long-name", RefusalReason::SidecarNameUnsafe),
        ("empty-media", RefusalReason::SidecarMediaTypeInvalid),
        (
            "missing-media-slash",
            RefusalReason::SidecarMediaTypeInvalid,
        ),
        ("quoted-media", RefusalReason::SidecarMediaTypeInvalid),
        (
            "undeclared-producer",
            RefusalReason::CandidateSidecarProducerUndeclared,
        ),
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
            _ => panic!("unknown case {case}"),
        }
        input.sidecars.push(artifact);
        assert_eq!(
            seal_refusal(&temp.path().join(format!("invalid-{index}")), input),
            Some(reason),
            "{case}"
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
    assert_eq!(
        seal_refusal(&temp.path().join("too-many"), too_many),
        Some(RefusalReason::CandidateSidecarsTooMany)
    );

    let mut missing_signature = fresh_candidate_input();
    missing_signature.outputs.signature = true;
    assert_eq!(
        seal_refusal(&temp.path().join("missing-signature"), missing_signature),
        Some(RefusalReason::CandidateSignatureMissing)
    );

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

    for (case, reason) in [
        ("path", RefusalReason::CandidateSidecarPathInvalid),
        ("checksum", RefusalReason::CandidateChecksumMalformed),
        ("size", RefusalReason::CandidateSidecarsTooLarge),
    ] {
        let directory = temp.path().join(format!("tampered-{case}"));
        let mut input = fresh_candidate_input();
        add_public_sidecar(&mut input, "evidence", "evidence.json");
        Candidate::seal(&directory, input).unwrap();
        mutate_candidate_json(&directory, |manifest| match case {
            "path" => manifest["sidecars"][0]["path"] = "sidecars/other/file".into(),
            "checksum" => manifest["sidecars"][0]["sha256"] = "g".repeat(64).into(),
            "size" => manifest["sidecars"][0]["size"] = u64::MAX.into(),
            _ => panic!("unknown case {case}"),
        });
        assert_eq!(verify_refusal(&directory), Some(reason), "{case}");
    }
}

/// GitHub renames an asset whose name it doesn't keep, so sealing and verifying refuse such a name before anything publishes.
#[test]
fn sealing_and_verifying_refuse_an_asset_name_that_github_would_rename() {
    let temp = tempfile::tempdir().unwrap();
    for name in [
        "sbom.cdx.json",
        "release-glz.intoto.jsonl",
        "widget_1.2.3-rc.1.tar.gz",
    ] {
        let mut input = fresh_candidate_input();
        add_public_sidecar(&mut input, "evidence", name);
        let sealed = Candidate::seal(&temp.path().join(name), input).unwrap();
        assert_eq!(sealed.sidecars[0].name, name);
        Candidate::verify(&temp.path().join(name)).unwrap();
    }

    for (index, name) in [
        "my evidence.json",
        ".evidence.json",
        "evidence.json.",
        "evidence+1.json",
        "evidence~1.json",
        "évidence.json",
    ]
    .into_iter()
    .enumerate()
    {
        let mut input = fresh_candidate_input();
        add_public_sidecar(&mut input, "evidence", name);
        let error =
            Candidate::seal(&temp.path().join(format!("renamed-{index}")), input).unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::SidecarNameUnsafe),
            "{name:?}"
        );
        assert!(
            error.to_string().contains("safe asset name"),
            "{name:?}: {error}"
        );

        let directory = temp.path().join(format!("tampered-{index}"));
        let mut input = fresh_candidate_input();
        add_public_sidecar(&mut input, "evidence", "evidence.json");
        Candidate::seal(&directory, input).unwrap();
        mutate_candidate_json(&directory, |manifest| {
            manifest["sidecars"][0]["name"] = name.into();
            manifest["sidecars"][0]["path"] = format!("sidecars/evidence/{name}").into();
        });
        let error = Candidate::verify(&directory).unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::SidecarNameUnsafe),
            "{name:?}"
        );
        assert!(
            error.to_string().contains("safe asset name"),
            "{name:?}: {error}"
        );
    }
}

#[test]
fn candidate_notify_hooks_are_an_ordered_idempotent_protocol() {
    let temp = tempfile::tempdir().unwrap();
    for (case, reason) in [
        ("empty-id", RefusalReason::NotifyHookIdInvalid),
        ("duplicate-id", RefusalReason::NotifyHookIdInvalid),
        ("missing-definition", RefusalReason::NotifyHooksMismatch),
        ("wrong-order", RefusalReason::NotifyHooksMismatch),
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
            _ => panic!("unknown case {case}"),
        }
        assert_eq!(
            seal_refusal(&temp.path().join(case), input),
            Some(reason),
            "{case}"
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
    assert_eq!(
        seal_refusal(&temp.path().join("no-release"), no_release),
        Some(RefusalReason::CandidateSidecarReleaseDisabled)
    );

    let mut private = candidate_input(package(), None, br#"{}"#.to_vec());
    add_public_sidecar(&mut private, "sbom", "evidence.json");
    private.private = true;
    assert!(!private.outputs.allow_private_evidence_upload);
    assert_eq!(
        seal_refusal(&temp.path().join("private"), private),
        Some(RefusalReason::CandidateSidecarPrivateUploadForbidden)
    );

    let mut duplicate = candidate_input(package(), None, br#"{}"#.to_vec());
    add_public_sidecar(&mut duplicate, "sbom", "evidence.json");
    add_public_sidecar(&mut duplicate, "provenance", "evidence.json");
    assert_eq!(
        seal_refusal(&temp.path().join("duplicate"), duplicate),
        Some(RefusalReason::CandidateSidecarNameDuplicate)
    );
}

#[test]
fn built_in_evidence_of_a_version_with_build_metadata_spells_its_plus_as_an_underscore() {
    let temp = tempfile::tempdir().unwrap();
    let mut input = candidate_input(
        hex_package(&[(
            "gleam.toml",
            b"name = \"widget\"\nversion = \"1.0.0+build.1\"\n",
        )]),
        None,
        br#"{"modules":{}}"#.to_vec(),
    );
    input.version = "1.0.0+build.1".parse().unwrap();
    input.tag = "v1.0.0+build.1".into();
    input.outputs.sbom = true;
    input.outputs.provenance = true;
    input.sidecars = Candidate::built_in_evidence(&input).unwrap();

    let sealed = Candidate::seal(&temp.path().join("candidate"), input).unwrap();

    assert_eq!(
        sealed
            .sidecars
            .iter()
            .map(|sidecar| sidecar.name.as_str())
            .collect::<Vec<_>>(),
        [
            "widget-1.0.0_build.1.cdx.json",
            "widget-1.0.0_build.1.intoto.jsonl"
        ]
    );
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
        release_glz::canonical::sha256(&input.package_tarball).as_str()
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
    assert_eq!(
        seal_refusal(&temp.path().join("missing"), missing),
        Some(RefusalReason::CandidateEvidencePolicyMismatch)
    );
}

#[test]
fn a_package_is_private_on_an_organization_or_a_hex_compatible_registry() {
    let temp = tempfile::tempdir().unwrap();
    let public_registry = concat!(
        "provider = \"hexpm\"\n",
        "api_url = \"https://hex.pm/api\"\n",
        "repository_url = \"https://repo.hex.pm\"\n",
        "docs_url = \"https://repo.hex.pm/docs\"\n",
    );
    assert!(POLICY_SOURCE.contains(public_registry));
    for (case, registry, private) in [
        ("public hex.pm", public_registry, false),
        (
            "a hex.pm organization",
            concat!(
                "provider = \"hexpm\"\n",
                "repository = \"acme\"\n",
                "api_url = \"https://hex.pm/api\"\n",
                "repository_url = \"https://repo.hex.pm/repos/acme\"\n",
                "docs_url = \"https://repo.hex.pm/repos/acme/docs\"\n",
            ),
            true,
        ),
        (
            "a hex-compatible registry",
            concat!(
                "provider = \"hex-compatible\"\n",
                "api_url = \"https://packages.example/api\"\n",
                "repository_url = \"https://packages.example/repo\"\n",
                "docs_url = \"https://packages.example/repo/docs\"\n",
            ),
            true,
        ),
    ] {
        let source = POLICY_SOURCE.replace(public_registry, registry);
        let manifest = Manifest::parse(temp.path().join("gleam.toml"), source).unwrap();
        let policy = SealedPolicy::from_source(&manifest, temp.path(), "gleam.toml").unwrap();
        assert_eq!(policy.private, private, "{case}");
    }
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

/// `bytes` with bit `bit` of the byte at `offset` inverted.
fn flipped(bytes: &[u8], offset: usize, bit: u8) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    bytes[offset] ^= 1 << bit;
    bytes
}

/// Spells the first letter of the digest in `digest` in uppercase, so the digest keeps its value and loses its one sealed spelling.
fn uppercase_first_letter(digest: &mut serde_json::Value) {
    let lowercase = digest.as_str().unwrap();
    let letter = lowercase.chars().find(char::is_ascii_lowercase).unwrap();
    let uppercase = letter.to_ascii_uppercase().to_string();
    *digest = lowercase.replacen(letter, &uppercase, 1).into();
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
        release_glz::hex::upper(&release_glz::canonical::finalize_sha256(digest)).into_bytes()
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
    release_glz::canonical::sha256(bytes).into()
}

proptest! {
    #![proptest_config(property::config(32))]

    /// A sealed Candidate verifies to the manifest that sealing returned, which records the input, and its files hold the bytes it sealed.
    #[test]
    fn generated_candidates_verify_to_the_manifest_that_sealed_them(input in candidate_inputs()) {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("candidate");
        let sealed = Candidate::seal(&directory, input.clone()).unwrap();
        let verified = Candidate::verify(&directory).unwrap();
        prop_assert_eq!(&verified, &sealed);
        prop_assert_eq!(Recorded::of_manifest(&verified), Recorded::of_input(&input));
        prop_assert_eq!(
            SealedBytes::read(&directory, &verified),
            SealedBytes::of_input(input)
        );
    }

    /// One changed, removed, or added byte in any sealed file fails verification with a reason that names the change.
    ///
    /// Every file but the manifest is held to its recorded size and digest, so its reason is exact.
    #[test]
    fn a_changed_sealed_file_fails_verification_with_its_reason(
        input in candidate_inputs(),
        changes in prop::collection::vec((any::<Index>(), property::byte_change()), 16),
    ) {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("candidate");
        let sealed = Candidate::seal(&directory, input).unwrap();
        let files = sealed_files(&sealed);
        for (file, change) in &changes {
            let file = &files[file.index(files.len())];
            let path = directory.join(file);
            let original = fs::read(&path).unwrap();
            fs::write(&path, change.apply(&original)).unwrap();
            let outcome = Candidate::verify(&directory)
                .map(drop)
                .map_err(|error| (refusal_reason(&error), format!("{error:#}")));
            fs::write(&path, &original).unwrap();
            let expected = if file == "candidate.json" {
                MANIFEST_REFUSALS
            } else {
                artifact_refusal(*change)
            };
            prop_assert!(
                matches!(&outcome, Err((Some(reason), _)) if expected.contains(reason)),
                "{change:?} of {file} gave {outcome:?}"
            );
        }
        Candidate::verify(&directory).unwrap();
    }
}

/// What a Candidate records of the input it was sealed from, apart from the bytes.
#[derive(Debug, PartialEq)]
struct Recorded<'a> {
    package: &'a str,
    version: &'a Version,
    tag: &'a str,
    source: &'a CandidateSource,
    compiler: &'a Version,
    registry: &'a RegistryIdentity,
    private: bool,
    github_repository: &'a str,
    release_branch_prefix: &'a str,
    release_notes: &'a str,
    approval: &'a ApprovalConfig,
    outputs: &'a OutputConfig,
    verify_hook_definitions: &'a [HookConfig],
    hook_evidence: &'a [HookEvidence],
    notify_hooks: &'a [String],
    notify_hook_definitions: &'a [HookConfig],
}

impl<'a> Recorded<'a> {
    fn of_input(input: &'a CandidateInput) -> Self {
        Self {
            package: &input.package,
            version: &input.version,
            tag: &input.tag,
            source: &input.source,
            compiler: &input.compiler,
            registry: &input.registry,
            private: input.private,
            github_repository: &input.github_repository,
            release_branch_prefix: &input.release_branch_prefix,
            release_notes: &input.release_notes,
            approval: &input.approval,
            outputs: &input.outputs,
            verify_hook_definitions: &input.verify_hook_definitions,
            hook_evidence: &input.hook_evidence,
            notify_hooks: &input.notify_hooks,
            notify_hook_definitions: &input.notify_hook_definitions,
        }
    }

    fn of_manifest(manifest: &'a CandidateManifest) -> Self {
        Self {
            package: &manifest.package,
            version: &manifest.version,
            tag: &manifest.tag,
            source: &manifest.source,
            compiler: &manifest.compiler,
            registry: &manifest.registry,
            private: manifest.private,
            github_repository: &manifest.github_repository,
            release_branch_prefix: &manifest.release_branch_prefix,
            release_notes: &manifest.release_notes,
            approval: &manifest.approval,
            outputs: &manifest.outputs,
            verify_hook_definitions: &manifest.verify_hook_definitions,
            hook_evidence: &manifest.hook_evidence,
            notify_hooks: &manifest.notify_hooks,
            notify_hook_definitions: &manifest.notify_hook_definitions,
        }
    }
}

/// The bytes a Candidate seals, with each sidecar under its name.
#[derive(Debug, PartialEq)]
struct SealedBytes {
    package: Vec<u8>,
    docs: Option<Vec<u8>>,
    interface: Vec<u8>,
    sidecars: Vec<(String, Vec<u8>)>,
}

impl SealedBytes {
    fn of_input(input: CandidateInput) -> Self {
        Self {
            package: input.package_tarball,
            docs: input.docs_tarball,
            interface: input.package_interface,
            sidecars: input
                .sidecars
                .into_iter()
                .map(|artifact| (artifact.name, artifact.bytes))
                .collect(),
        }
    }

    /// The bytes of the Candidate in `directory`, read through the descriptors of its verified `manifest`.
    fn read(directory: &std::path::Path, manifest: &CandidateManifest) -> Self {
        Self {
            package: Candidate::package_bytes(directory, manifest).unwrap(),
            docs: Candidate::docs_bytes(directory, manifest).unwrap(),
            interface: fs::read(directory.join(&manifest.artifacts.package_interface.path))
                .unwrap(),
            sidecars: Candidate::sidecar_bytes(directory, manifest)
                .unwrap()
                .into_iter()
                .map(|(descriptor, bytes)| (descriptor.name, bytes))
                .collect(),
        }
    }
}

/// The reasons that verification gives a manifest it refuses.
const MANIFEST_REFUSALS: &[RefusalReason] = &[
    RefusalReason::CandidateManifestInvalid,
    RefusalReason::CandidateSchemaUnsupported,
    RefusalReason::PackageNameInvalid,
    RefusalReason::CandidateSourceCommitInvalid,
    RefusalReason::PathNotRelative,
    RefusalReason::PathOutsideRepository,
    RefusalReason::GitRefUnsafe,
    RefusalReason::CandidateTagUnsafe,
    RefusalReason::CandidateTagVersionMismatch,
    RefusalReason::CredentialEnvInvalid,
    RefusalReason::RegistryRepositoryInvalid,
    RefusalReason::UrlMalformed,
    RefusalReason::UrlCredentials,
    RefusalReason::UrlNotHierarchical,
    RefusalReason::UrlQueryOrFragment,
    RefusalReason::UrlTransportUntrusted,
    RefusalReason::GithubRepositoryInvalid,
    RefusalReason::GitRefPrefixUnsafe,
    RefusalReason::CandidateReleaseNotesInvalid,
    RefusalReason::ApprovalEnvironmentInvalid,
    RefusalReason::ApprovalModeFixed,
    RefusalReason::ApprovalFallbackUnsupported,
    RefusalReason::ManualRefsEmpty,
    RefusalReason::ManualRefKindUnsupported,
    RefusalReason::ManualRefDuplicate,
    RefusalReason::CandidateHookEvidenceInvalid,
    RefusalReason::CandidateHookFailed,
    RefusalReason::CandidateChecksumMalformed,
    RefusalReason::CandidateSidecarsTooMany,
    RefusalReason::CandidateSidecarPathInvalid,
    RefusalReason::CandidateSidecarsTooLarge,
    RefusalReason::SidecarHookIdUnsafe,
    RefusalReason::SidecarNameUnsafe,
    RefusalReason::SidecarMediaTypeInvalid,
    RefusalReason::CandidateSidecarReleaseDisabled,
    RefusalReason::CandidateSidecarPrivateUploadForbidden,
    RefusalReason::CandidateSidecarNameDuplicate,
    RefusalReason::CandidateEvidencePolicyMismatch,
    RefusalReason::CandidateSignatureMissing,
    RefusalReason::HookIdUnsafe,
    RefusalReason::HookIdReserved,
    RefusalReason::HookArgvInvalid,
    RefusalReason::HookTimeoutOutOfRange,
    RefusalReason::HookEnvInvalid,
    RefusalReason::HookEnvProtected,
    RefusalReason::HookIdDuplicate,
    RefusalReason::CandidateHookEvidenceMismatch,
    RefusalReason::CandidateSidecarProducerUndeclared,
    RefusalReason::NotifyHookIdInvalid,
    RefusalReason::NotifyHooksMismatch,
    RefusalReason::CandidateDocsPolicyMismatch,
    RefusalReason::CandidateArtifactPathUnexpected,
    RefusalReason::CandidateInventoryMismatch,
    RefusalReason::CandidateFileTooLarge,
    RefusalReason::CandidateChecksumMismatch,
    RefusalReason::CandidateSemanticChecksumMismatch,
    RefusalReason::CandidateIntentDigestMismatch,
    RefusalReason::CandidateDigestMismatch,
];

/// The reason that verification gives a sealed file other than the manifest after `change`.
///
/// A file read past its recorded size is too large, and any other change breaks its size or digest.
fn artifact_refusal(change: ByteChange) -> &'static [RefusalReason] {
    match change {
        ByteChange::Flip(..) | ByteChange::Truncate(_) => {
            &[RefusalReason::CandidateChecksumMismatch]
        }
        ByteChange::Extend(_) => &[RefusalReason::CandidateFileTooLarge],
    }
}

/// The paths of the files a Candidate seals, as its manifest names them.
fn sealed_files(manifest: &CandidateManifest) -> Vec<String> {
    let artifacts = &manifest.artifacts;
    [
        "candidate.json",
        &artifacts.package.path,
        &artifacts.package_interface.path,
    ]
    .into_iter()
    .map(str::to_owned)
    .chain(artifacts.docs.iter().map(|docs| docs.path.clone()))
    .chain(manifest.sidecars.iter().map(|sidecar| sidecar.path.clone()))
    .collect()
}

/// Characters that JSON escapes, characters beyond the Basic Multilingual Plane, and plain letters, without a line break.
const ONE_LINE_CHARACTERS: &[char] = &[
    'a',
    'Z',
    '0',
    ' ',
    '"',
    '\\',
    '/',
    '\u{1}',
    '\u{8}',
    '\t',
    '\u{b}',
    '\u{c}',
    '\u{e}',
    '\u{1b}',
    '\u{1f}',
    '\u{7f}',
    'é',
    '\u{2028}',
    '\u{e000}',
    '\u{10000}',
];

/// Text without NUL, which no sealed text may hold, and with line breaks only where `line_breaks` allows them.
fn text(line_breaks: bool, length: Range<usize>) -> impl Strategy<Value = String> {
    let breaks: &'static [char] = if line_breaks { &['\n', '\r'] } else { &[' '] };
    let character = prop_oneof![
        4 => select(ONE_LINE_CHARACTERS),
        1 => select(breaks),
        1 => any::<char>().prop_filter("NUL, or a line break where none may be", move |character| {
            *character != '\0' && (line_breaks || !matches!(character, '\n' | '\r'))
        }),
    ];
    prop::collection::vec(character, length).prop_map(String::from_iter)
}

/// Semantic versions with and without prerelease identifiers and build metadata.
fn version() -> impl Strategy<Value = Version> {
    let number = || prop_oneof![0..20_u64, any::<u64>()];
    (
        number(),
        number(),
        number(),
        prop::option::of("[a-z]{1,5}(\\.(0|[1-9][0-9]{0,2}))?"),
        prop::option::of("[0-9a-zA-Z]{1,6}(\\.[0-9a-z]{1,3})?"),
    )
        .prop_map(|(major, minor, patch, pre, build)| Version {
            major,
            minor,
            patch,
            pre: pre.map_or(Prerelease::EMPTY, |pre| Prerelease::new(&pre).unwrap()),
            build: build.map_or(BuildMetadata::EMPTY, |build| {
                BuildMetadata::new(&build).unwrap()
            }),
        })
}

/// Registry origins that use HTTPS, or HTTP to a numeric loopback address.
fn registry_url() -> impl Strategy<Value = String> {
    prop_oneof![
        "https://[a-z]{1,8}\\.test(/[a-z]{1,6}){0,2}",
        "http://127\\.0\\.0\\.1:[1-9][0-9]{0,3}(/[a-z]{1,6}){0,2}",
        "http://\\[::1\\](/[a-z]{1,6}){0,2}",
    ]
}

fn registry() -> impl Strategy<Value = RegistryIdentity> {
    (
        any::<bool>(),
        prop::option::of("[A-Za-z0-9][A-Za-z0-9_-]{0,15}"),
        registry_url(),
        registry_url(),
        registry_url(),
        "REGISTRY_[A-Z0-9]{1,6}",
        any::<bool>(),
    )
        .prop_map(
            |(
                compatible,
                repository,
                api_url,
                repository_url,
                docs_url,
                credential_env,
                bearer,
            )| {
                RegistryIdentity {
                    provider: if compatible {
                        RegistryProvider::HexCompatible
                    } else {
                        RegistryProvider::HexPm
                    },
                    repository,
                    api_url,
                    repository_url,
                    docs_url,
                    credential_env,
                    auth: if bearer {
                        AuthKind::Bearer
                    } else {
                        AuthKind::HexToken
                    },
                }
            },
        )
}

fn approval() -> impl Strategy<Value = ApprovalConfig> {
    (
        text(false, 1..12),
        any::<bool>(),
        prop::collection::btree_set("refs/(heads|tags)/[a-z]{1,8}(/[a-z]{1,8})?", 1..3),
        any::<bool>(),
    )
        .prop_map(
            |(environment, strict, manual_refs, fallback)| ApprovalConfig {
                normal: ApprovalMode::ReleasePrAndEnvironment,
                manual: ApprovalMode::Environment,
                environment,
                separation: if strict {
                    SeparationMode::Strict
                } else {
                    SeparationMode::Solo
                },
                manual_refs: manual_refs.into_iter().collect(),
                private_repository_fallback: fallback
                    .then(|| "workflow-dispatch-digest".to_owned()),
            },
        )
}

/// Hex package tarballs that the product builder writes from generated metadata and modules.
fn package_tarball() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::collection::vec(any::<u8>(), 0..32),
        prop::collection::btree_map(
            "[a-z]{1,8}",
            prop::collection::vec(any::<u8>(), 0..48),
            0..4,
        ),
    )
        .prop_map(|(metadata, modules)| {
            let mut files = modules
                .into_iter()
                .map(|(name, source)| (format!("src/{name}.gleam"), source))
                .collect::<BTreeMap<_, _>>();
            files.insert("gleam.toml".into(), b"name = \"widget\"\n".to_vec());
            build_hex_tarball(&metadata, &files, ArchiveLimits::default()).unwrap()
        })
}

fn docs_tarball() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::btree_map(
        "[a-z]{1,8}\\.(html|js|css)",
        prop::collection::vec(any::<u8>(), 0..48),
        1..4,
    )
    .prop_map(|files| {
        tar_gz(
            &files
                .iter()
                .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
                .collect::<Vec<_>>(),
        )
    })
}

/// Package interfaces in compact or indented JSON, so the interface digest has to read past the spelling.
fn package_interface() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::collection::btree_map("[a-z][a-z0-9_/]{0,11}", text(true, 0..8), 0..4),
        any::<bool>(),
    )
        .prop_map(|(modules, indented)| {
            let interface = serde_json::json!({ "modules": modules });
            if indented {
                serde_json::to_vec_pretty(&interface).unwrap()
            } else {
                serde_json::to_vec(&interface).unwrap()
            }
        })
}

/// Verify hooks with the evidence that sealing records for them, and notify hooks, under distinct ids.
fn hooks() -> impl Strategy<Value = (Vec<HookConfig>, Vec<HookEvidence>, Vec<HookConfig>)> {
    let verify = (
        any::<bool>(),
        any::<bool>(),
        1..=3_600_u64,
        text(true, 1..8),
        prop::collection::vec("CI_[A-Z0-9]{1,6}", 0..2),
        "[0-9a-f]{64}",
    );
    (
        prop::collection::vec(verify, 0..3),
        prop::collection::vec((1..=3_600_u64, any::<bool>()), 0..3),
    )
        .prop_map(|(verify, notify)| {
            let mut definitions = Vec::new();
            let mut evidence = Vec::new();
            for (index, (required, succeeded, timeout_seconds, argument, env, output_sha256)) in
                verify.into_iter().enumerate()
            {
                let id = format!("verify-{index}");
                definitions.push(HookConfig {
                    id: id.clone(),
                    argv: vec![format!("./scripts/{id}"), argument],
                    timeout_seconds,
                    required,
                    env,
                });
                evidence.push(HookEvidence {
                    schema: "hook/v1".into(),
                    id,
                    kind: HookKind::Verify,
                    required,
                    success: required || succeeded,
                    output_sha256,
                });
            }
            let notify = notify
                .into_iter()
                .enumerate()
                .map(|(index, (timeout_seconds, required))| HookConfig {
                    id: format!("notify-{index}"),
                    argv: vec![format!("./scripts/notify-{index}")],
                    timeout_seconds,
                    required,
                    env: vec![],
                })
                .collect();
            (definitions, evidence, notify)
        })
}

/// Candidate inputs within the domain that sealing validates, with the built-in evidence that their outputs request.
fn candidate_inputs() -> impl Strategy<Value = CandidateInput> {
    let identity = (
        "[a-z][a-z0-9_]{0,11}",
        version(),
        "([a-z]{1,6}/){0,2}",
        "[0-9a-f]{40}",
        "([a-z]{1,6}/){0,2}gleam\\.toml",
        version(),
    );
    let policy = (
        registry(),
        any::<bool>(),
        "[A-Za-z0-9]{1,12}/[A-Za-z0-9_-][A-Za-z0-9._-]{0,19}",
        "([a-z]{1,8}[/-]){1,2}".prop_filter("a full ref", |prefix| !prefix.starts_with("refs/")),
        text(true, 0..32),
        approval(),
    );
    let outputs = (
        prop::option::of(docs_tarball()),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    );
    let contents = (package_tarball(), package_interface(), hooks());
    (identity, policy, outputs, contents).prop_map(
        |(
            (package, version, tag_prefix, commit_sha, manifest_path, compiler),
            (registry, private, github_repository, release_branch_prefix, release_notes, approval),
            (docs_tarball, github_release, sbom, provenance, allow_private_evidence_upload),
            (
                package_tarball,
                package_interface,
                (verify_hook_definitions, hook_evidence, notify_hook_definitions),
            ),
        )| {
            let mut input = CandidateInput {
                tag: format!("{tag_prefix}v{version}"),
                package,
                version,
                source: CandidateSource {
                    commit_sha,
                    manifest_path,
                },
                compiler,
                registry,
                private,
                github_repository,
                release_branch_prefix,
                release_notes,
                approval,
                outputs: OutputConfig {
                    docs: docs_tarball.is_some(),
                    github_release,
                    sbom,
                    provenance,
                    signature: false,
                    allow_private_evidence_upload,
                },
                package_tarball,
                docs_tarball,
                package_interface,
                notify_hooks: notify_hook_definitions
                    .iter()
                    .map(|hook| hook.id.clone())
                    .collect(),
                verify_hook_definitions,
                sidecar_hook_definitions: vec![],
                hook_evidence,
                sidecars: vec![],
                notify_hook_definitions,
            };
            input.sidecars = Candidate::built_in_evidence(&input).unwrap();
            input
        },
    )
}
