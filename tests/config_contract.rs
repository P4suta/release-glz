use std::collections::BTreeMap;
use std::ops::Range;
use std::path::PathBuf;

use proptest::prelude::*;
use proptest::sample::select;
use release_glz::config::{
    ApiException, ApprovalConfig, ApprovalMode, AuthKind, ChangelogConfig, HookConfig, HooksConfig,
    InitializationSettings, Manifest, MissingReleaseConfig, OutputConfig, RegistryConfig,
    RegistryProvider, ReleaseConfig, RepositoryConfig, SeparationMode, valid_env_name,
    validate_git_ref, validate_hook_config, validate_package_name, validate_relative_path,
};
use release_glz::failure::{FailureClass, RefusalReason, classify, refusal_reason};
use release_glz::model::PrereleaseChannel;
use release_glz_test_support::property;
use semver::{BuildMetadata, Prerelease, Version};
use serde::Serialize;

fn complete_config(extra: &str) -> String {
    format!(
        r#"name = "widget"
version = "0.4.2"

[repository]
type = "github"
user = "acme"
repo = "widget"

[tools.release-glz]
schema = 2
compiler = "1.12.3"
release_branch_prefix = "release-glz/"

[tools.release-glz.registry]
provider = "hexpm"
repository = "acme"
api_url = "https://hex.pm/api"
repository_url = "https://repo.hex.pm/repos/acme"
docs_url = "https://repo.hex.pm/repos/acme/docs"
credential_env = "HEXPM_API_KEY"
auth = "hex-token"

[tools.release-glz.approval]
normal = "release-pr-and-environment"
manual = "environment"
environment = "release"
separation = "strict"
manual_refs = ["refs/heads/main"]

[tools.release-glz.outputs]
docs = true
github_release = true
sbom = true
provenance = true
signature = false
allow_private_evidence_upload = false

[tools.release-glz.changelog]
path = "CHANGELOG.md"
managed_block = true
notes_dir = ".release-glz/notes"

[[tools.release-glz.hooks.verify]]
id = "policy"
argv = ["./scripts/verify-release", "--json"]
timeout_seconds = 45
required = true
env = ["CI"]

{extra}
"#
    )
}

#[test]
fn schema_two_is_fully_typed() {
    let manifest = Manifest::parse(PathBuf::from("gleam.toml"), complete_config("")).unwrap();
    let release = manifest.release().unwrap();
    assert_eq!(release.compiler.to_string(), "1.12.3");
    assert_eq!(release.registry.provider, RegistryProvider::HexPm);
    assert_eq!(release.registry.repository.as_deref(), Some("acme"));
    assert_eq!(release.registry.auth, AuthKind::HexToken);
    assert_eq!(
        release.approval.normal,
        ApprovalMode::ReleasePrAndEnvironment
    );
    assert_eq!(release.approval.manual, ApprovalMode::Environment);
    assert_eq!(release.approval.separation, SeparationMode::Strict);
    assert_eq!(release.approval.manual_refs, ["refs/heads/main"]);
    assert!(release.outputs.sbom);
    assert_eq!(release.hooks.verify[0].argv[0], "./scripts/verify-release");
    assert_eq!(
        release.changelog.notes_dir,
        PathBuf::from(".release-glz/notes")
    );
}

#[test]
fn a_manifest_without_a_release_table_names_init_and_is_a_usage_failure() {
    let manifest = Manifest::parse(
        PathBuf::from("gleam.toml"),
        "name = \"widget\"\nversion = \"1.0.0\"\n\n[tools.other]\nenabled = true\n".into(),
    )
    .unwrap();
    let refusal = manifest.release().unwrap_err();
    assert_eq!(refusal, MissingReleaseConfig);
    assert_eq!(
        refusal.to_string(),
        "the manifest has no `[tools.release-glz]` configuration; run `release-glz init` to write it"
    );
    let refusal = anyhow::Error::new(refusal);
    assert_eq!(classify(&refusal), FailureClass::UsageOrConfig);
    assert_eq!(refusal_reason(&refusal), Some(RefusalReason::ConfigMissing));
}

#[test]
fn a_manifest_named_without_a_directory_lives_in_the_current_directory() {
    for (path, directory) in [
        ("gleam.toml", "."),
        ("./gleam.toml", "."),
        ("packages/widget/gleam.toml", "packages/widget"),
    ] {
        let manifest = Manifest::parse(PathBuf::from(path), complete_config("")).unwrap();
        assert_eq!(
            manifest.package_dir(),
            std::path::Path::new(directory),
            "{path}"
        );
    }
}

/// The reason that `Manifest::parse` refuses `source` with, which panics when it accepts the source.
fn refusal(source: String) -> Option<RefusalReason> {
    refusal_reason(&Manifest::parse(PathBuf::from("gleam.toml"), source).unwrap_err())
}

#[test]
fn schema_two_rejects_unknown_keys_and_wrong_types() {
    let unknown = complete_config("[tools.release-glz.typo]\nenabled = true");
    let error = Manifest::parse(PathBuf::from("gleam.toml"), unknown).unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::ConfigTableInvalid)
    );
    assert!(
        error.to_string().contains("unknown field `typo`"),
        "{error}"
    );

    let wrong_type =
        complete_config("").replace("timeout_seconds = 45", "timeout_seconds = \"45\"");
    assert_eq!(refusal(wrong_type), Some(RefusalReason::ConfigTableInvalid));
}

#[test]
fn release_configuration_refuses_every_schema_but_two() {
    for (schema, found) in [
        ("schema = 1\n", "`schema = 1`"),
        ("schema = 0\n", "`schema = 0`"),
        ("schema = 3\n", "`schema = 3`"),
        ("schema = \"2\"\n", "`schema = \"2\"`"),
        ("schema = true\n", "`schema = true`"),
        ("", "no `schema`"),
    ] {
        let source = complete_config("").replace("schema = 2\n", schema);
        let error = Manifest::parse(PathBuf::from("gleam.toml"), source).unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::ConfigSchemaUnsupported)
        );
        assert_eq!(
            error.to_string(),
            format!("`[tools.release-glz]` requires `schema = 2`, but it sets {found}")
        );
    }
}

#[test]
fn a_release_table_with_only_top_level_keys_still_needs_schema_two() {
    for (table, found) in [
        ("changelog_path = \"NEWS.md\"\nschema = 1\n", "`schema = 1`"),
        ("prerelease = \"beta\"\n", "no `schema`"),
        (
            "[tools.release-glz.baseline_refs]\n\"1.0.0\" = \"refs/tags/v1.0.0\"\n",
            "no `schema`",
        ),
    ] {
        let source = if table.starts_with('[') {
            format!("name = \"widget\"\nversion = \"1.0.0\"\n\n{table}")
        } else {
            format!("name = \"widget\"\nversion = \"1.0.0\"\n\n[tools.release-glz]\n{table}")
        };
        let error = Manifest::parse(PathBuf::from("gleam.toml"), source).unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::ConfigSchemaUnsupported)
        );
        assert_eq!(
            error.to_string(),
            format!("`[tools.release-glz]` requires `schema = 2`, but it sets {found}")
        );
    }
    let inline = "name = \"widget\"\nversion = \"1.0.0\"\ntools = { release-glz = { prerelease = \"rc\" } }\n";
    assert_eq!(
        refusal(inline.into()),
        Some(RefusalReason::ConfigSchemaUnsupported)
    );
}

#[test]
fn schema_two_refuses_the_keys_that_its_tables_replace() {
    for (key, value) in [
        ("changelog_path", "\"NEWS.md\""),
        ("allow_unknown_api_for", "[\"1.0.0\"]"),
    ] {
        let source = complete_config("").replace(
            "release_branch_prefix = \"release-glz/\"",
            &format!("release_branch_prefix = \"release-glz/\"\n{key} = {value}"),
        );
        let error = Manifest::parse(PathBuf::from("gleam.toml"), source).unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::ConfigTableInvalid),
            "{key}"
        );
        assert!(
            error
                .to_string()
                .contains(&format!("unknown field `{key}`")),
            "{error}"
        );
    }
}

#[test]
fn the_registry_has_no_key_that_loosens_its_transport() {
    for value in ["true", "false"] {
        let source = complete_config("").replace(
            "auth = \"hex-token\"",
            &format!("auth = \"hex-token\"\nallow_http_loopback = {value}"),
        );
        let error = Manifest::parse(PathBuf::from("gleam.toml"), source).unwrap_err();
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::ConfigTableInvalid)
        );
        assert!(
            error
                .to_string()
                .contains("unknown field `allow_http_loopback`"),
            "{error}"
        );
    }
}

#[test]
fn schema_two_refuses_malformed_channels_and_baseline_refs() {
    let valid =
        complete_config("[tools.release-glz.baseline_refs]\n\"1.0.0\" = \"refs/tags/v1.0.0\"")
            .replace(
                "release_branch_prefix = \"release-glz/\"",
                "release_branch_prefix = \"releases/\"\nprerelease = \"beta\"",
            );
    Manifest::parse(PathBuf::from("gleam.toml"), valid.clone()).unwrap();
    for (invalid, reason) in [
        (
            valid.replace(
                "\"1.0.0\" = \"refs/tags/v1.0.0\"",
                "\"bad\" = \"refs/tags/v1\"",
            ),
            RefusalReason::ConfigTableInvalid,
        ),
        (
            valid.replace("\"refs/tags/v1.0.0\"", "1"),
            RefusalReason::ConfigTableInvalid,
        ),
        (
            valid.replace("\"refs/tags/v1.0.0\"", "\"refs/tags/../bad\""),
            RefusalReason::GitRefUnsafe,
        ),
        (
            valid.replace("prerelease = \"beta\"", "prerelease = \"preview\""),
            RefusalReason::ConfigTableInvalid,
        ),
    ] {
        assert_eq!(refusal(invalid.clone()), Some(reason), "{invalid}");
    }
}

#[test]
fn schema_two_does_not_silently_enable_zero_major_versions() {
    let omitted = Manifest::parse(PathBuf::from("gleam.toml"), complete_config("")).unwrap();
    assert!(!omitted.release().unwrap().allow_version_zero);
    let explicit = complete_config("").replace(
        "release_branch_prefix = \"release-glz/\"",
        "release_branch_prefix = \"release-glz/\"\nallow_version_zero = true",
    );
    assert!(
        Manifest::parse(PathBuf::from("gleam.toml"), explicit)
            .unwrap()
            .release()
            .unwrap()
            .allow_version_zero
    );
}

#[test]
fn paths_refs_and_hook_ids_are_safe() {
    for (from, to, reason) in [
        (
            "path = \"CHANGELOG.md\"",
            "path = \"../CHANGELOG.md\"",
            RefusalReason::PathOutsideRepository,
        ),
        (
            "notes_dir = \".release-glz/notes\"",
            "notes_dir = \"/tmp/notes\"",
            RefusalReason::PathOutsideRepository,
        ),
        (
            "release_branch_prefix = \"release-glz/\"",
            "release_branch_prefix = \"refs/heads/main\"",
            RefusalReason::GitRefPrefixUnsafe,
        ),
        (
            "id = \"policy\"",
            "id = \"policy/../../x\"",
            RefusalReason::HookIdUnsafe,
        ),
    ] {
        let source = complete_config("").replace(from, to);
        assert_eq!(refusal(source), Some(reason), "{to}");
    }
}

#[test]
fn no_hook_may_take_the_id_of_release_glz_evidence() {
    for phase in ["verify", "sidecar", "notify"] {
        let source = complete_config(&format!(
            "[[tools.release-glz.hooks.{phase}]]\nid = \"release-glz\"\nargv = [\"./scripts/hook\"]\ntimeout_seconds = 30\nrequired = true\n"
        ));
        let Err(error) = Manifest::parse(PathBuf::from("gleam.toml"), source) else {
            panic!("a {phase} hook named release-glz was accepted");
        };
        assert_eq!(
            refusal_reason(&error),
            Some(RefusalReason::HookIdReserved),
            "{phase}"
        );
        let error = format!("{error:#}");
        assert!(
            error.contains("hook id `release-glz` is reserved"),
            "{phase}: {error}"
        );
    }
}

#[test]
fn registry_requires_https_or_http_to_a_numeric_loopback_address() {
    for host in ["127.0.0.1", "127.8.9.10", "[::1]"] {
        let base = format!("http://{host}:8080");
        let loopback = complete_config("")
            .replace("https://hex.pm/api", &format!("{base}/api"))
            .replace(
                "https://repo.hex.pm/repos/acme",
                &format!("{base}/repos/acme"),
            );
        Manifest::parse(PathBuf::from("gleam.toml"), loopback).unwrap();
    }

    for (unsafe_url, reason) in [
        ("http://hex.pm/api", RefusalReason::UrlTransportUntrusted),
        (
            "http://localhost:8080/api",
            RefusalReason::UrlTransportUntrusted,
        ),
        ("http://192.0.2.1/api", RefusalReason::UrlTransportUntrusted),
        (
            "http://[::ffff:127.0.0.1]/api",
            RefusalReason::UrlTransportUntrusted,
        ),
        (
            "http://127.0.0.1.example.test/api",
            RefusalReason::UrlTransportUntrusted,
        ),
        (
            "https://hex.pm/api?redirect=https://evil.test",
            RefusalReason::UrlQueryOrFragment,
        ),
        (
            "https://hex.pm/api#fragment",
            RefusalReason::UrlQueryOrFragment,
        ),
        (
            "https://user:password@hex.pm/api",
            RefusalReason::UrlCredentials,
        ),
        (
            "http://user:password@127.0.0.1:8080/api",
            RefusalReason::UrlCredentials,
        ),
        ("ftp://hex.pm/api", RefusalReason::UrlTransportUntrusted),
        ("https;//hex.pm/api", RefusalReason::UrlMalformed),
        ("https://h%x.pm/api", RefusalReason::UrlMalformed),
    ] {
        let source = complete_config("").replace("https://hex.pm/api", unsafe_url);
        assert_eq!(refusal(source), Some(reason), "{unsafe_url}");
    }
}

#[test]
fn hex_organization_repository_is_a_safe_single_path_segment() {
    for invalid in ["", "../other", "acme/widgets", ".hidden", "acme org"] {
        let source = complete_config("").replace(
            "repository = \"acme\"",
            &format!("repository = \"{invalid}\""),
        );
        assert_eq!(
            refusal(source),
            Some(RefusalReason::RegistryRepositoryInvalid),
            "{invalid:?}"
        );
    }

    for valid in ["acme", "acme-labs", "acme_2"] {
        let source = complete_config("").replace(
            "repository = \"acme\"",
            &format!("repository = \"{valid}\""),
        );
        assert!(
            Manifest::parse(PathBuf::from("gleam.toml"), source).is_ok(),
            "rejected safe Hex organization {valid:?}"
        );
    }
}

#[test]
fn credential_configuration_names_an_environment_variable_not_a_secret() {
    for invalid in [
        "actual-token",
        "HEX TOKEN",
        "123_TOKEN",
        "GITHUB_TOKEN=secret",
    ] {
        let source = complete_config("").replace("HEXPM_API_KEY", invalid);
        assert_eq!(
            refusal(source),
            Some(RefusalReason::CredentialEnvInvalid),
            "{invalid}"
        );
    }

    let custom_credential = complete_config("")
        .replace(
            "credential_env = \"HEXPM_API_KEY\"",
            "credential_env = \"PRIVATE_REGISTRY_TOKEN\"",
        )
        .replace("env = [\"CI\"]", "env = [\"PRIVATE_REGISTRY_TOKEN\"]");
    assert_eq!(
        refusal(custom_credential),
        Some(RefusalReason::HookEnvProtected),
        "hooks must not receive the configured publication credential"
    );
}

#[test]
fn package_environment_hook_path_and_ref_lexers_cover_every_boundary() {
    for valid in ["widget", "widget_2", "a0"] {
        validate_package_name(valid).unwrap();
    }
    for invalid in [
        "",
        "Widget",
        "2widget",
        "_widget",
        "widget-name",
        "widget/name",
    ] {
        assert_eq!(
            refusal_reason(&validate_package_name(invalid).unwrap_err()),
            Some(RefusalReason::PackageNameInvalid),
            "{invalid:?}"
        );
    }

    for valid in ["A", "_A", "HEXPM_API_KEY", "A0"] {
        assert!(valid_env_name(valid), "rejected {valid:?}");
    }
    for invalid in ["", "0A", "lower", "A-B", "A B", "A=B", "Å"] {
        assert!(!valid_env_name(invalid), "accepted {invalid:?}");
    }

    for id in ["a", "Policy", "a0", "a_b-c.d"] {
        validate_hook_config(&HookConfig {
            id: id.into(),
            argv: vec!["program".into()],
            timeout_seconds: 1,
            required: true,
            env: vec!["CI".into()],
        })
        .unwrap();
    }
    for id in ["", "0a", "_a", "-a", ".a", "a/b", "a b", "å"] {
        let hook = HookConfig {
            id: id.into(),
            argv: vec!["program".into()],
            timeout_seconds: 3_600,
            required: true,
            env: vec![],
        };
        assert_eq!(
            refusal_reason(&validate_hook_config(&hook).unwrap_err()),
            Some(RefusalReason::HookIdUnsafe),
            "{id:?}"
        );
    }
    for (argv, timeout, env, reason) in [
        (vec![], 30, vec![], RefusalReason::HookArgvInvalid),
        (
            vec![String::new()],
            30,
            vec![],
            RefusalReason::HookArgvInvalid,
        ),
        (
            vec!["bad\0arg".into()],
            30,
            vec![],
            RefusalReason::HookArgvInvalid,
        ),
        (
            vec!["program".into()],
            0,
            vec![],
            RefusalReason::HookTimeoutOutOfRange,
        ),
        (
            vec!["program".into()],
            3_601,
            vec![],
            RefusalReason::HookTimeoutOutOfRange,
        ),
        (
            vec!["program".into()],
            30,
            vec!["bad-name".into()],
            RefusalReason::HookEnvInvalid,
        ),
    ] {
        let hook = HookConfig {
            id: "policy".into(),
            argv,
            timeout_seconds: timeout,
            required: false,
            env,
        };
        assert_eq!(
            refusal_reason(&validate_hook_config(&hook).unwrap_err()),
            Some(reason),
            "{hook:?}"
        );
    }
    for protected in [
        "HEXPM_API_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_RUNTIME_TOKEN",
        "GITHUB_ENV",
        "GITHUB_OUTPUT",
        "GITHUB_PATH",
        "GITHUB_STATE",
        "GITHUB_STEP_SUMMARY",
    ] {
        let hook = HookConfig {
            id: "protected".into(),
            argv: vec!["program".into()],
            timeout_seconds: 30,
            required: true,
            env: vec![protected.into()],
        };
        assert_eq!(
            refusal_reason(&validate_hook_config(&hook).unwrap_err()),
            Some(RefusalReason::HookEnvProtected),
            "hook accepted protected environment {protected}"
        );
    }

    for valid in ["CHANGELOG.md", ".release-glz/notes", "a/b"] {
        validate_relative_path(std::path::Path::new(valid), "test").unwrap();
    }
    for (invalid, reason) in [
        ("", RefusalReason::PathNotRelative),
        ("/tmp/x", RefusalReason::PathOutsideRepository),
        ("../x", RefusalReason::PathOutsideRepository),
        (".", RefusalReason::PathOutsideRepository),
        ("a/../b", RefusalReason::PathOutsideRepository),
        ("a\\b", RefusalReason::PathNotRelative),
    ] {
        assert_eq!(
            refusal_reason(
                &validate_relative_path(std::path::Path::new(invalid), "test").unwrap_err()
            ),
            Some(reason),
            "{invalid:?}"
        );
    }

    for valid in ["refs/heads/main", "refs/tags/v1.2.3", "abc123"] {
        validate_git_ref(valid, "test").unwrap();
    }
    for invalid in [
        "",
        "/x",
        "-x",
        ".x",
        "x/",
        "x.",
        "x..y",
        "x//y",
        "x@{y",
        "x\\y",
        "x~y",
        "x^y",
        "x:y",
        "x?y",
        "x*y",
        "x[y",
        "x y",
        "x\ny",
        "x\ry",
        "x\0y",
        "@",
        "refs/heads/main.lock",
        "refs/heads/.hidden",
        "refs/heads/x\ty",
        "refs/heads/x\u{1f}y",
        "refs/heads/x\u{7f}y",
    ] {
        assert_eq!(
            refusal_reason(&validate_git_ref(invalid, "test").unwrap_err()),
            Some(RefusalReason::GitRefUnsafe),
            "{invalid:?}"
        );
    }
}

#[test]
fn approval_and_registry_variants_are_strict_but_cover_supported_forms() {
    for (from, to, reason) in [
        (
            "environment = \"release\"",
            "environment = \"\"",
            RefusalReason::ApprovalEnvironmentInvalid,
        ),
        (
            "environment = \"release\"",
            "environment = \"release\\nproduction\"",
            RefusalReason::ApprovalEnvironmentInvalid,
        ),
        (
            "manual_refs = [\"refs/heads/main\"]",
            "manual_refs = [\"refs/heads/main\", \"refs/heads/main\"]",
            RefusalReason::ManualRefDuplicate,
        ),
        (
            "manual_refs = [\"refs/heads/main\"]",
            "manual_refs = [\"refs/notes/release\"]",
            RefusalReason::ManualRefKindUnsupported,
        ),
    ] {
        assert_eq!(
            refusal(complete_config("").replace(from, to)),
            Some(reason),
            "{to}"
        );
    }

    let fallback = complete_config("").replace(
        "manual_refs = [\"refs/heads/main\"]",
        "manual_refs = [\"refs/tags/v1.2.3\"]\nprivate_repository_fallback = \"workflow-dispatch-digest\"",
    );
    Manifest::parse(PathBuf::from("gleam.toml"), fallback).unwrap();
    let bad_fallback = complete_config("").replace(
        "manual_refs = [\"refs/heads/main\"]",
        "manual_refs = [\"refs/heads/main\"]\nprivate_repository_fallback = \"weaken-gate\"",
    );
    assert_eq!(
        refusal(bad_fallback),
        Some(RefusalReason::ApprovalFallbackUnsupported)
    );

    let custom = complete_config("")
        .replace("provider = \"hexpm\"", "provider = \"hex-compatible\"")
        .replace("repository = \"acme\"\napi_url", "api_url")
        .replace("auth = \"hex-token\"", "auth = \"bearer\"");
    let parsed = Manifest::parse(PathBuf::from("gleam.toml"), custom).unwrap();
    assert_eq!(
        parsed.release().unwrap().registry.provider,
        RegistryProvider::HexCompatible
    );
    assert_eq!(parsed.release().unwrap().registry.auth, AuthKind::Bearer);

    let custom_with_repository =
        complete_config("").replace("provider = \"hexpm\"", "provider = \"hex-compatible\"");
    let custom_with_repository =
        Manifest::parse(PathBuf::from("gleam.toml"), custom_with_repository).unwrap();
    assert_eq!(
        custom_with_repository
            .release()
            .unwrap()
            .registry
            .repository
            .as_deref(),
        Some("acme")
    );

    let non_hierarchical = complete_config("").replace("https://hex.pm/api", "file:///api");
    assert_eq!(
        refusal(non_hierarchical),
        Some(RefusalReason::UrlNotHierarchical)
    );
}

#[test]
fn approval_paths_have_fixed_non_substitutable_modes() {
    let wrong_normal = complete_config("").replace(
        "normal = \"release-pr-and-environment\"",
        "normal = \"environment\"",
    );
    assert_eq!(
        refusal(wrong_normal),
        Some(RefusalReason::ApprovalModeFixed)
    );

    let wrong_manual = complete_config("").replace(
        "manual = \"environment\"",
        "manual = \"release-pr-and-environment\"",
    );
    assert_eq!(
        refusal(wrong_manual),
        Some(RefusalReason::ApprovalModeFixed)
    );
}

#[test]
fn manual_release_policy_requires_explicit_safe_full_refs() {
    let missing = complete_config("").replace("manual_refs = [\"refs/heads/main\"]\n", "");
    let error = Manifest::parse(PathBuf::from("gleam.toml"), missing).unwrap_err();
    assert_eq!(
        refusal_reason(&error),
        Some(RefusalReason::ConfigTableInvalid)
    );
    assert!(
        error.to_string().contains("missing field `manual_refs`"),
        "{error}"
    );

    for (unsafe_ref, reason) in [
        ("main", RefusalReason::ManualRefKindUnsupported),
        ("refs/heads/../main", RefusalReason::GitRefUnsafe),
        ("refs/pull/1/head", RefusalReason::ManualRefKindUnsupported),
        ("refs/heads/*", RefusalReason::GitRefUnsafe),
    ] {
        let source = complete_config("").replace("refs/heads/main", unsafe_ref);
        assert_eq!(refusal(source), Some(reason), "{unsafe_ref}");
    }
}

#[test]
fn structured_api_exceptions_require_one_version_baseline_reason_and_date() {
    let exception = r#"
[[tools.release-glz.api_exceptions]]
version = "1.2.3"
baseline = "refs/tags/v1.2.3"
reason = "The historical compiler is unavailable"
expires = "2999-12-31"
"#;
    let parsed = Manifest::parse(PathBuf::from("gleam.toml"), complete_config(exception)).unwrap();
    let exceptions = &parsed.release().unwrap().api_exceptions;
    assert_eq!(exceptions.len(), 1);
    assert_eq!(exceptions[0].version, "1.2.3".parse().unwrap());

    for (name, reason, expected, invalid) in [
        (
            "empty reason",
            RefusalReason::ApiExceptionReasonMissing,
            "requires a reason",
            exception.replace(
                "reason = \"The historical compiler is unavailable\"",
                "reason = \"  \"",
            ),
        ),
        (
            "unsafe baseline",
            RefusalReason::GitRefUnsafe,
            "api_exceptions.baseline contains an unsafe git ref",
            exception.replace(
                "baseline = \"refs/tags/v1.2.3\"",
                "baseline = \"refs/tags/../secret\"",
            ),
        ),
        (
            "invalid expiry",
            RefusalReason::ApiExceptionExpiryInvalid,
            "must use YYYY-MM-DD",
            exception.replace("expires = \"2999-12-31\"", "expires = \"tomorrow\""),
        ),
        (
            "duplicate version",
            RefusalReason::ApiExceptionDuplicate,
            "duplicate API exception",
            format!("{exception}{exception}"),
        ),
    ] {
        let error =
            Manifest::parse(PathBuf::from("gleam.toml"), complete_config(&invalid)).unwrap_err();
        assert_eq!(refusal_reason(&error), Some(reason), "{name}");
        assert!(error.to_string().contains(expected), "{name}: {error}");
    }
}

proptest! {
    #![proptest_config(property::config(128))]

    /// A manifest parses to the configuration it states and renders back to its own bytes, and an edit renders a manifest that parses back to the edit with everything else kept.
    #[test]
    fn generated_manifests_render_and_parse_back_to_their_configuration(
        manifest in generated_manifests(),
        next in version(),
        channel in prop::option::of(channel()),
    ) {
        let path = PathBuf::from("gleam.toml");
        let parsed = Manifest::parse(path.clone(), manifest.source.clone()).unwrap();
        prop_assert_eq!(statement(&parsed), manifest.statement());
        prop_assert_eq!(parsed.render(), manifest.source.as_str());

        let bumped = Manifest::parse(path.clone(), parsed.render_with_version(&next)).unwrap();
        let (package, _, repository, release) = manifest.statement();
        prop_assert_eq!(statement(&bumped), (package, next, repository, release));

        let mut selected = parsed;
        selected.set_prerelease(channel).unwrap();
        let reselected = Manifest::parse(path, selected.render()).unwrap();
        let (package, version, repository, release) = manifest.statement();
        let release = ReleaseConfig {
            prerelease: channel,
            ..release
        };
        prop_assert_eq!(statement(&reselected), (package, version, repository, release));
    }

    /// The configuration that `init` renders for an unconfigured package parses back to the settings it was rendered from.
    #[test]
    fn initialized_configurations_parse_back_to_their_settings(
        package in package_name(),
        version in version(),
        repository in repository(),
        settings in initialization_settings(),
        layout in layout(),
    ) {
        let path = PathBuf::from("gleam.toml");
        let source = manifest_source(&package, &version, &repository, None, layout);
        let unconfigured = Manifest::parse(path.clone(), source.clone()).unwrap();
        let settings = InitializationSettings {
            allow_version_zero: settings.allow_version_zero || version.major == 0,
            ..settings
        };
        let rendered = unconfigured.render_initialized(&settings).unwrap();
        prop_assert!(rendered.starts_with(source.trim_end()));
        let initialized = Manifest::parse(path, rendered).unwrap();
        let expected = ReleaseConfig {
            compiler: settings.compiler.clone(),
            registry: settings.registry.clone(),
            approval: ApprovalConfig {
                manual_refs: vec![format!("refs/heads/{}", settings.default_branch)],
                ..ApprovalConfig::default()
            },
            outputs: OutputConfig::default(),
            hooks: HooksConfig::default(),
            changelog: ChangelogConfig::default(),
            api_exceptions: vec![],
            release_branch_prefix: "release-glz/".into(),
            allow_version_zero: settings.allow_version_zero,
            prerelease: None,
            baseline_refs: BTreeMap::new(),
        };
        prop_assert_eq!(statement(&initialized), (package, version, repository, expected));
    }
}

/// What a configured manifest states: its package, version, repository, and release configuration.
type Statement = (String, Version, RepositoryConfig, ReleaseConfig);

fn statement(manifest: &Manifest) -> Statement {
    (
        manifest.package.clone(),
        manifest.version.clone(),
        manifest.repository.clone(),
        manifest.release().unwrap().clone(),
    )
}

/// A generated manifest, the configuration it states, and its bytes.
#[derive(Debug, Clone)]
struct GeneratedManifest {
    package: String,
    version: Version,
    repository: RepositoryConfig,
    release: ReleaseConfig,
    source: String,
}

impl GeneratedManifest {
    fn statement(&self) -> Statement {
        (
            self.package.clone(),
            self.version.clone(),
            self.repository.clone(),
            self.release.clone(),
        )
    }
}

/// The layout of `gleam.toml` that the generated manifests take, which `toml_edit` writes.
#[derive(Serialize)]
struct ManifestToml<'a> {
    name: &'a str,
    version: String,
    repository: RepositoryToml<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<ToolsToml<'a>>,
}

#[derive(Serialize)]
struct RepositoryToml<'a> {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    kind: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repo: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "str::is_empty")]
    tag_prefix: &'a str,
}

#[derive(Serialize)]
struct ToolsToml<'a> {
    #[serde(rename = "release-glz")]
    release_glz: ReleaseTableToml<'a>,
}

#[derive(Serialize)]
struct ReleaseTableToml<'a> {
    schema: i64,
    compiler: String,
    release_branch_prefix: &'a str,
    allow_version_zero: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    prerelease: Option<PrereleaseChannel>,
    registry: &'a RegistryConfig,
    approval: &'a ApprovalConfig,
    outputs: &'a OutputConfig,
    hooks: HooksToml<'a>,
    changelog: ChangelogToml<'a>,
    api_exceptions: Vec<ApiExceptionToml<'a>>,
    baseline_refs: BTreeMap<String, &'a str>,
}

#[derive(Serialize)]
struct HooksToml<'a> {
    verify: &'a [HookConfig],
    sidecar: &'a [HookConfig],
    notify: &'a [HookConfig],
}

#[derive(Serialize)]
struct ChangelogToml<'a> {
    path: &'a str,
    managed_block: bool,
    notes_dir: &'a str,
}

#[derive(Serialize)]
struct ApiExceptionToml<'a> {
    version: String,
    baseline: &'a str,
    reason: &'a str,
    expires: &'a str,
}

/// How `toml_edit` lays out a generated manifest.
#[derive(Debug, Clone, Copy)]
enum Layout {
    /// Every table inline, on the line of its key.
    Inline,
    /// A header for each table and each array of tables, the way `init` writes a configuration.
    Headers,
}

fn layout() -> impl Strategy<Value = Layout> {
    prop_oneof![Just(Layout::Inline), Just(Layout::Headers)]
}

/// The bytes of a manifest that names `package` at `version` in `repository`, configured when `release` is present.
fn manifest_source(
    package: &str,
    version: &Version,
    repository: &RepositoryConfig,
    release: Option<&ReleaseConfig>,
    layout: Layout,
) -> String {
    let tools = release.map(|release| ToolsToml {
        release_glz: ReleaseTableToml {
            schema: 2,
            compiler: release.compiler.to_string(),
            release_branch_prefix: &release.release_branch_prefix,
            allow_version_zero: release.allow_version_zero,
            prerelease: release.prerelease,
            registry: &release.registry,
            approval: &release.approval,
            outputs: &release.outputs,
            hooks: HooksToml {
                verify: &release.hooks.verify,
                sidecar: &release.hooks.sidecar,
                notify: &release.hooks.notify,
            },
            changelog: ChangelogToml {
                path: release.changelog.path.to_str().unwrap(),
                managed_block: release.changelog.managed_block,
                notes_dir: release.changelog.notes_dir.to_str().unwrap(),
            },
            api_exceptions: release
                .api_exceptions
                .iter()
                .map(|exception| ApiExceptionToml {
                    version: exception.version.to_string(),
                    baseline: &exception.baseline,
                    reason: &exception.reason,
                    expires: &exception.expires,
                })
                .collect(),
            baseline_refs: release
                .baseline_refs
                .iter()
                .map(|(version, git_ref)| (version.to_string(), git_ref.as_str()))
                .collect(),
        },
    });
    let manifest = ManifestToml {
        name: package,
        version: version.to_string(),
        repository: RepositoryToml {
            kind: repository.kind.as_deref(),
            user: repository.user.as_deref(),
            repo: repository.repo.as_deref(),
            path: repository.path.as_deref(),
            tag_prefix: &repository.tag_prefix,
        },
        tools,
    };
    match layout {
        Layout::Inline => toml_edit::ser::to_string(&manifest),
        Layout::Headers => toml_edit::ser::to_string_pretty(&manifest),
    }
    .unwrap()
}

/// Characters that TOML escapes or quotes, characters beyond the Basic Multilingual Plane, and plain letters, without a line break.
const ONE_LINE_CHARACTERS: &[char] = &[
    'a',
    'Z',
    '0',
    ' ',
    '"',
    '\'',
    '\\',
    '#',
    '=',
    '[',
    '.',
    '\u{1}',
    '\t',
    '\u{1f}',
    '\u{7f}',
    'é',
    '\u{2028}',
    '\u{feff}',
    '\u{10000}',
];

/// Text without NUL, which no configured text may hold, and with line breaks only where `line_breaks` allows them.
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

fn channel() -> impl Strategy<Value = PrereleaseChannel> {
    select(
        &[
            PrereleaseChannel::Alpha,
            PrereleaseChannel::Beta,
            PrereleaseChannel::Rc,
        ][..],
    )
}

fn package_name() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9_]{0,11}"
}

/// Repository-relative `/` paths whose segments neither start with a dot nor name a drive.
fn relative_path() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_-][A-Za-z0-9_.-]{0,7}(/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,7}){0,2}"
}

/// Ref prefixes that leave a safe ref once a name follows them.
fn ref_prefix() -> impl Strategy<Value = String> {
    "([a-z]{1,8}[/-]){1,2}".prop_filter("a full ref", |prefix| !prefix.starts_with("refs/"))
}

/// Git refs that the manifest accepts as a baseline.
fn git_ref() -> impl Strategy<Value = String> {
    "(refs/tags/)?([a-z]{1,6}/)?v(0|[1-9][0-9]?)\\.(0|[1-9][0-9]?)\\.(0|[1-9][0-9]?)"
}

/// The `[repository]` table, whose forge fields `gleam.toml` doesn't constrain.
fn repository() -> impl Strategy<Value = RepositoryConfig> {
    (
        prop::option::of(prop_oneof![Just("github".to_owned()), text(true, 0..8)]),
        prop::option::of(text(true, 0..8)),
        prop::option::of(text(true, 0..8)),
        prop::option::of(relative_path()),
        prop_oneof![Just(String::new()), ref_prefix()],
    )
        .prop_map(|(kind, user, repo, path, tag_prefix)| RepositoryConfig {
            kind,
            user,
            repo,
            path,
            tag_prefix,
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

fn registry() -> impl Strategy<Value = RegistryConfig> {
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
                RegistryConfig {
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

fn outputs() -> impl Strategy<Value = OutputConfig> {
    prop::array::uniform6(any::<bool>()).prop_map(
        |[
            docs,
            github_release,
            sbom,
            provenance,
            signature,
            allow_private_evidence_upload,
        ]| {
            OutputConfig {
                docs,
                github_release,
                sbom,
                provenance,
                signature,
                allow_private_evidence_upload,
            }
        },
    )
}

/// The hooks of one phase, under ids that name the phase so that no two phases share one.
fn phase_hooks(phase: &'static str) -> impl Strategy<Value = Vec<HookConfig>> {
    let hook = (
        "[A-Za-z0-9_.-]{0,4}",
        prop::collection::vec(text(true, 1..8), 1..3),
        1..=3_600_u64,
        any::<bool>(),
        prop::collection::vec("CI_[A-Z0-9]{1,6}", 0..2),
    );
    prop::collection::vec(hook, 0..3).prop_map(move |hooks| {
        hooks
            .into_iter()
            .enumerate()
            .map(
                |(index, (suffix, argv, timeout_seconds, required, env))| HookConfig {
                    id: format!("{phase}-{index}{suffix}"),
                    argv,
                    timeout_seconds,
                    required,
                    env,
                },
            )
            .collect()
    })
}

fn api_exceptions() -> impl Strategy<Value = Vec<ApiException>> {
    let exception = (
        git_ref(),
        "[A-Za-z]",
        text(true, 0..12),
        1_000..=9_999_u32,
        1..=12_u32,
        1..=28_u32,
    );
    prop::collection::btree_map(version(), exception, 0..3).prop_map(|exceptions| {
        exceptions
            .into_iter()
            .map(
                |(version, (baseline, first, rest, year, month, day))| ApiException {
                    version,
                    baseline,
                    reason: format!("{first}{rest}"),
                    expires: format!("{year:04}-{month:02}-{day:02}"),
                },
            )
            .collect()
    })
}

/// Release configurations within the domain that the manifest validates.
fn release_config() -> impl Strategy<Value = ReleaseConfig> {
    let policy = (version(), registry(), approval(), outputs());
    let hooks = (
        phase_hooks("verify"),
        phase_hooks("sidecar"),
        phase_hooks("notify"),
    );
    let changelog = (relative_path(), any::<bool>(), relative_path());
    let releases = (
        api_exceptions(),
        ref_prefix(),
        any::<bool>(),
        prop::option::of(channel()),
        prop::collection::btree_map(version(), git_ref(), 0..3),
    );
    (policy, hooks, changelog, releases).prop_map(
        |(
            (compiler, registry, approval, outputs),
            (verify, sidecar, notify),
            (path, managed_block, notes_dir),
            (api_exceptions, release_branch_prefix, allow_version_zero, prerelease, baseline_refs),
        )| ReleaseConfig {
            compiler,
            registry,
            approval,
            outputs,
            hooks: HooksConfig {
                verify,
                sidecar,
                notify,
            },
            changelog: ChangelogConfig {
                path: PathBuf::from(path),
                managed_block,
                notes_dir: PathBuf::from(notes_dir),
            },
            api_exceptions,
            release_branch_prefix,
            allow_version_zero,
            prerelease,
            baseline_refs,
        },
    )
}

fn generated_manifests() -> impl Strategy<Value = GeneratedManifest> {
    (
        package_name(),
        version(),
        repository(),
        release_config(),
        layout(),
    )
        .prop_map(
            |(package, version, repository, release, layout)| GeneratedManifest {
                source: manifest_source(&package, &version, &repository, Some(&release), layout),
                package,
                version,
                repository,
                release,
            },
        )
}

fn initialization_settings() -> impl Strategy<Value = InitializationSettings> {
    (
        version(),
        "[a-z][a-z0-9_-]{0,8}(/[a-z][a-z0-9_-]{0,8})?",
        registry(),
        any::<bool>(),
    )
        .prop_map(|(compiler, default_branch, registry, allow_version_zero)| {
            InitializationSettings {
                compiler,
                default_branch,
                registry,
                allow_version_zero,
            }
        })
}
