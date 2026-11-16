use std::path::PathBuf;

use release_glz::config::{
    ApprovalMode, AuthKind, HookConfig, Manifest, MissingReleaseConfig, RegistryProvider,
    SeparationMode, valid_env_name, validate_git_ref, validate_hook_config, validate_package_name,
    validate_relative_path,
};
use release_glz::failure::{FailureClass, RefusalReason, classify, refusal_reason};

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
