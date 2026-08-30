use std::path::PathBuf;

use release_glz::config::{
    ApprovalMode, AuthKind, HookConfig, Manifest, RegistryProvider, SeparationMode, valid_env_name,
    validate_git_ref, validate_hook_config, validate_package_name, validate_relative_path,
};

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
    let release = &manifest.release;
    assert_eq!(release.schema, 2);
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
    assert!(release.compatibility_warnings.is_empty());
}

#[test]
fn schema_two_rejects_unknown_keys_and_wrong_types() {
    let unknown = complete_config("[tools.release-glz.typo]\nenabled = true");
    assert!(
        Manifest::parse(PathBuf::from("gleam.toml"), unknown)
            .unwrap_err()
            .to_string()
            .contains("unknown")
    );

    let wrong_type =
        complete_config("").replace("timeout_seconds = 45", "timeout_seconds = \"45\"");
    assert!(Manifest::parse(PathBuf::from("gleam.toml"), wrong_type).is_err());
}

#[test]
fn an_explicit_schema_is_never_silently_reinterpreted_as_legacy() {
    for schema in ["3", "0", "\"2\"", "true"] {
        let source = complete_config("").replace("schema = 2", &format!("schema = {schema}"));
        let error = Manifest::parse(PathBuf::from("gleam.toml"), source)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("schema"),
            "schema {schema} was not rejected explicitly: {error}"
        );
    }
}

#[test]
fn structured_configuration_requires_an_explicit_schema_two_marker() {
    for key in [
        "registry",
        "approval",
        "outputs",
        "hooks",
        "changelog",
        "api_exceptions",
    ] {
        let mut source = complete_config("").replace("schema = 2\n", "");
        if !source.contains(&format!("tools.release-glz.{key}")) {
            source.push_str(&format!("\n[tools.release-glz.{key}]\n"));
        }
        let error = Manifest::parse(PathBuf::from("gleam.toml"), source)
            .unwrap_err()
            .to_string();
        assert!(error.contains("schema = 2"), "{key}: {error}");
    }
}

#[test]
fn schema_two_does_not_silently_enable_zero_major_versions() {
    let omitted = Manifest::parse(PathBuf::from("gleam.toml"), complete_config("")).unwrap();
    assert!(!omitted.release.allow_version_zero);
    let explicit = complete_config("").replace(
        "release_branch_prefix = \"release-glz/\"",
        "release_branch_prefix = \"release-glz/\"\nallow_version_zero = true",
    );
    assert!(
        Manifest::parse(PathBuf::from("gleam.toml"), explicit)
            .unwrap()
            .release
            .allow_version_zero
    );
}

#[test]
fn paths_refs_and_hook_ids_are_safe() {
    for (from, to) in [
        ("path = \"CHANGELOG.md\"", "path = \"../CHANGELOG.md\""),
        (
            "notes_dir = \".release-glz/notes\"",
            "notes_dir = \"/tmp/notes\"",
        ),
        (
            "release_branch_prefix = \"release-glz/\"",
            "release_branch_prefix = \"refs/heads/main\"",
        ),
        ("id = \"policy\"", "id = \"policy/../../x\""),
    ] {
        let source = complete_config("").replace(from, to);
        assert!(
            Manifest::parse(PathBuf::from("gleam.toml"), source).is_err(),
            "accepted {to}"
        );
    }
}

#[test]
fn registry_requires_https_except_explicit_loopback_tests() {
    let insecure = complete_config("").replace("https://hex.pm/api", "http://hex.pm/api");
    assert!(Manifest::parse(PathBuf::from("gleam.toml"), insecure).is_err());

    let loopback = complete_config("")
        .replace("https://hex.pm/api", "http://127.0.0.1:8080/api")
        .replace(
            "https://repo.hex.pm/repos/acme",
            "http://127.0.0.1:8080/repos/acme",
        )
        .replace(
            "https://repo.hex.pm/repos/acme/docs",
            "http://127.0.0.1:8080/repos/acme/docs",
        )
        .replace(
            "auth = \"hex-token\"",
            "auth = \"hex-token\"\nallow_http_loopback = true",
        );
    assert!(Manifest::parse(PathBuf::from("gleam.toml"), loopback).is_ok());

    for unsafe_url in [
        "https://hex.pm/api?redirect=https://evil.test",
        "https://hex.pm/api#fragment",
        "https://user:password@hex.pm/api",
        "ftp://hex.pm/api",
    ] {
        let source = complete_config("").replace("https://hex.pm/api", unsafe_url);
        assert!(
            Manifest::parse(PathBuf::from("gleam.toml"), source).is_err(),
            "accepted registry URL {unsafe_url}"
        );
    }
}

#[test]
fn hex_organization_repository_is_a_safe_single_path_segment() {
    for invalid in ["", "../other", "acme/widgets", ".hidden", "acme org"] {
        let source = complete_config("").replace(
            "repository = \"acme\"",
            &format!("repository = \"{invalid}\""),
        );
        assert!(
            Manifest::parse(PathBuf::from("gleam.toml"), source).is_err(),
            "accepted unsafe Hex organization {invalid:?}"
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
        assert!(Manifest::parse(PathBuf::from("gleam.toml"), source).is_err());
    }

    let custom_credential = complete_config("")
        .replace(
            "credential_env = \"HEXPM_API_KEY\"",
            "credential_env = \"PRIVATE_REGISTRY_TOKEN\"",
        )
        .replace("env = [\"CI\"]", "env = [\"PRIVATE_REGISTRY_TOKEN\"]");
    assert!(
        Manifest::parse(PathBuf::from("gleam.toml"), custom_credential).is_err(),
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
        assert!(
            validate_package_name(invalid).is_err(),
            "accepted {invalid:?}"
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
        assert!(validate_hook_config(&hook).is_err(), "accepted hook {id:?}");
    }
    for (argv, timeout, env) in [
        (vec![], 30, vec![]),
        (vec![String::new()], 30, vec![]),
        (vec!["bad\0arg".into()], 30, vec![]),
        (vec!["program".into()], 0, vec![]),
        (vec!["program".into()], 3_601, vec![]),
        (vec!["program".into()], 30, vec!["bad-name".into()]),
    ] {
        assert!(
            validate_hook_config(&HookConfig {
                id: "policy".into(),
                argv,
                timeout_seconds: timeout,
                required: false,
                env,
            })
            .is_err()
        );
    }
    for protected in [
        "HEXPM_API_KEY",
        "GITHUB_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "GITHUB_ENV",
        "GITHUB_OUTPUT",
    ] {
        assert!(
            validate_hook_config(&HookConfig {
                id: "protected".into(),
                argv: vec!["program".into()],
                timeout_seconds: 30,
                required: true,
                env: vec![protected.into()],
            })
            .is_err(),
            "hook accepted protected environment {protected}"
        );
    }

    for valid in ["CHANGELOG.md", ".release-glz/notes", "a/b"] {
        validate_relative_path(std::path::Path::new(valid), "test").unwrap();
    }
    for invalid in ["", "/tmp/x", "../x", ".", "a/../b", "a\\b"] {
        assert!(
            validate_relative_path(std::path::Path::new(invalid), "test").is_err(),
            "accepted path {invalid:?}"
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
        assert!(
            validate_git_ref(invalid, "test").is_err(),
            "accepted ref {invalid:?}"
        );
    }
}

#[test]
fn approval_and_registry_variants_are_strict_but_cover_supported_forms() {
    for (from, to) in [
        ("environment = \"release\"", "environment = \"\""),
        (
            "environment = \"release\"",
            "environment = \"release\\nproduction\"",
        ),
        (
            "manual_refs = [\"refs/heads/main\"]",
            "manual_refs = [\"refs/heads/main\", \"refs/heads/main\"]",
        ),
        (
            "manual_refs = [\"refs/heads/main\"]",
            "manual_refs = [\"refs/notes/release\"]",
        ),
    ] {
        assert!(
            Manifest::parse(
                PathBuf::from("gleam.toml"),
                complete_config("").replace(from, to),
            )
            .is_err(),
            "accepted {to}"
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
    assert!(Manifest::parse(PathBuf::from("gleam.toml"), bad_fallback).is_err());

    let custom = complete_config("")
        .replace("provider = \"hexpm\"", "provider = \"hex-compatible\"")
        .replace("repository = \"acme\"\napi_url", "api_url")
        .replace("auth = \"hex-token\"", "auth = \"bearer\"");
    let parsed = Manifest::parse(PathBuf::from("gleam.toml"), custom).unwrap();
    assert_eq!(
        parsed.release.registry.provider,
        RegistryProvider::HexCompatible
    );
    assert_eq!(parsed.release.registry.auth, AuthKind::Bearer);

    let custom_with_repository =
        complete_config("").replace("provider = \"hexpm\"", "provider = \"hex-compatible\"");
    let custom_with_repository =
        Manifest::parse(PathBuf::from("gleam.toml"), custom_with_repository).unwrap();
    assert_eq!(
        custom_with_repository
            .release
            .registry
            .repository
            .as_deref(),
        Some("acme")
    );

    for host in ["localhost", "127.0.0.1", "[::1]"] {
        let base = format!("http://{host}:8080");
        let loopback = complete_config("")
            .replace("https://hex.pm/api", &format!("{base}/api"))
            .replace(
                "https://repo.hex.pm/repos/acme",
                &format!("{base}/repos/acme"),
            )
            .replace(
                "https://repo.hex.pm/repos/acme/docs",
                &format!("{base}/repos/acme/docs"),
            )
            .replace(
                "auth = \"hex-token\"",
                "auth = \"hex-token\"\nallow_http_loopback = true",
            );
        Manifest::parse(PathBuf::from("gleam.toml"), loopback).unwrap();
    }

    let external_http = complete_config("")
        .replace("https://hex.pm/api", "http://192.0.2.1/api")
        .replace(
            "auth = \"hex-token\"",
            "auth = \"hex-token\"\nallow_http_loopback = true",
        );
    assert!(Manifest::parse(PathBuf::from("gleam.toml"), external_http).is_err());
    let non_hierarchical = complete_config("").replace("https://hex.pm/api", "file:///api");
    assert!(Manifest::parse(PathBuf::from("gleam.toml"), non_hierarchical).is_err());
}

#[test]
fn legacy_options_reject_malformed_overrides_and_accept_complete_compatible_values() {
    let valid = r#"name = "widget"
version = "0.9.0"

[tools.release-glz]
schema = 1
changelog_path = "NEWS.md"
release_branch_prefix = "releases/"
allow_version_zero = true
prerelease = "beta"
allow_unknown_api_for = ["1.0.0"]

[tools.release-glz.baseline_refs]
"1.0.0" = "refs/tags/v1.0.0"
"#;
    let parsed = Manifest::parse(PathBuf::from("gleam.toml"), valid.into()).unwrap();
    assert_eq!(parsed.release.changelog_path, PathBuf::from("NEWS.md"));
    assert_eq!(parsed.release.release_branch_prefix, "releases/");
    assert!(parsed.release.allow_version_zero);
    assert_eq!(parsed.release.prerelease.unwrap().as_str(), "beta");
    assert_eq!(parsed.release.baseline_refs.len(), 1);

    for invalid in [
        valid.replace("[\"1.0.0\"]", "[1]"),
        valid.replace("[\"1.0.0\"]", "[\"not-semver\"]"),
        valid.replace(
            "\"1.0.0\" = \"refs/tags/v1.0.0\"",
            "\"bad\" = \"refs/tags/v1\"",
        ),
        valid.replace("\"refs/tags/v1.0.0\"", "1"),
        valid.replace("\"refs/tags/v1.0.0\"", "\"refs/tags/../bad\""),
        valid.replace("prerelease = \"beta\"", "prerelease = \"preview\""),
    ] {
        assert!(Manifest::parse(PathBuf::from("gleam.toml"), invalid).is_err());
    }
}

#[test]
fn approval_paths_have_fixed_non_substitutable_modes() {
    let wrong_normal = complete_config("").replace(
        "normal = \"release-pr-and-environment\"",
        "normal = \"environment\"",
    );
    assert!(Manifest::parse(PathBuf::from("gleam.toml"), wrong_normal).is_err());

    let wrong_manual = complete_config("").replace(
        "manual = \"environment\"",
        "manual = \"release-pr-and-environment\"",
    );
    assert!(Manifest::parse(PathBuf::from("gleam.toml"), wrong_manual).is_err());
}

#[test]
fn manual_release_policy_requires_explicit_safe_full_refs() {
    let missing = complete_config("").replace("manual_refs = [\"refs/heads/main\"]\n", "");
    assert!(Manifest::parse(PathBuf::from("gleam.toml"), missing).is_err());

    for unsafe_ref in [
        "main",
        "refs/heads/../main",
        "refs/pull/1/head",
        "refs/heads/*",
    ] {
        let source = complete_config("").replace("refs/heads/main", unsafe_ref);
        assert!(
            Manifest::parse(PathBuf::from("gleam.toml"), source).is_err(),
            "accepted {unsafe_ref}"
        );
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
    assert_eq!(parsed.release.api_exceptions.len(), 1);
    assert!(
        parsed
            .release
            .allow_unknown_api_for
            .contains(&"1.2.3".parse().unwrap())
    );

    for (name, expected, invalid) in [
        (
            "empty reason",
            "requires a reason",
            exception.replace(
                "reason = \"The historical compiler is unavailable\"",
                "reason = \"  \"",
            ),
        ),
        (
            "unsafe baseline",
            "api_exceptions.baseline contains an unsafe git ref",
            exception.replace(
                "baseline = \"refs/tags/v1.2.3\"",
                "baseline = \"refs/tags/../secret\"",
            ),
        ),
        (
            "invalid expiry",
            "must use YYYY-MM-DD",
            exception.replace("expires = \"2999-12-31\"", "expires = \"tomorrow\""),
        ),
        (
            "duplicate version",
            "duplicate API exception",
            format!("{exception}{exception}"),
        ),
    ] {
        let error = Manifest::parse(PathBuf::from("gleam.toml"), complete_config(&invalid))
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{name}: {error}");
    }
}

#[test]
fn legacy_flat_configuration_remains_readable_with_a_migration_warning() {
    let source = r#"name = "widget"
version = "1.0.0"

[tools.release-glz]
changelog_path = "CHANGELOG.md"
allow_version_zero = false
"#;
    let manifest = Manifest::parse(PathBuf::from("gleam.toml"), source.into()).unwrap();
    assert_eq!(manifest.release.schema, 1);
    assert!(
        manifest
            .release
            .compatibility_warnings
            .iter()
            .any(|warning| warning.contains("migrate"))
    );
}
