#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use release_glz::config::{AuthKind, Manifest, RegistryProvider};

const ACTION_SHA: &str = "abcdef0123456789abcdef0123456789abcdef01";

fn package(version: &str) -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    Command::new("git")
        .args(["init", "--initial-branch=trunk"])
        .current_dir(temp.path())
        .output()
        .unwrap();
    std::fs::write(
        temp.path().join("gleam.toml"),
        format!(
            "name = \"widget\"\nversion = \"{version}\"\n\n[repository]\ntype = \"github\"\nuser = \"acme\"\nrepo = \"widget\"\n"
        ),
    )
    .unwrap();
    let gleam = temp.path().join("fake-gleam");
    std::fs::write(&gleam, "#!/bin/sh\nprintf '%s\\n' 'gleam 1.18.1'\n").unwrap();
    let mut permissions = std::fs::metadata(&gleam).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&gleam, permissions).unwrap();
    (temp, gleam)
}

fn init(root: &Path, gleam: &Path, arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(root)
        .env("RELEASE_GLZ_GLEAM", gleam)
        .args(["--output", "json", "init"])
        .args(arguments)
        .args(["--action-sha", ACTION_SHA])
        .output()
        .unwrap()
}

#[test]
fn public_profile_check_then_update_generates_complete_schema_two_configuration() {
    let (temp, gleam) = package("1.0.0");
    let original = std::fs::read_to_string(temp.path().join("gleam.toml")).unwrap();
    let check = init(temp.path(), &gleam, &["--profile", "public", "--check"]);
    assert_eq!(check.status.code(), Some(3));
    assert_eq!(
        std::fs::read_to_string(temp.path().join("gleam.toml")).unwrap(),
        original
    );
    assert!(
        !temp
            .path()
            .join(".github/workflows/release-glz.yml")
            .exists()
    );
    let envelope: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(envelope["result"]["manifest_changed"], true);
    assert_eq!(
        envelope["next_actions"][0]["argv"],
        serde_json::json!([
            "release-glz",
            "init",
            "--update",
            "--action-sha",
            ACTION_SHA,
            "--profile",
            "public"
        ])
    );

    let update = init(temp.path(), &gleam, &["--profile", "public", "--update"]);
    assert!(
        update.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&update.stdout),
        String::from_utf8_lossy(&update.stderr)
    );
    let manifest = Manifest::load(temp.path().join("gleam.toml")).unwrap();
    assert_eq!(manifest.release.schema, 2);
    assert_eq!(manifest.release.compiler.to_string(), "1.18.1");
    assert_eq!(manifest.release.registry, Default::default());
    assert_eq!(manifest.release.approval.manual_refs, ["refs/heads/trunk"]);
    let workflow =
        std::fs::read_to_string(temp.path().join(".github/workflows/release-glz.yml")).unwrap();
    assert!(workflow.contains(&format!("P4suta/release-glz@{ACTION_SHA}")));
}

#[test]
fn organization_and_private_profiles_require_exact_non_secret_inputs() {
    let (organization, gleam) = package("1.0.0");
    let missing = init(
        organization.path(),
        &gleam,
        &["--profile", "organization", "--check"],
    );
    assert_eq!(missing.status.code(), Some(2));
    let check = init(
        organization.path(),
        &gleam,
        &[
            "--profile",
            "organization",
            "--organization",
            "acme_team",
            "--check",
        ],
    );
    assert_eq!(check.status.code(), Some(3));
    let check: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(check["next_actions"][0]["argv"][6], "organization");
    assert!(
        check["next_actions"][0]["argv"]
            .as_array()
            .unwrap()
            .iter()
            .any(|argument| argument == "--organization")
    );
    let update = init(
        organization.path(),
        &gleam,
        &[
            "--profile",
            "organization",
            "--organization",
            "acme_team",
            "--update",
        ],
    );
    assert!(update.status.success());
    let configured = Manifest::load(organization.path().join("gleam.toml")).unwrap();
    assert_eq!(
        configured.release.registry.repository.as_deref(),
        Some("acme_team")
    );
    assert_eq!(configured.release.registry.api_url, "https://hex.pm/api");
    assert_eq!(
        configured.release.registry.repository_url,
        "https://repo.hex.pm/repos/acme_team"
    );
    assert_eq!(
        configured.release.registry.docs_url,
        "https://repo.hex.pm/repos/acme_team/docs"
    );

    let (private, gleam) = package("1.0.0");
    let missing = init(private.path(), &gleam, &["--profile", "private", "--check"]);
    assert_eq!(missing.status.code(), Some(2));
    let check = init(
        private.path(),
        &gleam,
        &[
            "--profile",
            "private",
            "--api-url",
            "https://hex.example.test/api",
            "--repository-url",
            "https://hex.example.test/repo",
            "--docs-url",
            "https://hex.example.test/docs",
            "--credential-env",
            "PRIVATE_HEX_TOKEN",
            "--auth",
            "bearer",
            "--allow-version-zero",
            "--check",
        ],
    );
    assert_eq!(check.status.code(), Some(3));
    let check: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    let argv = check["next_actions"][0]["argv"].as_array().unwrap();
    for expected in [
        "--api-url",
        "--repository-url",
        "--docs-url",
        "--credential-env",
        "--auth",
        "--allow-version-zero",
    ] {
        assert!(argv.iter().any(|argument| argument == expected));
    }
    let update = init(
        private.path(),
        &gleam,
        &[
            "--profile",
            "private",
            "--api-url",
            "https://hex.example.test/api",
            "--repository-url",
            "https://hex.example.test/repo",
            "--docs-url",
            "https://hex.example.test/docs",
            "--credential-env",
            "PRIVATE_HEX_TOKEN",
            "--auth",
            "bearer",
            "--update",
        ],
    );
    assert!(
        update.status.success(),
        "{}",
        String::from_utf8_lossy(&update.stdout)
    );
    let configured = Manifest::load(private.path().join("gleam.toml")).unwrap();
    assert_eq!(
        configured.release.registry.provider,
        RegistryProvider::HexCompatible
    );
    assert_eq!(configured.release.registry.auth, AuthKind::Bearer);
    assert_eq!(
        configured.release.registry.credential_env,
        "PRIVATE_HEX_TOKEN"
    );
}

#[test]
fn profiles_reject_cross_profile_options_and_each_omitted_required_value() {
    let (public, gleam) = package("1.0.0");
    let invalid_public = init(
        public.path(),
        &gleam,
        &["--profile", "public", "--organization", "acme", "--check"],
    );
    assert_eq!(invalid_public.status.code(), Some(2));

    let (organization, gleam) = package("1.0.0");
    let invalid_organization = init(
        organization.path(),
        &gleam,
        &[
            "--profile",
            "organization",
            "--organization",
            "acme",
            "--api-url",
            "https://hex.example.test/api",
            "--check",
        ],
    );
    assert_eq!(invalid_organization.status.code(), Some(2));

    let (private, gleam) = package("1.0.0");
    let invalid_private = init(
        private.path(),
        &gleam,
        &["--profile", "private", "--organization", "acme", "--check"],
    );
    assert_eq!(invalid_private.status.code(), Some(2));

    let (missing_profile, gleam) = package("1.0.0");
    assert_eq!(
        init(missing_profile.path(), &gleam, &["--check"])
            .status
            .code(),
        Some(2)
    );

    let complete = [
        ("--api-url", "https://hex.example.test/api"),
        ("--repository-url", "https://hex.example.test/repo"),
        ("--docs-url", "https://hex.example.test/docs"),
        ("--credential-env", "PRIVATE_HEX_TOKEN"),
    ];
    for omitted in 0..complete.len() {
        let (package, gleam) = package("1.0.0");
        let mut arguments = vec!["--profile", "private"];
        for (index, (option, value)) in complete.iter().enumerate() {
            if index != omitted {
                arguments.extend([*option, *value]);
            }
        }
        arguments.extend(["--auth", "hex-token", "--check"]);
        assert_eq!(
            init(package.path(), &gleam, &arguments).status.code(),
            Some(2),
            "private profile accepted a missing {}",
            complete[omitted].0
        );
    }

    let (missing_auth, gleam) = package("1.0.0");
    let mut arguments = vec!["--profile", "private"];
    for (option, value) in complete {
        arguments.extend([option, value]);
    }
    arguments.push("--check");
    assert_eq!(
        init(missing_auth.path(), &gleam, &arguments).status.code(),
        Some(2)
    );
}

#[test]
fn zero_version_existing_configuration_and_missing_mode_fail_closed() {
    let (zero, gleam) = package("0.2.0");
    let denied = init(zero.path(), &gleam, &["--profile", "public", "--check"]);
    assert_eq!(denied.status.code(), Some(2));
    let allowed = init(
        zero.path(),
        &gleam,
        &["--profile", "public", "--allow-version-zero", "--update"],
    );
    assert!(allowed.status.success());
    assert!(
        Manifest::load(zero.path().join("gleam.toml"))
            .unwrap()
            .release
            .allow_version_zero
    );

    let repeated = init(zero.path(), &gleam, &["--profile", "public", "--check"]);
    assert_eq!(repeated.status.code(), Some(2));
    let no_mode = init(zero.path(), &gleam, &[]);
    assert_eq!(no_mode.status.code(), Some(2));
}

#[test]
fn manifest_paths_with_spaces_remain_single_canonical_argv_elements() {
    let temp = tempfile::tempdir().unwrap();
    Command::new("git")
        .args(["init", "--initial-branch=main"])
        .current_dir(temp.path())
        .output()
        .unwrap();
    let package = temp.path().join("package with space");
    std::fs::create_dir(&package).unwrap();
    std::fs::write(
        package.join("gleam.toml"),
        "name = \"widget\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();
    let gleam = temp.path().join("fake-gleam");
    std::fs::write(&gleam, "#!/bin/sh\nprintf '%s\\n' 'gleam 1.18.1'\n").unwrap();
    let mut permissions = std::fs::metadata(&gleam).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&gleam, permissions).unwrap();
    let relative = "package with space/gleam.toml";
    let check = Command::new(env!("CARGO_BIN_EXE_release-glz"))
        .current_dir(temp.path())
        .env("RELEASE_GLZ_GLEAM", &gleam)
        .args([
            "--manifest-path",
            relative,
            "--output",
            "json",
            "init",
            "--profile",
            "public",
            "--check",
            "--action-sha",
            ACTION_SHA,
        ])
        .output()
        .unwrap();
    assert_eq!(check.status.code(), Some(3));
    let envelope: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(
        envelope["next_actions"][0]["argv"][2],
        serde_json::Value::String(relative.into())
    );
    assert_eq!(envelope["next_actions"][0]["argv"][3], "init");
}
