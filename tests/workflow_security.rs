use release_glz_test_support::fs;
use serde_norway::{Mapping, Value};

#[test]
fn distribution_builds_and_smokes_every_supported_native_target() {
    let yaml = fs::read_to_string(".github/workflows/distribute.yml");
    serde_norway::from_str::<serde_norway::Value>(&yaml).unwrap();
    for target in [
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
        "aarch64-pc-windows-msvc",
    ] {
        assert!(
            yaml.contains(&format!("target: {target}")),
            "missing {target}"
        );
    }
    assert!(yaml.contains("runner: windows-2025"));
    assert!(!yaml.contains("runner: windows-latest"));
    assert!(yaml.contains("runner: windows-11-arm"));
    assert!(yaml.contains("binary=\"target/$TARGET/release/release-glz\""));
    assert!(yaml.contains("\"$binary\" --version"));
    assert!(yaml.contains("release-glz.exe\" --version"));
    assert!(yaml.contains("ldd") && yaml.contains("not a dynamic executable"));
}

/// Whether a workflow uses an action and pins it to a full commit SHA.
///
/// Asserting the SHA itself would make this test the second place that has to know it, so every routine bump of the action would fail here until someone copied the new value across.
/// What matters is the property — the action is used, and it is pinned — which survives the bump.
fn pinned_to_a_commit(yaml: &str, action: &str) -> bool {
    let marker = format!("{action}@");
    yaml.lines().any(|line| {
        line.split_once(&marker).is_some_and(|(_, rest)| {
            rest.chars()
                .take_while(char::is_ascii_hexdigit)
                .count()
                .eq(&40)
        })
    })
}

/// Check that the workflow grants no default permission and that only the `release` job may sign with the run's OIDC token or write attestations.
fn only_the_release_job_attests(workflow: &Value) -> Result<(), String> {
    if workflow["permissions"].as_mapping().map(Mapping::len) != Some(0) {
        return Err("the workflow grants a default permission".into());
    }
    let jobs = workflow["jobs"]
        .as_mapping()
        .ok_or("the workflow has no jobs")?;
    if !jobs.contains_key("release") {
        return Err("the workflow has no release job".into());
    }
    for (name, job) in jobs {
        let name = name.as_str().ok_or("a job name is not a string")?;
        // Only the job that attests and publishes the release signs with the run's OIDC token.
        let attests = name == "release";
        for scope in ["id-token", "attestations"] {
            if grants_write(job.get("permissions"), scope)? != attests {
                return Err(format!("{name}: {scope}"));
            }
        }
    }
    Ok(())
}

/// Whether a job's `permissions` grants `write` on `scope`, in each form that GitHub Actions accepts.
///
/// `write-all` grants every scope.
/// `read-all`, an empty mapping, and an absent key, which inherits the empty workflow default, grant none.
fn grants_write(permissions: Option<&Value>, scope: &str) -> Result<bool, String> {
    match permissions {
        None => Ok(false),
        Some(Value::Mapping(scopes)) => {
            Ok(scopes.get(scope).and_then(Value::as_str) == Some("write"))
        }
        Some(Value::String(all)) if all == "write-all" => Ok(true),
        Some(Value::String(all)) if all == "read-all" => Ok(false),
        Some(other) => Err(format!("unsupported job permissions {other:?}")),
    }
}

/// `workflow` with the `permissions` of job `name` replaced by `permissions`, or removed for `None`.
fn with_job_permissions(workflow: &Value, name: &str, permissions: Option<&str>) -> Value {
    let mut planted = workflow.clone();
    let job = planted["jobs"][name].as_mapping_mut().unwrap();
    match permissions {
        Some(permissions) => job.insert("permissions".into(), permissions.into()),
        None => job.remove("permissions"),
    };
    planted
}

#[test]
fn a_scalar_job_permission_can_neither_widen_nor_hide_the_attesting_job() {
    let workflow: Value =
        serde_norway::from_str(&fs::read_to_string(".github/workflows/distribute.yml")).unwrap();
    assert_eq!(only_the_release_job_attests(&workflow), Ok(()));
    let others = workflow["jobs"]
        .as_mapping()
        .unwrap()
        .keys()
        .filter_map(Value::as_str)
        .filter(|name| *name != "release")
        .collect::<Vec<_>>();
    assert!(!others.is_empty());
    for name in others {
        assert_eq!(
            only_the_release_job_attests(&with_job_permissions(&workflow, name, Some("write-all"))),
            Err(format!("{name}: id-token")),
            "{name}: write-all"
        );
        assert_eq!(
            only_the_release_job_attests(&with_job_permissions(&workflow, name, Some("read-all"))),
            Ok(()),
            "{name}: read-all"
        );
        assert_eq!(
            only_the_release_job_attests(&with_job_permissions(&workflow, name, None)),
            Ok(()),
            "{name}: inherited"
        );
        for unknown in ["write", "none", ""] {
            assert_eq!(
                only_the_release_job_attests(&with_job_permissions(&workflow, name, Some(unknown))),
                Err(format!(
                    "unsupported job permissions {:?}",
                    Value::from(unknown)
                )),
                "{name}: {unknown:?}"
            );
        }
    }
    for permissions in [Some("read-all"), None] {
        assert_eq!(
            only_the_release_job_attests(&with_job_permissions(&workflow, "release", permissions)),
            Err("release: id-token".to_owned()),
            "release: {permissions:?}"
        );
    }
    let mut writable = workflow;
    writable["permissions"] = "write-all".into();
    assert_eq!(
        only_the_release_job_attests(&writable),
        Err("the workflow grants a default permission".to_owned())
    );
}

#[test]
fn distribution_is_attested_and_uploaded_to_a_draft_exactly_once() {
    let yaml = fs::read_to_string(".github/workflows/distribute.yml").replace("\r\n", "\n");
    assert!(!yaml.contains("--clobber"));
    // GitHub's tag endpoint answers only with a published Release, so it can't find the draft.
    assert!(!yaml.contains("releases/tags/"));
    assert!(yaml.contains("gh release view \"$TAG\" --json databaseId"));
    let workflow: Value = serde_norway::from_str(&yaml).unwrap();
    assert_eq!(only_the_release_job_attests(&workflow), Ok(()));
    assert!(
        pinned_to_a_commit(&yaml, "actions/attest"),
        "attestation must run from an action pinned to a full commit SHA"
    );
    assert!(yaml.contains("release create") && yaml.contains("--draft"));
    assert_eq!(yaml.matches("gh release upload").count(), 1);
    assert!(yaml.contains("gh attestation verify"));
    for pin in [
        r#"--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/distribute.yml""#,
        r#"--source-ref "$GITHUB_REF""#,
        r#"--source-digest "$GITHUB_SHA""#,
        "--deny-self-hosted-runners",
    ] {
        assert!(
            yaml.contains(pin),
            "attestation verification must pin {pin}"
        );
    }
    assert!(
        yaml.contains(r#"cmp -- "$file" "../dist/$file""#),
        "every re-downloaded asset must match this run's own build byte for byte"
    );
    assert!(!yaml.contains("sha256sum --check SHA256SUMS"));
    assert!(yaml.contains("generate-action-checksums.js"));
    assert!(yaml.contains("--check action/checksums.json"));
    assert!(yaml.contains("generate-provenance.js"));
    assert!(yaml.contains(".intoto.jsonl"));
    assert!(yaml.contains("gh release edit") && yaml.contains("--draft=false"));
    assert!(yaml.contains("SHA256SUMS"));
    assert!(yaml.contains("release-glz.cdx.json"));
    assert!(yaml.contains("THIRD_PARTY_LICENSES.json"));
    assert!(yaml.contains("asset=$(jq -c"));
    assert!(yaml.contains(".digest // empty"));
    assert!(yaml.contains("exists without a digest"));
    let inventory_check = yaml
        .find("node scripts/verify-release-assets.js --artifacts dist")
        .expect("draft assets must be checked against the sealed dist inventory");
    let upload_loop = yaml.find("for file in dist/*").unwrap();
    assert!(inventory_check < upload_loop);
    let complete_inventory = "node scripts/verify-release-assets.js --artifacts dist --complete";
    let complete_checks = yaml
        .match_indices(complete_inventory)
        .map(|(position, _)| position)
        .collect::<Vec<_>>();
    assert_eq!(
        complete_checks.len(),
        2,
        "the complete asset inventory must be checked after upload and immediately before finalization"
    );
    let finalize = yaml.find("gh release edit \"$TAG\" --draft=false").unwrap();
    assert!(
        upload_loop < complete_checks[0]
            && complete_checks[0] < complete_checks[1]
            && complete_checks[1] < finalize,
        "complete inventory checks must bracket post-upload verification and release finalization"
    );
    assert!(yaml.contains("diff -u \\\n"));

    for line in yaml.lines().filter(|line| {
        line.trim_start()
            .trim_start_matches("- ")
            .starts_with("uses:")
    }) {
        let code = line.split_once(" #").map_or(line, |(code, _)| code);
        if code.trim() == "uses: ./.github/workflows/assurance.yml" {
            continue;
        }
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
fn distribution_requires_same_source_assurance_before_preparation_and_publication() {
    let source = fs::read_to_string(".github/workflows/distribute.yml");
    let workflow: serde_norway::Value = serde_norway::from_str(&source).unwrap();
    let jobs = &workflow["jobs"];
    assert_eq!(jobs["assurance"]["needs"].as_str(), Some("validate"));
    assert_eq!(
        jobs["assurance"]["uses"].as_str(),
        Some("./.github/workflows/assurance.yml")
    );
    assert_eq!(
        jobs["assurance"]["permissions"]["contents"].as_str(),
        Some("read")
    );
    assert!(jobs["assurance"]["secrets"].is_null());
    for stage in ["prepare", "release"] {
        let prerequisites = jobs[stage]["needs"].as_sequence().unwrap();
        assert!(
            prerequisites
                .iter()
                .any(|value| value.as_str() == Some("assurance"))
        );
        assert!(
            jobs[stage]["if"]
                .as_str()
                .is_some_and(|condition| !condition.contains("always()"))
        );
    }
}

#[test]
fn distribution_prepares_checksums_without_mutating_a_release_before_the_tag() {
    let yaml = fs::read_to_string(".github/workflows/distribute.yml");
    assert!(yaml.contains("workflow_dispatch:"));
    assert!(yaml.contains("version:"));
    assert!(yaml.contains("prepare:"));
    assert!(yaml.contains("github.event_name == 'workflow_dispatch'"));
    assert!(yaml.contains("--out action-checksums.json"));
    assert!(yaml.contains("name: action-checksums-${{ needs.validate.outputs.version }}"));
    assert!(yaml.contains("path: action-checksums.json"));
    assert!(yaml.contains("github.event_name == 'push'"));
    assert!(yaml.contains("toolchain: 1.100.0"));
    assert!(!yaml.contains("RELEASE_GLZ_ACTION_SHA"));
    assert!(yaml.contains("git cat-file -t \"$GITHUB_REF\""));
    assert!(yaml.contains("git rev-parse \"$GITHUB_REF^{}\""));
    assert!(yaml.contains("git diff --name-only \"$GITHUB_SHA^\" \"$GITHUB_SHA\""));
    assert!(yaml.contains("= action/checksums.json"));
    assert!(yaml.contains("Print checksum preparation evidence"));
    assert!(yaml.contains("steps.upload_checksums.outputs.artifact-digest"));
    assert!(yaml.contains("node scripts/package-windows.js"));
    assert!(!yaml.contains("Compress-Archive"));
}

#[test]
fn distribution_packages_unix_archives_without_the_runner_tar() {
    let yaml = fs::read_to_string(".github/workflows/distribute.yml");
    assert!(yaml.contains("node scripts/package-unix.js"));
    for host_archiver in ["tar -C", "tar -c", "gzip -n", "touch -t"] {
        assert!(
            !yaml.contains(host_archiver),
            "the Unix archive bytes must not depend on the runner's `{host_archiver}`"
        );
    }
}
