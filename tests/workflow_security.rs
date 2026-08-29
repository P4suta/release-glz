use std::fs;

#[test]
fn distribution_builds_and_smokes_every_supported_native_target() {
    let yaml = fs::read_to_string(".github/workflows/distribute.yml").unwrap();
    serde_yaml::from_str::<serde_yaml::Value>(&yaml).unwrap();
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
    assert!(yaml.contains("runner: windows-11-arm"));
    assert!(yaml.contains("release-glz --version"));
    assert!(yaml.contains("ldd") && yaml.contains("not a dynamic executable"));
}

#[test]
fn distribution_is_attested_and_uploaded_to_a_draft_exactly_once() {
    let yaml = fs::read_to_string(".github/workflows/distribute.yml").unwrap();
    assert!(!yaml.contains("--clobber"));
    assert!(yaml.contains("permissions: {}"));
    assert!(yaml.contains("id-token: write"));
    assert!(yaml.contains("attestations: write"));
    assert!(yaml.contains("actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26"));
    assert!(yaml.contains("release create") && yaml.contains("--draft"));
    assert_eq!(yaml.matches("gh release upload").count(), 1);
    assert!(yaml.contains("gh attestation verify"));
    assert!(yaml.contains("generate-action-checksums.js"));
    assert!(yaml.contains("--check action/checksums.json"));
    assert!(yaml.contains("generate-provenance.js"));
    assert!(yaml.contains(".intoto.jsonl"));
    assert!(yaml.contains("gh release edit") && yaml.contains("--draft=false"));
    assert!(yaml.contains("SHA256SUMS"));
    assert!(yaml.contains("release-glz.cdx.json"));
    assert!(yaml.contains("THIRD_PARTY_LICENSES.json"));

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
fn distribution_prepares_checksums_without_mutating_a_release_before_the_tag() {
    let yaml = fs::read_to_string(".github/workflows/distribute.yml").unwrap();
    assert!(yaml.contains("workflow_dispatch:"));
    assert!(yaml.contains("version:"));
    assert!(yaml.contains("prepare:"));
    assert!(yaml.contains("github.event_name == 'workflow_dispatch'"));
    assert!(yaml.contains("--out action-checksums.json"));
    assert!(yaml.contains("name: action-checksums-${{ needs.validate.outputs.version }}"));
    assert!(yaml.contains("path: action-checksums.json"));
    assert!(yaml.contains("github.event_name == 'push'"));
    assert!(yaml.contains("toolchain: 1.88.0"));
    assert!(yaml.contains("RELEASE_GLZ_ACTION_SHA: ${{ github.sha }}"));
    assert!(yaml.contains("node scripts/package-windows.js"));
    assert!(!yaml.contains("Compress-Archive"));
}
