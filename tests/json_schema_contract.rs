use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use release_glz::candidate::{
    CandidateArtifacts, CandidateManifest, CandidateSource, HookEvidence, HookKind,
    RegistryIdentity, SealedArtifact,
};
use release_glz::config::{ApprovalConfig, AuthKind, OutputConfig, RegistryProvider};
use release_glz::model::{
    ApiDiff, Baseline, BaselineSource, Bump, CommandEnvelope, ReleasePlan, ReleaseStage,
    ReleaseState,
};
use release_glz::reconciler::ExternalReleaseState;
use release_glz_test_support::schema::{
    RESULT_SCHEMAS, assert_matches, assert_published_envelope, published_schemas, violations,
};
use semver::Version;
use serde_json::{Value, json};

/// Published formats that no command prints as its result: the envelope around every result, the evidence a hook reports, and the external state the reconciler compares.
const DOMAIN_SCHEMAS: [(&str, &str); 3] = [
    ("command/v2", "command-envelope.schema.json"),
    ("hook/v1", "hook.schema.json"),
    ("state/v1", "release-state.schema.json"),
];

/// Formats that never leave release-glz, so they have no published schema.
const INTERNAL_FORMATS: [&str; 5] = [
    // The canonical bytes that the intent digest hashes.
    "intent/v1",
    // The planner's cache of baseline artifacts.
    "baseline-cache/v1",
    // What writing the workflow found, which `init` reports in `init/v1`.
    "workflow/v1",
    // The record of the generated workflow, which only `init` reads back.
    "workflow-state/v1",
    // The reconciler's plan, whose effects `release/v1` reports.
    "reconcile/v1",
];

#[test]
fn every_format_the_source_names_is_either_published_or_internal() {
    let named = named_formats(Path::new("src"));
    let published = RESULT_SCHEMAS
        .iter()
        .chain(&DOMAIN_SCHEMAS)
        .map(|(identifier, _)| *identifier)
        .collect::<BTreeSet<_>>();
    let internal = INTERNAL_FORMATS.into_iter().collect::<BTreeSet<_>>();
    assert!(published.is_disjoint(&internal));
    assert_eq!(
        named.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        &published | &internal,
        "a format the source names is neither published nor declared internal"
    );
}

#[test]
fn every_published_schema_is_a_closed_draft_2020_document_bound_to_the_v1_tag() {
    let schemas = published_schemas();
    let described = RESULT_SCHEMAS
        .iter()
        .chain(&DOMAIN_SCHEMAS)
        .map(|(_, file)| *file)
        .collect::<Vec<_>>();
    assert_eq!(
        schemas.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        described.iter().copied().collect::<BTreeSet<_>>(),
        "docs/ holds a schema that describes no published format"
    );
    assert_eq!(
        described.len(),
        described.iter().collect::<BTreeSet<_>>().len(),
        "one schema describes two formats"
    );
    for (identifier, file) in RESULT_SCHEMAS.iter().chain(&DOMAIN_SCHEMAS) {
        let schema = &schemas[*file];
        assert_eq!(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema",
            "{file}"
        );
        assert_eq!(
            schema["$id"],
            format!("https://raw.githubusercontent.com/P4suta/release-glz/v1.0.0/docs/{file}")
        );
        assert_eq!(
            schema["properties"]["schema"]["const"], *identifier,
            "{file}"
        );
        let version = identifier.rsplit_once('/').unwrap().1;
        let title = schema["title"].as_str().unwrap();
        assert!(
            title.starts_with("release-glz ") && title.ends_with(version),
            "{file}: {title}"
        );
        assert_eq!(schema["type"], "object", "{file}");
        assert_eq!(schema["additionalProperties"], false, "{file}");
        let properties = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let required = schema["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(properties, required, "{file} has an optional property");
        // Building the validator resolves every reference and refuses a format it doesn't know.
        assert!(!violations(file, &json!({})).is_empty(), "{file}");
    }
}

#[test]
fn checked_in_plan_schema_exactly_covers_the_serialized_surface() {
    assert_schema_surface(
        "docs/release-plan.schema.json",
        "release-glz ReleasePlan v3",
        "plan/v3",
        serde_json::to_value(plan()).unwrap(),
    );
}

#[test]
fn every_public_domain_schema_exactly_covers_its_serialized_surface() {
    assert_schema_surface(
        "docs/candidate.schema.json",
        "release-glz Candidate v1",
        "candidate/v1",
        serde_json::to_value(candidate()).unwrap(),
    );
    assert_schema_surface(
        "docs/release-state.schema.json",
        "release-glz ReleaseState v1",
        "state/v1",
        serde_json::to_value(ExternalReleaseState::default()).unwrap(),
    );
    assert_schema_surface(
        "docs/hook.schema.json",
        "release-glz Hook Evidence v1",
        "hook/v1",
        serde_json::to_value(hook_evidence()).unwrap(),
    );
    assert_schema_surface(
        "docs/command-envelope.schema.json",
        "release-glz Command Envelope v2",
        "command/v2",
        serde_json::to_value(CommandEnvelope::success(
            "plan",
            serde_json::json!({"schema": "plan/v3"}),
            vec![],
            vec![],
        ))
        .unwrap(),
    );
}

#[test]
fn every_public_serializer_validates_against_its_complete_draft_2020_schema() {
    assert_matches(
        "release-plan.schema.json",
        &serde_json::to_value(plan()).unwrap(),
    );
    assert_matches(
        "candidate.schema.json",
        &serde_json::to_value(candidate()).unwrap(),
    );
    assert_matches(
        "release-state.schema.json",
        &serde_json::to_value(ExternalReleaseState::default()).unwrap(),
    );
    assert_matches(
        "hook.schema.json",
        &serde_json::to_value(hook_evidence()).unwrap(),
    );
    assert_published_envelope(
        &serde_json::to_value(CommandEnvelope::success("plan", plan(), vec![], vec![])).unwrap(),
    );

    let mut candidate = serde_json::to_value(candidate()).unwrap();
    candidate["registry"]["unexpected"] = json!(true);
    assert!(!violations("candidate.schema.json", &candidate).is_empty());
}

/// Each case breaks one rule of a schema and names the schema that has to refuse it.
#[test]
fn every_result_schema_refuses_what_its_command_never_prints() {
    let sha = "a".repeat(64);
    let release = json!({
        "schema": "release/v1",
        "state": "released",
        "candidate_digest": sha,
        "applied": [{"kind": "publish_package"}],
        "remaining": [{"kind": "notify", "hook_id": "announce", "idempotency_key": sha, "required": false}],
    });
    let intent = json!({
        "schema": "release-pr-intent/v1",
        "state": "planned",
        "intent_binding": "bound",
        "version": "1.2.3",
        "intent_digest": sha,
        "candidate_digest": sha,
        "pr_url": "https://github.com/acme/widget/pull/7",
    });
    let doctor = json!({
        "schema": "doctor/v1",
        "state": "blocked",
        "config_schema": 2,
        "required_compiler": "1.18.1",
        "installed_compiler": null,
        "diagnostics": [{"code": "compiler_missing", "level": "error", "message": "missing", "detail": null}],
        "next_actions": [{"argv": [], "command": "install Gleam 1.18.1", "description": "Install it."}],
    });
    let init = json!({
        "schema": "init/v1",
        "manifest_path": "gleam.toml",
        "workflow_path": ".github/workflows/release-glz.yml",
        "action_sha": "b".repeat(40),
        "manifest_changed": false,
        "workflow_changed": true,
        "changed": true,
        "written": false,
        "manifest_diff": null,
        "workflow_diff": "@@ -0,0 +1 @@\n+name: release-glz\n",
    });
    let migration = json!({
        "schema": "migration/v1",
        "changed": true,
        "written": true,
        "manifest_path": "gleam.toml",
        "legacy_backup_path": ".release-glz/legacy-gleam.toml",
        "diff": null,
    });
    let verification = json!({
        "schema": "verify/v1",
        "state": "candidate_ready",
        "candidate": serde_json::to_value(candidate()).unwrap(),
    });
    let envelope = json!({
        "schema": "command/v2",
        "ok": false,
        "command": "release",
        "result": null,
        "diagnostics": [{"code": "policy_or_approval", "level": "error", "message": "no approval", "detail": null}],
        "next_actions": [],
    });
    for (file, valid) in [
        ("release-report.schema.json", &release),
        ("release-pr-intent.schema.json", &intent),
        ("doctor-report.schema.json", &doctor),
        ("init-outcome.schema.json", &init),
        ("migration-outcome.schema.json", &migration),
        ("candidate-verification.schema.json", &verification),
        ("command-envelope.schema.json", &envelope),
    ] {
        assert_matches(file, valid);
        let mut unknown = valid.clone();
        unknown["unexpected"] = json!(true);
        assert!(!violations(file, &unknown).is_empty(), "{file}");
    }

    let refused = [
        (
            "a release that leaves a required effect",
            "release-report.schema.json",
            with(&release, "/remaining/0/required", json!(true)),
        ),
        (
            "an approval wait that applied an effect",
            "release-report.schema.json",
            with(&release, "/state", json!("awaiting_approval")),
        ),
        (
            "an effect with an unknown kind",
            "release-report.schema.json",
            with(&release, "/applied/0/kind", json!("replace_package")),
        ),
        (
            "a Release PR URL that is not a URI",
            "release-pr-intent.schema.json",
            with(&intent, "/pr_url", json!("pull 7")),
        ),
        (
            "a bound intent without its Release PR",
            "release-pr-intent.schema.json",
            with(&intent, "/pr_url", Value::Null),
        ),
        (
            "an unbound intent that claims a plan",
            "release-pr-intent.schema.json",
            with(&intent, "/intent_binding", json!("unbound")),
        ),
        (
            "a blocked report without an error",
            "doctor-report.schema.json",
            with(&doctor, "/diagnostics/0/level", json!("warning")),
        ),
        (
            "a clean report with an error",
            "doctor-report.schema.json",
            with(&doctor, "/state", json!("up_to_date")),
        ),
        (
            "an init that reports no change while its workflow changed",
            "init-outcome.schema.json",
            with(&init, "/changed", json!(false)),
        ),
        (
            "a manifest diff for an unchanged manifest",
            "init-outcome.schema.json",
            with(&init, "/manifest_diff", json!("@@")),
        ),
        (
            "a migration that wrote an unchanged manifest",
            "migration-outcome.schema.json",
            with(&migration, "/changed", json!(false)),
        ),
        (
            "an init manifest path outside the repository",
            "init-outcome.schema.json",
            with(&init, "/manifest_path", json!("../gleam.toml")),
        ),
        (
            "an absolute migration path",
            "migration-outcome.schema.json",
            with(
                &migration,
                "/manifest_path",
                json!("/repository/gleam.toml"),
            ),
        ),
        (
            "a migration path on a Windows drive",
            "migration-outcome.schema.json",
            with(
                &migration,
                "/manifest_path",
                json!("C:/repository/gleam.toml"),
            ),
        ),
        (
            "a migration path with a Windows separator",
            "migration-outcome.schema.json",
            with(&migration, "/manifest_path", json!("packages\\gleam.toml")),
        ),
        (
            "a backup path through the current directory",
            "migration-outcome.schema.json",
            with(
                &migration,
                "/legacy_backup_path",
                json!("./.release-glz/legacy-gleam.toml"),
            ),
        ),
        (
            "a verified Candidate missing its digest",
            "candidate-verification.schema.json",
            without(&verification, "/candidate", "candidate_digest"),
        ),
        (
            "a verified Candidate whose registry URL is not a URI",
            "candidate-verification.schema.json",
            with(
                &verification,
                "/candidate/registry/api_url",
                json!("hex pm"),
            ),
        ),
        (
            "a failure without an error",
            "command-envelope.schema.json",
            with(&envelope, "/diagnostics/0/level", json!("info")),
        ),
        (
            "a success without a result",
            "command-envelope.schema.json",
            with(&envelope, "/ok", json!(true)),
        ),
    ];
    for (case, file, value) in refused {
        assert!(
            !violations(file, &value).is_empty(),
            "{file} accepted {case}"
        );
    }
}

/// `value` with the member at `pointer` replaced by `replacement`.
fn with(value: &Value, pointer: &str, replacement: Value) -> Value {
    let mut changed = value.clone();
    *changed
        .pointer_mut(pointer)
        .unwrap_or_else(|| panic!("no member at {pointer}")) = replacement;
    changed
}

/// `value` without the member `key` of the object at `pointer`.
fn without(value: &Value, pointer: &str, key: &str) -> Value {
    let mut changed = value.clone();
    changed
        .pointer_mut(pointer)
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("no object at {pointer}"))
        .remove(key)
        .unwrap_or_else(|| panic!("no member {key} at {pointer}"));
    changed
}

/// Every format identifier a `schema` field or constant in the Rust sources under `directory` names.
fn named_formats(directory: &Path) -> BTreeSet<String> {
    let mut formats = BTreeSet::new();
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            formats.extend(named_formats(&path));
            continue;
        }
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let source = fs::read_to_string(&path).unwrap();
        for prefix in ["schema: \"", "\"schema\": \"", "SCHEMA: &'static str = \""] {
            for (start, _) in source.match_indices(prefix) {
                let literal = &source[start + prefix.len()..];
                let identifier = &literal[..literal.find('"').unwrap()];
                if is_format_identifier(identifier) {
                    formats.insert(identifier.to_owned());
                }
            }
        }
    }
    formats
}

/// Whether `identifier` has the `name/vN` shape of a format identifier.
fn is_format_identifier(identifier: &str) -> bool {
    identifier.split_once("/v").is_some_and(|(name, version)| {
        name.starts_with(|first: char| first.is_ascii_lowercase())
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            && !version.is_empty()
            && version.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn assert_schema_surface(path: &str, title: &str, schema_id: &str, actual: serde_json::Value) {
    let schema: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["title"], title);
    assert_eq!(schema["properties"]["schema"]["const"], schema_id);
    assert_eq!(schema["additionalProperties"], false);
    let actual_keys = actual
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let property_keys = schema["properties"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let required_keys = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(property_keys, actual_keys, "{path}");
    assert_eq!(required_keys, actual_keys, "{path}");
}

fn hook_evidence() -> HookEvidence {
    HookEvidence {
        schema: "hook/v1".into(),
        id: "policy".into(),
        kind: HookKind::Verify,
        required: true,
        success: true,
        output_sha256: "1".repeat(64),
    }
}

fn candidate() -> CandidateManifest {
    let artifact = |path: &str, digit: char| SealedArtifact {
        path: path.into(),
        sha256: digit.to_string().repeat(64),
        semantic_sha256: digit.to_string().repeat(64),
        size: 1,
    };
    CandidateManifest {
        schema: "candidate/v1".into(),
        package: "widget".into(),
        version: Version::new(1, 2, 3),
        tag: "v1.2.3".into(),
        source: CandidateSource {
            commit_sha: "a".repeat(40),
            manifest_path: "gleam.toml".into(),
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
        release_notes: "notes".into(),
        approval: ApprovalConfig::default(),
        outputs: OutputConfig::default(),
        artifacts: CandidateArtifacts {
            package: artifact("artifacts/package.tar", '1'),
            docs: Some(artifact("artifacts/docs.tar.gz", '2')),
            package_interface: artifact("artifacts/package-interface.json", '3'),
        },
        verify_hook_definitions: vec![],
        sidecar_hook_definitions: vec![],
        hook_evidence: vec![],
        sidecars: vec![],
        notify_hooks: vec![],
        notify_hook_definitions: vec![],
        intent_digest: "4".repeat(64),
        candidate_digest: "5".repeat(64),
    }
}

fn plan() -> ReleasePlan {
    ReleasePlan {
        schema: ReleasePlan::SCHEMA.into(),
        state: ReleaseState::Planned,
        package: "widget".into(),
        manifest_path: "gleam.toml".into(),
        published_version: Some(Version::new(1, 0, 0)),
        manifest_version: Version::new(1, 0, 0),
        version: Version::new(1, 1, 0),
        bump: Bump::Minor,
        release_required: true,
        artifacts_changed: true,
        prerelease: None,
        tag: "v1.1.0".into(),
        baseline: Baseline {
            version: Some(Version::new(1, 0, 0)),
            git_ref: Some("v1.0.0".into()),
            sha: Some("a".repeat(40)),
            source: BaselineSource::Tag,
            retired: false,
        },
        reasons: vec![],
        api: ApiDiff::default(),
        changes: vec![],
        warnings: vec![],
        required_approvals: vec![],
        stages: vec![ReleaseStage::VerifyHooks],
        pr_url: None,
        release_pr_head: None,
        hex_url: None,
        github_release_url: None,
    }
}
