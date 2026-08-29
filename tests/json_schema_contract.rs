use std::collections::BTreeSet;
use std::fs;

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
use semver::Version;

#[test]
fn checked_in_plan_schema_exactly_covers_the_serialized_v2_surface() {
    let schema: serde_json::Value =
        serde_json::from_str(&fs::read_to_string("docs/release-plan.schema.json").unwrap())
            .unwrap();
    assert_eq!(schema["title"], "release-glz ReleasePlan v2");
    assert_eq!(schema["properties"]["schema"]["const"], "plan/v2");
    assert_eq!(schema["additionalProperties"], false);

    let actual = serde_json::to_value(plan()).unwrap();
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
    assert_eq!(property_keys, actual_keys);
    assert_eq!(required_keys, actual_keys);
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
        serde_json::to_value(HookEvidence {
            schema: "hook/v1".into(),
            id: "policy".into(),
            kind: HookKind::Verify,
            required: true,
            success: true,
            output_sha256: "1".repeat(64),
        })
        .unwrap(),
    );
    assert_schema_surface(
        "docs/command-envelope.schema.json",
        "release-glz Command Envelope v2",
        "command/v2",
        serde_json::to_value(CommandEnvelope::success(
            "plan",
            serde_json::json!({"schema": "plan/v2"}),
            vec![],
            vec![],
        ))
        .unwrap(),
    );
}

#[test]
fn every_public_serializer_validates_against_its_complete_draft_2020_schema() {
    let mut cases = vec![
        (
            "docs/release-plan.schema.json",
            serde_json::to_value(plan()).unwrap(),
        ),
        (
            "docs/candidate.schema.json",
            serde_json::to_value(candidate()).unwrap(),
        ),
        (
            "docs/release-state.schema.json",
            serde_json::to_value(ExternalReleaseState::default()).unwrap(),
        ),
        (
            "docs/hook.schema.json",
            serde_json::to_value(HookEvidence {
                schema: "hook/v1".into(),
                id: "policy".into(),
                kind: HookKind::Verify,
                required: true,
                success: true,
                output_sha256: "1".repeat(64),
            })
            .unwrap(),
        ),
        (
            "docs/command-envelope.schema.json",
            serde_json::to_value(CommandEnvelope::success(
                "plan",
                serde_json::json!({"schema": "plan/v2"}),
                vec![],
                vec![],
            ))
            .unwrap(),
        ),
    ];
    for (path, actual) in &cases {
        let schema: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        let validator = jsonschema::validator_for(&schema)
            .unwrap_or_else(|error| panic!("invalid schema {path}: {error}"));
        if let Err(error) = validator.validate(actual) {
            panic!("{path} rejected its serializer: {error}");
        }
    }

    let (path, candidate) = &mut cases[1];
    candidate["registry"]["unexpected"] = serde_json::json!(true);
    let schema: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(!validator.is_valid(candidate));
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
        intent_digest: None,
        pr_url: None,
        hex_url: None,
        github_release_url: None,
    }
}
