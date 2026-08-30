use release_glz::model::{
    ApiDiff, ApprovalKind, ApprovalRequirement, Baseline, BaselineSource, Bump, ReleasePlan,
    ReleaseStage, ReleaseState,
};
use semver::Version;
use serde_json::json;

#[test]
fn release_plan_uses_the_independently_versioned_v2_contract() {
    let plan = ReleasePlan {
        schema: "plan/v2".into(),
        state: ReleaseState::Planned,
        package: "widget".into(),
        manifest_path: "packages/widget/gleam.toml".into(),
        published_version: Some(Version::new(0, 4, 0)),
        manifest_version: Version::new(0, 4, 0),
        version: Version::new(0, 5, 0),
        bump: Bump::Minor,
        release_required: true,
        artifacts_changed: true,
        prerelease: None,
        tag: "widget-v0.5.0".into(),
        baseline: Baseline {
            version: Some(Version::new(0, 4, 0)),
            git_ref: Some("widget-v0.4.0".into()),
            sha: Some("a".repeat(40)),
            source: BaselineSource::Tag,
            retired: false,
        },
        reasons: vec![],
        api: ApiDiff::default(),
        changes: vec![],
        warnings: vec![],
        required_approvals: vec![
            ApprovalRequirement {
                kind: ApprovalKind::ReleasePr,
                environment: None,
            },
            ApprovalRequirement {
                kind: ApprovalKind::Environment,
                environment: Some("release".into()),
            },
        ],
        stages: vec![ReleaseStage::VerifyHooks, ReleaseStage::PublishPackage],
        intent_digest: Some("0".repeat(64)),
        pr_url: None,
        hex_url: Some("https://hex.pm/packages/widget/0.5.0".into()),
        github_release_url: None,
    };
    let value = serde_json::to_value(plan).unwrap();
    assert_eq!(value["schema"], "plan/v2");
    assert_eq!(value["state"], "planned");
    assert_eq!(value["manifest_path"], "packages/widget/gleam.toml");
    assert_eq!(
        value["required_approvals"],
        json!([
            {"kind": "release_pr", "environment": null},
            {"kind": "environment", "environment": "release"}
        ])
    );
    assert!(value.get("schema_version").is_none());
    assert!(value.get("released").is_none());
}
