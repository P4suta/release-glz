use std::fs;

use serde_json::{Value, json};

fn load(path: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn rule<'a>(ruleset: &'a Value, kind: &str) -> &'a Value {
    ruleset["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["type"] == kind)
        .unwrap_or_else(|| panic!("missing `{kind}` rule"))
}

#[test]
fn default_branch_requires_checked_linear_changes() {
    let ruleset = load(".github/rulesets/main.json");
    assert_eq!(ruleset["name"], "main");
    assert_eq!(ruleset["target"], "branch");
    assert_eq!(ruleset["enforcement"], "active");
    assert_eq!(ruleset["bypass_actors"], json!([]));
    assert_eq!(
        ruleset["conditions"]["ref_name"],
        json!({"include": ["~DEFAULT_BRANCH"], "exclude": []})
    );

    let rule_types = ruleset["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule["type"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        rule_types,
        [
            "deletion",
            "non_fast_forward",
            "required_linear_history",
            "required_signatures",
            "pull_request",
            "required_status_checks"
        ]
    );

    let pull_request = &rule(&ruleset, "pull_request")["parameters"];
    assert_eq!(pull_request["allowed_merge_methods"], json!(["squash"]));
    assert_eq!(pull_request["dismiss_stale_reviews_on_push"], true);
    assert_eq!(pull_request["required_approving_review_count"], 0);
    assert_eq!(pull_request["required_review_thread_resolution"], true);

    let checks = &rule(&ruleset, "required_status_checks")["parameters"];
    assert_eq!(checks["strict_required_status_checks_policy"], true);
    assert_eq!(
        checks["required_status_checks"],
        json!([{"context": "required", "integration_id": 15368}])
    );
}

#[test]
fn the_required_check_is_the_ci_job_that_aggregates_every_selected_check() {
    let ruleset = load(".github/rulesets/main.json");
    let contexts = rule(&ruleset, "required_status_checks")["parameters"]["required_status_checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|check| check["context"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let ci: serde_norway::Value =
        serde_norway::from_str(&fs::read_to_string(".github/workflows/ci.yml").unwrap()).unwrap();
    let job_names = ci["jobs"]
        .as_mapping()
        .unwrap()
        .values()
        .filter_map(|job| job["name"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    for context in contexts {
        assert!(
            job_names.contains(&context),
            "the ruleset requires `{context}`, which no CI job reports"
        );
    }
}

#[test]
fn release_tags_are_immutable_after_creation() {
    let ruleset = load(".github/rulesets/release-tags.json");
    assert_eq!(ruleset["name"], "release tags");
    assert_eq!(ruleset["target"], "tag");
    assert_eq!(ruleset["enforcement"], "active");
    assert_eq!(ruleset["bypass_actors"], json!([]));
    assert_eq!(
        ruleset["conditions"]["ref_name"],
        json!({"include": ["refs/tags/v*"], "exclude": []})
    );
    rule(&ruleset, "deletion");
    rule(&ruleset, "non_fast_forward");
    rule(&ruleset, "update");
    assert_eq!(ruleset["rules"].as_array().unwrap().len(), 3);
}

#[test]
fn repository_policy_records_the_solo_review_tradeoff_and_real_checksum_path() {
    let policy = fs::read_to_string("docs/repository-rulesets.md").unwrap();
    assert!(policy.contains("## Accepted solo-maintainer risk"));
    assert!(policy.contains("no independent human approval"));

    let readiness = fs::read_to_string("docs/release-readiness.md").unwrap();
    assert!(readiness.contains("`action/checksums.json` contains"));
    assert!(!readiness.contains("`action-checksums.json` contains"));
}
