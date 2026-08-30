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
    assert_eq!(ruleset["name"], "Protect main");
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
            "pull_request",
            "required_status_checks"
        ]
    );

    let pull_request = &rule(&ruleset, "pull_request")["parameters"];
    assert_eq!(pull_request["allowed_merge_methods"], json!(["squash"]));
    assert_eq!(pull_request["dismiss_stale_reviews_on_push"], false);
    assert_eq!(pull_request["required_approving_review_count"], 0);
    assert_eq!(pull_request["required_review_thread_resolution"], true);

    let checks = &rule(&ruleset, "required_status_checks")["parameters"];
    assert_eq!(checks["strict_required_status_checks_policy"], true);
    assert_eq!(
        checks["required_status_checks"],
        json!([
            {"context": "Required CI", "integration_id": 15368},
            {"context": "CodeRabbit", "integration_id": 347564}
        ])
    );
}

#[test]
fn release_tags_are_immutable_after_creation() {
    let ruleset = load(".github/rulesets/release-tags.json");
    assert_eq!(ruleset["name"], "Protect release tags");
    assert_eq!(ruleset["target"], "tag");
    assert_eq!(ruleset["enforcement"], "active");
    assert_eq!(ruleset["bypass_actors"], json!([]));
    assert_eq!(
        ruleset["conditions"]["ref_name"],
        json!({"include": ["refs/tags/v*"], "exclude": []})
    );
    rule(&ruleset, "deletion");
    rule(&ruleset, "non_fast_forward");
    assert_eq!(ruleset["rules"].as_array().unwrap().len(), 2);
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
