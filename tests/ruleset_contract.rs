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
fn default_branch_requires_reviewed_signed_linear_changes() {
    let ruleset = load(".github/rulesets/main.json");
    assert_eq!(ruleset["name"], "Protect main");
    assert_eq!(ruleset["target"], "branch");
    assert_eq!(ruleset["enforcement"], "active");
    assert_eq!(
        ruleset["bypass_actors"],
        json!([{
            "actor_id": 42543015,
            "actor_type": "User",
            "bypass_mode": "pull_request"
        }])
    );
    assert_eq!(
        ruleset["conditions"]["ref_name"],
        json!({"include": ["~DEFAULT_BRANCH"], "exclude": []})
    );

    for kind in [
        "deletion",
        "non_fast_forward",
        "required_linear_history",
        "required_signatures",
    ] {
        rule(&ruleset, kind);
    }

    let pull_request = &rule(&ruleset, "pull_request")["parameters"];
    assert_eq!(pull_request["allowed_merge_methods"], json!(["squash"]));
    assert_eq!(pull_request["dismiss_stale_reviews_on_push"], true);
    assert_eq!(pull_request["required_approving_review_count"], 1);
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
