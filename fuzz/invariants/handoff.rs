//! Properties of the reader of a plan file that one job hands to another.
//!
//! An accepted file names schema `plan/v1` and no Release PR, and the bytes that `plan --out` writes for its plan read back as the same plan.
//! Each member of an accepted file is a member of that rendering, so the file differs from what `plan --out` writes only by members that take their default.
//! A refused file carries the handoff refusal that names what it got wrong, and reading bytes never refuses for a reason that needs a checkout.

use release_glz::handoff::{MAX_PLAN_BYTES, Refusal, parse};
use release_glz::model::ReleasePlan;
use serde_json::Value;

/// A verdict that accepted an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reached {
    Plan,
}

pub fn check(data: &[u8]) -> Vec<Reached> {
    let plan = match parse(data) {
        Ok(plan) => plan,
        Err(error) => {
            let refusal = error
                .downcast_ref::<Refusal>()
                .unwrap_or_else(|| panic!("not a handoff refusal: {error:#}"));
            assert_refusal_names_the_fault(refusal, data);
            return Vec::new();
        }
    };
    assert_eq!(plan.schema, ReleasePlan::SCHEMA);
    assert_eq!(plan.pr_url, None);
    assert_eq!(plan.release_pr_head, None);
    let rendered = serde_json::to_value(&plan).expect("a plan serializes");
    let written = serde_json::to_vec_pretty(&plan).expect("a plan serializes");
    let reread = parse(&written).expect("the plan file that `plan --out` writes reads back");
    assert_eq!(
        serde_json::to_value(&reread).expect("a plan serializes"),
        rendered
    );
    let file: Value = serde_json::from_slice(data).expect("an accepted plan file is JSON");
    assert!(
        is_within(&file, &rendered),
        "the plan file holds a member that `plan --out` never writes\n{file}"
    );
    vec![Reached::Plan]
}

fn assert_refusal_names_the_fault(refusal: &Refusal, data: &[u8]) {
    let too_large =
        u64::try_from(data.len()).expect("an input length fits in u64") > MAX_PLAN_BYTES;
    assert_eq!(matches!(refusal, Refusal::TooLarge), too_large, "{refusal}");
    let read = serde_json::from_slice::<ReleasePlan>(data);
    match refusal {
        Refusal::TooLarge => {}
        Refusal::NotAPlan(_) => {
            if let Ok(plan) = &read {
                let file: Value = serde_json::from_slice(data).expect("a read plan file is JSON");
                let rendered = serde_json::to_value(plan).expect("a plan serializes");
                assert!(!is_within(&file, &rendered), "{refusal}");
            }
        }
        Refusal::Schema(schema) => {
            let plan = read.expect("a plan of another schema is a plan document");
            assert_eq!(&plan.schema, schema);
            assert_ne!(schema, ReleasePlan::SCHEMA);
        }
        Refusal::ReleasePrNamed => {
            let plan = read.expect("a plan that names a Release PR is a plan document");
            assert_eq!(plan.schema, ReleasePlan::SCHEMA);
            assert!(plan.pr_url.is_some() || plan.release_pr_head.is_some());
        }
        Refusal::OtherManifest { .. } | Refusal::BaselineOutsideHistory(_) => {
            panic!("reading bytes refused for a reason that needs a checkout: {refusal}")
        }
    }
}

/// Whether every member of `file` is a member of `rendered` with the same value, at every depth.
fn is_within(file: &Value, rendered: &Value) -> bool {
    match (file, rendered) {
        (Value::Object(file), Value::Object(rendered)) => file.iter().all(|(name, value)| {
            rendered
                .get(name)
                .is_some_and(|rendered| is_within(value, rendered))
        }),
        (Value::Array(file), Value::Array(rendered)) => {
            file.len() == rendered.len()
                && file
                    .iter()
                    .zip(rendered)
                    .all(|(file, rendered)| is_within(file, rendered))
        }
        _ => file == rendered,
    }
}
