//! Kani's JSON export of one run, and its audit with the committed inventory.
//!
//! The audit reads only what decides admission, and it keeps that part as evidence of every run.

use std::collections::BTreeSet;

use assurance_core::{ControlRun, ProofRun};
use serde::{Deserialize, Serialize};

use crate::inventory::{Control, Harness};

/// The version of Kani's export format that the audit reads.
pub const EXPORT_SCHEMA: &str = "1.0";
/// The Kani release that `verification/kani.Dockerfile` installs.
pub const KANI_VERSION: &str = "0.68.0";
/// The model checker that Kani 0.68.0 runs.
pub const CBMC_VERSION: &str = "6.11.0 (cbmc-6.11.0)";
/// The target every proof runs for.
pub const PROOF_TARGET: &str = "x86_64-unknown-linux-gnu";

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Metadata {
    version: String,
    kani_version: String,
    target: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Tools {
    kani: String,
    cbmc: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct HarnessAttributes {
    kind: String,
    should_panic: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct HarnessMetadata {
    pretty_name: String,
    crate_name: String,
    attributes: HarnessAttributes,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Summary {
    total_harnesses: usize,
    executed: usize,
    status: String,
    successful: usize,
    failed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
enum CheckStatus {
    Success,
    Failure,
    Unreachable,
    Undetermined,
    Satisfied,
    Unsatisfiable,
    SolverError,
    Covered,
    Uncovered,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Check {
    id: usize,
    function: String,
    status: CheckStatus,
    category: String,
    description: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct HarnessResult {
    harness_id: String,
    status: CheckStatus,
    checks: Vec<Check>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct PropertyCounts {
    total_properties: usize,
    passed: usize,
    failed: usize,
    unreachable: usize,
    undetermined: usize,
    solver_error: usize,
    satisfied: usize,
    unsatisfiable: usize,
    covered: usize,
    uncovered: usize,
}

impl PropertyCounts {
    fn of(checks: &[Check]) -> Self {
        let count = |status| checks.iter().filter(|check| check.status == status).count();
        Self {
            total_properties: checks.len(),
            passed: count(CheckStatus::Success),
            failed: count(CheckStatus::Failure),
            unreachable: count(CheckStatus::Unreachable),
            undetermined: count(CheckStatus::Undetermined),
            solver_error: count(CheckStatus::SolverError),
            satisfied: count(CheckStatus::Satisfied),
            unsatisfiable: count(CheckStatus::Unsatisfiable),
            covered: count(CheckStatus::Covered),
            uncovered: count(CheckStatus::Uncovered),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PropertySummary {
    harness_id: String,
    property_details: PropertyCounts,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ErrorDetails {
    harness_id: String,
    has_errors: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failed_properties_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exit_status: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct VerificationResults {
    summary: Summary,
    results: Vec<HarnessResult>,
}

/// The part of Kani's export that decides admission.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProofReport {
    metadata: Metadata,
    tools: Tools,
    harness_metadata: Vec<HarnessMetadata>,
    error_details: Vec<ErrorDetails>,
    property_details: Vec<PropertySummary>,
    verification_results: VerificationResults,
}

/// The crates whose harnesses a run may report.
const PROOF_CRATES: [&str; 2] = ["release_glz_core", "assurance_core"];

impl ProofReport {
    fn tools_valid(&self) -> bool {
        self.metadata.version == EXPORT_SCHEMA
            && self.metadata.kani_version == KANI_VERSION
            && self.metadata.target == PROOF_TARGET
            && self.tools.kani == KANI_VERSION
            && self.tools.cbmc == CBMC_VERSION
            && self.harness_metadata.iter().all(|harness| {
                PROOF_CRATES.contains(&harness.crate_name.as_str())
                    && harness.attributes.kind == "Proof"
                    && !harness.attributes.should_panic
            })
    }

    /// Whether every section of the report names exactly `names`, once each.
    fn names_exactly(&self, names: &BTreeSet<&str>) -> bool {
        let exact = |listed: Vec<&str>| {
            listed.len() == names.len() && listed.into_iter().collect::<BTreeSet<_>>() == *names
        };
        exact(
            self.harness_metadata
                .iter()
                .map(|harness| harness.pretty_name.as_str())
                .collect(),
        ) && exact(
            self.verification_results
                .results
                .iter()
                .map(|result| result.harness_id.as_str())
                .collect(),
        ) && exact(
            self.error_details
                .iter()
                .map(|error| error.harness_id.as_str())
                .collect(),
        ) && exact(
            self.property_details
                .iter()
                .map(|summary| summary.harness_id.as_str())
                .collect(),
        )
    }

    /// Whether the property counts of `result` are the ones its checks add up to.
    fn counts_consistent(&self, result: &HarnessResult) -> bool {
        self.property_details.iter().any(|summary| {
            summary.harness_id == result.harness_id
                && summary.property_details == PropertyCounts::of(&result.checks)
        })
    }

    fn result(&self, name: &str) -> Option<&HarnessResult> {
        self.verification_results
            .results
            .iter()
            .find(|result| result.harness_id == name)
    }

    fn errors(&self, name: &str) -> Option<&ErrorDetails> {
        self.error_details
            .iter()
            .find(|error| error.harness_id == name)
    }

    /// The harnesses of this report that the audit wouldn't admit: one that failed, has errors, or doesn't meet its listed covers and owned assertions, and one that `inventory` doesn't list.
    pub fn unproved(&self, inventory: &[Harness]) -> Vec<String> {
        self.verification_results
            .results
            .iter()
            .filter(|result| {
                let listed = inventory
                    .iter()
                    .find(|harness| harness.name == result.harness_id);
                let clean = self
                    .errors(&result.harness_id)
                    .is_some_and(|errors| !errors.has_errors);
                !(clean && listed.is_some_and(|harness| proved(result, harness)))
            })
            .map(|result| result.harness_id.clone())
            .collect()
    }

    /// The number of harnesses that the run executed.
    pub fn executed(&self) -> usize {
        self.verification_results.summary.executed
    }

    /// What this report of a run of every harness shows, before the exit status, logs, and source binding are known.
    pub fn audit_proofs(&self, expected: &[Harness]) -> ProofRun {
        let names = expected
            .iter()
            .map(|harness| harness.name)
            .collect::<BTreeSet<_>>();
        let properties_valid = self.tools_valid()
            && names.len() == expected.len()
            && expected.iter().all(|harness| {
                self.result(harness.name)
                    .is_some_and(|result| proved(result, harness) && self.counts_consistent(result))
                    && self.errors(harness.name).is_some_and(|errors| {
                        !errors.has_errors
                            && errors.error_type.is_none()
                            && errors.failed_properties_type.is_none()
                            && errors.exit_status.is_none()
                    })
            });
        let summary = &self.verification_results.summary;
        ProofRun {
            expected: expected.len(),
            total: summary.total_harnesses,
            executed: summary.executed,
            verified: summary.successful,
            failed: summary.failed,
            completed: summary.status == "completed",
            inventory_matches: self.names_exactly(&names),
            properties_valid,
            logs_supported: false,
            source_matches: false,
        }
    }

    /// What this report of a run of `control` shows, before the logs and source binding are known.
    pub fn audit_control(&self, control: &Control) -> ControlRun {
        let summary = &self.verification_results.summary;
        let result = self.result(control.harness);
        let failed_as_expected = result.is_some_and(|result| {
            let failures = result
                .checks
                .iter()
                .filter(|check| check.status == CheckStatus::Failure)
                .collect::<Vec<_>>();
            result.status == CheckStatus::Failure
                && !failures.is_empty()
                && failures.iter().all(|check| {
                    check.category == "assertion"
                        && check.function == control.harness
                        && check.description == control.assertion
                })
        }) && self.errors(control.harness).is_some_and(|errors| {
            errors.has_errors
                && errors.error_type.as_deref() == Some("assertion_failure")
                && errors.failed_properties_type.as_deref() == Some("PanicsOnly")
                && errors.exit_status.as_deref() == Some("properties_failed")
        });
        let checks_resolved = result.is_some_and(|result| {
            self.counts_consistent(result)
                && result.checks.iter().all(|check| {
                    matches!(
                        check.status,
                        CheckStatus::Success
                            | CheckStatus::Failure
                            | CheckStatus::Unreachable
                            | CheckStatus::Satisfied
                            | CheckStatus::Unsatisfiable
                    )
                })
        });
        ControlRun {
            total: summary.total_harnesses,
            failed: summary.failed,
            completed: summary.status == "completed" && summary.executed == 1,
            harness_matches: self.names_exactly(&BTreeSet::from([control.harness])),
            failed_as_expected,
            checks_resolved,
            tools_valid: self.tools_valid(),
            logs_supported: false,
            source_matches: false,
        }
    }
}

/// Whether `result` proves `harness`: every owned assertion succeeded, exactly its covers were satisfied, and nothing else failed, stayed undetermined, or covered nothing.
fn proved(result: &HarnessResult, harness: &Harness) -> bool {
    let owned = result
        .checks
        .iter()
        .filter(|check| check.category == "assertion" && check.function == harness.name)
        .collect::<Vec<_>>();
    let covers = result
        .checks
        .iter()
        .filter(|check| check.category == "cover")
        .collect::<Vec<_>>();
    let ids = result
        .checks
        .iter()
        .map(|check| check.id)
        .collect::<BTreeSet<_>>();
    result.status == CheckStatus::Success
        && ids.len() == result.checks.len()
        && result
            .checks
            .iter()
            .all(|check| !check.description.is_empty() && !check.category.is_empty())
        && !owned.is_empty()
        && owned
            .iter()
            .all(|check| check.status == CheckStatus::Success)
        && harness.covers > 0
        && covers.len() == harness.covers
        && covers
            .iter()
            .all(|check| check.status == CheckStatus::Satisfied)
        && result.checks.iter().all(|check| match check.status {
            CheckStatus::Success | CheckStatus::Unreachable => check.category != "cover",
            CheckStatus::Satisfied => check.category == "cover",
            _ => false,
        })
}

/// Whether the logs of a run show no value that Kani replaced with an arbitrary one.
///
/// Kani turns each unsupported construct into a check that fails when the construct is reachable, and the audit refuses any such failure, so its warning that a construct exists decides nothing.
pub fn logs_supported(stdout: &str, stderr: &str) -> bool {
    const UNSOUND_DIAGNOSTICS: [&str; 2] =
        ["not enough arguments", "inserting non-deterministic value"];
    [stdout, stderr].iter().all(|log| {
        !UNSOUND_DIAGNOSTICS
            .iter()
            .any(|message| log.contains(message))
    })
}

#[cfg(test)]
mod tests {
    use assurance_core::{Admission, admit_control, admit_proofs};
    use serde_json::Value;

    use super::{KANI_VERSION, ProofReport, PropertyCounts, logs_supported};
    use crate::inventory::{Control, Harness};

    /// The audited part of a real run of every harness by the pinned Kani.
    ///
    /// The tests audit it with the inventory it was a run of, so a harness added later leaves them unchanged, and the release gate audits every live run with the live inventory.
    const PROOFS: &str = include_str!("../tests/fixtures/kani.json");
    /// The audited part of a real run of [`CONTROL`].
    const CONTROL_RUN: &str = include_str!("../tests/fixtures/kani-control.json");

    /// The harness of the recorded run whose report the tests tamper with.
    const HARNESS: &str =
        "proofs::a_proof_run_is_admitted_only_when_every_expected_harness_verified";

    /// The negative control of the recorded control run.
    const CONTROL: Control = Control {
        package: "assurance-core",
        feature: "negative-control-incomplete-run",
        harness: HARNESS,
        assertion: "a proof run must complete before admission",
    };

    /// The inventory the recorded run was a run of: each harness it reports, with the covers it checked.
    fn recorded_inventory() -> Vec<Harness> {
        let report: ProofReport = serde_json::from_str(PROOFS).unwrap();
        report
            .verification_results
            .results
            .iter()
            .map(|result| Harness {
                name: Box::leak(result.harness_id.clone().into_boxed_str()),
                covers: result
                    .checks
                    .iter()
                    .filter(|check| check.category == "cover")
                    .count(),
            })
            .collect()
    }

    fn proofs_admitted(report: &Value) -> bool {
        let report: ProofReport = serde_json::from_value(report.clone()).unwrap();
        let mut run = report.audit_proofs(&recorded_inventory());
        run.logs_supported = true;
        run.source_matches = true;
        admit_proofs(Some(0), run) == Admission::Admit
    }

    fn control_admitted(report: &Value) -> bool {
        let report: ProofReport = serde_json::from_value(report.clone()).unwrap();
        let mut run = report.audit_control(&CONTROL);
        run.logs_supported = true;
        run.source_matches = true;
        admit_control(Some(1), run) == Admission::Admit
    }

    fn proofs() -> Value {
        serde_json::from_str(PROOFS).unwrap()
    }

    fn control_run() -> Value {
        serde_json::from_str(CONTROL_RUN).unwrap()
    }

    /// The checks Kani reported for `harness`.
    fn checks<'a>(report: &'a mut Value, harness: &str) -> &'a mut Vec<Value> {
        report["verification_results"]["results"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|result| result["harness_id"] == harness)
            .unwrap()["checks"]
            .as_array_mut()
            .unwrap()
    }

    /// The first check of `harness` that `select` picks.
    fn check<'a>(
        report: &'a mut Value,
        harness: &str,
        select: impl Fn(&Value) -> bool,
    ) -> &'a mut Value {
        checks(report, harness)
            .iter_mut()
            .find(|check| select(check))
            .unwrap()
    }

    /// Rewrite the property counts of every harness from its checks, as Kani would have reported them for those checks.
    ///
    /// A tampered report then differs from a real one only in the property under test.
    fn recount(report: &mut Value) {
        let parsed: ProofReport = serde_json::from_value(report.clone()).unwrap();
        for result in &parsed.verification_results.results {
            let counts = serde_json::to_value(PropertyCounts::of(&result.checks)).unwrap();
            report["property_details"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .filter(|summary| summary["harness_id"] == result.harness_id.as_str())
                .for_each(|summary| summary["property_details"] = counts.clone());
        }
    }

    /// Picks one kind of check in a harness's report.
    type Selection<'a> = &'a dyn Fn(&Value) -> bool;

    fn owned_assertion(harness: &str) -> impl Fn(&Value) -> bool {
        move |check| check["category"] == "assertion" && check["function"] == harness
    }

    fn cover(check: &Value) -> bool {
        check["category"] == "cover"
    }

    #[test]
    fn the_recorded_runs_are_admitted() {
        assert!(proofs_admitted(&proofs()));
        assert!(control_admitted(&control_run()));
        let mut recounted = proofs();
        recount(&mut recounted);
        assert_eq!(recounted, proofs(), "the fixture's counts are Kani's own");
    }

    #[test]
    fn counts_that_differ_from_the_checks_are_refused() {
        let mut report = proofs();
        report["property_details"][0]["property_details"]["passed"] = serde_json::json!(0);
        assert!(!proofs_admitted(&report));
        let mut report = control_run();
        report["property_details"][0]["property_details"]["failed"] = serde_json::json!(0);
        assert!(!control_admitted(&report));
    }

    #[test]
    fn a_wrong_summary_count_or_an_incomplete_run_is_refused() {
        for (field, value) in [
            ("total_harnesses", serde_json::json!(0)),
            ("executed", serde_json::json!(3)),
            ("successful", serde_json::json!(2)),
            ("failed", serde_json::json!(1)),
            ("status", serde_json::json!("incomplete")),
        ] {
            let mut report = proofs();
            report["verification_results"]["summary"][field] = value;
            assert!(!proofs_admitted(&report), "admitted a summary with {field}");
        }
    }

    #[test]
    fn a_missing_duplicated_or_unregistered_harness_is_refused() {
        for section in ["harness_metadata", "error_details", "property_details"] {
            let mut report = proofs();
            let entries = report[section].as_array_mut().unwrap();
            let entry = entries.pop().unwrap();
            assert!(
                !proofs_admitted(&report),
                "admitted a missing {section} entry"
            );
            let entries = report[section].as_array_mut().unwrap();
            entries.push(entry.clone());
            entries.push(entry);
            assert!(
                !proofs_admitted(&report),
                "admitted a duplicated {section} entry"
            );
        }
        let mut report = proofs();
        report["verification_results"]["results"][0]["harness_id"] =
            serde_json::json!("proofs::unregistered");
        assert!(!proofs_admitted(&report));
    }

    #[test]
    fn an_unresolved_unreachable_or_vacuous_property_is_refused() {
        let harness = HARNESS;
        let owned = owned_assertion(harness);
        let library = |check: &Value| {
            check["category"] != "cover"
                && check["function"] != harness
                && check["status"] == "Success"
        };
        let selections: [(&str, Selection<'_>); 3] = [
            ("an owned assertion", &owned),
            ("a cover", &cover),
            ("a library check", &library),
        ];
        for (what, select) in selections {
            for status in [
                "Failure",
                "Unreachable",
                "Undetermined",
                "Satisfied",
                "Unsatisfiable",
                "SolverError",
                "Covered",
                "Uncovered",
            ] {
                let mut report = proofs();
                let check = check(&mut report, harness, select);
                if check["status"] == status
                    || (what == "a library check" && status == "Unreachable")
                {
                    continue;
                }
                check["status"] = serde_json::json!(status);
                recount(&mut report);
                assert!(
                    !proofs_admitted(&report),
                    "admitted {what} with status {status}"
                );
            }
        }
    }

    #[test]
    fn a_harness_without_its_listed_covers_or_owned_assertions_is_refused() {
        let harness = HARNESS;
        for select in [&cover as Selection<'_>, &owned_assertion(harness)] {
            let mut report = proofs();
            let checks = checks(&mut report, harness);
            checks.retain(|check| !select(check));
            recount(&mut report);
            assert!(!proofs_admitted(&report));
        }
        let mut report = proofs();
        let extra = check(&mut report, harness, cover).clone();
        let checks = checks(&mut report, harness);
        let id = checks
            .iter()
            .filter_map(|check| check["id"].as_u64())
            .max()
            .unwrap()
            + 1;
        checks.push(extra);
        checks.last_mut().unwrap()["id"] = serde_json::json!(id);
        recount(&mut report);
        assert!(!proofs_admitted(&report), "admitted an unlisted cover");
    }

    #[test]
    fn a_duplicated_check_id_or_an_empty_description_is_refused() {
        let harness = HARNESS;
        let mut report = proofs();
        let checks = checks(&mut report, harness);
        let first = checks[0]["id"].clone();
        checks[1]["id"] = first;
        assert!(!proofs_admitted(&report));
        let mut report = proofs();
        check(&mut report, harness, |_| true)["description"] = serde_json::json!("");
        assert!(!proofs_admitted(&report));
    }

    #[test]
    fn a_harness_with_errors_is_refused() {
        for (field, value) in [
            ("has_errors", serde_json::json!(true)),
            ("error_type", serde_json::json!("assertion_failure")),
            ("failed_properties_type", serde_json::json!("PanicsOnly")),
            ("exit_status", serde_json::json!("properties_failed")),
        ] {
            let mut report = proofs();
            report["error_details"][0][field] = value;
            assert!(!proofs_admitted(&report), "admitted an error with {field}");
        }
    }

    #[test]
    fn another_tool_version_target_or_an_expected_panic_is_refused() {
        for (path, value) in [
            (&["metadata", "kani_version"][..], "0.67.0"),
            (&["tools", "kani"][..], "0.67.0"),
            (&["tools", "cbmc"][..], "6.10.0 (cbmc-6.10.0)"),
            (&["metadata", "target"][..], "aarch64-unknown-linux-gnu"),
        ] {
            let mut report = proofs();
            let mut field = &mut report;
            for key in path {
                field = &mut field[*key];
            }
            *field = serde_json::json!(value);
            assert!(!proofs_admitted(&report), "admitted {path:?} = {value}");
        }
        let mut report = proofs();
        report["harness_metadata"][0]["attributes"]["should_panic"] = serde_json::json!(true);
        assert!(!proofs_admitted(&report));
    }

    #[test]
    fn a_negative_control_must_fail_only_its_expected_assertion() {
        let harness = CONTROL.harness;
        let failed = |check: &Value| check["status"] == "Failure";

        let mut report = control_run();
        check(&mut report, harness, failed)["status"] = serde_json::json!("Success");
        recount(&mut report);
        assert!(
            !control_admitted(&report),
            "admitted a control that failed nothing"
        );

        let mut report = control_run();
        check(&mut report, harness, |check| {
            check["status"] == "Success" && check["category"] != "cover"
        })["status"] = serde_json::json!("Failure");
        recount(&mut report);
        assert!(
            !control_admitted(&report),
            "admitted a control that failed elsewhere"
        );

        let mut report = control_run();
        check(&mut report, harness, failed)["description"] = serde_json::json!("another assertion");
        assert!(
            !control_admitted(&report),
            "admitted another failed assertion"
        );

        for status in ["Undetermined", "SolverError", "Covered", "Uncovered"] {
            let mut report = control_run();
            check(&mut report, harness, |check| check["status"] == "Success")["status"] =
                serde_json::json!(status);
            recount(&mut report);
            assert!(
                !control_admitted(&report),
                "admitted an unresolved {status} check"
            );
        }

        for (field, value) in [
            ("error_type", "unwinding_assertion_failure"),
            ("failed_properties_type", "Other"),
            ("exit_status", "timeout"),
        ] {
            let mut report = control_run();
            report["error_details"][0][field] = serde_json::json!(value);
            assert!(
                !control_admitted(&report),
                "admitted an error with {field} {value}"
            );
        }

        let mut report = control_run();
        report["verification_results"]["summary"]["executed"] = serde_json::json!(2);
        assert!(
            !control_admitted(&report),
            "admitted a control run of two harnesses"
        );

        let report: ProofReport = serde_json::from_value(control_run()).unwrap();
        let mut run = report.audit_control(&CONTROL);
        run.logs_supported = true;
        run.source_matches = true;
        for exit in [None, Some(0), Some(124), Some(137)] {
            assert_ne!(admit_control(exit, run), Admission::Admit, "exit {exit:?}");
        }
    }

    #[test]
    fn a_run_whose_logs_show_an_unsupported_construct_is_refused() {
        assert!(logs_supported(
            "VERIFICATION:- SUCCESSFUL",
            "warning: unused"
        ));
        assert!(logs_supported(
            "warning: Found the following unsupported constructs:\n - caller_location (1)",
            " - Description: \"Kani does not support reasoning about pointer to unallocated memory\""
        ));
        for diagnostic in ["not enough arguments", "inserting non-deterministic value"] {
            assert!(!logs_supported(diagnostic, ""));
            assert!(!logs_supported("", diagnostic));
        }
    }

    /// The image and the audit name the same Kani release, so a version bump has to change both.
    #[test]
    fn the_image_installs_the_kani_release_the_audit_expects() {
        let dockerfile = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../verification/kani.Dockerfile"),
        )
        .unwrap();
        assert!(dockerfile.contains(&format!("kani-verifier --version {KANI_VERSION}")));
    }
}
