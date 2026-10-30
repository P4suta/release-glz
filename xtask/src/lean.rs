//! Lean theorems about the publication model, tied to the core crate by complete refinement vectors.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use release_glz_core::{Decision, Object, Outcome, Presence, ReleaseState, reconcile};

use crate::container::{Container, Failure};

/// The Lean release that `verification/lean.Dockerfile` installs.
const LEAN_VERSION: &str = "4.35.0";

/// The theorems of the publication model, which the axiom audit expects in this order.
pub(crate) const MODEL_THEOREMS: [&str; 9] = [
    "ReleaseGlz.create_means_missing",
    "ReleaseGlz.conflict_iff_differs",
    "ReleaseGlz.effect_concerns_missing_object",
    "ReleaseGlz.differing_object_conflicts",
    "ReleaseGlz.no_effect_without_approval",
    "ReleaseGlz.effects_within_objects",
    "ReleaseGlz.publishing_removes_exactly_that_effect",
    "ReleaseGlz.publishing_shortens_the_plan",
    "ReleaseGlz.released_iff_no_blocking_effect",
];

/// The refinement theorems, which compare the model with the core crate on every listed input.
pub(crate) const REFINEMENT_THEOREMS: [&str; 2] = [
    "ReleaseGlz.Refinement.decision_refines_rust",
    "ReleaseGlz.Refinement.reconcile_refines_rust",
];

/// The axioms a theorem may depend on, which Lean's kernel and standard library assume.
const ALLOWED_AXIOMS: [&str; 3] = ["propext", "Classical.choice", "Quot.sound"];

/// The longest object list whose reconcile outcome the vectors compare.
const VECTOR_OBJECTS: usize = 2;

const PRESENCES: [Presence; 4] = [
    Presence::Absent,
    Presence::Pending,
    Presence::Matches,
    Presence::Differs,
];

/// Every object the core can decide about.
fn objects() -> Vec<Object> {
    let mut objects = Vec::new();
    for wanted in [false, true] {
        for presence in PRESENCES {
            for blocking in [false, true] {
                objects.push(Object {
                    wanted,
                    presence,
                    blocking,
                });
            }
        }
    }
    objects
}

/// Every list of at most `length` objects.
fn lists(length: usize) -> Vec<Vec<Object>> {
    let mut lists = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..length {
        let mut next = Vec::new();
        for list in &frontier {
            for object in objects() {
                let mut longer: Vec<Object> = list.clone();
                longer.push(object);
                next.push(longer);
            }
        }
        lists.extend(next.iter().cloned());
        frontier = next;
    }
    lists
}

fn lean_presence(presence: Presence) -> &'static str {
    match presence {
        Presence::Absent => ".absent",
        Presence::Pending => ".pending",
        Presence::Matches => ".matches",
        Presence::Differs => ".differs",
    }
}

fn lean_object(object: Object) -> String {
    format!(
        "⟨{}, {}, {}⟩",
        object.wanted,
        lean_presence(object.presence),
        object.blocking
    )
}

fn lean_decision(decision: Decision) -> &'static str {
    match decision {
        Decision::Create => ".create",
        Decision::Keep => ".keep",
        Decision::Conflict => ".conflict",
    }
}

fn lean_outcome(outcome: Outcome<'_>) -> Result<String, Failure> {
    Ok(match outcome {
        Outcome::Conflict(index) => format!(".conflict {index}"),
        Outcome::AwaitingApproval => ".awaitingApproval".into(),
        Outcome::Proceed { state, effects } => {
            let state = match state {
                ReleaseState::Released => ".released",
                ReleaseState::PartiallyReleased => ".partiallyReleased",
                ReleaseState::CandidateReady => ".candidateReady",
                other => return Err(Failure::new(format!("the core reported state {other:?}"))),
            };
            let effects = effects.map(|index| index.to_string()).collect::<Vec<_>>();
            format!(".proceed {state} [{}]", effects.join(", "))
        }
    })
}

/// The Lean module that compares the model with the core crate on every object and every list of at most [`VECTOR_OBJECTS`] objects.
pub fn refinement() -> Result<String, Failure> {
    let mut source = String::from(
        "import Publication\n\nset_option autoImplicit false\nset_option maxRecDepth 100000\n\nnamespace ReleaseGlz.Refinement\n\nopen ReleaseGlz\n\ndef decisionVectors : List (Obj × Decision) := [\n",
    );
    let mut rows = Vec::new();
    for object in objects() {
        rows.push(format!(
            "  ({}, {})",
            lean_object(object),
            lean_decision(object.decision())
        ));
    }
    source.push_str(&rows.join(",\n"));
    source.push_str("\n]\n\ndef reconcileVectors : List (List Obj × Bool × Outcome) := [\n");
    let mut rows = Vec::new();
    for list in lists(VECTOR_OBJECTS) {
        let objects = list
            .iter()
            .map(|object| lean_object(*object))
            .collect::<Vec<_>>()
            .join(", ");
        for approved in [false, true] {
            rows.push(format!(
                "  ([{objects}], {approved}, {})",
                lean_outcome(reconcile(&list, approved))?
            ));
        }
    }
    source.push_str(&rows.join(",\n"));
    source.push_str("\n]\n\n");
    writeln!(
        source,
        "theorem decision_refines_rust :\n    decisionVectors.all (fun (object, expected) => decision object == expected) = true := by\n  decide\n\ntheorem reconcile_refines_rust :\n    reconcileVectors.all (fun (objects, approved, expected) => reconcile objects approved == expected) = true := by\n  decide\n\n#print axioms decision_refines_rust\n#print axioms reconcile_refines_rust\n\nend ReleaseGlz.Refinement"
    )
    .map_err(|error| Failure::new(error.to_string()))?;
    Ok(source)
}

/// Whether `report` holds exactly one axiom line for each of `theorems`, each depending on allowed axioms only.
fn axioms_admitted(report: &str, theorems: &[&str]) -> bool {
    let lines = report
        .lines()
        .filter(|line| line.starts_with('\''))
        .collect::<Vec<_>>();
    lines.len() == theorems.len()
        && theorems.iter().all(|theorem| {
            let prefix = format!("'{theorem}' ");
            let reports = lines
                .iter()
                .filter_map(|line| line.strip_prefix(&prefix))
                .collect::<Vec<_>>();
            match reports.as_slice() {
                [report] => {
                    *report == "does not depend on any axioms"
                        || report
                            .strip_prefix("depends on axioms: [")
                            .and_then(|axioms| axioms.strip_suffix(']'))
                            .is_some_and(|axioms| {
                                axioms
                                    .split(',')
                                    .all(|axiom| ALLOWED_AXIOMS.contains(&axiom.trim()))
                            })
                }
                _ => false,
            }
        })
}

/// Check the model, its refinement of the core crate, and a fresh kernel replay of both, in the pinned image.
pub fn run(root: &Path) -> Result<(), Failure> {
    let evidence = crate::container::evidence_directory(root, "lean")?;
    fs::write(evidence.join("Refinement.lean"), refinement()?).map_err(Failure::io)?;
    let container = Container::build(root, &evidence, "verification/lean.Dockerfile")?;
    let version = container.output(root, &evidence, &["lean", "--version"])?;
    if !version.contains(LEAN_VERSION) {
        return Err(Failure::new(format!(
            "the image runs another Lean release: {version}"
        )));
    }
    for (module, directory, theorems) in [
        (
            "Publication",
            "/workspace/verification/lean",
            MODEL_THEOREMS.as_slice(),
        ),
        ("Refinement", "/evidence", REFINEMENT_THEOREMS.as_slice()),
    ] {
        let report = container.output(
            root,
            &evidence,
            &[
                "lean",
                "-DwarningAsError=true",
                &format!("--root={directory}"),
                "-o",
                &format!("/evidence/{module}.olean"),
                &format!("{directory}/{module}.lean"),
            ],
        )?;
        fs::write(evidence.join(format!("{module}-axioms.log")), &report).map_err(Failure::io)?;
        if !axioms_admitted(&report, theorems) {
            return Err(Failure::new(format!(
                "{module} proves another set of theorems or depends on an untrusted axiom; see {}",
                evidence.display()
            )));
        }
        container.output(root, &evidence, &["leanchecker", "--fresh", module])?;
    }
    println!(
        "Lean {LEAN_VERSION} proved {} model theorems and {} refinements of the core crate; evidence in {}",
        MODEL_THEOREMS.len(),
        REFINEMENT_THEOREMS.len(),
        evidence.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{axioms_admitted, lists, objects, refinement};

    #[test]
    fn the_vectors_cover_every_object_and_every_short_list() {
        assert_eq!(objects().len(), 16);
        assert_eq!(lists(2).len(), 1 + 16 + 16 * 16);
        let source = refinement().unwrap();
        let rows = |name: &str| {
            source
                .split_once(&format!("def {name}"))
                .and_then(|(_, rest)| rest.split_once("\n]\n"))
                .map_or(0, |(table, _)| {
                    table.lines().filter(|line| line.starts_with("  (")).count()
                })
        };
        assert_eq!(rows("decisionVectors"), 16);
        assert_eq!(rows("reconcileVectors"), 2 * (1 + 16 + 16 * 16));
        assert!(source.contains("theorem reconcile_refines_rust"));
    }

    /// The audit expects exactly the theorems whose axioms the model prints, so a theorem can't leave the gate unnoticed.
    #[test]
    fn the_audited_theorems_are_the_ones_the_model_prints() {
        let model = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../verification/lean/Publication.lean"),
        )
        .unwrap();
        let printed = model
            .lines()
            .filter_map(|line| line.strip_prefix("#print axioms "))
            .map(|name| format!("ReleaseGlz.{}", name.trim()))
            .collect::<Vec<_>>();
        assert_eq!(printed, super::MODEL_THEOREMS);
        assert!(
            !model.contains("sorry"),
            "the model admits an unproved step"
        );
    }

    #[test]
    fn the_axiom_audit_refuses_a_missing_extra_or_untrusted_report() {
        let theorems = ["ReleaseGlz.a"];
        assert!(axioms_admitted(
            "'ReleaseGlz.a' depends on axioms: [propext, Quot.sound]\n",
            &theorems
        ));
        for report in [
            "",
            "'ReleaseGlz.a' depends on axioms: [sorryAx]\n",
            "'ReleaseGlz.a' depends on axioms: [Lean.ofReduceBool]\n",
            "'ReleaseGlz.b' does not depend on any axioms\n",
            "'ReleaseGlz.a' does not depend on any axioms\n'ReleaseGlz.a' does not depend on any axioms\n",
        ] {
            assert!(!axioms_admitted(report, &theorems), "{report:?}");
        }
    }
}
