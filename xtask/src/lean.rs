//! Lean theorems about the publication model, tied to the core crate by complete refinement vectors.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use release_glz_core::{Decision, Object, Outcome, Presence, ReleaseState, reconcile};

use crate::container::{Container, Failure, Mounts};

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

/// Where the refinement of a broken decision table lives in the container, beside the evidence of the real one.
const BROKEN: &str = "/evidence/broken";

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
    refinement_with(Object::decision)
}

/// The republish defect: a decision table that publishes a wanted object again although the world already holds it.
fn republish(object: Object) -> Decision {
    match (object.wanted, object.presence) {
        (true, Presence::Matches) => Decision::Create,
        _ => object.decision(),
    }
}

/// The refinement module whose decision vectors come from `decide` and whose plan vectors come from the core crate.
fn refinement_with(decide: impl Fn(Object) -> Decision) -> Result<String, Failure> {
    let mut source = String::from(
        "import Publication\n\nset_option autoImplicit false\nset_option maxRecDepth 100000\n\nnamespace ReleaseGlz.Refinement\n\nopen ReleaseGlz\n\ndef decisionVectors : List (Obj × Decision) := [\n",
    );
    let mut rows = Vec::new();
    for object in objects() {
        rows.push(format!(
            "  ({}, {})",
            lean_object(object),
            lean_decision(decide(object))
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

/// Whether the report of the refinement of a broken decision table shows that only the decision refinement failed: it rests on `sorryAx`, and the plan refinement keeps the allowed axioms.
fn refuses_the_defect(report: &str) -> bool {
    let [decision, plan] = REFINEMENT_THEOREMS;
    let failed = format!("'{decision}' depends on axioms: [");
    let plan_prefix = format!("'{plan}' ");
    let plan_report = report
        .lines()
        .filter(|line| line.starts_with(&plan_prefix))
        .collect::<Vec<_>>()
        .join("\n");
    report.lines().any(|line| {
        line.strip_prefix(&failed).is_some_and(|axioms| {
            axioms
                .trim_end_matches(']')
                .split(',')
                .any(|axiom| axiom.trim() == "sorryAx")
        })
    }) && axioms_admitted(&plan_report, &[plan])
}

/// Check the model, its refinement of the core crate, a fresh kernel replay of both, and the refusal of a broken decision table, in the pinned image.
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

    // The same refinement has to fail for a table with the republish defect, and only on the decision vectors.
    fs::create_dir(evidence.join("broken")).map_err(Failure::io)?;
    fs::write(
        evidence.join("broken").join("Refinement.lean"),
        refinement_with(republish)?,
    )
    .map_err(Failure::io)?;
    let mounts = Mounts {
        workspace: root,
        evidence: &evidence,
        network: false,
    };
    let broken = container.run(
        &mounts,
        &[],
        &[
            "lean",
            "-DwarningAsError=true",
            &format!("--root={BROKEN}"),
            "-o",
            &format!("{BROKEN}/Refinement.olean"),
            &format!("{BROKEN}/Refinement.lean"),
        ],
    )?;
    let report = format!("{}{}", broken.stdout, broken.stderr);
    fs::write(evidence.join("broken-axioms.log"), &report).map_err(Failure::io)?;
    if broken.code == Some(0) || !refuses_the_defect(&report) {
        return Err(Failure::new(format!(
            "the refinement admitted a decision table that republishes matching objects; see {}",
            evidence.display()
        )));
    }
    println!(
        "Lean {LEAN_VERSION} proved {} model theorems and {} refinements of the core crate, and refused the republish defect; evidence in {}",
        MODEL_THEOREMS.len(),
        REFINEMENT_THEOREMS.len(),
        evidence.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        axioms_admitted, lists, objects, refinement, refinement_with, refuses_the_defect, republish,
    };
    use release_glz_core::Object;

    #[test]
    fn the_broken_table_differs_from_the_core_only_where_the_defect_republishes() {
        let differing = objects()
            .into_iter()
            .filter(|object| republish(*object) != object.decision())
            .collect::<Vec<_>>();
        assert_eq!(differing.len(), 2, "{differing:?}");
        assert_ne!(refinement().unwrap(), refinement_with(republish).unwrap());
        assert_eq!(
            refinement().unwrap(),
            refinement_with(Object::decision).unwrap()
        );
    }

    #[test]
    fn only_a_failed_decision_refinement_with_an_intact_plan_refinement_shows_the_defect() {
        let failed = "'ReleaseGlz.Refinement.decision_refines_rust' depends on axioms: [sorryAx]\n'ReleaseGlz.Refinement.reconcile_refines_rust' depends on axioms: [propext]\n";
        assert!(refuses_the_defect(failed));
        for report in [
            "'ReleaseGlz.Refinement.decision_refines_rust' does not depend on any axioms\n'ReleaseGlz.Refinement.reconcile_refines_rust' does not depend on any axioms\n",
            "'ReleaseGlz.Refinement.decision_refines_rust' depends on axioms: [sorryAx]\n'ReleaseGlz.Refinement.reconcile_refines_rust' depends on axioms: [sorryAx]\n",
            "'ReleaseGlz.Refinement.decision_refines_rust' depends on axioms: [sorryAx]\n",
            "error: unknown package 'Publication'\n",
        ] {
            assert!(!refuses_the_defect(report), "{report:?}");
        }
    }

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
