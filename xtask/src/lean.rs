//! Lean theorems about the models of the core crate, tied to it by complete refinement vectors.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use release_glz_core::{
    Decision, MARKER_KEYS, MARKER_PREFIX, MARKER_SUFFIX, NOTIFICATION_DOMAIN, Object, Outcome,
    Presence, ReleaseState, Segment, frame_file, marker_start, marker_values, notification_frame,
    reconcile, redaction_segments, write_inert, write_marker,
};

use crate::container::{Container, Failure, Mounts};

/// The Lean release that `verification/lean.Dockerfile` installs.
const LEAN_VERSION: &str = "4.35.0";

/// The theorems of the publication model, which the axiom audit expects in this order.
const PUBLICATION_THEOREMS: [&str; 9] = [
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

/// The theorems of the redaction model, which the axiom audit expects in this order.
const REDACTION_THEOREMS: [&str; 5] = [
    "ReleaseGlz.Redaction.reach_decides_coverage",
    "ReleaseGlz.Redaction.coverage_is_the_definition",
    "ReleaseGlz.Redaction.segments_cover_every_byte_once",
    "ReleaseGlz.Redaction.segments_are_nonempty",
    "ReleaseGlz.Redaction.neighboring_segments_differ",
];

/// The theorems of the framing model, which the axiom audit expects in this order.
const FRAMING_THEOREMS: [&str; 3] = [
    "ReleaseGlz.Framing.fromBe8_be8",
    "ReleaseGlz.Framing.the_files_framing_is_injective",
    "ReleaseGlz.Framing.the_notification_framing_is_injective",
];

/// The theorems of the marker model, which the axiom audit expects in this order.
const MARKER_THEOREMS: [&str; 5] = [
    "ReleaseGlz.Marker.inert_holds_no_less_than",
    "ReleaseGlz.Marker.a_rendered_marker_ends_the_body",
    "ReleaseGlz.Marker.an_earlier_marker_is_refused",
    "ReleaseGlz.Marker.the_fields_give_back_every_value",
    "ReleaseGlz.Marker.the_marker_round_trips",
];

/// The model modules under `verification/lean`, in the order they compile, with the theorems each must print.
pub(crate) const MODELS: [(&str, &[&str]); 4] = [
    ("Publication", &PUBLICATION_THEOREMS),
    ("Redaction", &REDACTION_THEOREMS),
    ("Framing", &FRAMING_THEOREMS),
    ("Marker", &MARKER_THEOREMS),
];

/// The refinement theorems, which compare the models with the core crate on every listed input.
pub(crate) const REFINEMENT_THEOREMS: [&str; 9] = [
    "ReleaseGlz.Refinement.decision_refines_rust",
    "ReleaseGlz.Refinement.reconcile_refines_rust",
    "ReleaseGlz.Refinement.redaction_refines_rust",
    "ReleaseGlz.Refinement.files_framing_refines_rust",
    "ReleaseGlz.Refinement.notification_framing_refines_rust",
    "ReleaseGlz.Refinement.inert_refines_rust",
    "ReleaseGlz.Refinement.render_refines_rust",
    "ReleaseGlz.Refinement.marker_start_refines_rust",
    "ReleaseGlz.Refinement.marker_values_refines_rust",
];

/// The refinement theorems that no defect of [`BROKEN_TABLES`] touches, which keep the allowed axioms when the others fail.
const INTACT_THEOREMS: [&str; 1] = ["ReleaseGlz.Refinement.reconcile_refines_rust"];

/// The axioms a theorem may depend on, which Lean's kernel and standard library assume.
const ALLOWED_AXIOMS: [&str; 3] = ["propext", "Classical.choice", "Quot.sound"];

/// The longest object list whose reconcile outcome the vectors compare.
const VECTOR_OBJECTS: usize = 2;

/// The longest text whose redaction the vectors compare, over the bytes of `a` and `b`.
const VECTOR_TEXT: usize = 3;

/// The secrets the redaction vectors pair up: every byte string of at most two bytes over `a` and `b`.
const VECTOR_SECRETS: [&[u8]; 7] = [b"", b"a", b"b", b"aa", b"ab", b"ba", b"bb"];

/// The paths and contents whose framing the vectors compare.
const VECTOR_PARTS: [&[u8]; 4] = [b"", b"\0", b"\xff", b"\x01\x02"];

/// The Candidate digests and hook ids whose notification framing the vectors compare, with no NUL in a digest.
const VECTOR_DIGESTS: [&[u8]; 3] = [b"", b"a", b"ab"];
const VECTOR_HOOKS: [&[u8]; 3] = [b"", b"\0", b"h\0"];

/// The longest text whose inert form the vectors compare, over the bytes of `a` and `<`.
const VECTOR_INERT: usize = 3;

/// The marker values the marker vectors use: empty values, the values of a release, and values that hold `=`, `<`, and the ends of a marker.
const VECTOR_VALUES: [[&[u8]; 6]; 3] = [
    [b"", b"", b"", b"", b"", b""],
    [
        b"glz",
        b"release-glz/glz",
        b"0123abcd",
        b"abcd0123",
        b"1.2.3-rc.1",
        b"pending",
    ],
    [b"a=b", b"<", b"-->", b"<!--", b"=", b"x"],
];

/// Text that the marker vectors put before a marker, with and without `<`.
const VECTOR_LEADS: [&[u8]; 3] = [b"", b"notes\n", b"a <b>"];

/// Where the refinement of the broken tables lives in the container, beside the evidence of the real one.
const BROKEN: &str = "/evidence/broken";

const PRESENCES: [Presence; 4] = [
    Presence::Absent,
    Presence::Pending,
    Presence::Matches,
    Presence::Differs,
];

/// Redaction segments, each as whether it is redacted and its length.
type Segments = Vec<(bool, usize)>;

/// The values of a marker, when its fields give them.
type FieldValues = Option<[Vec<u8>; 6]>;

/// The implementation whose results fill the refinement vectors that each model checks.
struct Tables {
    decide: fn(Object) -> Decision,
    redact: fn(&[u8], &[&[u8]]) -> Segments,
    frame_file: fn(&[u8], &[u8]) -> Vec<u8>,
    frame_notification: fn(&[u8], &[u8]) -> Vec<u8>,
    inert: fn(&[u8]) -> Vec<u8>,
    render: fn([&[u8]; 6]) -> Vec<u8>,
    find_marker: fn(&[u8]) -> Option<usize>,
    read_fields: fn(&[Vec<u8>]) -> FieldValues,
}

/// The core crate's implementation.
const CORE_TABLES: Tables = Tables {
    decide: Object::decision,
    redact: core_segments,
    frame_file: framed_file,
    frame_notification: framed_notification,
    inert: inert_text,
    render: rendered,
    find_marker: marker_start,
    read_fields: core_values,
};

/// One defect in each table, none of which touches the plan vectors.
const BROKEN_TABLES: Tables = Tables {
    decide: republish,
    redact: overreach,
    frame_file: unframed_file,
    frame_notification: unframed_notification,
    inert: <[u8]>::to_vec,
    render: joined,
    find_marker: last_only,
    read_fields: repeated,
};

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

/// Every list of at most `length` items drawn from `items`.
fn lists<T: Clone>(items: &[T], length: usize) -> Vec<Vec<T>> {
    let mut lists = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..length {
        let mut next = Vec::new();
        for list in &frontier {
            for item in items {
                let mut longer: Vec<T> = list.clone();
                longer.push(item.clone());
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

/// A byte string as a Lean list of numbers.
fn lean_bytes(bytes: &[u8]) -> String {
    let bytes = bytes.iter().map(u8::to_string).collect::<Vec<_>>();
    format!("[{}]", bytes.join(", "))
}

/// Segments as the model writes them: whether each is redacted, and its length.
fn lean_segments(segments: &[(bool, usize)]) -> String {
    let segments = segments
        .iter()
        .map(|(redacted, length)| format!("({redacted}, {length})"))
        .collect::<Vec<_>>();
    format!("[{}]", segments.join(", "))
}

/// The segments that the core's redaction yields, each as whether it is redacted and its length.
fn core_segments(text: &[u8], secrets: &[&[u8]]) -> Segments {
    redaction_segments(text, secrets)
        .map(|segment| match segment {
            Segment::Kept(range) => (false, range.len()),
            Segment::Redacted(range) => (true, range.len()),
        })
        .collect()
}

/// The maximal runs of equal flags, each as its flag and its length.
fn runs(flags: &[bool]) -> Segments {
    let mut runs: Segments = Vec::new();
    for flag in flags {
        match runs.last_mut() {
            Some((last, length)) if last == flag => *length += 1,
            _ => runs.push((*flag, 1)),
        }
    }
    runs
}

/// The overreach defect: redaction that also removes the byte after each redacted run.
fn overreach(text: &[u8], secrets: &[&[u8]]) -> Segments {
    let mut flags = core_segments(text, secrets)
        .into_iter()
        .flat_map(|(redacted, length)| std::iter::repeat_n(redacted, length))
        .collect::<Vec<_>>();
    for index in (1..flags.len()).rev() {
        if flags[index - 1] {
            flags[index] = true;
        }
    }
    runs(&flags)
}

/// The bytes the core frames for one file.
fn framed_file(path: &[u8], contents: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    frame_file(path, contents, |part| bytes.extend_from_slice(part));
    bytes
}

/// The unframed defect: a file's path and contents without their lengths.
fn unframed_file(path: &[u8], contents: &[u8]) -> Vec<u8> {
    [path, contents].concat()
}

/// The bytes the core frames for one notification.
fn framed_notification(digest: &[u8], hook: &[u8]) -> Vec<u8> {
    notification_frame(digest, hook).concat()
}

/// The unframed defect: a notification without the byte that ends its Candidate digest.
fn unframed_notification(digest: &[u8], hook: &[u8]) -> Vec<u8> {
    [NOTIFICATION_DOMAIN, digest, hook].concat()
}

/// The republish defect: a decision table that publishes a wanted object again although the world already holds it.
fn republish(object: Object) -> Decision {
    match (object.wanted, object.presence) {
        (true, Presence::Matches) => Decision::Create,
        _ => object.decision(),
    }
}

/// The bytes of `text` in the inert form the core writes.
fn inert_text(text: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_inert(text, |part| bytes.extend_from_slice(part));
    bytes
}

/// The marker the core writes for `values`.
fn rendered(values: [&[u8]; 6]) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_marker(values, |part| bytes.extend_from_slice(part));
    bytes
}

/// The joined defect: a marker without the spaces between its fields.
fn joined(values: [&[u8]; 6]) -> Vec<u8> {
    let mut bytes = MARKER_PREFIX.as_bytes().to_vec();
    for (key, value) in MARKER_KEYS.iter().zip(values) {
        bytes.extend_from_slice(key.as_bytes());
        bytes.push(b'=');
        bytes.extend_from_slice(value);
    }
    bytes.extend_from_slice(MARKER_SUFFIX.as_bytes());
    bytes
}

/// The last-only defect: a search that takes the last marker without looking for an earlier one.
fn last_only(body: &[u8]) -> Option<usize> {
    let (prefix, suffix) = (MARKER_PREFIX.as_bytes(), MARKER_SUFFIX.as_bytes());
    let start = body
        .windows(prefix.len())
        .rposition(|window| window == prefix)?;
    let end = body[start..]
        .windows(suffix.len())
        .position(|window| window == suffix)?
        + start
        + suffix.len();
    (end == body.len()).then_some(start)
}

/// The values that the core reads from `fields`.
fn core_values(fields: &[Vec<u8>]) -> FieldValues {
    marker_values(fields.iter().map(Vec::as_slice)).map(|values| values.map(<[u8]>::to_vec))
}

/// The repeat defect: reading that lets a later field replace an earlier one with the same key.
fn repeated(fields: &[Vec<u8>]) -> FieldValues {
    let mut values: [Option<Vec<u8>>; 6] = Default::default();
    for field in fields {
        let separator = field.iter().position(|byte| *byte == b'=')?;
        let slot = MARKER_KEYS
            .iter()
            .position(|key| key.as_bytes() == &field[..separator])?;
        values[slot] = Some(field[separator + 1..].to_vec());
    }
    let [package, branch, head, digest, version, intent] = values;
    Some([package?, branch?, head?, digest?, version?, intent?])
}

/// The bodies whose marker the vectors compare: each lead before each rendered marker, and bodies that no marker ends.
fn marker_bodies() -> Vec<Vec<u8>> {
    let mut bodies = vec![Vec::new(), MARKER_PREFIX.as_bytes().to_vec()];
    for values in VECTOR_VALUES {
        let marker = rendered(values);
        for lead in VECTOR_LEADS {
            bodies.push([lead, marker.as_slice()].concat());
        }
        bodies.push([marker.as_slice(), b"x"].concat());
        bodies.push([MARKER_PREFIX.as_bytes(), b"x", marker.as_slice()].concat());
        bodies.push(marker[..marker.len() - MARKER_SUFFIX.len()].to_vec());
    }
    bodies
}

/// The field lists whose values the vectors compare: rendered fields, and lists with a key missing, repeated, unknown, or without `=`.
fn field_lists() -> Vec<Vec<Vec<u8>>> {
    let fields = |values: [&[u8]; 6]| -> Vec<Vec<u8>> {
        MARKER_KEYS
            .iter()
            .zip(values)
            .map(|(key, value)| [key.as_bytes(), b"=", value].concat())
            .collect()
    };
    let release = fields(VECTOR_VALUES[1]);
    let mut missing = release.clone();
    missing.pop();
    let mut unseparated = missing.clone();
    unseparated.push(b"intent".to_vec());
    let mut lists = VECTOR_VALUES.into_iter().map(fields).collect::<Vec<_>>();
    lists.push(missing);
    lists.push([release.clone(), vec![release[0].clone()]].concat());
    lists.push([release.clone(), vec![b"other=1".to_vec()]].concat());
    lists.push(unseparated);
    lists.push(release.iter().rev().cloned().collect());
    lists.push(Vec::new());
    lists
}

/// Marker values as the model writes them.
fn lean_values(values: [&[u8]; 6]) -> String {
    let values = values.map(lean_bytes);
    format!("⟨{}⟩", values.join(", "))
}

/// Append one Lean table named `name` of type `kind` with `rows`.
fn table(source: &mut String, name: &str, kind: &str, rows: &[String]) {
    source.push_str(&format!("def {name} : {kind} := [\n"));
    source.push_str(&rows.join(",\n"));
    source.push_str("\n]\n\n");
}

/// The Lean module that compares the models with the core crate on every listed input.
///
/// The publication vectors cover every object and every list of at most [`VECTOR_OBJECTS`] objects.
/// The redaction vectors cover every text of at most [`VECTOR_TEXT`] bytes over `a` and `b` with every pair of [`VECTOR_SECRETS`].
pub fn refinement() -> Result<String, Failure> {
    refinement_with(&CORE_TABLES)
}

/// The refinement module whose vectors come from `tables`, apart from the plan vectors, which always come from the core crate.
fn refinement_with(tables: &Tables) -> Result<String, Failure> {
    let mut source = String::from(
        "import Publication\nimport Redaction\nimport Framing\nimport Marker\n\nset_option autoImplicit false\nset_option maxRecDepth 100000\n\nnamespace ReleaseGlz.Refinement\n\nopen ReleaseGlz\n\n",
    );
    let decisions = objects()
        .into_iter()
        .map(|object| {
            format!(
                "  ({}, {})",
                lean_object(object),
                lean_decision((tables.decide)(object))
            )
        })
        .collect::<Vec<_>>();
    table(
        &mut source,
        "decisionVectors",
        "List (Obj × Decision)",
        &decisions,
    );
    let mut reconciliations = Vec::new();
    for list in lists(&objects(), VECTOR_OBJECTS) {
        let objects = list
            .iter()
            .map(|object| lean_object(*object))
            .collect::<Vec<_>>()
            .join(", ");
        for approved in [false, true] {
            reconciliations.push(format!(
                "  ([{objects}], {approved}, {})",
                lean_outcome(reconcile(&list, approved))?
            ));
        }
    }
    table(
        &mut source,
        "reconcileVectors",
        "List (List Obj × Bool × Outcome)",
        &reconciliations,
    );
    let mut redactions = Vec::new();
    for text in lists(b"ab", VECTOR_TEXT) {
        for first in VECTOR_SECRETS {
            for second in VECTOR_SECRETS {
                let secrets = [first, second];
                redactions.push(format!(
                    "  ({}, [{}, {}], {})",
                    lean_bytes(&text),
                    lean_bytes(first),
                    lean_bytes(second),
                    lean_segments(&(tables.redact)(&text, &secrets))
                ));
            }
        }
    }
    table(
        &mut source,
        "redactionVectors",
        "List (List Nat × List (List Nat) × List (Bool × Nat))",
        &redactions,
    );
    let mut files = Vec::new();
    for path in VECTOR_PARTS {
        for contents in VECTOR_PARTS {
            files.push(format!(
                "  ({}, {}, {})",
                lean_bytes(path),
                lean_bytes(contents),
                lean_bytes(&(tables.frame_file)(path, contents))
            ));
        }
    }
    table(
        &mut source,
        "fileFrameVectors",
        "List (List Nat × List Nat × List Nat)",
        &files,
    );
    let mut notifications = Vec::new();
    for digest in VECTOR_DIGESTS {
        for hook in VECTOR_HOOKS {
            notifications.push(format!(
                "  ({}, {}, {})",
                lean_bytes(digest),
                lean_bytes(hook),
                lean_bytes(&(tables.frame_notification)(digest, hook))
            ));
        }
    }
    table(
        &mut source,
        "notificationVectors",
        "List (List Nat × List Nat × List Nat)",
        &notifications,
    );
    let inert = lists(b"a<", VECTOR_INERT)
        .into_iter()
        .map(|text| {
            format!(
                "  ({}, {})",
                lean_bytes(&text),
                lean_bytes(&(tables.inert)(&text))
            )
        })
        .collect::<Vec<_>>();
    table(
        &mut source,
        "inertVectors",
        "List (List Nat × List Nat)",
        &inert,
    );
    let renders = VECTOR_VALUES
        .into_iter()
        .map(|values| {
            format!(
                "  ({}, {})",
                lean_values(values),
                lean_bytes(&(tables.render)(values))
            )
        })
        .collect::<Vec<_>>();
    table(
        &mut source,
        "renderVectors",
        "List (Marker.Values × List Nat)",
        &renders,
    );
    let starts = marker_bodies()
        .into_iter()
        .map(|body| {
            let start = (tables.find_marker)(&body)
                .map_or_else(|| "none".to_owned(), |start| format!("some {start}"));
            format!("  ({}, {start})", lean_bytes(&body))
        })
        .collect::<Vec<_>>();
    table(
        &mut source,
        "markerStartVectors",
        "List (List Nat × Option Nat)",
        &starts,
    );
    let readings = field_lists()
        .into_iter()
        .map(|fields| {
            let listed = fields
                .iter()
                .map(|field| lean_bytes(field))
                .collect::<Vec<_>>();
            let values = (tables.read_fields)(&fields).map_or_else(
                || "none".to_owned(),
                |values| format!("some {}", lean_values(values.each_ref().map(Vec::as_slice))),
            );
            format!("  ([{}], {values})", listed.join(", "))
        })
        .collect::<Vec<_>>();
    table(
        &mut source,
        "markerValuesVectors",
        "List (List (List Nat) × Option Marker.Values)",
        &readings,
    );
    writeln!(
        source,
        "def notificationDomain : List Nat := {}\n",
        lean_bytes(NOTIFICATION_DOMAIN)
    )
    .map_err(|error| Failure::new(error.to_string()))?;
    writeln!(
        source,
        "theorem decision_refines_rust :\n    decisionVectors.all (fun (object, expected) => decision object == expected) = true := by\n  decide\n\ntheorem reconcile_refines_rust :\n    reconcileVectors.all (fun (objects, approved, expected) => reconcile objects approved == expected) = true := by\n  decide\n\ntheorem redaction_refines_rust :\n    redactionVectors.all (fun (text, secrets, expected) => Redaction.segments text secrets == expected) = true := by\n  decide\n\ntheorem files_framing_refines_rust :\n    fileFrameVectors.all (fun (path, contents, expected) => Framing.frameFile path contents == expected) = true := by\n  decide\n\ntheorem notification_framing_refines_rust :\n    notificationVectors.all (fun (digest, hook, expected) => Framing.frameNotification notificationDomain digest hook == expected) = true := by\n  decide\n\ntheorem inert_refines_rust :\n    inertVectors.all (fun (text, expected) => Marker.inert text == expected) = true := by\n  decide\n\ntheorem render_refines_rust :\n    renderVectors.all (fun (values, expected) => Marker.render values == expected) = true := by\n  decide\n\ntheorem marker_start_refines_rust :\n    markerStartVectors.all (fun (body, expected) => Marker.markerStart body == expected) = true := by\n  decide\n\ntheorem marker_values_refines_rust :\n    markerValuesVectors.all (fun (fields, expected) => Marker.markerValues fields == expected) = true := by\n  decide\n\n#print axioms decision_refines_rust\n#print axioms reconcile_refines_rust\n#print axioms redaction_refines_rust\n#print axioms files_framing_refines_rust\n#print axioms notification_framing_refines_rust\n#print axioms inert_refines_rust\n#print axioms render_refines_rust\n#print axioms marker_start_refines_rust\n#print axioms marker_values_refines_rust\n\nend ReleaseGlz.Refinement"
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

/// Whether the report of the refinement of the broken tables shows that exactly the refinements they break failed: each rests on `sorryAx`, and the plan refinement keeps the allowed axioms.
fn refuses_the_defects(report: &str) -> bool {
    let rests_on_sorry = |theorem: &str| {
        let failed = format!("'{theorem}' depends on axioms: [");
        report.lines().any(|line| {
            line.strip_prefix(&failed).is_some_and(|axioms| {
                axioms
                    .trim_end_matches(']')
                    .split(',')
                    .any(|axiom| axiom.trim() == "sorryAx")
            })
        })
    };
    let intact_report = report
        .lines()
        .filter(|line| {
            INTACT_THEOREMS
                .iter()
                .any(|theorem| line.starts_with(&format!("'{theorem}' ")))
        })
        .collect::<Vec<_>>()
        .join("\n");
    REFINEMENT_THEOREMS
        .iter()
        .filter(|theorem| !INTACT_THEOREMS.contains(theorem))
        .all(|theorem| rests_on_sorry(theorem))
        && axioms_admitted(&intact_report, &INTACT_THEOREMS)
}

/// Check the models, their refinement of the core crate, a fresh kernel replay of each, and the refusal of broken tables, in the pinned image.
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
    let modules = MODELS
        .iter()
        .map(|(module, theorems)| (*module, "/workspace/verification/lean", *theorems))
        .chain([("Refinement", "/evidence", REFINEMENT_THEOREMS.as_slice())]);
    for (module, directory, theorems) in modules {
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

    // The same refinement has to fail for the broken tables, on exactly the vectors they break.
    fs::create_dir(evidence.join("broken")).map_err(Failure::io)?;
    fs::write(
        evidence.join("broken").join("Refinement.lean"),
        refinement_with(&BROKEN_TABLES)?,
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
    if broken.code == Some(0) || !refuses_the_defects(&report) {
        return Err(Failure::new(format!(
            "the refinement admitted a broken decision, redaction, or framing table; see {}",
            evidence.display()
        )));
    }
    let model_theorems = MODELS
        .iter()
        .map(|(_, theorems)| theorems.len())
        .sum::<usize>();
    println!(
        "Lean {LEAN_VERSION} proved {model_theorems} model theorems and {} refinements of the core crate, and refused a broken table for each refinement but the plan; evidence in {}",
        REFINEMENT_THEOREMS.len(),
        evidence.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        BROKEN_TABLES, CORE_TABLES, MODELS, VECTOR_DIGESTS, VECTOR_HOOKS, VECTOR_PARTS,
        VECTOR_SECRETS, VECTOR_VALUES, axioms_admitted, field_lists, lists, marker_bodies, objects,
        refinement, refinement_with, refuses_the_defects,
    };

    #[test]
    fn the_broken_tables_differ_from_the_core_in_each_table() {
        let differing = objects()
            .into_iter()
            .filter(|object| (BROKEN_TABLES.decide)(*object) != object.decision())
            .collect::<Vec<_>>();
        assert_eq!(differing.len(), 2, "{differing:?}");
        let text = b"ab".as_slice();
        let secrets = [b"a".as_slice()];
        assert_eq!(
            (CORE_TABLES.redact)(text, &secrets),
            [(true, 1), (false, 1)]
        );
        assert_eq!((BROKEN_TABLES.redact)(text, &secrets), [(true, 2)]);
        assert_eq!(
            (BROKEN_TABLES.redact)(b"ba", &secrets),
            (CORE_TABLES.redact)(b"ba", &secrets),
            "a run that ends the text has no byte after it"
        );
        for path in VECTOR_PARTS {
            for contents in VECTOR_PARTS {
                assert_ne!(
                    (BROKEN_TABLES.frame_file)(path, contents),
                    (CORE_TABLES.frame_file)(path, contents)
                );
            }
        }
        for digest in VECTOR_DIGESTS {
            for hook in VECTOR_HOOKS {
                assert_ne!(
                    (BROKEN_TABLES.frame_notification)(digest, hook),
                    (CORE_TABLES.frame_notification)(digest, hook)
                );
            }
        }
        assert_eq!((CORE_TABLES.inert)(b"a<b"), b"a&lt;b");
        assert_eq!((BROKEN_TABLES.inert)(b"a<b"), b"a<b");
        for values in VECTOR_VALUES {
            assert_ne!((BROKEN_TABLES.render)(values), (CORE_TABLES.render)(values));
        }
        let starts = marker_bodies()
            .iter()
            .filter(|body| (BROKEN_TABLES.find_marker)(body) != (CORE_TABLES.find_marker)(body))
            .count();
        assert_eq!(
            starts,
            VECTOR_VALUES.len(),
            "only bodies with an earlier marker differ"
        );
        let readings = field_lists()
            .iter()
            .filter(|fields| {
                (BROKEN_TABLES.read_fields)(fields) != (CORE_TABLES.read_fields)(fields)
            })
            .count();
        assert_eq!(readings, 1, "only the repeated key differs");
        assert_ne!(
            refinement().unwrap(),
            refinement_with(&BROKEN_TABLES).unwrap()
        );
        assert_eq!(
            refinement().unwrap(),
            refinement_with(&CORE_TABLES).unwrap()
        );
    }

    #[test]
    fn only_failed_broken_refinements_with_an_intact_plan_refinement_show_the_defects() {
        let line = |theorem: &str, axioms: &str| {
            format!("'ReleaseGlz.Refinement.{theorem}' depends on axioms: [{axioms}]\n")
        };
        let broken = [
            "decision_refines_rust",
            "redaction_refines_rust",
            "files_framing_refines_rust",
            "notification_framing_refines_rust",
            "inert_refines_rust",
            "render_refines_rust",
            "marker_start_refines_rust",
            "marker_values_refines_rust",
        ];
        let report = |intact: &str, failing: &[&str]| {
            failing
                .iter()
                .map(|theorem| line(theorem, "sorryAx"))
                .chain([line("reconcile_refines_rust", intact)])
                .collect::<String>()
        };
        assert!(refuses_the_defects(&report("propext", &broken)));
        assert!(!refuses_the_defects(&report("sorryAx", &broken)));
        for kept in broken {
            let failing = broken
                .iter()
                .copied()
                .filter(|theorem| *theorem != kept)
                .collect::<Vec<_>>();
            assert!(
                !refuses_the_defects(&report("propext", &failing)),
                "{kept} kept its axioms"
            );
        }
        assert!(!refuses_the_defects(
            &broken
                .iter()
                .map(|theorem| line(theorem, "sorryAx"))
                .collect::<String>()
        ));
        assert!(!refuses_the_defects(
            "error: unknown package 'Publication'\n"
        ));
    }

    #[test]
    fn the_vectors_cover_every_object_and_every_short_list() {
        assert_eq!(objects().len(), 16);
        assert_eq!(lists(&objects(), 2).len(), 1 + 16 + 16 * 16);
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
        assert_eq!(
            rows("redactionVectors"),
            (1 + 2 + 4 + 8) * VECTOR_SECRETS.len() * VECTOR_SECRETS.len()
        );
        assert_eq!(rows("fileFrameVectors"), 16);
        assert_eq!(rows("notificationVectors"), 9);
        assert_eq!(rows("inertVectors"), 1 + 2 + 4 + 8);
        assert_eq!(rows("renderVectors"), VECTOR_VALUES.len());
        assert_eq!(rows("markerStartVectors"), 2 + 6 * VECTOR_VALUES.len());
        assert_eq!(rows("markerValuesVectors"), VECTOR_VALUES.len() + 6);
        assert!(source.contains("theorem marker_values_refines_rust"));
    }

    /// The audit expects exactly the theorems whose axioms each model prints, so a theorem can't leave the gate unnoticed.
    #[test]
    fn the_audited_theorems_are_the_ones_the_models_print() {
        for (module, theorems) in MODELS {
            let model = std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join(format!("../verification/lean/{module}.lean")),
            )
            .unwrap();
            let namespace = model
                .lines()
                .find_map(|line| line.strip_prefix("namespace "))
                .unwrap()
                .trim();
            let printed = model
                .lines()
                .filter_map(|line| line.strip_prefix("#print axioms "))
                .map(|name| format!("{namespace}.{}", name.trim()))
                .collect::<Vec<_>>();
            assert_eq!(printed, theorems, "{module}");
            assert!(!model.contains("sorry"), "{module} admits an unproved step");
        }
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
