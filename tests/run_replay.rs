//! Replays the traces of `verification/quint/release_run.qnt` through `release_glz_core::Run` and requires every decision in a trace to be the production decision.
//!
//! `cargo xtask quint` writes the traces again and requires them to equal the committed ones, so these tests replay what the model checker's model does.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use release_glz_core::{Object, Presence, ReleaseState, Run, Step};
use serde_json::Value;

/// The committed traces.
const TRACES: &str = "verification/quint/traces";

/// The number of objects of a release in the model.
const OBJECTS: usize = 3;

/// The model's variables carry the module path as a prefix, which the replay drops.
fn variable<'a>(state: &'a Value, name: &str) -> Result<&'a Value> {
    state
        .as_object()
        .context("an ITF state is an object")?
        .iter()
        .find_map(|(key, value)| (key.rsplit("::").next() == Some(name)).then_some(value))
        .with_context(|| format!("the trace has no variable {name}"))
}

fn integer(value: &Value) -> Result<i64> {
    value["#bigint"]
        .as_str()
        .context("an ITF integer")?
        .parse()
        .context("an ITF integer")
}

/// An index of an object, where the model writes -1 for none.
fn index(value: &Value) -> Result<Option<usize>> {
    let number = integer(value)?;
    Ok(if number < 0 {
        None
    } else {
        Some(usize::try_from(number)?)
    })
}

fn tag(value: &Value) -> Result<&str> {
    value["tag"].as_str().context("an ITF variant")
}

fn presence(value: &Value) -> Result<Presence> {
    Ok(match tag(value)? {
        "Absent" => Presence::Absent,
        "Pending" => Presence::Pending,
        "Matches" => Presence::Matches,
        "Differs" => Presence::Differs,
        other => bail!("unknown presence {other}"),
    })
}

fn state(value: &Value) -> Result<ReleaseState> {
    Ok(match tag(value)? {
        "CandidateReady" => ReleaseState::CandidateReady,
        "PartiallyReleased" => ReleaseState::PartiallyReleased,
        "Released" => ReleaseState::Released,
        "AwaitingApproval" => ReleaseState::AwaitingApproval,
        "Blocked" => ReleaseState::Blocked,
        other => bail!("unknown state {other}"),
    })
}

/// The values of a map from each object's index.
fn per_object<T>(value: &Value, decode: impl Fn(&Value) -> Result<T>) -> Result<[T; OBJECTS]>
where
    T: Default + Copy,
{
    let mut decoded = [T::default(); OBJECTS];
    for pair in value["#map"].as_array().context("an ITF map")? {
        let index = index(&pair[0])?.context("a map from object indices")?;
        *decoded
            .get_mut(index)
            .context("an object beyond the model")? = decode(&pair[1])?;
    }
    Ok(decoded)
}

fn flag(value: &Value) -> Result<bool> {
    value.as_bool().context("an ITF Boolean")
}

/// What the Candidate fixes for the whole release.
struct Candidate {
    wanted: [bool; OBJECTS],
    blocking: [bool; OBJECTS],
    approved: bool,
}

fn candidate(state: &Value) -> Result<Candidate> {
    let candidate = variable(state, "candidate")?;
    Ok(Candidate {
        wanted: per_object(&candidate["wanted"], flag)?,
        blocking: per_object(&candidate["blocking"], flag)?,
        approved: flag(&candidate["approved"])?,
    })
}

/// The objects that an observation of `state` shows.
fn objects(candidate: &Candidate, state: &Value) -> Result<[Object; OBJECTS]> {
    let shown = per_object(variable(state, "shown")?, |value| presence(value).map(Some))?;
    let mut objects = [Object {
        wanted: false,
        presence: Presence::Absent,
        blocking: false,
    }; OBJECTS];
    for (index, object) in objects.iter_mut().enumerate() {
        *object = Object {
            wanted: candidate.wanted[index],
            presence: shown[index].context("the observation shows every object")?,
            blocking: candidate.blocking[index],
        };
    }
    Ok(objects)
}

/// The decision of the runner's newest step, or `None` before its first one.
fn last(state: &Value) -> Result<Option<Step>> {
    let last = &variable(state, "runner")?["last"];
    let value = &last["value"];
    Ok(Some(match tag(last)? {
        "Start" => return Ok(None),
        "Apply" => Step::Apply(index(value)?.context("an applied object")?),
        "Finish" => Step::Finish(self::state(value)?),
        "Conflicted" => Step::Conflict(index(value)?.context("a conflicting object")?),
        "FailedAt" => Step::Failed {
            index: index(&value["index"])?.context("a failed object")?,
            state: self::state(&value["state"])?,
        },
        "Diverged" => Step::Diverged,
        "Unobserved" => return Ok(None),
        other => bail!("unknown step {other}"),
    }))
}

/// The state that a run reports after a failed observation, which the model records as the runner's newest step.
fn unobserved(state: &Value) -> Result<ReleaseState> {
    let last = &variable(state, "runner")?["last"];
    ensure!(
        tag(last)? == "Unobserved",
        "a failed observation stops the run"
    );
    self::state(&last["value"])
}

fn runner_field(state: &Value, field: &str) -> Result<Option<usize>> {
    index(&variable(state, "runner")?[field])
}

/// What one step of the model did, as the states before and after it show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Observe,
    Call { succeeded: bool },
    Show,
    Race,
    Blind,
    Restart,
}

fn action(before: &Value, after: &Value) -> Result<Action> {
    let runs = |state| variable(state, "runs").and_then(integer);
    let action = if runs(after)? != runs(before)? {
        Action::Restart
    } else if variable(after, "blinded")? != variable(before, "blinded")? {
        Action::Blind
    } else if variable(after, "raced")? != variable(before, "raced")? {
        Action::Race
    } else if variable(after, "shown")? != variable(before, "shown")? {
        Action::Show
    } else if runner_field(before, "applying")?.is_some() {
        Action::Call {
            succeeded: runner_field(after, "failed")?.is_none(),
        }
    } else {
        Action::Observe
    };
    if let Some(taken) = after["mbt::actionTaken"].as_str() {
        let named = match action {
            Action::Observe => "observe",
            Action::Call { .. } => "call",
            Action::Show => "show",
            Action::Race => "race",
            Action::Blind => "blind",
            Action::Restart => "restart",
        };
        ensure!(
            taken == named,
            "the trace took {taken}, but its states show {named}"
        );
    }
    Ok(action)
}

/// The decisions that a set of traces reaches.
#[derive(Debug, Default)]
struct Coverage(BTreeSet<String>);

impl Coverage {
    fn note(&mut self, what: impl Into<String>) {
        self.0.insert(what.into());
    }
}

/// Replay one trace through `Run`, and note the decisions it reaches.
fn replay(text: &str, coverage: &mut Coverage) -> Result<()> {
    let document: Value = serde_json::from_str(text)?;
    let states = document["states"]
        .as_array()
        .context("a trace lists states")?;
    let first = states.first().context("a trace starts somewhere")?;
    let candidate = candidate(first)?;
    ensure!(last(first)?.is_none(), "a trace starts before any step");
    let mut position = 1;
    'runs: loop {
        let mut marks = [false; OBJECTS];
        let mut run = Run::new(&mut marks, candidate.approved);
        while position < states.len() {
            let (before, after) = (&states[position - 1], &states[position]);
            position += 1;
            match action(before, after)? {
                Action::Restart => {
                    coverage.note("restart");
                    continue 'runs;
                }
                Action::Observe => {
                    let objects = objects(&candidate, before)?;
                    let step = run.observed(&objects);
                    ensure!(
                        last(after)? == Some(step),
                        "state {position}: the model decided {:?}, and Run decided {step:?}",
                        last(after)?
                    );
                    let landed = runner_field(after, "landed")?;
                    ensure!(
                        run.landed() == landed,
                        "state {position}: the model counted {landed:?} as landed, and Run counted {:?}",
                        run.landed()
                    );
                    coverage.note(match step {
                        Step::Apply(_) => "apply".to_owned(),
                        Step::Finish(state) => format!("finish {state:?}"),
                        Step::Conflict(_) => "conflict".to_owned(),
                        Step::Failed { .. } => "failed".to_owned(),
                        Step::Diverged => "diverged".to_owned(),
                        Step::Reshaped => "reshaped".to_owned(),
                    });
                    if landed.is_some() {
                        coverage.note("landed");
                    }
                    if let Step::Apply(index) = step
                        && objects[..index]
                            .iter()
                            .any(|object| object.decision() == release_glz_core::Decision::Create)
                    {
                        coverage.note("passed over");
                    }
                }
                Action::Call { succeeded } => run.applied(succeeded),
                Action::Blind => {
                    let expected = unobserved(after)?;
                    ensure!(
                        run.unobserved() == expected,
                        "state {position}: the model reported {expected:?} after a failed observation, and Run reported {:?}",
                        run.unobserved()
                    );
                    coverage.note(if expected == ReleaseState::Blocked {
                        "unobserved before a failure"
                    } else {
                        "unobserved after a failure"
                    });
                }
                Action::Show | Action::Race => {}
            }
        }
        return Ok(());
    }
}

fn traces() -> Vec<PathBuf> {
    let mut traces = fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join(TRACES))
        .expect("the committed traces")
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    traces.sort();
    traces
}

#[test]
fn every_committed_trace_replays_through_the_run_machine() {
    let mut coverage = Coverage::default();
    let traces = traces();
    assert!(!traces.is_empty(), "no committed traces");
    for trace in &traces {
        replay(&fs::read_to_string(trace).unwrap(), &mut coverage)
            .unwrap_or_else(|error| panic!("{}: {error:#}", trace.display()));
    }
    for decision in [
        "apply",
        "finish Released",
        "finish AwaitingApproval",
        "conflict",
        "failed",
        "diverged",
        "landed",
        "passed over",
        "unobserved before a failure",
        "unobserved after a failure",
        "restart",
    ] {
        assert!(
            coverage.0.contains(decision),
            "no committed trace reaches {decision}: {:?}",
            coverage.0
        );
    }
}

/// A trace whose decision differs from `Run` fails the replay, so the replay compares the decisions.
#[test]
fn a_trace_that_decides_otherwise_fails_the_replay() {
    let trace = traces()
        .into_iter()
        .find(|path| path.ends_with("release_run_publishesInOrderTest.itf.json"))
        .expect("the trace of the in-order test");
    let mut document: Value = serde_json::from_str(&fs::read_to_string(trace).unwrap()).unwrap();
    let states = document["states"].as_array_mut().unwrap();
    let applied = states
        .iter_mut()
        .find_map(|state| {
            state
                .as_object_mut()
                .unwrap()
                .iter_mut()
                .find(|(key, value)| key.ends_with("::runner") && value["last"]["tag"] == "Apply")
                .map(|(_, runner)| runner)
        })
        .expect("an applied effect");
    applied["last"]["value"]["#bigint"] = Value::from("2");
    let error = replay(&document.to_string(), &mut Coverage::default())
        .expect_err("the replay admitted a decision that Run doesn't make");
    assert!(error.to_string().contains("the model decided"), "{error:#}");
}
