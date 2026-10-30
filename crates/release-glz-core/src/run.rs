//! The steps of one release run, decided from what each observation holds and how each effect ended.
//!
//! The shell observes the world, applies the effect that a [`Run`] chooses, and reports whether the call succeeded.
//! Every decision in between lives here: which effect comes next, how many attempts a run may make, when a failed effect still counts as applied, and which state the run stops in.

use crate::ReleaseState;
use crate::publication::{Decision, Object, Outcome, reconcile};

/// What a run does after an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Apply the effect of the object at this index, report how the call ended with [`Run::applied`], and observe again.
    Apply(usize),
    /// Stop in this state, with the effects of the observed plan still to do.
    Finish(ReleaseState),
    /// Stop, because the object at this index exists and publishing the Candidate would replace it.
    Conflict(usize),
    /// Stop, because the effect of the blocking object at this index failed and the world still lacks the object.
    Failed {
        /// The object whose effect failed.
        index: usize,
        /// The state of the plan that still lists the effect.
        state: ReleaseState,
    },
    /// Stop, because the run would need more attempts than its first plan listed effects.
    Diverged,
    /// Stop, because the observation holds another number of objects than the first one, so the run's record of attempted effects no longer applies.
    Reshaped,
}

/// The decisions of one release run.
///
/// A run applies one effect at a time, always the first one that the newest plan lists, and passes over an optional effect it already attempted.
/// The first plan that lists an effect fixes how many attempts the run may make, so a world that never holds an effect can't keep a run going.
#[derive(Debug)]
pub struct Run<'a> {
    /// Whether the run already attempted the effect of each object.
    attempted: &'a mut [bool],
    /// Whether the run has approval, which holds for the whole run.
    approved: bool,
    /// Attempts left, which the first plan that lists an effect sets to its number of effects.
    budget: Option<usize>,
    /// The effect of the last [`Step::Apply`], until the shell reports how its call ended.
    applying: Option<usize>,
    /// The effect whose call failed, until the next observation shows whether it landed.
    failed: Option<usize>,
    /// The state of the plan that chose the last effect.
    planned: ReleaseState,
    /// The failed effect that the newest observation no longer lists.
    landed: Option<usize>,
}

impl<'a> Run<'a> {
    /// A run over releases of `attempted.len()` objects that has attempted nothing yet.
    pub fn new(attempted: &'a mut [bool], approved: bool) -> Self {
        attempted.fill(false);
        Self {
            attempted,
            approved,
            budget: None,
            applying: None,
            failed: None,
            planned: ReleaseState::Blocked,
            landed: None,
        }
    }

    /// Decide what to do about a fresh observation of `objects`, given in publication order.
    pub fn observed(&mut self, objects: &[Object]) -> Step {
        self.landed = None;
        let failed = self.failed.take();
        let state = match reconcile(objects, self.approved) {
            Outcome::Conflict(index) => return Step::Conflict(index),
            Outcome::AwaitingApproval => return Step::Finish(ReleaseState::AwaitingApproval),
            Outcome::Proceed { state, .. } => state,
        };
        if let Some(step) = reshaped(objects.len(), self.attempted.len()) {
            return step;
        }
        if let Some(index) = failed {
            if !owes(objects, index) {
                self.landed = Some(index);
            } else if let Some(step) = stop_after_failure(objects, index, state) {
                return step;
            }
        }
        #[cfg(feature = "negative-control-stall")]
        if let Some(step) = negative_control_stall(self.budget, state) {
            return step;
        }
        let Some(index) = self.next(objects) else {
            return Step::Finish(state);
        };
        let budget = self.budget.get_or_insert_with(|| planned(objects));
        let Some(left) = spend(*budget) else {
            return Step::Diverged;
        };
        *budget = left;
        if let Some(attempted) = self.attempted.get_mut(index) {
            *attempted = true;
        }
        self.applying = Some(index);
        self.planned = state;
        Step::Apply(index)
    }

    /// Record how the call of the last [`Step::Apply`] ended.
    pub fn applied(&mut self, succeeded: bool) {
        let applying = self.applying.take();
        if !succeeded {
            self.failed = applying;
        }
    }

    /// The effect whose call failed but which the newest observation no longer lists, so it counts as applied.
    pub fn landed(&self) -> Option<usize> {
        self.landed
    }

    /// The state to report when an observation fails.
    ///
    /// After a failed effect, the world may already hold it, so the run reports the state of the plan that chose the effect, and otherwise it reports blocked.
    pub fn unobserved(&self) -> ReleaseState {
        #[cfg(feature = "negative-control-forget-failure")]
        if let Some(state) = negative_control_forget_failure() {
            return state;
        }
        if self.failed.is_some() {
            self.planned
        } else {
            ReleaseState::Blocked
        }
    }

    /// The first effect of the plan that the run doesn't pass over.
    fn next(&self, objects: &[Object]) -> Option<usize> {
        #[cfg(feature = "negative-control-skip-ahead")]
        if let Some(next) = negative_control_skip_ahead(self, objects) {
            return next;
        }
        (0..objects.len()).find(|&index| self.chooses(objects, index))
    }

    /// Whether the run may apply the effect of the object at `index`: the plan lists it, and the run doesn't pass over it.
    fn chooses(&self, objects: &[Object], index: usize) -> bool {
        owes(objects, index) && !self.passes_over(objects, index)
    }

    /// Whether the run passes over the effect of the object at `index`, which is an optional effect it already attempted.
    fn passes_over(&self, objects: &[Object], index: usize) -> bool {
        #[cfg(feature = "negative-control-retry-optional")]
        if let Some(passes) = negative_control_retry_optional() {
            return passes;
        }
        !blocks(objects, index) && self.attempted.get(index).copied().unwrap_or(false)
    }
}

/// Whether the effect of the object at `index` has to finish before the release counts as released.
fn blocks(objects: &[Object], index: usize) -> bool {
    objects.get(index).is_some_and(|object| object.blocks())
}

/// Whether an approved plan of `objects` lists the effect of the object at `index`, which it does exactly when the release creates that object.
fn owes(objects: &[Object], index: usize) -> bool {
    objects
        .get(index)
        .is_some_and(|object| object.decision() == Decision::Create)
}

/// The number of effects that an approved plan of `objects` lists.
fn planned(objects: &[Object]) -> usize {
    objects
        .iter()
        .filter(|object| object.decision() == Decision::Create)
        .count()
}

/// The stop for an observation of `observed` objects in a run that recorded `recorded`, if the counts differ.
fn reshaped(observed: usize, recorded: usize) -> Option<Step> {
    #[cfg(feature = "negative-control-reshape")]
    if let Some(step) = negative_control_reshape() {
        return step;
    }
    (observed != recorded).then_some(Step::Reshaped)
}

/// The stop for a failed effect of the object at `index` that the world still lacks, which only a blocking effect causes.
fn stop_after_failure(objects: &[Object], index: usize, state: ReleaseState) -> Option<Step> {
    #[cfg(feature = "negative-control-trust-failure")]
    if let Some(step) = negative_control_trust_failure() {
        return step;
    }
    blocks(objects, index).then_some(Step::Failed { index, state })
}

/// The attempts left after one more, or `None` once the budget is spent.
fn spend(budget: usize) -> Option<usize> {
    #[cfg(feature = "negative-control-unbudgeted")]
    if let Some(left) = negative_control_unbudgeted(budget) {
        return left;
    }
    budget.checked_sub(1)
}

/// Keeps every attempt free, so a run never spends its budget.
#[cfg(feature = "negative-control-unbudgeted")]
fn negative_control_unbudgeted(budget: usize) -> Option<Option<usize>> {
    Some(Some(budget))
}

/// Never passes over an optional effect, so a run retries one that failed.
#[cfg(feature = "negative-control-retry-optional")]
fn negative_control_retry_optional() -> Option<bool> {
    Some(false)
}

/// Chooses the last effect that a run may apply instead of the first.
#[cfg(feature = "negative-control-skip-ahead")]
fn negative_control_skip_ahead(run: &Run<'_>, objects: &[Object]) -> Option<Option<usize>> {
    Some(
        (0..objects.len())
            .rev()
            .find(|&index| run.chooses(objects, index)),
    )
}

/// Goes on after a failed blocking effect that the world still lacks.
#[cfg(feature = "negative-control-trust-failure")]
fn negative_control_trust_failure() -> Option<Option<Step>> {
    Some(None)
}

/// Stops a run once it has attempted anything, whatever remains.
#[cfg(feature = "negative-control-stall")]
fn negative_control_stall(budget: Option<usize>, state: ReleaseState) -> Option<Step> {
    budget.map(|_| Step::Finish(state))
}

/// Reports blocked after a failed effect too.
#[cfg(feature = "negative-control-forget-failure")]
fn negative_control_forget_failure() -> Option<ReleaseState> {
    Some(ReleaseState::Blocked)
}

/// Goes on with an observation of another number of objects.
#[cfg(feature = "negative-control-reshape")]
fn negative_control_reshape() -> Option<Option<Step>> {
    Some(None)
}

#[cfg(kani)]
mod proofs {
    use super::{Run, Step};
    use crate::ReleaseState;
    use crate::publication::{Decision, Object, Outcome, Presence, reconcile};

    /// The number of objects that these proofs cover, so their results hold for releases of at most this many objects.
    const OBJECTS: usize = 3;

    /// The observations a run of [`OBJECTS`] objects can make: the first one, and one after each of at most [`OBJECTS`] attempts.
    const OBSERVATIONS: usize = OBJECTS + 1;

    /// The number of objects that the step proof covers, which needs no history and so reaches further than the run proofs.
    const STEP_OBJECTS: usize = 5;

    /// An arbitrary observation of a release whose Candidate fixes which objects it wants and which effects block.
    fn observation(wanted: [bool; OBJECTS], blocking: [bool; OBJECTS]) -> [Object; OBJECTS] {
        core::array::from_fn(|index| Object {
            wanted: wanted[index],
            presence: kani::any(),
            blocking: blocking[index],
        })
    }

    fn owed(object: &Object) -> bool {
        object.decision() == Decision::Create
    }

    /// The state that the plan of `objects` reports, when the run goes on.
    fn plan_state(objects: &[Object], approved: bool) -> Option<ReleaseState> {
        match reconcile(objects, approved) {
            Outcome::Proceed { state, .. } => Some(state),
            Outcome::Conflict(_) | Outcome::AwaitingApproval => None,
        }
    }

    /// For any world, a run applies only an approved effect that the newest observation lacks, and only once no earlier object needs an effect, apart from optional effects it already attempted.
    #[kani::proof]
    #[kani::unwind(5)]
    fn a_run_applies_only_owed_effects_in_publication_order() {
        let wanted: [bool; OBJECTS] = kani::any();
        let blocking: [bool; OBJECTS] = kani::any();
        let approved: bool = kani::any();
        let mut marks = [false; OBJECTS];
        let mut run = Run::new(&mut marks, approved);
        let mut attempted = [false; OBJECTS];
        let mut passed_over = false;
        for _ in 0..OBSERVATIONS {
            let objects = observation(wanted, blocking);
            let Step::Apply(index) = run.observed(&objects) else {
                break;
            };
            kani::assert(
                approved && owed(&objects[index]),
                "a run must apply only an approved effect that the world lacks",
            );
            for earlier in 0..index {
                let object = &objects[earlier];
                let attempted_optional = !object.blocking && attempted[earlier];
                kani::assert(
                    !owed(object) || attempted_optional,
                    "a run must apply effects in publication order",
                );
                passed_over |= owed(object) && attempted_optional;
            }
            attempted[index] = true;
            run.applied(kani::any());
        }
        kani::cover!(passed_over);
    }

    /// For any world, a run attempts each optional effect at most once and makes at most as many attempts as its first plan listed effects, so it stops within [`OBSERVATIONS`] observations.
    #[kani::proof]
    #[kani::unwind(5)]
    fn a_run_attempts_each_optional_effect_once_within_its_first_plan() {
        let wanted: [bool; OBJECTS] = kani::any();
        let blocking: [bool; OBJECTS] = kani::any();
        let mut marks = [false; OBJECTS];
        let mut run = Run::new(&mut marks, true);
        let mut attempted = [false; OBJECTS];
        let mut planned = None;
        let mut attempts = 0_usize;
        let mut diverged = false;
        for _ in 0..OBSERVATIONS {
            let objects = observation(wanted, blocking);
            match run.observed(&objects) {
                Step::Apply(index) => {
                    let planned = *planned
                        .get_or_insert(objects.iter().filter(|object| owed(object)).count());
                    attempts += 1;
                    kani::assert(
                        attempts <= planned,
                        "a run must attempt at most as many effects as its first plan listed",
                    );
                    if !blocking[index] {
                        kani::assert(
                            !attempted[index],
                            "a run must attempt each optional effect at most once",
                        );
                    }
                    attempted[index] = true;
                    run.applied(kani::any());
                }
                Step::Diverged => {
                    diverged = true;
                    break;
                }
                _ => break,
            }
        }
        kani::cover!(diverged);
        kani::cover!(attempts == OBJECTS);
    }

    /// For any world, an effect counts as applied only when its call succeeded or the next observation no longer lists it, a failed blocking effect that the world still lacks stops the run, and a failed observation reports the state the run can vouch for.
    #[kani::proof]
    #[kani::unwind(5)]
    fn a_failed_effect_counts_only_once_the_world_holds_it() {
        let wanted: [bool; OBJECTS] = kani::any();
        let blocking: [bool; OBJECTS] = kani::any();
        let mut marks = [false; OBJECTS];
        let mut run = Run::new(&mut marks, true);
        let mut failed: Option<(usize, ReleaseState)> = None;
        let mut landed = false;
        let mut stopped = false;
        for _ in 0..OBSERVATIONS {
            kani::assert(
                run.unobserved() == failed.map_or(ReleaseState::Blocked, |(_, state)| state),
                "a run that can't observe must report the state of the plan that chose its failed effect",
            );
            let objects = observation(wanted, blocking);
            let state = plan_state(&objects, true);
            let step = run.observed(&objects);
            match (failed, state) {
                (Some((index, _)), Some(state)) if owed(&objects[index]) => {
                    kani::assert(
                        run.landed().is_none(),
                        "an effect must count as applied only when its call succeeded or the world holds it",
                    );
                    if blocking[index] {
                        kani::assert(
                            step == Step::Failed { index, state },
                            "a failed blocking effect that the world lacks must stop the run",
                        );
                        stopped = true;
                    }
                }
                (Some((index, _)), Some(_)) => {
                    kani::assert(
                        run.landed() == Some(index),
                        "a failed effect that the world holds must count as applied",
                    );
                    landed = true;
                }
                _ => kani::assert(
                    run.landed().is_none(),
                    "an effect must count as applied only when its call succeeded or the world holds it",
                ),
            }
            let Step::Apply(index) = step else {
                break;
            };
            let succeeded: bool = kani::any();
            run.applied(succeeded);
            failed = match (succeeded, state) {
                (false, Some(state)) => Some((index, state)),
                _ => None,
            };
        }
        kani::cover!(landed);
        kani::cover!(stopped);
    }

    /// For any world, a run stops only when nothing but optional effects it already attempted remains, and it reports released exactly when no blocking effect remains.
    #[kani::proof]
    #[kani::unwind(5)]
    fn a_run_stops_only_when_nothing_but_attempted_optional_effects_remains() {
        let wanted: [bool; OBJECTS] = kani::any();
        let blocking: [bool; OBJECTS] = kani::any();
        let mut marks = [false; OBJECTS];
        let mut run = Run::new(&mut marks, true);
        let mut attempted = [false; OBJECTS];
        let mut released_with_optional_left = false;
        for _ in 0..OBSERVATIONS {
            let objects = observation(wanted, blocking);
            match run.observed(&objects) {
                Step::Apply(index) => {
                    attempted[index] = true;
                    run.applied(kani::any());
                }
                Step::Finish(state) => {
                    let mut blocking_left = false;
                    for index in 0..OBJECTS {
                        let object = &objects[index];
                        kani::assert(
                            !owed(object) || (!object.blocking && attempted[index]),
                            "a run must stop only when nothing but optional effects it attempted remains",
                        );
                        blocking_left |= owed(object) && object.blocking;
                        released_with_optional_left |= owed(object);
                    }
                    kani::assert(
                        (state == ReleaseState::Released) == !blocking_left,
                        "a run must report released exactly when no blocking effect remains",
                    );
                    break;
                }
                _ => break,
            }
        }
        kani::cover!(released_with_optional_left);
    }

    /// A run in a world where every effect it applies lands ends released, whether or not each call reported success.
    #[kani::proof]
    #[kani::unwind(5)]
    fn a_run_whose_effects_land_ends_released() {
        let mut objects: [Object; OBJECTS] = kani::any();
        kani::assume(
            objects
                .iter()
                .all(|object| object.decision() != Decision::Conflict),
        );
        let mut marks = [false; OBJECTS];
        let mut run = Run::new(&mut marks, true);
        let mut finished = false;
        let mut failed_call = false;
        for _ in 0..OBSERVATIONS {
            match run.observed(&objects) {
                Step::Apply(index) => {
                    objects[index].presence = Presence::Matches;
                    let succeeded: bool = kani::any();
                    failed_call |= !succeeded;
                    run.applied(succeeded);
                }
                step => {
                    kani::assert(
                        step == Step::Finish(ReleaseState::Released),
                        "a run whose effects land must end released",
                    );
                    finished = true;
                    break;
                }
            }
        }
        kani::assert(finished, "a run whose effects land must end released");
        kani::cover!(failed_call && objects.iter().all(|object| object.wanted));
    }

    /// One step from any record a run can hold applies only the first owed effect that the run doesn't pass over, spends exactly one attempt for it, records exactly that attempt, and counts a failed effect as applied exactly when the world holds it.
    ///
    /// A new run starts with an empty record and no budget, so by induction on its steps these facts carry the bounds of the run proofs to runs of any length.
    #[kani::proof]
    #[kani::unwind(7)]
    fn every_step_keeps_the_record_that_bounds_a_run() {
        let before: [bool; STEP_OBJECTS] = kani::any();
        let mut marks = before;
        let approved: bool = kani::any();
        let budget: Option<usize> = kani::any();
        let failed: Option<usize> = kani::any();
        kani::assume(failed.is_none_or(|index| index < STEP_OBJECTS));
        let objects: [Object; STEP_OBJECTS] = kani::any();
        let mut run = Run {
            attempted: &mut marks,
            approved,
            budget,
            applying: None,
            failed,
            planned: kani::any(),
            landed: None,
        };
        let step = run.observed(&objects);
        let spent = run.budget;
        let landed = run.landed();
        let passed_over = |index: usize| !objects[index].blocking && before[index];
        match step {
            Step::Apply(index) => {
                let first =
                    (0..index).all(|earlier| !owed(&objects[earlier]) || passed_over(earlier));
                kani::assert(
                    approved && owed(&objects[index]) && !passed_over(index) && first,
                    "a step must apply the first owed effect that the run doesn't pass over",
                );
                let available =
                    budget.unwrap_or_else(|| objects.iter().filter(|object| owed(object)).count());
                kani::assert(
                    available > 0 && spent == Some(available - 1),
                    "a step must spend exactly one attempt",
                );
            }
            _ => kani::assert(spent == budget, "a step must spend exactly one attempt"),
        }
        for index in 0..STEP_OBJECTS {
            kani::assert(
                marks[index] == (before[index] || step == Step::Apply(index)),
                "a step must record exactly the effect it applies",
            );
        }
        let proceeds = matches!(reconcile(&objects, approved), Outcome::Proceed { .. });
        kani::assert(
            landed == failed.filter(|&index| proceeds && !owed(&objects[index])),
            "a step must count a failed effect as applied exactly when the world holds it",
        );
        kani::cover!(matches!(step, Step::Apply(_)) && budget.is_some());
        kani::cover!(landed.is_some());
    }

    /// A run stops on an observation that holds another number of objects than it recorded, unless the observation conflicts or the run lacks approval.
    #[kani::proof]
    #[kani::unwind(5)]
    fn a_run_stops_when_the_number_of_objects_changes() {
        let objects: [Object; OBJECTS] = kani::any();
        let count: usize = kani::any();
        kani::assume(count < OBJECTS);
        let approved: bool = kani::any();
        let mut marks = [false; OBJECTS];
        let mut run = Run::new(&mut marks, approved);
        let step = run.observed(&objects[..count]);
        kani::assert(
            matches!(
                step,
                Step::Conflict(_) | Step::Finish(ReleaseState::AwaitingApproval) | Step::Reshaped
            ),
            "a run must stop when the number of objects changes",
        );
        kani::cover!(step == Step::Reshaped);
    }
}
