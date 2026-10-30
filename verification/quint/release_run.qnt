// The release protocol: one runner at a time follows the decisions of `release_glz_core::Run` against a world that shows commits late, may commit a call that reports failure, races another publisher, and refuses to replace an object that exists.
// `crates/release-glz-core/src/run.rs` makes the runner's decisions, and `tests/run_replay.rs` replays the traces of this model through it.
module release_run_model {
  // Whether the runner is the broken one that the probe checks: it applies the last effect it may apply instead of the first.
  const BUGGY: bool

  // The number of objects of a release, in publication order.
  pure val OBJECTS = 3
  // How many runs a release may start, which bounds the traces.
  pure val RUNS = 2

  pure val INDICES = 0.to(OBJECTS - 1)

  // How the world holds one object, or how an observation shows it.
  type Presence = Absent | Pending | Matches | Differs

  // What the core decides about one object.
  type Decision = Create | Keep | Conflict

  // The states that a run reports.
  type State = CandidateReady | PartiallyReleased | Released | AwaitingApproval | Blocked

  // The decision of the runner's newest step, which the replay compares with `Run`.
  type Step =
    | Start
    | Apply(int)
    | Finish(State)
    | Conflicted(int)
    | FailedAt({ index: int, state: State })
    | Diverged
    | Unobserved(State)

  // What the Candidate fixes for the whole release.
  type Candidate = { wanted: int -> bool, blocking: int -> bool, approved: bool }

  // The record that one `Run` keeps, field for field, where -1 stands for none.
  type Runner = {
    attempted: int -> bool,
    budget: int,
    failed: int,
    applying: int,
    planned: State,
    landed: int,
    stopped: bool,
    last: Step,
  }

  var candidate: Candidate
  // What the world holds.
  var held: int -> Presence
  // What an observation shows, which catches up with the world one object at a time.
  var shown: int -> Presence
  var runner: Runner
  var runs: int
  // Whether the runner ever committed an object while an earlier blocking object lacked the Candidate's content.
  var outOfOrder: bool
  // Whether the runner ever committed an object without approval.
  var unapproved: bool
  // Whether another publisher already raced the release.
  var raced: bool
  // Whether an observation already failed, which happens at most once in a release.
  var blinded: bool

  pure def decide(wanted: bool, presence: Presence): Decision =
    match presence {
      | Differs => Conflict
      | Absent => if (wanted) Create else Keep
      | Pending => if (wanted) Create else Conflict
      | Matches => if (wanted) Keep else Conflict
    }

  pure def least(candidates: Set[int]): int =
    candidates.fold(OBJECTS, (found, index) => if (index < found) index else found)

  pure def greatest(candidates: Set[int]): int =
    candidates.fold(-1, (found, index) => if (index > found) index else found)

  // A run that has attempted nothing yet.
  pure val fresh: Runner = {
    attempted: INDICES.mapBy(_ => false),
    budget: -1,
    failed: -1,
    applying: -1,
    planned: Blocked,
    landed: -1,
    stopped: false,
    last: Start,
  }

  // `Run::observed`: the runner's decision about one observation.
  pure def observedBy(r: Runner, c: Candidate, view: int -> Presence, buggy: bool): Runner = {
    val conflicts = INDICES.filter(index => decide(c.wanted.get(index), view.get(index)) == Conflict)
    val owed = INDICES.filter(index => decide(c.wanted.get(index), view.get(index)) == Create)
    val state =
      if (owed.forall(index => not(c.blocking.get(index)))) Released
      else if (INDICES.exists(index => view.get(index) != Absent)) PartiallyReleased
      else CandidateReady
    val cleared = r.with("failed", -1).with("landed", -1)
    if (conflicts.size() > 0)
      cleared.with("stopped", true).with("last", Conflicted(least(conflicts)))
    else if (not(c.approved))
      cleared.with("stopped", true).with("last", Finish(AwaitingApproval))
    else if (r.failed >= 0 and owed.contains(r.failed) and c.blocking.get(r.failed))
      cleared.with("stopped", true).with("last", FailedAt({ index: r.failed, state: state }))
    else {
      val landed = if (r.failed >= 0 and not(owed.contains(r.failed))) r.failed else -1
      val chosen = owed.filter(index => c.blocking.get(index) or not(r.attempted.get(index)))
      val going = cleared.with("landed", landed)
      if (chosen.size() == 0)
        going.with("stopped", true).with("last", Finish(state))
      else {
        val index = if (buggy) greatest(chosen) else least(chosen)
        val available = if (r.budget < 0) owed.size() else r.budget
        if (available == 0)
          going.with("stopped", true).with("last", Diverged)
        else
          going
            .with("attempted", r.attempted.set(index, true))
            .with("budget", available - 1)
            .with("applying", index)
            .with("planned", state)
            .with("last", Apply(index))
      }
    }
  }

  // `Run::applied`: the runner records how its call ended.
  pure def appliedBy(r: Runner, succeeded: bool): Runner =
    r.with("failed", if (succeeded) r.failed else r.applying).with("applying", -1)

  // `Run::unobserved`: the state that a run reports when an observation fails.
  pure def unobservedBy(r: Runner): State =
    if (r.failed >= 0) r.planned else Blocked

  // Whether the object at `index` either needn't block the release or holds the Candidate's content.
  pure def settled(c: Candidate, world: int -> Presence, index: int): bool =
    not(c.wanted.get(index) and c.blocking.get(index)) or world.get(index) == Matches

  // Whether a call that the world accepts creates or completes the object at `index`, which only an object that the world lacks or holds pending allows.
  pure def commits(world: int -> Presence, index: int, accepted: bool): bool =
    accepted and (world.get(index) == Absent or world.get(index) == Pending)

  // Whether committing the object at `index` comes before an earlier blocking object holds the Candidate's content.
  pure def early(c: Candidate, world: int -> Presence, index: int): bool =
    INDICES.exists(earlier => earlier < index and not(settled(c, world, earlier)))

  // Whether a record of misbehavior holds after one more event.
  pure def noted(record: bool, event: bool): bool = record or event

  // Whether a call reports success, which only a committed call can.
  pure def reports(committed: bool, report: bool): bool = committed and report

  action initFrom(c: Candidate, world: int -> Presence): bool = all {
    candidate' = c,
    held' = world,
    shown' = world,
    runner' = fresh,
    runs' = 1,
    outOfOrder' = false,
    unapproved' = false,
    raced' = false,
    blinded' = false,
  }

  // Any release, from a world that already holds any of its wanted objects with the Candidate's content or pending, as a resumed release finds it.
  // A world that starts with an object the Candidate lacks only stops the first observation, and the race reaches that conflict later in a run.
  action init = {
    nondet wanted = INDICES.setOfMaps(Bool).oneOf()
    nondet blocking = INDICES.setOfMaps(Bool).oneOf()
    nondet approved = Bool.oneOf()
    nondet world = INDICES
      .setOfMaps(Set(Absent, Pending, Matches))
      .filter(world => INDICES.forall(index => wanted.get(index) or world.get(index) == Absent))
      .oneOf()
    initFrom({ wanted: wanted, blocking: blocking, approved: approved }, world)
  }

  // The runner observes the world and decides its next step.
  action observe = all {
    not(runner.stopped),
    runner.applying < 0,
    runner' = observedBy(runner, candidate, shown, BUGGY),
    candidate' = candidate,
    held' = held,
    shown' = shown,
    runs' = runs,
    outOfOrder' = outOfOrder,
    unapproved' = unapproved,
    raced' = raced,
    blinded' = blinded,
  }

  // The runner's call reaches the world, which creates or completes the object only if it lacks it or holds it pending, and the call may report failure either way.
  action callAs(commit: bool, report: bool): bool = all {
    runner.applying >= 0,
    held' = if (commits(held, runner.applying, commit)) held.set(runner.applying, Matches) else held,
    runner' = appliedBy(runner, reports(commits(held, runner.applying, commit), report)),
    outOfOrder' = noted(outOfOrder, commits(held, runner.applying, commit) and early(candidate, held, runner.applying)),
    unapproved' = noted(unapproved, commits(held, runner.applying, commit) and not(candidate.approved)),
    candidate' = candidate,
    shown' = shown,
    runs' = runs,
    raced' = raced,
    blinded' = blinded,
  }

  action call = {
    nondet commit = Bool.oneOf()
    nondet report = Bool.oneOf()
    callAs(commit, report)
  }

  // The world shows what it holds of the object at `index`.
  action showAs(index: int): bool = all {
    shown.get(index) != held.get(index),
    shown' = shown.set(index, held.get(index)),
    candidate' = candidate,
    held' = held,
    runner' = runner,
    runs' = runs,
    outOfOrder' = outOfOrder,
    unapproved' = unapproved,
    raced' = raced,
    blinded' = blinded,
  }

  action show = {
    nondet index = INDICES.oneOf()
    showAs(index)
  }

  // Another publisher, which races the release at most once, creates the object at `index`, which the world lacks, with other content.
  action raceAs(index: int): bool = all {
    not(raced),
    held.get(index) == Absent,
    held' = held.set(index, Differs),
    candidate' = candidate,
    shown' = shown,
    runner' = runner,
    runs' = runs,
    outOfOrder' = outOfOrder,
    unapproved' = unapproved,
    raced' = true,
    blinded' = blinded,
  }

  action race = {
    nondet index = INDICES.oneOf()
    raceAs(index)
  }

  // An observation fails, at most once in a release, and the run stops in the state it can vouch for.
  action blind = all {
    not(blinded),
    not(runner.stopped),
    runner.applying < 0,
    runner' = runner.with("stopped", true).with("last", Unobserved(unobservedBy(runner))),
    candidate' = candidate,
    held' = held,
    shown' = shown,
    runs' = runs,
    outOfOrder' = outOfOrder,
    unapproved' = unapproved,
    raced' = raced,
    blinded' = true,
  }

  // The run ends, by stopping or by crashing between calls, and the release starts a new run.
  action restart = all {
    runs < RUNS,
    runner.applying < 0,
    runner' = fresh,
    runs' = runs + 1,
    candidate' = candidate,
    held' = held,
    shown' = shown,
    outOfOrder' = outOfOrder,
    unapproved' = unapproved,
    raced' = raced,
    blinded' = blinded,
  }

  action step = any { observe, call, show, race, blind, restart }

  // The runner commits an object only when every earlier blocking object holds the Candidate's content.
  val ordered = not(outOfOrder)
  // A run that reports a release as released leaves every blocking object with the Candidate's content.
  val releasedHoldsTheCandidate =
    runner.last == Finish(Released) implies INDICES.forall(index => settled(candidate, held, index))
  // Nothing commits without approval.
  val approvalFirst = not(unapproved)

  val safe = ordered and releasedHoldsTheCandidate and approvalFirst

  // Three wanted, blocking objects, under approval.
  pure val everything: Candidate = {
    wanted: INDICES.mapBy(_ => true),
    blocking: INDICES.mapBy(_ => true),
    approved: true,
  }

  // Three wanted objects under approval, of which the first is an optional notification.
  pure val optionalFirst: Candidate = everything.with("blocking", INDICES.mapBy(index => index > 0))

  // A world that lacks every object.
  pure val nothing: int -> Presence = INDICES.mapBy(_ => Absent)

  // A world that holds every object but the first.
  pure val allButFirst: int -> Presence = INDICES.mapBy(index => if (index == 0) Absent else Matches)
}

module release_run {
  import release_run_model(BUGGY = false).*

  // A run publishes every object of a fresh release in order and reports it released.
  run publishesInOrderTest =
    initFrom(everything, nothing)
      .then(observe).then(callAs(true, true)).then(showAs(0))
      .then(observe).then(callAs(true, true)).then(showAs(1))
      .then(observe).then(callAs(true, true)).then(showAs(2))
      .then(observe)
      .expect(runner.last == Finish(Released) and safe)

  // A call that commits but reports failure counts once the world shows the object.
  run aLandedFailureCountsTest =
    initFrom(everything, nothing)
      .then(observe).then(callAs(true, false)).then(showAs(0))
      .then(observe)
      .expect(runner.landed == 0 and runner.last == Apply(1) and safe)

  // A commit that the world doesn't show yet looks missing, the world refuses the repeat, and the run stops instead of going on.
  run anUnshownCommitStopsTheRunTest =
    initFrom(everything, nothing)
      .then(observe).then(callAs(true, true))
      .then(observe).then(callAs(true, true))
      .then(observe)
      .expect(runner.last == FailedAt({ index: 0, state: CandidateReady }) and safe)

  // Another publisher's object stops the release at the next observation.
  run aRaceStopsTheReleaseTest =
    initFrom(everything, nothing)
      .then(raceAs(1)).then(showAs(1))
      .then(observe)
      .expect(runner.last == Conflicted(1) and safe)

  // A failed optional effect doesn't stop the run, which passes over it and still ends released.
  run aFailedOptionalEffectIsPassedOverTest =
    initFrom(optionalFirst, nothing)
      .then(observe).then(callAs(false, false))
      .then(observe)
      .expect(runner.last == Apply(1) and runner.landed < 0 and safe)
      .then(callAs(true, true)).then(showAs(1))
      .then(observe).then(callAs(true, true)).then(showAs(2))
      .then(observe)
      .expect(runner.last == Finish(Released) and safe)

  // A world that never shows what the run publishes uses up the attempts of the first plan.
  run aWorldThatNeverShowsTheEffectDivergesTest =
    initFrom(everything, allButFirst)
      .then(observe).then(callAs(true, true))
      .then(observe)
      .expect(runner.last == Diverged and safe)

  // An observation that fails after a failed call reports the state of the plan that chose the call.
  run aFailedObservationAfterAFailedCallKeepsThePlanTest =
    initFrom(everything, nothing)
      .then(observe).then(callAs(false, false))
      .then(blind)
      .expect(runner.last == Unobserved(CandidateReady) and safe)

  // An observation that fails before anything else reports the release as blocked.
  run aFailedFirstObservationBlocksTest =
    initFrom(everything, nothing)
      .then(blind)
      .expect(runner.last == Unobserved(Blocked) and safe)

  // A run without approval applies nothing.
  run anUnapprovedRunAppliesNothingTest =
    initFrom(everything.with("approved", false), nothing)
      .then(observe)
      .expect(runner.last == Finish(AwaitingApproval) and safe)

  // A second run after a crash completes what the first one started.
  run aSecondRunResumesTheReleaseTest =
    initFrom(everything, nothing)
      .then(observe).then(callAs(true, true)).then(showAs(0))
      .then(restart)
      .then(observe)
      .expect(runner.last == Apply(1) and safe)
      .then(callAs(true, true)).then(showAs(1))
      .then(observe).then(callAs(true, true)).then(showAs(2))
      .then(observe)
      .expect(runs == 2 and runner.last == Finish(Released) and safe)
}

module release_run_buggy {
  import release_run_model(BUGGY = true).*

  // The broken runner publishes the last object first.
  run skipsAheadTest =
    initFrom(everything, nothing)
      .then(observe).then(callAs(true, true))
      .expect(runner.last == Apply(2) and not(safe))
}
