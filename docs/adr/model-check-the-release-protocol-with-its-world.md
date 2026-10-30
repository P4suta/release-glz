---
date: 2026-10-30
---

# Model-check the release protocol with its world

## Status

Proposed.

## Context

Kani proves each decision of [`Run`](../../crates/release-glz-core/src/run.rs) for any sequence of observations, as [decide each run step in the core](decide-each-run-step-in-the-core.md) records.
Those proofs say nothing about how the world answers a run.
A registry or GitHub may show a committed object only later, and a call may commit and still report failure.
Another publisher may race a release, an observation may fail, and a run may crash and start again.
A release has to stay safe across these behaviors.
It must never publish an object before an earlier blocking one, never report a release as released while a blocking object is missing, and never commit without approval.

## Decision

[`verification/quint/release_run.qnt`](../../verification/quint/release_run.qnt) models the world and one runner at a time in Quint.

- The world holds each object and shows it to observations late, one object at a time.
  It creates or completes an object only when it lacks the object or holds it pending, so it refuses to replace one that exists.
  A call may commit and report either result, and another publisher may create one object with other content.
- The runner's state is the record that `Run` keeps, and its step functions follow `Run::observed`, `Run::applied`, and `Run::unobserved`.
  An observation may fail once, and the release may start a second run after a stop or a crash between calls.
- The invariant combines three properties.
  The runner commits an object only when every earlier blocking object holds the Candidate's content.
  A run reports released only when every blocking object holds it, and nothing commits without approval.

`cargo xtask quint` checks the model in the image that [`verification/quint.Dockerfile`](../../verification/quint.Dockerfile) pins.

- An explicit-state model checker visits every state of releases of up to three objects and two runs, and the task requires the recorded number of distinct states.
- A probe module whose runner applies the last effect first has to break the order, so the check can fail.
- The task writes the traces of the scenario tests and of a seeded simulation again and requires them to equal [`verification/quint/traces`](../../verification/quint/traces).

[`tests/run_replay.rs`](../../tests/run_replay.rs) replays every committed trace through `Run` on each pull request.
It requires each decision, each landed effect, and each state after a failed observation to equal the model's.
It also requires the traces to reach every step of `Run` except a change in the number of objects, which the model leaves out.

## Consequences

- The model check covers the protocol for three objects and two runs, and the replay binds the model's runner to `Run` on the committed traces only.
  The Kani proofs cover the decisions of `Run` for every observation, so the replay adds evidence that the model follows `Run`, not that `Run` is correct.
- The model trusts the registry and GitHub to refuse to replace an object that exists, which the adapters can't prove.
- A change of the model changes the number of distinct states or the traces, and the task then fails until the change records both.
- Rejected: a symbolic check with Apalache alone.
  The state space is small enough for an explicit check of every state, which needs no step bound.
- Rejected: replaying random traces only.
  In 320 simulated traces, no trace reached a landed failure, so the scenario tests supply those traces.
