---
date: 2026-10-30
---

# Decide each run step in the core

## Status

Proposed.

## Context

`CandidateReleaseRunner` decided every step of a release run inside its async loop.
It chose the next effect, counted the attempts a run may make, and judged whether a failed call still counted as applied.
It also chose the state to report when an observation failed.
These decisions keep a run from finalizing a Release before its assets, from retrying an optional notification without end, and from reporting success after a failed effect.
Only tests with fake targets covered them, and a fake covers only the worlds it simulates.

## Decision

[`Run`](../../crates/release-glz-core/src/run.rs) in the core crate makes every decision of a run from what each observation holds and how each call ended.
The shell observes the world, applies the effect that `Run` chooses, and reports whether the call succeeded.

- [`Observation`](../../src/reconciler.rs) describes one observation as core objects in publication order, with the effect and the conflict that each object names.
- A run applies the first effect that the plan lists, and it passes over an optional effect it already attempted.
- The first plan that lists an effect fixes the number of attempts the run may make.
- After a failed call, the next observation decides whether the effect landed, and it also chooses the next effect, so the run no longer observes twice.
- The shell sizes the record of attempted effects from the first observation, and the run stops on an observation with another number of objects.
  Only an unsealed asset changes that number, and it conflicts first.

Kani proves six properties for every sequence of observations over releases of at most three objects.

- A run applies only an approved effect that the world lacks, in publication order.
- It attempts each optional effect at most once and stops within the attempts that its first plan listed.
- A failed call counts as applied only once the world holds its object, and a failed blocking effect that the world lacks stops the run.
- A run stops only when nothing but optional effects it attempted remains, and it reports released exactly when no blocking effect remains.
- A run whose effects land ends released.
- An observation of another number of objects stops the run.

A seventh harness proves one step from any record that a run can hold, over releases of at most five objects.
The step applies only the first owed effect that the run doesn't pass over, spends exactly one attempt, and records exactly that attempt.
A new run starts with an empty record and no budget.
By induction on its steps, the order, the single attempt at each optional effect, and the attempt bound then hold for runs of any length.

Each harness has a negative control that the proof gate requires to fail.

## Consequences

- The proofs cover the decisions and not the adapters.
  The world may change between an observation and the call that follows it.
  Then the release stays safe because the registry and GitHub refuse to replace an immutable object.
- The proofs assume that the Candidate fixes which objects a release wants and which effects block, which holds because the sealed Candidate supplies both.
- The proofs stop at three objects and four observations, and the Lean model of publication covers the plans of longer releases.
- A failed effect costs one observation instead of two.
- Rejected: proving the async loop itself.
  Kani doesn't model the async runtime or the network, so the decisions had to leave the loop to become provable.
- Rejected: a protocol model in Quint alone.
  A model without a binding to the production code would check a design and not the runner.
