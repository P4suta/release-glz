---
date: 2026-10-30
---

# Decide publication from object presence

## Status

Proposed.

## Context

The reconciler decides which effects a release still owes and when an observed object stops it with a conflict.
Those decisions keep a release from replacing or skipping a public object, and they lived in [`src/reconciler.rs`](../../src/reconciler.rs) next to the string comparisons, maps, and digests that feed them.
Tests and mutation runs checked them, but no proof could, because a model checker can't cover strings and maps of every size.

## Decision

The decisions move into the core crate as functions of finite values, and the reconciler only describes the world in those values.

- [`Object`](../../crates/release-glz-core/src/publication.rs) describes each object a release publishes by whether the Candidate wants it, how the world holds it, and whether its effect blocks completion.
  `Presence` is `absent`, `pending`, `matches`, or `differs`.
- `Object::decision` creates an object only when the Candidate wants it and the world lacks it or holds it pending.
  It reports a conflict for any object that exists outside the Candidate's description.
- `reconcile` reports the first conflicting object, withholds every effect without approval, and derives the release state from the remaining effects.
- [`Approval::approves`](../../crates/release-glz-core/src/approval.rs) decides approval from booleans that the reconciler computes by comparing the evidence with the Candidate.
- The reconciler keeps the checks that concern the Candidate alone, such as duplicate asset names, and the mapping from observations to `Presence`.

Kani proves the decisions of one object and of an approval for every input.
It proves four list properties for releases of at most three objects.
Effects concern only missing objects, any differing object ends in a conflict, nothing leaves without approval, and publishing one object removes exactly its effect.
Each harness has a negative control that the release gate builds and requires to fail.

## Consequences

- The proofs cover the decisions, not the mapping from observations to `Presence` or the shell's own checks, which tests and mutation runs keep covering.
- The list proofs stop at three objects, and theorems for every length belong to a model that refines these functions.
- A notification record for a hook that the Candidate doesn't have no longer counts as a started release.
  It never caused a conflict, and the live observer never reports one.
- When two or more objects conflict, the reconciler reports the first one in publication order, so the tag outranks the package.
- Rejected: proving the existing functions over bounded strings and maps.
  The proofs would cover a few short values and say nothing about the decision itself.
