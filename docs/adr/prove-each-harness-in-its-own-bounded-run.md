---
date: 2026-10-31
---

# Prove each harness in its own bounded run

## Status

Proposed.
It supersedes [prove each module in its own bounded run](prove-each-module-in-its-own-bounded-run.md).

## Context

The gate proved the harnesses of each module in one bounded run, and the owner's policy gives each container 2 GiB of memory and 900 seconds.
Memory stays in the container from one harness of a run to the next.
In a run of the ten archive harnesses, the container held about 650 MB of anonymous memory between harnesses and almost no page cache.
The image has no process listing, so the run didn't show which process held that memory.
Kani's driver outlives every harness of the run, which makes it the likely holder.
The two largest archive harnesses pass alone and as a pair, and both exceeded 2 GiB in the run of their module.
A run that the limit stops leaves the gate without a verdict.
A proof-mutation campaign that proves its mutants through the same runs can't classify a mutant of that module either.
A module that outgrows the limit could move some harnesses to a module of their own.
Then the layout of the sources would depend on memory that a run keeps and that no inventory records.

## Decision

The gate proves each harness of the inventory in its own bounded run.

- The census build stays, and the gate still refuses a harness that only the census or only the inventory names.
- Each run selects its harness by its full name with Kani's `--exact`, so no run selects another harness, and the gate drops its check of module filters.
- Each run must meet every condition that the run of a module met, for exactly its harness.

## Consequences

- Neither the memory nor the time of a run grows with the other harnesses, so a harness that passes alone under the policy passes in the gate.
- Each run starts a container and builds the crates for its harness.
  On an owner machine that took about 9 seconds beyond the proof, about 15 minutes over 84 harnesses.
- A campaign that proves mutants through these runs gets a verdict for each harness and can stop at the first that fails.
- Rejected: splitting a module whenever its run outgrows the limit.
  It holds only until the module grows again, and nothing in the gate records the reason for a split.
- Rejected: a larger memory limit for proof runs.
  The owner's bounded-run policy fixes the limits for every tool.
