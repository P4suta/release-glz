---
date: 2026-10-30
---

# Prove each module in its own bounded run

## Status

Superseded by [prove each harness in its own bounded run](prove-each-harness-in-its-own-bounded-run.md) while still proposed.
It partly superseded [admit proofs only from audited reports](admit-proofs-only-from-audited-reports.md), whose gate proved every harness in one run.

## Context

`cargo xtask proofs` ran every harness of the proof packages in one container, and the bounded-run policy stops each container after 900 seconds.
The run's length grows with every harness, and on a branch with 47 harnesses it took 866 seconds beside three other proof containers.
A run that the limit stops leaves the gate without a verdict, so the next module of proofs would have made the gate unable to admit anything.
Raising the limit only moves the ceiling, and narrowing proofs to fit a timer would weaken the properties the gate exists to show.

## Decision

The gate proves the harnesses of each module in their own bounded run.

- First, a census build compiles every harness of the proof packages without verifying any, in a target directory of its own.
  Kani's compiler records each crate's harnesses in a metadata file, and [`xtask/src/proofs.rs`](../../xtask/src/proofs.rs) reads exactly one such file for each proof package.
- The gate refuses a harness that only the census or only the inventory names, and a harness outside every module, before the first run.
  It also refuses a module whose harness filter would select another module's harness.
- Each run selects its module's harnesses by their common name prefix, so Kani still reports any harness of that module, and the audit refuses one that the inventory lacks.
- Each run must meet every condition that the single run met, for exactly the harnesses of its module.

## Consequences

- Each container run lasts as long as one module's harnesses, so the limit applies to the largest module instead of the whole inventory.
- The census comes from the compiler, so a harness in a nested or generated module still counts, and the gate never depends on how the sources are laid out.
- The census reads a metadata file that Kani writes for its own use.
  The pinned Kani release fixes its format, and a file the census can't read stops the gate.
- Each run builds the crates for its own harness filter, which adds a short build to every module.
- A module whose harnesses alone outgrow the limit needs a split of its own, which the gate reports as a run without a verdict.
- The proof-mutation campaign can prove the other modules of a package one at a time when a mutant survives its own module's harnesses.
- Rejected: one run with a longer time limit.
  The owner's bounded-run policy fixes the limit for every tool, and a longer limit only delays the same failure.
- Rejected: Kani's parallel jobs inside the single run.
  Two model checkers would share the run's memory limit, and the run would still grow with every harness.
