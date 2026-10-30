---
date: 2026-10-30
---

# Show that the proofs detect core mutants

## Status

Proposed.

## Context

Each Kani harness has a negative control, which shows that the harness rejects one chosen broken decision.
Nothing showed that the harnesses together pin down every decision of the core crates, so a harness set that left some behavior unconstrained still verified.
The core crates have no tests of their own, because Kani proves them, so cargo-mutants with the test suite as its oracle finds nothing there.
The release gate's mutation job also listed two core files that it never mutated, because cargo-mutants mutates another workspace member only with `--workspace`.
The owner keeps mutation campaigns off Actions because of their cost.

## Decision

`cargo xtask proof-mutants` runs every mutant of the core crates through the Kani harnesses on an owner machine, in the image that [`verification/kani.Dockerfile`](../../verification/kani.Dockerfile) pins with cargo-mutants.

- It proves the unmutated core first, through the same audit as `cargo xtask proofs`, and stops unless the audit admits that run.
- cargo-mutants lists the mutants, and the campaign leaves out the harnesses and the negative controls by their place in the source.
- The campaign applies each mutant to a copy of the frozen sources and runs the harnesses of the mutant's module, stopping at the first failure.
  Before it calls a mutant a survivor, it runs every harness of the package.
- Each outcome comes from Kani's audited report: detected when a harness fails the audit, unviable when the mutant doesn't compile, and inconclusive otherwise.
  An inconclusive mutant fails the campaign.
- A survivor has to appear in [`verification/equivalent-mutants.json`](../../verification/equivalent-mutants.json) with the reason that no harness can detect it.
  The list names each mutant by file, function, original text, and replacement, so edits elsewhere in a file leave it valid.
  The campaign refuses an entry that no longer survives.
- The campaign writes a receipt with the digest of the core sources, the tool releases, and the outcome of every mutant, which the owner commits as [`verification/proof-mutants.json`](../../verification/proof-mutants.json).

The release gate runs `cargo xtask proof-mutants check`.
It refuses a receipt for other core sources or other tool releases, a receipt without a detected mutant, and a receipt whose survivors differ from the equivalent list.

## Consequences

- A change to a core crate needs a new campaign before a release can pass, though no pull request waits for one.
- The release gate checks the receipt's binding to the sources, not its computation.
  Anyone with the pinned image can reproduce a receipt, and a reviewer reads each outcome in the diff.
- An unviable mutant counts as neither detected nor survived, because the compiler rejects it before any proof runs.
- Rejected: the campaign on Actions.
  It takes the time of one Kani run per mutant, which the owner keeps on owner machines.
- Rejected: cargo-mutants with the test suite as its oracle.
  The core crates have no tests, and their harnesses are the oracle that matters.
