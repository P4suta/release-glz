---
date: 2026-10-30
---

# Admit proofs only from audited reports

## Status

Proposed.
[Prove each harness in its own bounded run](prove-each-harness-in-its-own-bounded-run.md) partly supersedes it, after [prove each module in its own bounded run](prove-each-module-in-its-own-bounded-run.md) did.
The gate proves each harness in its own run, and each run meets the conditions below for its harness.

## Context

The release gate ran `cargo kani` in a shell step and searched its text output.
A negative control passed when the output contained `Failed Checks:` and the expected message, and a proof run passed when Kani exited with status 0.
Kani's text output is no contract, and a successful check can describe reasoning that Kani doesn't support.
The step never compared the harnesses Kani ran with the harnesses in the sources, so a harness that stopped compiling under the verifier left the gate green.
It also never showed that each cover was reachable, that the run read the reviewed sources, or that a negative control failed only its own assertion.

## Decision

Actions and owner machines run the proofs only through `cargo xtask proofs`.

- It copies the sources into a new evidence directory, builds the image that [`verification/kani.Dockerfile`](../../verification/kani.Dockerfile) pins, and runs Kani from the copy with fixed limits.
- It reads Kani's JSON export and keeps the part that decides admission beside each run.
- [`xtask/src/inventory.rs`](../../xtask/src/inventory.rs) names every harness with its cover count, and every negative control with its harness and the one assertion that has to fail.
  A test without the solver keeps the inventory equal to the harnesses, covers, and features in the sources.
- [`assurance-core`](../../crates/assurance-core/src/lib.rs) decides admission, and its own Kani harnesses prove the rules, each with a negative control.

A run of every harness counts only when each of these holds:

- Kani exited with status 0 and completed the run.
- Every listed harness ran and verified, and no other harness ran.
- Every assertion that a harness owns succeeded, and each harness reached exactly its listed covers.
- Every other check succeeded or was unreachable, and the property counts match the checks.
- No harness expected a panic, and the export names the pinned Kani, model checker, and target.
- The logs show no value that Kani replaced with an arbitrary one.
- The repository and the copy still hold the sources the run started from.

A negative control counts only when Kani exited with status 1 after running only its harness.
That harness has to fail only the expected assertion, and every one of its checks has to resolve.
The tool, log, and source conditions of a proof run apply to it as well.

## Consequences

- A harness without an inventory entry or a negative control fails the fast gate, so the release gate can't skip it.
- A new Kani release or export format needs the audit to accept it explicitly, because the audit refuses any other version.
- The gate builds and runs each negative control on its own, so it costs one Kani run per control.
- [`xtask/tests/fixtures`](../../xtask/tests/fixtures) holds the audited reports of a real run, and the audit tests show that every tampered field ends in a refusal.
- The audit trusts the verdicts of Kani and its model checker, and the proofs hold only under each harness's assumptions and bounds.
- The mutation job no longer lists the core files.
  cargo-mutants mutates another workspace member only with `--workspace`, so those entries never ran, and [#160](https://github.com/P4suta/release-glz/issues/160) tracks showing that the harnesses detect each mutant of the core.
- Rejected: matching more of Kani's text output.
  The format can change in any release, and text can't show which harnesses ran or which assertion failed.
- Rejected: one run with every negative control enabled.
  One control would mask another, and the gate couldn't tell which assertion each one broke.
