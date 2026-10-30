---
date: 2026-10-30
---

# Bind each approval conjunct to a checked source

## Status

Proposed.

## Context

The reconciler publishes only when every conjunct of the approval in [`approved`](../../src/reconciler.rs) holds.
[Derive approval evidence only from verification](derive-approval-evidence-only-from-verification.md) made the run identity come only from a verified OIDC token.
The other values in the evidence still came from the publish job's environment.

- The intent digest came from `RELEASE_GLZ_APPROVED_INTENT_DIGEST`, which the same run set from its own outputs.
  The run had already checked the merged Release PR on the server, but the evidence didn't carry what that check found.
- The Environment came from `RELEASE_GLZ_ENVIRONMENT`, which the generated workflow set to the configured name.
  The verified OIDC claims already name the Environment that released the job.

A conjunct whose value the run supplies for itself only repeats what the run already knew.

## Decision

Each conjunct takes its value from a check that GitHub answered, and [`verify_approval`](../../src/approval.rs) gathers them.

| Conjunct | Push release | Manual release |
| --- | --- | --- |
| Run identity: repository, workflow, ref, commit, run | Verified OIDC claims | Verified OIDC claims |
| Environment | Verified OIDC claims | Verified OIDC claims |
| Intent digest | Marker of the merged Release PR that GitHub returns for the source commit | The verified Candidate's own |
| Candidate digest | The preparing job's output in the same run | The dispatcher's `candidate-digest` input |
| Candidate artifact | Artifact and run checked with the Actions API | Artifact and run checked with the Actions API |
| Source commit and reason | Not used | The dispatcher's inputs |

- [`merged_release_pr`](../../src/forge.rs) reports the intent that the marker recorded, instead of filtering on the intent the caller expects.
  The comparison happens once, in `approved`.
- The generated workflow no longer sets `RELEASE_GLZ_APPROVED_INTENT_DIGEST` or `RELEASE_GLZ_ENVIRONMENT`, and release-glz no longer reads them.

## Consequences

- A push release publishes only an intent that a merged Release PR recorded, whatever the job's environment says.
- An approval follows the Environment that GitHub signed into the OIDC token, so the evidence holds no second Environment that could disagree with it.
- A manual release has no Release PR, so its intent digest conjunct compares the Candidate with itself and binds nothing.
  The conjunct stays until the owner decides whether the approval gate should drop it, because removing a conjunct changes the approval policy.
- On a push, the Candidate digest conjunct also compares two values that the same run produced.
  The Actions artifact check and the merged Release PR carry that path's binding.
- Workflows generated before this change still pass the two variables, and release-glz ignores them.
- Rejected: keeping the intent filter in the forge and also comparing in `approved`.
  Two comparisons of the same value would let a change to one of them go unnoticed.
