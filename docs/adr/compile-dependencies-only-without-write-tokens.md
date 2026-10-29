---
date: 2026-10-30
---

# Compile dependencies only in jobs without write tokens

## Status

Proposed.

## Context

Planning and rehearsal run `gleam export`, which builds every dependency, and a dependency's build can run code.
The generated workflow ran that build in the job that also held `contents: write` and `pull-requests: write` to update the Release PR.
The compiler environment allowlist keeps tokens out of the compiler's environment, but code running as the same user can still look for them on the runner.

The generated workflow also relied on a `pull_request` run to rehearse the Release PR head and bind its intent.
`GITHUB_TOKEN` writes the Release PR, and GitHub starts no workflow run for events that this token causes, so the binding never ran and publication stopped at `blocked`.
One workflow-wide concurrency group made every run wait behind a publication that waited for Environment approval.

## Decision

No job of the generated workflow both runs the compiler and holds a write permission.

- `plan` compiles with read access and uploads its plan as an artifact.
- `release-pr` writes the Release PR from that plan with `release-pr --plan`, which treats the plan as untrusted input and never starts the compiler.
- `rehearse-release-pr` compiles the new Release PR head with read access, and `bind-release-pr` records its intent with `pull-requests: write` and no compiler.
- The workflow runs for pushes and manual dispatches only.
- Only `release-pr`, `bind-release-pr`, and `publish` serialize, each in its own per-package concurrency group.

[`tests/workflow_permissions.rs`](../../tests/workflow_permissions.rs) checks the rule on the parsed workflow, and [`src/handoff.rs`](../../src/handoff.rs) holds the plan checks.

## Consequences

- A compromised dependency build no longer runs beside a token that can push commits or edit pull requests.
- It can still choose what the plan proposes and what the rehearsal produces, so human review of the Release PR and Environment approval of the `candidate_digest` remain the gates.
- Every push that needs a release compiles three times: in `plan`, in `rehearse-release-pr`, and in `prepare`.
- A Release PR merged before its push run binds the intent stops at `blocked`.
- Rejected: a personal access token or GitHub App token for the Release PR, so that its `pull_request` run binds the intent.
  It would put a long-lived credential in the repository and still compile beside it.
- Rejected: one concurrency group for `release-pr` and `bind-release-pr`.
  A newly queued job cancels the pending job of its group, so a bind could cancel a newer Release PR update.
  Instead, `release-pr` writes only from the current default branch tip, and a binding for a replaced head reports `superseded`.
