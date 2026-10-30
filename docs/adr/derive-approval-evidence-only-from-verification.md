---
date: 2026-10-30
---

# Derive approval evidence only from verification

## Status

Proposed.

## Context

The reconciler lets a release publish only when its approval evidence holds a `VerifiedGithubOidc`, the identity of the run that GitHub's OIDC token proves.
That type documented that nobody could hold one without the signature and claim checks.
`validate_github_claims` was public, though, and it returned one after the claim checks alone.
`release --dry-run`, `verify --online`, and `status --online` used it to invent an identity for an `inspection` ref and run `1`, so the reconciler treated every inspection as an approved release.
Only a `dry_run` flag in another argument kept that evidence from authorizing publication.
A caller that passed the invented evidence without the flag would have published with no approval at all.

## Decision

A verified identity comes only from signature verification, and an inspection holds no approval evidence.

- [`verify_github_oidc_token`](../../src/authorization.rs) is the only public path to a `VerifiedGithubOidc`, and the claim check is private to it.
- [`CandidateReleaseRunner`](../../src/release.rs) has two entry points.
  `run` applies effects under approval evidence, and `inspect` takes none and reconciles through [`preview`](../../src/reconciler.rs), which lists the effects an approval would unlock and authorizes nothing.
- `release --dry-run`, `verify --online`, and `status --online` call `inspect`.
- Tests that need a verified identity sign their claims with the RFC 7515 example key in the shared test support crate and verify the token.

## Consequences

- No combination of public calls publishes with an identity that a signature check didn't produce.
- An inspection reports the same remaining effects as an approved run, since `preview` and `reconcile` share the planning and the checks of the observed state.
- Library callers that built evidence from unsigned claims, or passed `ReleaseExecutionOptions`, must sign their claims or call `inspect`.
- The values in the approval evidence other than the identity still come from the workflow, and [bind each approval conjunct to a checked source](bind-each-approval-conjunct-to-a-checked-source.md) covers their sources.
- Rejected: keeping `dry_run` beside an authority enum.
  Two separate entry points leave no call that pairs inspection with an apply.
- Rejected: a test-only constructor behind a feature flag.
  Features are additive, so any build could turn it on.
