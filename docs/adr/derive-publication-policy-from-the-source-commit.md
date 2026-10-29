---
date: 2026-10-30
---

# Derive publication policy from the source commit

## Status

Proposed.

## Context

The `prepare` job compiles the package, so dependency build code runs there, and the same job seals the Candidate.
[Compile dependencies only in jobs without write tokens](compile-dependencies-only-without-write-tokens.md) keeps write tokens out of that job and accepts that build code can shape what rehearsal produces.
The publish job then built its registry client, credential variable, notify hooks, and approval policy from the Candidate alone.
Build code that rewrote the Candidate into another self-consistent one could choose where the publish job sends the registry credential and which commands that job runs.
A reviewer who approves the `candidate_digest` gets only a digest to compare.

## Decision

Publication trusts a Candidate only for its products and takes every policy field from the source commit.

- [`SealedPolicy`](../../src/candidate.rs) names every Candidate field that decides where, as whom, and with which commands a release goes out.
  Its projection destructures the manifest without a rest pattern, so a new field doesn't compile until someone classifies it as policy, product, or digest.
- `SealedPolicy::from_source` derives the policy from a package configuration, and rehearsal builds every Candidate from it.
- [`SourceBoundCandidate::bind`](../../src/release.rs) reads the configuration from the committed tree at the Candidate's source commit, at the manifest path that the command names.
  It refuses a Candidate whose policy differs in any field and names each field.
- `LiveReleaseTarget` starts only from a `SourceBoundCandidate`.
  `release`, `verify --online`, and `status --online` bind before they create an approval, GitHub, or registry client.

## Consequences

- Build code in `prepare` can no longer redirect the registry credential, add a notify command, widen the manual refs, or change the release notes.
- It can still shape the package, documentation, and interface bytes, the hook evidence, and the sidecars, which the approved digest covers.
- A Candidate that an earlier release-glz sealed fails the comparison when the publishing release-glz reads the configuration differently, and needs a new `prepare`.
- Publication reads the source commit with `git archive`, so it needs the full checkout but no compiler.
- Rejected: signing the Candidate in `prepare`.
  The signing key would sit in the job that runs build code.
- Rejected: comparing only the registry identity.
  Notify hooks and approval refs steer the same job.
