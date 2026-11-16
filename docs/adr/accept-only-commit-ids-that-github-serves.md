---
date: 2026-11-16
---

# Accept only commit IDs that GitHub serves

## Status

Accepted.

## Context

Sealing accepted 40- or 64-digit commit IDs, while OIDC verification and the generated workflow accepted 40, so a SHA-256 repository sealed a Candidate that could never publish.
GitHub hasn't announced support for SHA-256 repositories, and reports from October 2026 say it refuses their pushes.

## Decision

A commit ID is a `CommitId`: exactly 40 lowercase hexadecimal digits.
Rehearsal refuses a SHA-256 repository before it builds, with a stable reason.

## Alternatives

Widening every check to 64 digits would accept a path that GitHub can't serve and that no test can exercise against the real system.

## Consequences

A SHA-256 repository fails early with a reason instead of at publication.

## Confirmation

A test refuses a repository made with `git init --object-format=sha256`.
Reconsider when GitHub documents support for SHA-256 repositories.
