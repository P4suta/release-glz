---
date: 2026-11-16
---

# Decide release policy in the one proved core

## Status

Accepted.

## Context

The shell still computes approval conjuncts, validates identifiers, and orders versions, and duplicated rules there disagree.
Kani proves `release-glz-core`, and one mutation receipt covers both proof crates.

## Decision

Every release decision lives in `release-glz-core`, which takes borrowed bytes or fact enums and returns a decision or a named refusal, with no owned type outside `cfg(kani)`.
Owned checked types live in an unproved `release-glz-domain`, whose constructors yield only values that a core predicate accepts.
`cargo xtask structure` refuses breaches, and its `DEBT` list shrinks with each change.

## Alternatives

A second proof crate shares the receipt digest, so it would protect nothing and split the inventory.
Owned newtypes inside the core would add mutants that no harness can kill.

## Consequences

Each identifier has one rule, and wire bytes stay unchanged through transparent serde.

## Confirmation

`cargo xtask structure` passes with an empty `DEBT` list once the core migration ends.
Reconsider if policy changes need a release without a new campaign.
