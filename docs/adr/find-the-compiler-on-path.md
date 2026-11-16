---
date: 2026-11-16
---

# Find the compiler on PATH

## Status

Accepted.

## Context

Tests replaced the Gleam compiler with a script through an undocumented environment variable that also reached the isolated build.

## Decision

release-glz runs `gleam` from `PATH`, as a developer and the generated workflow install it.
Tests put a directory that holds a fake `gleam` first on the `PATH` they pass to the binary.

## Alternatives

Documenting the variable would keep a second way to choose the compiler that every build step has to forward.
A compiler path in `gleam.toml` would let a configuration point a protected job at any executable.

## Consequences

The variable disappears, and release-glz checks the version of whatever `gleam` the `PATH` resolves.
A test fake on Windows has to be an executable that `PATH` resolves, not a shell script.

## Confirmation

No variable selects the compiler, and `tests/compiler_environment.rs` shows that no `RELEASE_GLZ_` variable reaches it while a fake `gleam` first on `PATH` passes the compiler tests.
Reconsider if users need to pin a compiler that `PATH` can't select.
