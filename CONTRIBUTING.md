# Contributing

Every behavior change is developed with TDD: add the smallest failing test
(RED), implement only enough production behavior to pass (GREEN), then refactor
with the suite green. Bug fixes need a regression test that demonstrates the
original failure. Security and state-machine changes should begin at the pure
boundary, then add adapter contract and end-to-end tests.

Tests must not publish a real package or use a real credential. Use loopback
fake Hex/GitHub services, local bare git repositories, committed fixture
snapshots, and fake argv-based hooks. Keep secret redaction assertions on every
new error path.

Run the local gates before opening a pull request:

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo doc --workspace --no-deps
npm test --prefix action
cargo deny check
cargo audit
cargo machete
```

Workflow changes must also pass actionlint, zizmor, and the repository's
workflow-verifier/de-shell scripts. Fuzz targets cover archive, config, PR
markers, API interfaces, and structured inputs. Release assurance requires at
least 90% line and 85% branch coverage, and zero critical mutation survivors in
version, registry, archive, and reconciler code.

Public JSON is a compatibility contract. All commands use `command/v2`, while
`plan/v2`, `candidate/v1`, `state/v1`, and `hook/v1` evolve independently.
Update schemas, golden tests, docs, human output, and Action outputs together.
Paths crossing the public boundary are repository-relative `/` strings.

Never weaken a failing assurance threshold or replace a pinned Action SHA to
make CI pass. Distribution checksum placeholders are intentionally fail-closed;
the release preparation workflow must generate real manifests for the exact
tag commit before v1 publication.
