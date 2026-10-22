# Contributing

Begin behavior changes with a failing test, implement the required behavior, and refactor with the suite passing.
Keep regression cases for bugs and boundary tests for security and state transitions.

Tests use loopback Hex and GitHub services, local bare Git repositories, committed fixtures, and fake hooks.
Never publish a package or use a registry credential in tests.
Keep secret-redaction assertions on new error paths.

Run the fast checks before opening a pull request:

```console
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo doc --workspace --no-deps --locked
npm test --prefix action
node --test scripts/*.test.js
node scripts/verify-workflows.js .github/workflows
node scripts/de-shell.js .github/workflows
actionlint
jq -L .github -n -e -f .github/check-required.jq
```

Ordinary CI uses one Linux Rust gate and always checks workflow metadata, Action behavior, and distribution evidence tools.
Other native platforms and the minimum and configured Gleam versions run through shipping assurance.
Distribution builds and smokes every supported native release target.

The reusable [shipping assurance workflow](.github/workflows/assurance.yml) runs on the exact release candidate before checksum preparation or publication.
It also supports an explicit manual run.
It checks dependency policy, generated workflows, coverage, all configured critical-path mutations, and the four parser fuzz targets.
Parser fuzz smoke uses 10,000 runs per target with seed 1.
Release coverage requires at least 90% lines and 85% branches, with no viable critical-path mutation survivors.
Workflow changes must pass zizmor against both repository workflows and the generated consumer workflow during shipping assurance.

Public JSON is a compatibility contract.
Commands use `command/v2`, while `plan/v2`, `candidate/v1`, `state/v1`, and `hook/v1` evolve independently.
Update schemas, fixtures, documentation, human output, and Action outputs together.
Public paths use repository-relative `/` strings.

Keep assurance thresholds and immutable Action references.
The release preparation workflow must generate real checksum manifests for the exact tag commit before v1 publication.
