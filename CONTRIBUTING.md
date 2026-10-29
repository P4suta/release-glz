# Contributing

Begin behavior changes with a failing test, implement the required behavior, and refactor with the suite passing.
Keep regression cases for bugs and boundary tests for security and state transitions.

Tests use loopback Hex and GitHub services, local bare Git repositories, committed fixtures, and fake hooks.
Never publish a package or use a registry credential in tests.
Keep secret-redaction assertions on new error paths.

`mise.toml` pins the Rust, Gleam, Erlang/OTP, Node, and workflow tool versions that CI uses, and `mise install` installs them.
Tests that build a real package fail when Gleam is missing instead of passing without running.
`.cargo/config.toml` points every process Cargo runs at the isolated Git configuration in `tests/fixtures/git`, so global settings, signing, hooks, and credential prompts never reach a test.
A test runs the CLI through `release_glz_test_support::isolated_command`, which passes only an explicit environment and never a developer's token.
Tests run in parallel and write only inside their own temporary directories.

Run the fast checks before opening a pull request:

```console
mise x -- cargo fmt --all -- --check
mise x -- cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
mise x -- cargo test --workspace --all-targets --locked
mise x -- cargo doc --workspace --no-deps --locked
mise x -- npm test --prefix action
mise x -- node --test scripts/*.test.js
mise x -- node scripts/verify-workflows.js .github/workflows
mise x -- node scripts/de-shell.js .github/workflows
mise x -- actionlint
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
