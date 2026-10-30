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

Every parser has a fuzz target in `fuzz/fuzz_targets`, whose properties live in the `invariants` library under `fuzz/invariants` and whose seeds live in `fuzz/corpus`.
`cargo test` replays every seed through the same properties, so a property violation fails the ordinary suite.
Add a seed for each accepted and refused input class that a parser change introduces.
`tests/fuzz_corpus.rs` builds some archive seeds itself and checks that the committed bytes match, and `RELEASE_GLZ_WRITE_CORPUS=1 cargo test --test fuzz_corpus` rewrites them after a builder changes.
Give a local fuzz run a scratch corpus before the committed one, so new inputs stay out of `fuzz/corpus` until you choose them:

```console
mkdir -p target/fuzz-corpus/config
cargo +nightly fuzz run config target/fuzz-corpus/config fuzz/corpus/config
```

Release decisions that depend only on their inputs live in `crates/release-glz-core`, which has no dependency outside `core`.
Kani proves its `#[kani::proof]` harnesses for every admitted input, and each harness carries cover properties that show its assumptions leave inputs to check.
Kani 0.68.0 runs in the image that `verification/kani.Dockerfile` pins, inside the bounded container on an owner machine:

```console
docker build --platform linux/amd64 --file verification/kani.Dockerfile --tag release-glz-kani:0.68.0 verification
dotfiles bounded run --image release-glz-kani@sha256:<image digest> --project . -- \
  env CARGO_TARGET_DIR=/tmp/kani-target cargo kani --package release-glz-core
```

The `negative-control` feature swaps the checked increment for a wrapping one, and shipping assurance requires that build to fail the bump proof.

Run the fast checks before opening a pull request:

```console
mise x -- cargo fmt --all -- --check
mise x -- cargo fmt --manifest-path fuzz/Cargo.toml -- --check
mise x -- cargo fetch --locked --manifest-path fuzz/Cargo.toml
mise x -- cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
mise x -- cargo test --workspace --all-targets --locked
mise x -- cargo doc --workspace --no-deps --locked
mise x -- npm ci --ignore-scripts
mise x -- npm run typecheck
mise x -- npm test --prefix action
mise x -- node --test scripts/*.test.js
mise x -- node scripts/verify-workflows.js .github/workflows
mise x -- node scripts/de-shell.js .github/workflows
mise x -- actionlint
jq -L .github -n -e -f .github/check-required.jq
```

The TypeScript compiler that `package-lock.json` pins checks the Action and the release scripts in strict mode from their JSDoc types.
Every JavaScript file starts with `// @ts-check`, and `scripts/type-contracts.test.js` refuses a named function whose JSDoc declares no return type.
The Action itself has no dependencies, so the compiler stays a development tool of the repository.

Ordinary CI uses one Linux Rust gate and always checks workflow metadata, Action behavior, and distribution evidence tools.
Other native platforms and the minimum and configured Gleam versions run through shipping assurance.
Distribution builds and smokes every supported native release target.

The reusable [shipping assurance workflow](.github/workflows/assurance.yml) runs on the exact release candidate before checksum preparation or publication.
It also supports an explicit manual run.
It checks dependency policy, generated workflows, coverage, all configured critical-path mutations, every parser fuzz target, and every Kani harness with its negative control.
Parser fuzz smoke uses 10,000 runs per target with seed 1.
Release coverage requires at least 90% lines and 85% branches, with no viable critical-path mutation survivors.
Workflow changes must pass zizmor against both repository workflows and the generated consumer workflow during shipping assurance.

Public JSON is a compatibility contract.
Commands use `command/v2`, while `plan/v3`, `candidate/v1`, `state/v1`, and `hook/v1` evolve independently.
Update schemas, fixtures, documentation, human output, and Action outputs together.
Public paths use repository-relative `/` strings.

Keep assurance thresholds and immutable Action references.
The release preparation workflow must generate real checksum manifests for the exact tag commit before v1 publication.
