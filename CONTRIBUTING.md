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
`cargo xtask proofs` builds the image that `verification/kani.Dockerfile` pins to Kani 0.68.0, and it runs Kani from a frozen copy of the sources with the bounded runner's limits.
It audits Kani's JSON report with the committed inventory in `xtask/src/inventory.rs`, which names every harness and its cover count.
A run counts only when every listed harness verified and no other ran, and when every owned assertion succeeded.
Each harness must also reach exactly its listed covers, and the tool versions and target must be the pinned ones.
The audit also refuses a source that changed during the run, and `crates/assurance-core` decides admission from what the audit found, under its own Kani proofs.

Each `negative-control-*` feature breaks one decision, such as the checked increment or the conflict for an object that differs, inside a `negative_control_*` function that production code calls only under that feature.
The task builds each negative control on its own and requires its harness to fail on exactly the expected assertion and on nothing else.
Every harness has a negative control, and a test without the solver keeps the inventory equal to the harnesses, covers, and features in the sources.
`.cargo/mutants.toml` keeps cargo-mutants away from the functions of the negative controls, which no test build compiles.
cargo-mutants names a mutant without its module path, so the configuration can't name the harnesses.
The proof campaign leaves the harnesses out by their place in the source instead.

`cargo xtask proof-mutants` shows that the harnesses pin down the core decisions, and it runs on an owner machine, never on Actions.
It proves the unmutated core first, then applies each mutant of the core crates to a frozen copy and runs the harnesses of its module.
Before it calls a mutant a survivor, it runs every harness of the mutant's package.
Each outcome comes from Kani's audited report: detected, unviable when the mutant doesn't compile, or inconclusive, which fails the campaign.
A survivor has to appear in `verification/equivalent-mutants.json` with the reason no harness can detect it, and the campaign refuses an entry that no longer survives.
The campaign writes a receipt with the digest of the core sources and the outcome of every mutant, and the owner commits it as `verification/proof-mutants.json`.
The release gate runs `cargo xtask proof-mutants check`, which refuses a receipt for other core sources, so a change to the core needs a new campaign before a release.
The harnesses over lists of objects and over runs cover releases of at most three objects, and the decisions for single objects and approvals cover every input.
A run harness lets the world answer each observation with any presence of each object, so its properties hold for every way the world changes between observations.

`verification/lean/Publication.lean` models the same decisions in Lean 4 and proves the list properties for releases of every length.
`cargo xtask lean` builds the image that `verification/lean.Dockerfile` pins and runs Lean in a container with the same limits as the bounded runner.
It generates refinement vectors from the core crate, and Lean proves by `decide` that the model decides every object and every list of at most two objects as the core does.
It refuses a theorem that depends on an axiom outside Lean's standard three, and it replays every module through `leanchecker --fresh`.

`verification/quint/release_run.qnt` models a release run and the world it talks to in Quint 0.33.1.
The world shows commits late, may commit a call that reports failure, races another publisher once, and refuses to replace an object that exists.
The runner may fail to observe the world, and it may crash and start again.
`cargo xtask quint` builds the image that `verification/quint.Dockerfile` pins and has the explicit-state model checker `tlc` visit every state of releases of up to three objects.
It requires the recorded number of distinct states and requires the probe module, whose runner applies effects out of order, to break the invariant.
It also writes the traces of the model's scenario tests and of a seeded simulation again and requires them to equal `verification/quint/traces`.
`tests/run_replay.rs` replays those traces through `release_glz_core::Run` on every pull request and requires each decision of a trace to be the production decision.

`docs/assurance.md` maps each release and security property to the harnesses, theorems, model invariants and tests, fuzz targets, and tests that check it.
`cargo xtask trace`, and a test that the fast gate runs, refuse a citation that names nothing and a property without evidence.
They also refuse a harness, theorem, invariant, model test, or fuzz target that no property cites, so a new check needs a property before it merges.
The theorems for longer lists concern the model, so they bind the core only through the refinement on the short lists and the shared structure of the two definitions.
The task also generates the decision vectors from a table with the republish defect, and it requires Lean to fail on exactly the decision refinement then.

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
Commands use `command/v2`, and every result format, `hook/v1`, and `state/v1` evolve independently with the schemas that [docs/README.md](docs/README.md#machine-readable-contract) lists.
A new format needs its schema under `docs/` and an entry in `release_glz_test_support::schema::RESULT_SCHEMAS`, or `tests/json_schema_contract.rs` fails.
Tests that print a result check it with `assert_published_envelope` or `assert_published_result`.
Update schemas, fixtures, documentation, human output, and Action outputs together.
Public paths use repository-relative `/` strings.

Keep assurance thresholds and immutable Action references.
The release preparation workflow must generate real checksum manifests for the exact tag commit before v1 publication.
