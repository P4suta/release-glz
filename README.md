# release-glz

`release-glz` is Candidate-first release automation for one Gleam package. It
plans from immutable git history, seals the bytes that were reviewed, and then
reconciles Hex, HexDocs, git, and GitHub without replacing an existing object.

The v1 model has three deliberately separate layers:

- `ReleasePlan` is a read-only decision: version, reasons, warnings, required
  approvals, and ordered stages.
- `Candidate` is the sealed publication unit: one committed source SHA, exact
  package and docs bytes, policy and hook evidence, and their digests.
- `ReleaseState` is an observation of external systems, used to resume a
  partial release monotonically.

The central invariant is simple: `release --candidate` publishes the exact
bytes created by `rehearse --ref`; it never rebuilds them from a checkout.

## Status and scope

v1 supports one package per invocation on GitHub.com with:

- public Hex.pm;
- a Hex.pm Organization repository; and
- a standard Hex API/repository compatible private registry (`hex-compatible`).

Multiple manifests in one repository can be released independently, but a
single Candidate always represents one package. Non-standard self-hosted
publish protocols, atomic multi-package releases, crates.io, Homebrew, and
Scoop are outside the v1 contract.

See the registry-specific guides:

- [Public Hex quickstart](docs/quickstart-public.md)
- [Hex.pm Organization quickstart](docs/quickstart-organization.md)
- [Private registry quickstart](docs/quickstart-private.md)

## Candidate-first quick start

Configure an exact compiler and schema 2 in `gleam.toml` (the public quickstart
contains the complete example):

```toml
[tools.release-glz]
schema = 2
compiler = "1.18.1"
```

Check the repository and generate the managed workflow without silently
overwriting a modified file:

```console
release-glz doctor
release-glz init --diff
release-glz init --update
```

The normal GitHub path creates one rolling Release PR. A secret-free Candidate
job checks out an exact commit, while the protected Environment job downloads
that same Actions artifact and publishes it. External Actions and release-glz
itself are pinned to full commit SHAs in the generated workflow.

The equivalent local inspection flow is:

```console
release-glz plan
release-glz rehearse --ref 0123456789abcdef0123456789abcdef01234567 --out .release-glz/candidate
release-glz verify --candidate .release-glz/candidate
release-glz verify --candidate .release-glz/candidate --online
release-glz status --candidate .release-glz/candidate --online
release-glz release --candidate .release-glz/candidate --dry-run
```

`rehearse` requires a full commit SHA and uses `git archive`, so uncommitted and
ignored working-tree files cannot enter the Candidate. Real publication also
requires approval evidence supplied by the protected workflow; a local dry run
does not manufacture that authority.

## Commands

| Command | Contract |
|---|---|
| `plan` | Reads git, registry, API, and change history and returns a `plan/v2`; it changes neither external state nor tracked files. |
| `rehearse --ref <SHA> --out <DIR>` | Builds from the committed snapshot with the configured compiler, validates archives, runs verify/sidecar hooks, and seals a `candidate/v1`. |
| `verify --candidate <DIR> [--online]` | Verifies checksums, semantic fingerprints, source, policy, inventory, and hook evidence; online mode also observes registry and GitHub. |
| `release --candidate <DIR>` | Publishes the sealed bytes through the monotonic reconciler; `--dry-run` reports all remaining effects. |
| `status [--candidate <DIR>] [--online]` | Reports the current state and next safe command, including partial releases. |
| `doctor` | Audits schema, compiler, managed workflow, Environment policy, branch protection, and registry credential permissions. |
| `release-pr` / `update` | Maintains the rolling managed PR; when no release is required it closes the verified PR and removes its unchanged managed branch. |
| `prerelease` / `set-version` | Selects a channel or raises the automatically required version; neither can lower the safety requirement. |
| `init` / `migrate` | Supports `--check`, `--diff`, and `--update`; modified managed files are never overwritten without an explicit update. |
| `completion` | Generates bash, zsh, fish, or PowerShell completion source. |

Global options include `--manifest-path`, `--output human|json`, and
`--dry-run`. Repository paths in public data are normalized to relative `/`
paths.

## Configuration

Publishing requires strictly typed `[tools.release-glz] schema = 2`. Unknown
keys, wrong types, paths outside the repository, unsafe ref prefixes, URLs with
embedded credentials, and non-HTTPS registry origins are rejected. Explicit
HTTP is accepted only for loopback tests.

```toml
[tools.release-glz]
schema = 2
compiler = "1.18.1"
release_branch_prefix = "release-glz/"
allow_version_zero = true

[tools.release-glz.registry]
provider = "hexpm"
api_url = "https://hex.pm/api"
repository_url = "https://repo.hex.pm"
docs_url = "https://repo.hex.pm/docs"
credential_env = "HEXPM_API_KEY"
auth = "hex-token"

[tools.release-glz.approval]
normal = "release-pr-and-environment"
manual = "environment"
environment = "release"
separation = "solo"
manual_refs = ["refs/heads/main"]

[tools.release-glz.outputs]
docs = true
github_release = true
sbom = true
provenance = true
signature = false
allow_private_evidence_upload = false

[tools.release-glz.changelog]
path = "CHANGELOG.md"
managed_block = true
notes_dir = ".release-glz/notes"
```

`credential_env` is an environment-variable name, never a credential value.
For a private repository, the generated trusted `plan` and rolling-PR jobs can
use a repository-level read-only secret under that name; the protected
Environment supplies a separate publish-capable value with the same name. The
Candidate and pull-request jobs receive neither secret.
For hooks, each entry contains an ID, an argv array, timeout, required flag, and
an allowlist of environment names; shell command strings are not accepted.

Legacy flat configuration remains readable during v1.x but cannot produce a
Candidate. Use `release-glz migrate --check`, inspect `migrate --diff`, then
apply `migrate --update`. See the [v1 migration guide](docs/migration-v1.md).

## Version selection

The selected requirement is the maximum of publication-input changes, commit
intent, public API compatibility, and an explicit higher version. For 1.x and
later, fixes are patch, features and additive API are minor, and breaking API
is major. For 0.x, fixes are patch while features, API additions, and breaking
changes are minor. `doctor` warns about Gleam's recommendation to begin at
1.0.0 but does not block a deliberate 0.x release.

API comparison uses `package-interface.json`. If a historical API cannot be
determined, planning blocks by default. A schema 2 `api_exceptions` entry must
bind an exact version to a baseline ref, a reason, and an expiry date.

Prerelease channels move `alpha → beta → rc → stable`, or increment within the
same channel. Moving backward requires an explicitly higher core version.

## Digests and approvals

Both digests are SHA-256 over RFC 8785-style canonical JSON, but they answer
different questions:

- `intent_digest` excludes nondeterministic ordering/time details and binds the
  semantic package, API, and docs content reviewed in the Release PR.
- `candidate_digest` additionally binds the exact source SHA, package/docs
  checksums, policy, hook definitions/evidence, and sidecars approved by the
  GitHub Environment.

The normal route requires both the verified server-side Release PR merge and
the protected Environment. Solo mode can use a self-approval Environment gate.
Strict separation additionally requires a different reviewer,
prevent-self-review, protected default branch, and protected-branch-only
deployment policy. `doctor` refuses to silently weaken these rules when a
private repository's GitHub plan cannot provide required reviewers; solo mode
may explicitly configure `private_repository_fallback =
"workflow-dispatch-digest"`.

Manual promotion requires a full allowed source SHA, a reason, the Candidate
digest, and Environment approval. The publish job validates GitHub OIDC claims
for repository, environment, workflow, event, ref, run, and source SHA, so a
fork or different workflow cannot reuse approval evidence.

## Publication and recovery

Before an effect, release-glz observes package, docs, tag, draft/final GitHub
Release, assets, and notifications. Existing matching objects are retained;
different bytes or targets are an immutable conflict. The ordered effects are:

1. required verify hooks;
2. annotated git tag preparation;
3. draft GitHub Release preparation;
4. Hex package publication;
5. docs publication;
6. approved evidence/sidecar upload and GitHub Release finalization;
7. idempotent notify hooks.

An ambiguous publish response is resolved by polling for the exact checksum,
not by immediately posting again. A later required failure produces
`partially_released`; rerun `status` and `release` with the same Candidate.
There is no `--replace`, asset clobber, automatic revert, or rollback of an
immutable package. The detailed table is in [recovery.md](docs/recovery.md).

## Machine-readable contract

JSON output uses the `command/v2` envelope with `ok`, `command`, `result`,
`diagnostics`, and `next_actions`. Domain schemas evolve independently:
`plan/v2`, `candidate/v1`, `state/v1`, and `hook/v1`. Published schemas are in
[`docs/`](docs/).

States are `up_to_date`, `planned`, `candidate_ready`, `awaiting_approval`,
`partially_released`, `released`, `conflict`, and `blocked`.

Exit code meanings are stable:

| Exit code | Meaning |
|---:|---|
| 0 | Success or safe no-op |
| 1 | Internal failure |
| 2 | Usage or configuration error |
| 3 | Policy or approval missing |
| 4 | Immutable-state conflict |
| 5 | Temporary external failure |
| 6 | Hook failure |
| 7 | Partial release requiring resume |

The Action exposes `state`, `release-required`, `version`, `intent-digest`,
`candidate-digest`, `pr-url`, `hex-url`, `github-release-url`, and
`next-action`.

## Supply chain

The dependency-free Node wrapper streams subprocess output, propagates
cancellation, enforces time and download limits, permits only same-origin
redirects, validates archive inventory, checks SHA-256, and cleans temporary
files. An optional binary version override must supply its checksum and
provenance digest.

Release assets cover Linux musl x86_64/aarch64, macOS x86_64/arm64, and Windows
x86_64/arm64, with checksums, licenses, CycloneDX SBOM, provenance, and GitHub
artifact attestations. A release maintainer must replace the fail-closed
placeholder checksum manifest with the output of the preparation workflow
before creating an immutable tag.

See [design](docs/design.md), [threat model](docs/threat-model.md), and
[security policy](SECURITY.md).

## License

Licensed under either Apache-2.0 or MIT, at your option.
