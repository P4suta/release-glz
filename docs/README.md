# release-glz

`release-glz` is Candidate-first release automation for one Gleam package.
It plans from immutable git history, seals the bytes that were reviewed, and then reconciles Hex, HexDocs, git, and GitHub without replacing an existing object.

The model has three deliberately separate layers:

- `ReleasePlan` is a read-only decision: version, reasons, warnings, required approvals, and ordered stages.
- `Candidate` is the sealed publication unit: one committed source SHA, exact package and docs bytes, policy and hook evidence, and their digests.
- `ReleaseState` is an observation of external systems, used to resume a partial release monotonically.

The central invariant is simple: `release --candidate` publishes the exact bytes created by `rehearse --ref`; it never rebuilds them from a checkout.

## Status and scope

release-glz supports one package per invocation on GitHub.com with:

- public Hex.pm;
- a Hex.pm Organization repository; and
- a standard Hex API/repository compatible private registry (`hex-compatible`).

Multiple manifests in one repository can be released independently, but a single Candidate always represents one package.
Non-standard self-hosted publish protocols, atomic multi-package releases, crates.io, Homebrew, and Scoop are outside the release-glz contract.

See the registry-specific guides:

- [Public Hex quickstart](quickstart-public.md)
- [Hex.pm Organization quickstart](quickstart-organization.md)
- [Private registry quickstart](quickstart-private.md)

## Install, verify, update, and remove

`release-glz` is not published to crates.io, and no GitHub Release is currently published.
Install the current source with Cargo:

```console
cargo install --git https://github.com/P4suta/release-glz --locked release-glz
release-glz --version
```

The package requires Rust 1.100 or newer.
Repeat the source installation command to update.
Remove a source installation with `cargo uninstall release-glz`.
The repository includes a GitHub Action definition, but its default run downloads a versioned release binary, and no published release assets are available yet.
Homebrew and Scoop are outside the release-glz contract.

After immutable release assets are published, use the following commands to verify and install the archive for your host:

```console
VERSION=v1.0.0
TARGET=x86_64-unknown-linux-musl # or aarch64-unknown-linux-musl / *-apple-darwin
ARCHIVE=release-glz-$TARGET.tar.gz
gh release download "$VERSION" --repo P4suta/release-glz --pattern "$ARCHIVE" --pattern SHA256SUMS
EXPECTED=$(awk -v archive="$ARCHIVE" '$2 == archive || $2 == ("*" archive) { print $1 }' SHA256SUMS)
test "${#EXPECTED}" -eq 64
printf '%s  %s\n' "$EXPECTED" "$ARCHIVE" | sha256sum --check -
gh attestation verify "$ARCHIVE" --repo P4suta/release-glz \
  --signer-workflow P4suta/release-glz/.github/workflows/distribute.yml \
  --source-ref "refs/tags/$VERSION"
tar --extract --gzip --file "$ARCHIVE"
sudo install -m 0755 release-glz /usr/local/bin/release-glz
release-glz --version
```

macOS includes `shasum`; use the same exact `EXPECTED` selection followed by `printf '%s %s\n' "$EXPECTED" "$ARCHIVE" | shasum -a 256 --check` when `sha256sum` is not installed.
On Windows PowerShell:

```powershell
$Version = "v1.0.0"
$Target = "x86_64-pc-windows-msvc" # or aarch64-pc-windows-msvc
$Archive = "release-glz-$Target.zip"
gh release download $Version --repo P4suta/release-glz --pattern $Archive --pattern SHA256SUMS
$ExpectedDigests = @()
foreach ($Line in Get-Content SHA256SUMS) {
  if ($Line -match '^([a-f0-9]{64}) [ *](.+)$' -and $Matches[2] -ceq $Archive) {
    $ExpectedDigests += $Matches[1]
  }
}
if ($ExpectedDigests.Count -ne 1) { throw "checksum manifest must contain the archive exactly once" }
$Expected = $ExpectedDigests[0]
if ((Get-FileHash $Archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) { throw "checksum mismatch" }
gh attestation verify $Archive --repo P4suta/release-glz `
  --signer-workflow P4suta/release-glz/.github/workflows/distribute.yml `
  --source-ref "refs/tags/$Version"
Expand-Archive $Archive -DestinationPath .\release-glz-bin
New-Item -ItemType Directory -Force "$env:LOCALAPPDATA\Programs\release-glz" | Out-Null
Copy-Item .\release-glz-bin\release-glz.exe "$env:LOCALAPPDATA\Programs\release-glz\release-glz.exe"
```

Add the Windows destination to the user `PATH`.
For a later published version, repeat the download, checksum, attestation, and install steps; never reuse a checksum from another version.
To uninstall, remove `/usr/local/bin/release-glz` on Unix or the Windows `%LOCALAPPDATA%\Programs\release-glz` directory and its `PATH` entry.
The [release-readiness checklist](release-readiness.md) defines how maintainers prepare the six intended assets and independently verify them once published.

## Candidate-first quick start

For an unconfigured public package, preview and then apply a complete explicit `[tools.release-glz]` configuration and managed workflow:

```console
release-glz init --profile public --diff
release-glz init --profile public --update
release-glz doctor
release-glz doctor --online
release-glz doctor --candidate-build
```

release-glz runs the `gleam` that `PATH` finds first, and `init` detects its exact version and the git default branch.
Use `release-glz init --profile organization --organization NAME --diff` for a Hex.pm Organization, or `release-glz init --profile private --api-url URL --repository-url URL --docs-url URL --credential-env NAME --auth bearer --diff` for a private target.
The private profile requires all of `--api-url`, `--repository-url`, `--docs-url`, `--credential-env`, and `--auth hex-token|bearer`.
A package whose version is 0.x additionally requires `--allow-version-zero`.
For offline development only, `--action-sha <40-lowercase-hex>` overrides lookup of the annotated official `v<release-glz-version>` tag; normal initialization peels that tag through the GitHub API and pins its commit.
Until the first official tag is published, a source-only initialization preview requires the verified source commit through `--action-sha`.

The normal GitHub path creates one rolling Release PR.
A secret-free Candidate job checks out an exact commit, while the protected Environment job downloads that same Actions artifact and publishes it.
External Actions and release-glz itself are pinned to full commit SHAs in the generated workflow.

### Generated workflow

The workflow runs for pushes to the default branch and for manual dispatches.
A job that runs the compiler holds no write permission, and a job that can write never installs the compiler.

| Job | Runs | Compiler | Permissions |
|---|---|---|---|
| `plan` | every push and `prepare` dispatch | yes | `contents: read`, `pull-requests: read` |
| `release-pr` | every push, from the plan artifact | no | `contents: write`, `pull-requests: write` |
| `rehearse-release-pr` | when `release-pr` wrote or confirmed a head | yes | `contents: read` |
| `bind-release-pr` | after that rehearsal | no | `contents: read`, `pull-requests: write` |
| `prepare` | a push that requires a release, or a `prepare` dispatch | yes | `contents: read`, `pull-requests: read` |
| `validate-promotion` | a `promote` dispatch | no | none |
| `authorize` | a push with a sealed Candidate | no | `contents: read`, `pull-requests: read` |
| `publish` | an approved Candidate | no | `actions: read`, `contents: write`, `id-token: write`, `pull-requests: read`, and the Environment secret |

`GITHUB_TOKEN` writes the Release PR, and GitHub starts no workflow run for events that token causes.
The push run that wrote the Release PR therefore rehearses the new head itself and binds its intent.
Merge the Release PR only after that run's `bind-release-pr` job succeeds, because a merge without a bound intent stops publication at `blocked`.
`release-pr`, `bind-release-pr`, and `publish` each serialize per package, and no other job waits for them.

The equivalent local inspection flow is:

```console
release-glz plan
release-glz rehearse --ref 0123456789abcdef0123456789abcdef01234567 --out .release-glz/candidate
release-glz verify --candidate .release-glz/candidate
release-glz verify --candidate .release-glz/candidate --online
release-glz status --candidate .release-glz/candidate --online
release-glz release --candidate .release-glz/candidate --dry-run
```

`rehearse` requires a full commit SHA and uses `git archive`, so uncommitted and ignored working-tree files cannot enter the Candidate.
A commit ID is exactly 40 lowercase hexadecimal digits, the only form that GitHub serves, so `rehearse` refuses a SHA-256 repository with `repository_object_format_unsupported` before it builds anything.
Real publication also requires approval evidence supplied by the protected workflow; a local dry run does not manufacture that authority.

## Commands

| Command | Contract |
|---|---|
| `plan [--out <FILE>]` | Reads git, registry, API, and change history and returns a `plan/v1`; it changes neither external state nor tracked files. `--out` also writes the plan to a new file and refuses to replace an existing one. |
| `rehearse --ref <SHA> --out <DIR>` | Builds from the committed snapshot with the configured compiler, validates archives, runs verify/sidecar hooks, and seals a `candidate/v1`. |
| `verify --candidate <DIR> [--online]` | Verifies checksums, semantic fingerprints, source, policy, inventory, and hook evidence; online mode also observes registry and GitHub. |
| `release --candidate <DIR>` | Publishes the sealed bytes through the monotonic reconciler; `--dry-run` reports all remaining effects. |
| `status [--candidate <DIR>] [--online]` | Reports the current state and next safe command, including partial releases. |
| `doctor [--online] [--candidate-build]` | Defaults to local configuration/compiler/workflow checks; online mode audits registry credentials and GitHub protections; candidate-build mode uses isolated caches and no credentials. A manifest without `[tools.release-glz]` reports `config_missing`, a `version_zero` warning for a 0.x package, and how `init` writes the configuration. |
| `release-pr [--plan <FILE>]` | Maintains the rolling managed PR as one generated commit on the current default branch tip. The commit writes only the rendered files that differ from the tip, and when none differs, it writes no commit and reports `release_files_current`. When the plan needs no release, it closes the verified PR and removes its unchanged managed branch. It writes or closes only when the checkout is that tip, and otherwise reports `release_pr_superseded`. At the merge commit of the Release PR for the planned version it writes nothing and reports `release_pr_merged`. It looks up the pull requests of at most 200 commits since the baseline, and over that it lists every commit by subject and reports `changes_listed_by_commit`. It fails before any write when `[repository]` differs from GitHub's spelling of the slug, including letter case. The result's `release_pr_head` names the head commit it wrote or confirmed. |
| `release-pr --candidate <DIR>` | Binds the Candidate's `intent_digest` to the open Release PR whose head is the Candidate's source commit. Its `release-pr-intent/v1` result reports `intent_binding`: `bound`, `merged` when the merged Release PR already carries the intent, `unbound` in a dry run, or `superseded` when a newer head replaced the Candidate's and nothing was written. |
| `prerelease` / `set-version` | Selects a channel or raises the automatically required version; neither can lower the safety requirement. |
| `init` | Requires exactly one of `--check`, `--diff`, or `--update`; modified managed files are never overwritten without an explicit update. |
| `completion` | Generates bash, zsh, fish, or PowerShell completion source. |

Global options are `--manifest-path` and `--output human|json`.
`--dry-run` exists only on commands that can mutate state (`release`, `release-pr`, `set-version`, and `prerelease`).
Repository paths in public data are normalized to relative `/` paths.

### Writing the Release PR without the compiler

Compiling a package runs its dependencies' build code, so the job that holds a token able to write the repository shouldn't compile.
`plan --out <FILE>` runs in a read-only job, and `release-pr --plan <FILE>` writes the Release PR in a separate job that never starts the compiler.
`release-pr --plan` treats the file as untrusted input.
It refuses the file unless all of these hold:

- The file is a `plan/v1` document of at most 4 MiB with no unknown field.
- The plan names no Release PR yet.
- The plan's package and manifest version match the checked-out `gleam.toml`.
- The plan's baseline, when it has one, is a full commit id in the history of `HEAD`.

A shallow clone lacks the baseline commit, so the writing job needs the full history, such as `fetch-depth: 0` for `actions/checkout`.
The writing job then fetches the change list with its own token and renders `gleam.toml` and the changelog from its own checkout.
Every refusal exits with status 2 before any request to GitHub.

## Configuration

release-glz reads only a strictly typed `[tools.release-glz]` table with `schema = 2`.
A table that sets any other `schema`, or none, is refused with exit code 2.
Without the table, `init` writes it, `doctor` reports `config_missing`, and every other command that reads the configuration exits with code 2 and names `release-glz init`.
Unknown keys, wrong types, paths outside the repository, unsafe ref prefixes, URLs with embedded credentials, and registry origins without HTTPS are rejected.
The one exception is plain HTTP to a numeric loopback address in `127.0.0.0/8` or `::1`, and no key changes that rule.
A host name, `localhost` included, needs HTTPS.

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
Only the protected publish job receives the configured registry credential.
Planning, rolling-PR authorization, and Candidate preparation receive no secret.
release-glz supports publishing to a private hex-compatible target only when all dependencies needed to build the Candidate are available without credentials.
`doctor --candidate-build` reports the original isolated compiler/dependency failure and blocks when the credential-free build cannot complete.
For a private dependency, replace/vendor it, use a public dependency source, or build outside the release-glz publication path.
release-glz does not implement a private dependency resolver.
For hooks, each entry contains an ID, an argv array, timeout, required flag, and an allowlist of environment names; shell command strings are not accepted.
The registry publication credential, GitHub/OIDC authorization tokens, and GitHub environment/output control files are never forwardable to hooks, even when named in that allowlist.
That keeps them out of a hook's own environment, but a notification hook runs as the runner's user in the publishing job, so it can still read them from the processes that started it.
Configure only hooks that you trust as much as the release workflow.
Notification hooks use a separate least-privilege service credential.

## Version selection

The selected requirement is the maximum of publication-input changes, commit intent, public API compatibility, and an explicit higher version.
For 1.x and later, fixes are patch, features and additive API are minor, and breaking API is major.
For 0.x, fixes are patch while features, API additions, and breaking changes are minor.
`doctor` warns about Gleam's recommendation to begin at 1.0.0 but does not block a deliberate 0.x release.

API comparison uses `package-interface.json`.
If a historical API cannot be determined, planning blocks by default.
An `api_exceptions` entry must bind an exact version to a baseline ref, a reason, and an expiry date.

Prerelease channels move `alpha → beta → rc → stable`, or increment within the same channel.
Moving backward requires an explicitly higher core version.

## Digests and approvals

Both digests are SHA-256 over RFC 8785-style canonical JSON, but they answer different questions:

- `intent_digest` excludes nondeterministic ordering/time details and binds the semantic package, API, and docs content reviewed in the Release PR.
- `candidate_digest` additionally binds the exact source SHA, package/docs checksums, policy, hook definitions/evidence, and sidecars approved by the GitHub Environment.

The normal route requires both the verified server-side Release PR merge and the protected Environment.
The approved intent is the one that the merged Release PR's marker recorded, and the Environment is the one that the verified OIDC claims name.
Solo mode can use a self-approval Environment gate.
Strict separation additionally requires a different reviewer, prevent-self-review, protected default branch, and protected-branch-only deployment policy.
`doctor` refuses to silently weaken these rules when a private repository's GitHub plan cannot provide required reviewers; solo mode may explicitly configure `private_repository_fallback = "workflow-dispatch-digest"`.

Manual publication is two-stage.
A secret-free `prepare` dispatch stores the Candidate and prints its Candidate digest, run ID, artifact ID, and artifact digest.
A later `promote` dispatch requires those four values plus the full source SHA and a non-empty reason, downloads that prior-run artifact through the official token/run-id contract, and never rebuilds it.
The publish job validates the artifact-generating repository, successful managed workflow run, source, IDs, and digests independently from the promotion run's OIDC claims.
It also requires Environment approval.
The publish job validates GitHub OIDC claims for repository, environment, workflow, event, ref, run, and source SHA, so a fork or different workflow cannot reuse approval evidence.

## Publication and recovery

Before an effect, release-glz observes package, docs, tag, draft/final GitHub Release, assets, and notifications.
Existing matching objects are retained; different bytes or targets are an immutable conflict.
The ordered effects are:

1. required verify hooks;
2. annotated git tag preparation;
3. draft GitHub Release preparation;
4. Hex package publication;
5. docs publication;
6. approved evidence/sidecar upload and GitHub Release finalization;
7. idempotent notify hooks.

An ambiguous publish response is resolved by polling for the exact checksum, not by immediately posting again.
A later required failure produces `partially_released`; rerun `status` and `release` with the same Candidate.
There is no `--replace`, asset clobber, automatic revert, or rollback of an immutable package.
The detailed table is in [recovery.md](recovery.md).

## Machine-readable contract

JSON output uses the `command/v1` envelope with `ok`, `command`, `result`, `diagnostics`, and `next_actions`, which [command-envelope.schema.json](command-envelope.schema.json) describes.
`ok` is `false` exactly when a diagnostic has the `error` level, and a successful command always carries a result.
A failed command carries `null` for its result, except that `doctor` and `init --check` also report the result that failed.
Executable next actions contain canonical `argv`; non-portable human guidance uses an empty array.
The `command` field is always display-only and must never be reparsed or sent to a shell.

Every result names its format in its own `schema` field, and each format has a published schema:

| `schema` | Printed by | Schema |
|---|---|---|
| `plan/v1` | `plan`, `release-pr` without `--candidate`, `status` without `--candidate`, `set-version`, `prerelease` | [release-plan.schema.json](release-plan.schema.json) |
| `candidate/v1` | `rehearse` | [candidate.schema.json](candidate.schema.json) |
| `verify/v1` | `verify` without `--online` | [candidate-verification.schema.json](candidate-verification.schema.json) |
| `status/v1` | `status --candidate` without `--online` | [candidate-status.schema.json](candidate-status.schema.json) |
| `release/v1` | `release`, `verify --online`, `status --candidate --online` | [release-report.schema.json](release-report.schema.json) |
| `release-pr-intent/v1` | `release-pr --candidate` | [release-pr-intent.schema.json](release-pr-intent.schema.json) |
| `doctor/v1` | `doctor` | [doctor-report.schema.json](doctor-report.schema.json) |
| `init/v1` | `init` | [init-outcome.schema.json](init-outcome.schema.json) |
| `completion/v1` | `completion` | [completion.schema.json](completion.schema.json) |

Formats evolve independently, and a format's identifier changes only when its meaning does.
A hook prints `hook/v1` evidence, which [hook.schema.json](hook.schema.json) describes and a Candidate records.
`state/v1`, which [release-state.schema.json](release-state.schema.json) describes, is the external state that `release` compares, and no command prints it.
`init` reports the manifest path relative to the repository, wherever it runs.
`doctor` reports a `null` `required_compiler` for a manifest without `[tools.release-glz]`.

States are `up_to_date`, `planned`, `candidate_ready`, `awaiting_approval`, `partially_released`, `released`, `conflict`, and `blocked`.

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

A failed command without a result carries one error diagnostic, whose `code` names what failed.
A refusal that release-glz names carries its reason code, which decides the exit code; any other failure carries the code of its class.
A step that imposes another class on a refusal, such as a release that stops after it published part of a release, carries the code of that class instead.
The class codes are `internal_failure`, `usage_or_config`, `policy_or_approval`, `immutable_state_conflict`, `temporary_external_failure`, `hook_failure`, and `partial_release`, for exit codes 1 to 7 in order.
Reason codes are stable, and a code is never reused for another refusal:

| Reason code | Exit code | Meaning |
|---|---:|---|
| `config_missing` | 2 | The manifest has no `[tools.release-glz]` table. |
| `config_schema_unsupported` | 2 | The `[tools.release-glz]` table sets a `schema` other than 2. |
| `config_table_invalid` | 2 | The `[tools.release-glz]` table has an unknown key, lacks a required key, or holds a value of the wrong type. |
| `manifest_changed` | 4 | The manifest changed on disk after release-glz read it, so it isn't replaced. |
| `package_name_invalid` | 2 | A package name isn't one Hex accepts. |
| `path_not_relative` | 2 | A configured path is empty or not `/`-separated. |
| `path_outside_repository` | 2 | A configured path leaves the repository. |
| `git_ref_unsafe` | 2 | A git ref is unsafe, or git itself would refuse it. |
| `git_ref_prefix_unsafe` | 2 | A ref prefix, such as the release branch prefix, could produce an unsafe ref. |
| `hook_id_unsafe` | 2 | A hook id isn't a safe name. |
| `hook_id_reserved` | 2 | A hook takes the id of the evidence that release-glz builds itself. |
| `hook_argv_invalid` | 2 | A hook argv is empty or holds an empty or NUL-containing argument. |
| `hook_timeout_out_of_range` | 2 | A hook timeout lies outside the permitted range. |
| `hook_env_invalid` | 2 | A hook allows an environment variable whose name is invalid. |
| `hook_env_protected` | 2 | A hook allows a credential or a GitHub control file that no hook may receive. |
| `credential_env_invalid` | 2 | The registry credential setting isn't the name of an environment variable. |
| `registry_repository_invalid` | 2 | The Hex organization isn't a safe single path segment. |
| `url_malformed` | 2 | A configured URL isn't a well-formed URL. |
| `url_credentials` | 2 | A configured URL carries credentials. |
| `url_not_hierarchical` | 2 | A configured URL isn't absolute and hierarchical. |
| `url_query_or_fragment` | 2 | A configured URL carries a query or a fragment. |
| `url_transport_untrusted` | 2 | A configured URL uses neither HTTPS nor HTTP to a numeric loopback address. |
| `approval_environment_invalid` | 2 | The approval Environment name is empty or spans lines. |
| `approval_mode_fixed` | 2 | An approval path names a mode other than its fixed one. |
| `approval_fallback_unsupported` | 2 | The private repository fallback names an unsupported value. |
| `manual_ref_kind_unsupported` | 2 | A manual release ref names neither a branch nor a tag. |
| `manual_ref_duplicate` | 2 | A manual release ref is listed twice. |
| `api_exception_duplicate` | 2 | Two API exceptions name the same version. |
| `api_exception_reason_missing` | 2 | An API exception gives no reason. |
| `api_exception_expiry_invalid` | 2 | An API exception expiry isn't a `YYYY-MM-DD` date. |
| `github_repository_invalid` | 2 | A GitHub repository isn't an `owner/name` that GitHub accepts. |
| `github_token_missing` | 5 | A command that writes to GitHub has neither `GITHUB_TOKEN` nor `GH_TOKEN`. |
| `github_environment_empty` | 2 | The GitHub Environment to audit has an empty name. |
| `github_default_branch_missing` | 2 | GitHub reports no default branch for the repository. |
| `release_pr_marker_mismatch` | 5 | The managed Release PR at the Candidate head describes another release. |
| `release_pr_head_unverified` | 5 | The managed Release PR head isn't the generated commit that GitHub verified. |
| `release_pr_intent_conflict` | 5 | The managed Release PR is already bound to another Candidate intent. |
| `release_pr_changed` | 5 | The managed Release PR changed while its intent was being bound. |
| `candidate_run_from_another_push` | 3 | A push publishes a Candidate that another run prepared. |
| `candidate_run_promotes_itself` | 3 | A manual promotion names a Candidate from its own run. |
| `candidate_run_event_unsupported` | 3 | An event other than a push or a manual promotion publishes a Candidate. |
| `approval_github_token_missing` | 3 | The release approval can't verify its Actions artifact without `GITHUB_TOKEN` or `GH_TOKEN`. |
| `actions_artifact_identity_invalid` | 3 | The Actions artifact ID or digest that the approval names is malformed. |
| `actions_run_id_invalid` | 3 | The Actions run ID that the approval names isn't a canonical number. |
| `actions_artifact_expired` | 3 | The Candidate's Actions artifact has expired. |
| `actions_artifact_mismatch` | 3 | The Actions artifact doesn't match its sealed run, source, and digest. |
| `actions_run_mismatch` | 3 | The Actions run doesn't match the repository, managed workflow, source, and required state. |
| `github_tag_target_not_commit` | 5 | An annotated tag on GitHub targets something other than a commit. |
| `github_tag_object_unsupported` | 5 | A tag ref on GitHub points at an unsupported object type. |
| `github_tag_creation_unexpected` | 5 | GitHub created an annotated tag object other than the one requested. |
| `github_release_tag_ambiguous` | 4 | Two or more GitHub Releases have the Candidate's tag. |
| `release_asset_draft_required` | 5 | A Release asset upload targets a Release that is no longer a draft. |
| `release_asset_name_unsafe` | 5 | A Release asset name is unsafe. |
| `release_asset_media_type_invalid` | 5 | A Release asset media type is invalid. |
| `release_upload_url_malformed` | 5 | GitHub's Release upload URL is malformed. |
| `release_upload_url_untrusted` | 5 | GitHub's Release upload URL has an untrusted origin. |
| `release_upload_url_mismatch` | 5 | GitHub's Release upload URL names another repository or Release. |
| `release_asset_upload_unexpected` | 5 | GitHub reports an uploaded Release asset whose identity differs from the bytes sent. |
| `release_asset_on_published_release` | 5 | A Release asset to delete belongs to a published Release. |
| `release_asset_uploaded` | 5 | A Release asset to delete is already uploaded. |
| `release_asset_missing` | 5 | The Release has no asset of the name to delete. |
| `release_asset_duplicate` | 5 | The Release has two assets of the name to delete. |
| `release_asset_id_missing` | 5 | A Release asset to delete has no id. |
| `candidate_not_directory` | 2 | A `--candidate` path isn't a directory. |
| `candidate_destination_exists` | 4 | The Candidate destination already exists, and a sealed Candidate is never replaced. |
| `candidate_source_commit_invalid` | 2 | The Candidate source commit isn't a commit ID of 40 lowercase hexadecimal digits. |
| `candidate_tag_unsafe` | 2 | The Candidate tag is a full ref or a peeled ref. |
| `candidate_tag_version_mismatch` | 2 | The Candidate tag doesn't end with the Candidate version. |
| `candidate_release_notes_invalid` | 2 | The Candidate release notes hold a NUL or exceed 1 MiB. |
| `manual_refs_empty` | 2 | The Candidate lists no manual release ref. |
| `hook_id_duplicate` | 2 | Two hooks share an id. |
| `notify_hook_id_invalid` | 2 | A notify hook id is empty or listed twice. |
| `notify_hooks_mismatch` | 2 | The sealed notify hook definitions don't match the ordered notify hook ids. |
| `candidate_docs_policy_mismatch` | 2 | The documentation archive's presence contradicts `outputs.docs`. |
| `candidate_interface_too_large` | 2 | The package interface exceeds the archive size limit. |
| `candidate_schema_unsupported` | 4 | The Candidate manifest names an unsupported schema. |
| `candidate_manifest_invalid` | 4 | The Candidate manifest isn't the strict JSON that a seal writes. |
| `candidate_file_not_regular` | 4 | A Candidate file isn't a regular file. |
| `candidate_file_too_large` | 4 | A Candidate file exceeds its size limit. |
| `candidate_artifact_path_unexpected` | 4 | A Candidate artifact sits at a path other than its fixed one. |
| `candidate_checksum_malformed` | 4 | A checksum that the Candidate records isn't a lowercase SHA-256 digest. |
| `candidate_checksum_mismatch` | 4 | A Candidate file's size or SHA-256 differs from what the Candidate records. |
| `candidate_inventory_mismatch` | 4 | The Candidate directory holds files or directories other than the sealed ones. |
| `candidate_semantic_checksum_mismatch` | 4 | An archive's semantic checksum differs from what the Candidate records. |
| `candidate_intent_digest_mismatch` | 4 | The Candidate's intent digest differs from the intent it records. |
| `candidate_digest_mismatch` | 4 | The Candidate digest differs from the manifest it records. |
| `candidate_hook_evidence_invalid` | 4 | Hook evidence names an unsupported schema, or an empty or duplicate id. |
| `candidate_hook_failed` | 4 | A required hook did not succeed. |
| `candidate_hook_evidence_mismatch` | 4 | Hook evidence doesn't match the configured verify and sidecar hooks. |
| `candidate_sidecar_producer_undeclared` | 4 | A sidecar artifact comes from a hook that the Candidate doesn't declare. |
| `candidate_sidecars_too_many` | 4 | The Candidate carries more sidecar artifacts than the limit. |
| `candidate_sidecar_path_invalid` | 4 | A sidecar artifact path is invalid or duplicated. |
| `candidate_sidecars_too_large` | 4 | The sidecar artifacts exceed their size limit. |
| `candidate_sidecar_release_disabled` | 4 | A public sidecar artifact needs `outputs.github_release`. |
| `candidate_sidecar_private_upload_forbidden` | 4 | A public sidecar artifact of a private package needs `outputs.allow_private_evidence_upload`. |
| `candidate_sidecar_name_duplicate` | 4 | Two public sidecar artifacts share a GitHub Release asset name. |
| `candidate_evidence_policy_mismatch` | 4 | The built-in SBOM or provenance evidence contradicts the output policy. |
| `candidate_signature_missing` | 4 | `outputs.signature` is set, and no signature sidecar artifact is sealed. |
| `sidecar_hook_id_unsafe` | 6 | A sidecar artifact names an unsafe hook id. |
| `sidecar_name_unsafe` | 6 | A sidecar artifact name isn't one that GitHub keeps as it is. |
| `sidecar_media_type_invalid` | 6 | A sidecar artifact media type is invalid. |
| `candidate_source_mismatch` | 4 | The checkout isn't at the Candidate's source commit. |
| `candidate_policy_differs` | 4 | The Candidate's policy differs from the configuration at its source commit. |
| `registry_credential_missing` | 3 | A private registry's credential variable is not set. |
| `oidc_url_untrusted` | 3 | A GitHub OIDC URL is malformed, carries credentials or a fragment, or has an origin other than GitHub's. |
| `oidc_token_unverified` | 3 | The GitHub OIDC token isn't a well-formed RS256 compact JWS that one key of the issuer's key set verifies. |
| `oidc_claims_mismatch` | 3 | The GitHub OIDC claims don't canonically name the trusted issuer, the release-glz audience, the sealed Candidate's repository, Environment, workflow, ref, and commit, the publishing run, and an authorized event. |
| `oidc_token_outside_validity` | 3 | The GitHub OIDC token has expired, was issued in the future, or isn't valid yet. |
| `version_number_exhausted` | 2 | A release step or prerelease train would pass the largest number that a version component holds. |
| `prerelease_train_backward` | 2 | A prerelease train would move backwards, stay behind the published core, or not sort after the published version, without an explicitly higher core version. |
| `explicit_version_refused` | 2 | An explicit version is below the version that the changes require, or doesn't belong to the configured prerelease train. |
| `version_not_after_published` | 2 | The selected version doesn't follow the published version, so there is nothing new to release. |
| `changelog_notes_layout_invalid` | 1 | The structured changelog notes path isn't a directory, holds more note files than the limit, or holds a note that isn't a regular file within the size limit. |
| `changelog_note_invalid` | 1 | A structured changelog note has an unsafe id or one other than its filename, text other than one trimmed line within the length limit, or a zero pull request. |
| `gleam_compiler_unsupported` | 2 | The installed Gleam compiler is older than the oldest one that release-glz supports. |
| `gleam_repository_invalid` | 2 | The package `repository` names an unsupported type, or lacks the user, repository, host, or URL that its type needs. |
| `release_pr_marker_not_trailing` | 5 | The managed Release PR body doesn't end in exactly one release-glz marker. |
| `workflow_input_unsafe` | 2 | A value that the generated workflow embeds holds characters that are unsafe in YAML, or names the default branch as a full ref. |
| `action_sha_invalid` | 2 | The release-glz Action pin isn't a full lowercase commit SHA. |
| `workflow_modified` | 4 | The managed workflow lacks a valid managed-state record or changed after generation, so it isn't overwritten. |
| `registry_release_invalid` | 5 | The registry's release response isn't valid JSON, or names an invalid version, a release other than the one observed, or a checksum that isn't a SHA-256 digest. |
| `registry_release_not_visible` | 5 | A published release didn't appear on the registry within the visibility poll. |
| `archive_limit_exceeded` | 2 | An archive exceeds its compressed size, entry count, per-entry size, or expanded size limit. |
| `archive_path_unsafe` | 2 | An archive entry path isn't a safe relative UTF-8 path that every supported OS can represent. |
| `archive_entry_not_regular` | 2 | An archive entry, or a file that a package publishes, isn't a regular file, or a directory entry has content. |
| `archive_entry_duplicate` | 2 | Two archive entries name the same path, also once letter case and Unicode normalization no longer count. |
| `archive_extension_header_invalid` | 2 | An archive carries a global or link extension header, or a path extension header that is malformed, unsupported, consecutive, or dangling. |
| `hex_inner_checksum_mismatch` | 2 | A Hex package's `CHECKSUM` doesn't match its `VERSION`, `metadata.config`, and `contents.tar.gz`. |
| `hook_snapshot_modified` | 6 | A verify or sidecar hook changed the snapshot that it ran against. |
| `hook_timed_out` | 6 | A hook ran past its timeout and was terminated. |
| `hook_reported_failure` | 6 | A required verify or sidecar hook, or a notify hook delivering its notification, exited unsuccessfully or reported failure. |
| `hook_observation_failed` | 6 | A required notify hook exited unsuccessfully or reported failure while observing whether its notification was delivered. |
| `hook_output_limit_exceeded` | 6 | A hook wrote more to stdout or stderr than its limit. |
| `hook_output_invalid` | 6 | A hook's output isn't strict `hook/v1` JSON with a non-empty summary and object evidence, or a notify hook's observation lacks a boolean `complete`. |
| `sidecar_artifacts_invalid` | 6 | A sidecar hook's evidence isn't a list of artifacts with only known fields and base64 content, or names one artifact twice. |
| `sidecar_artifacts_limit_exceeded` | 6 | Sidecar hooks returned more artifacts, or more bytes, than a Candidate holds. |
| `hook_snapshot_entry_not_regular` | 6 | The snapshot that hooks run against holds an entry that is neither a regular file nor a directory. |
| `source_commit_unresolved` | 2 | The commit SHA that a rehearsal seals names no commit, or git resolves it as a ref to another commit. |
| `gleam_compiler_mismatch` | 2 | The installed Gleam compiler isn't the version that the configuration pins. |
| `version_lowering_forbidden` | 3 | An explicit version is below the manifest version of a package that has no release yet. |
| `manifest_version_behind_published` | 3 | The manifest or explicit version is behind the latest release on the registry. |
| `baseline_ref_unresolved` | 2 | A configured baseline ref, or the baseline of an API exception, names no commit. |
| `api_exception_expired` | 3 | The API exception for the published version has expired. |
| `baseline_not_found` | 3 | No tag, `baseline_refs` entry, or commit within the bounded history search matches the published Hex artifact. |
| `release_file_outside_repository` | 1 | The manifest or changelog that a Release PR writes lies outside the repository. |
| `registry_package_invalid` | 5 | The registry's package response isn't valid JSON, or lists an invalid version. |
| `registry_redirect_cross_origin` | 5 | A registry redirect leaves the origin that the request was sent to. |
| `registry_redirect_limit_exceeded` | 5 | A registry request was redirected more times than the redirect limit. |
| `registry_redirect_location_invalid` | 5 | A registry redirect has no `Location` header, or one that isn't ASCII. |
| `registry_response_too_large` | 5 | A registry response exceeds its download limit. |
| `release_asset_unfinished` | 4 | A GitHub Release asset is unfinished where a release can't complete it: the Candidate doesn't seal it, or its Release is published or isn't the Candidate's draft. |
| `approval_request_incomplete` | 3 | The publishing job's environment lacks a variable that release approval checks. |
| `approval_release_pr_missing` | 3 | A push release has no server-verified merged managed Release PR for its Candidate. |
| `repository_object_format_unsupported` | 2 | The repository that a rehearsal builds from names its objects with a hash other than SHA-1, so GitHub can't serve its commits. |
| `registry_release_precedence_tie` | 4 | Two registry releases share the highest precedence, among every release or among the stable ones, and differ in build metadata, so neither is the latest. |
| `github_redirect_refused` | 5 | GitHub answered a request with a redirect, which release-glz never follows, so the token reaches no other URL. |
| `oidc_redirect_refused` | 3 | The runner answered the GitHub Actions OIDC token request, or the issuer answered its discovery or key set request, with a redirect, which release-glz never follows. |
| `registry_publish_redirect_refused` | 5 | The registry answered a publish with a redirect, which release-glz never follows, so the archive and the credential reach no other URL. |
| `canonical_number_non_finite` | 1 | A value that canonical JSON writes holds a number without a finite double value, such as NaN or an infinity, which RFC 8785 refuses. |

A release run that stops after it published part of a release exits 7 whatever stopped it, including a required notify hook that fails after publication.
Inspection commands, `status`, `verify --online`, and `release --dry-run`, exit 0 whenever they can report a state, and that `state` names what remains.
A `--candidate` path that isn't a directory exits 2, and only a Candidate that fails its own checks exits 4.
Offline `verify --candidate` and `status --candidate` read only the Candidate, so they need no manifest in the working directory.

The Action parses the same envelope even after a non-zero CLI exit, preserves its diagnostics, next action, and original exit code, and exposes `state`, `release-required`, `version`, `intent-digest`, `candidate-digest`, `pr-url`, `release-pr-head`, `intent-binding`, `hex-url`, `github-release-url`, and `next-action`.
`next-action-argv` is the JSON-encoded canonical argv array.
The Action's `plan-file` input becomes `plan --out` or `release-pr --plan`, and no other command accepts it.

## Supply chain

The dependency-free Node wrapper streams subprocess output, propagates cancellation, enforces time and download limits, permits only same-origin redirects, validates archive inventory, checks SHA-256, and cleans temporary files.
An optional binary version override must supply its checksum and provenance digest.

When published, release assets are intended to cover Linux musl x86_64/aarch64, macOS x86_64/arm64, and Windows x86_64/arm64, with checksums, licenses, CycloneDX SBOM, provenance, and GitHub artifact attestations.
A release maintainer must replace the fail-closed placeholder checksum manifest with the output of the preparation workflow before creating an immutable tag.

See [design](design.md), [threat model](threat-model.md), [release readiness](release-readiness.md), and [security policy](../SECURITY.md).

## License

Licensed under either Apache-2.0 or MIT, at your option.
