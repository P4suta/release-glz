# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial Hex-native release planner, rolling Release PR manager, resumable publisher, GitHub Action, and cross-platform binary distribution workflows.
- `release-glz plan --out <FILE>` writes the plan it prints to a new file, and `release-glz release-pr --plan <FILE>` writes the Release PR from that file without running the compiler.
  The writing job refuses a plan file that isn't a `plan/v2` document, carries an unknown field, or already names a Release PR.
  It also refuses a plan for another package or manifest version, or with a baseline outside the checked-out history.
- `plan/v2` gains `release_pr_head`, the Release PR head commit that `release-pr` wrote or confirmed.
- The Action accepts a `plan-file` input for `plan` and `release-pr`, and it exposes a `release-pr-head` output.
- The `release-pr --candidate` result reports `intent_binding`, and the Action exposes it as `intent-binding`.
  A Candidate whose head a newer Release PR head replaced reports `superseded`, writes nothing, and exits with status 0 instead of failing.
  The binding refuses a Release PR at the Candidate head whose marker describes another release.
- Every command result format has a published JSON Schema under `docs/`, and `docs/README.md` lists the commands that print each format.
  The `command/v2` schema also states that `ok` is false exactly when a diagnostic has the `error` level.
  Tests check the real output of every command with these schemas and assert every `format`.
- `completion --output json` names its result format as `completion/v1`, like every other command result.

### Changed

- When the observed world contradicts the Candidate in more than one object, the conflict names the first object in publication order, so a tag conflict outranks a package conflict.
- A notification record for a hook that the Candidate doesn't have no longer makes a release count as `partially_released`.

### Security

- A verified approval identity comes only from signature verification of the GitHub OIDC token.
  `release --dry-run`, `verify --online`, and `status --online` used to build one from invented claims, and only a dry-run flag in another argument kept that evidence from approving a publication.
  They now inspect through a runner entry point that holds no evidence and applies no effect.
- A push release takes its approved intent digest from the marker of the merged Release PR that GitHub returns for the source commit, and every approval takes its Environment from the verified OIDC claims.
  The generated workflow used to pass both values from the publish job's own outputs, so their comparisons only repeated what the run already knew.
  It no longer sets `RELEASE_GLZ_APPROVED_INTENT_DIGEST` or `RELEASE_GLZ_ENVIRONMENT`, and release-glz ignores them.
- On Windows, a hook runs in a job object from its first instruction, and a hook that times out ends together with every process it started.
  Only the hook's own process used to end, so its children kept running and could hold its pipes open after release-glz moved on.
- Archive validation refuses, on every host, a path that some supported OS can't store under the same name, and two entries that collide once letter case no longer counts.
  That covers a colon, a character or device name that Windows forbids, such as `aux.html`, and a component that ends in a dot or a space.
  A package, documentation archive, or source snapshot with such a path now fails instead of extracting into a different tree on macOS or Windows.
- No configured hook may take the id `release-glz`, which marks the SBOM and provenance that release-glz builds itself.
  Such a hook's output used to count as built-in evidence.
- The job that publishes release-glz's own GitHub Release no longer holds `actions: read`, which none of its steps used.
  Each permission it keeps names the steps that need it.
- The files digest of a Release PR commit starts from a domain tag and puts a length before every path and content.
  Two different file sets could hash the same input before, and an open Release PR gets one rebuilt commit under the new digest.
- Redaction finds every occurrence of every secret before it replaces any, and replaces each run of covered text once.
  A secret inside another, or two that overlapped in the text, used to leave part of one in error messages and logs.
- Publishing release-glz's own GitHub Release compares the release with the run's own build.
  Every asset's GitHub digest must equal the local file's SHA-256 before more uploads and before finalizing, and every re-downloaded asset must match byte for byte.
  The run used to compare asset names only and verified the downloads with the `SHA256SUMS` that came with them.
- Attestation checks in the distribution workflow and the install guide require `distribute.yml` at the release tag, so an attestation from another workflow or ref in the repository no longer passes.
- A Release PR commit counts as generated only when the files it added or modified match the files digest its message records.
  A maintainer's verified amend that kept the message used to count, so release-glz could adopt it or reset the branch over it.
  It now takes the path for human work, and a failure to read a file from GitHub fails the run instead of closing the Release PR.
- The Release PR commit writes only the rendered files that differ from the default branch tip, so its diff lists exactly the files its digest covers.
  When the tip already holds every rendered file, `release-pr` writes no commit and reports `release_files_current`.
- A registry `Retry-After` header can ask for at most one minute, so a response can no longer stall a run indefinitely.
- Candidate verification checks each sealed file again through the handle it opened and reads at most one byte past the file's limit.
  A file swapped after the path check can no longer make verification read without bound.
- A sealed artifact can't declare a size over the largest archive that the tarball validators accept, and sealing refuses a package interface over that size.
- The generated workflow no longer runs the compiler in a job that can write.
  `plan` compiles with read access and hands its plan to `release-pr`, which writes the Release PR without the compiler.
  `rehearse-release-pr` and `bind-release-pr` then rehearse the new Release PR head and bind its intent in the same push run.
  The workflow drops its `pull_request` trigger, and only the Release PR, binding, and publish jobs serialize, each per package.
- A merged or open Release PR counts only when its head branch lives in the repository itself and it targets the default branch, so a fork's pull request can't stand in for a managed Release PR.
- A generated Release PR commit must have exactly one parent in addition to its server-verified signature and digest trailer.
- A managed Release PR body must end in exactly one complete marker, and the reasons and API summaries it renders can no longer contain one.
- A remote tag lookup accepts only the exact tag ref, so a tag whose name merely ends in the release tag can't answer for it.
- Git children pass refs after `--end-of-options` and never wait for a credential prompt.
- The Gleam compiler, and every dependency build it runs, receives only the variables that locate executables, home and cache directories, temporary space, the locale, proxies, and certificates.
  GitHub and Actions tokens, OIDC request values, Action inputs, runner command files, and registry credentials no longer appear in its environment.
  Build code still runs as the runner's user, so the threat model counts on compiling jobs holding no write token instead.
- Hooks can't receive `GITHUB_STATE`, like the other runner command files.
- The Action always runs the release-glz binary that it downloaded and verified.
  It no longer runs a program that the undocumented `RELEASE_GLZ_BINARY` variable names, which an earlier step could set without either check.
- The Action pauses workflow commands with an unpredictable token while it runs release-glz and writes its diagnostics.
  A line of compiler, git, or registry output that starts with `::` can no longer run a workflow command in the step.
- Every Action download has a ten-minute total deadline across its redirects, besides the idle timeout of one minute.
  A server that trickled bytes could otherwise keep the download going until the job timed out.
- Publication takes its policy from the source commit instead of the Candidate.
  `release`, `verify --online`, and `status --online` refuse a Candidate whose registry, credential variable, hooks, approval policy, release notes, or other policy field differs from the configuration committed at its source.
  Build code in `prepare` could otherwise rewrite the Candidate so that the publish job sent the registry credential elsewhere or ran other notify commands.
  A Candidate that an earlier build sealed needs a new `prepare` when the two builds read the configuration differently.
- The bundled root store no longer trusts the distrusted emSign roots that RUSTSEC-2026-0381 reports.
- Both lockfiles resolve `quinn-proto` 0.11.19, past RUSTSEC-2026-0338 through RUSTSEC-2026-0342, and the fuzz lockfile resolves `rustls-webpki` 0.103.16, past RUSTSEC-2026-0382.
  Shipping assurance audits the fuzz lockfile too.
- YAML parsing uses `serde_norway`, whose `libyaml` translation is maintained, instead of `serde_yaml` and the unmaintained `unsafe-libyaml`.

### Removed

- The plan result's `intent_digest`, which no command ever set, and the plan format moves to `plan/v3`.
  The intent digest appears in the Candidate and in the `release-pr --candidate` result.
- The `update` command, which ran the same code as `release-pr`; use `release-glz release-pr`.
- `ReleaseExecutionOptions` and the public `validate_github_claims`.
  A library caller previews with `CandidateReleaseRunner::inspect` and verifies a token with `verify_github_oidc_token`.
- `HexRegistry::default` and `Planner::default`, which no command used and which read registry locations from `RELEASE_GLZ_HEX_*` variables.
  Build a registry from the manifest configuration instead.
- The undocumented `RELEASE_GLZ_POLL_ATTEMPTS` and `RELEASE_GLZ_POLL_INTERVAL_MS` variables, which changed how long publication waited for the registry.
  A library caller sets `VisibilityPoll` through `HexRegistry::with_visibility_poll` instead.
- `GitHubClient::create_release`, which published a Release in one request and let GitHub create a missing tag.
  It bypassed the draft and its checks.
- `GitRepo::create_tag`, `GitRepo::create_annotated_tag`, and `GitRepo::push_tag`, which wrote and pushed tags with the local git.
  release-glz creates its tag through the GitHub Git Data API, and nothing outside the tests called them.

### Fixed

- A failure's diagnostic lists every cause beneath its message, as an unclassified failure's already did.
  A refused release approval used to say only that OIDC verification failed, without the check that refused it.
- The `init` and `migrate` results and their diffs give the manifest path relative to the repository, as every other result does.
  They used to repeat the `--manifest-path` value, which names the file from the repository root only when the command runs there with a relative path.
  `migrate` also put `./` before the backup path, and outside any repository it now reports both paths relative to the package directory.
- A plan lists `verify_hooks` only when the configuration names a verify hook, and `prepare_github_draft` only when `outputs.github_release` is on.
  It used to list both for every release, though neither ran without its configuration.
- A Conventional Commit type counts in any letter case, so `Feat:` asks for a minor release and lands under Added, as Conventional Commits 1.0.0 requires.
  `BREAKING CHANGE:` and `BREAKING-CHANGE:` still count only in uppercase.
- A `--candidate` path that isn't a directory exits 2 as a usage error instead of 4 as a conflict.
  Offline `verify --candidate` and `status --candidate` no longer need a manifest in the working directory, and the exit code table describes partial releases and inspection commands.
- The Action installs release-glz on Windows.
  Its archive scripts used `[IO.Compression.ZipFile]` without loading the assembly that Windows PowerShell 5.1 needs, and the extraction passed an argument that only .NET Core accepts.
- The Action and the release evidence scripts check the type of every JSON field they read.
  The Action refuses a `command/v2` diagnostic without a code or a message, and a bundled checksum that isn't a string.
  It used to print `undefined` for a missing field, and a checksum stored as a list failed later with an unrelated error.
  The SBOM generator refuses `cargo metadata` whose package fields have another type.
- A Unix release archive depends only on the binary inside it, as the Windows ZIP already did.
  `scripts/package-unix.js` writes one ustar entry with a fixed mode, owner, group, and time.
  It stores the binary uncompressed, so no compressor version or CPU feature changes the bytes.
  The runner's `tar` used to record the runner account.
  On macOS, bsdtar could also add an AppleDouble entry and an extended header that the Action's tar reader refuses.
- Publication after a merged Release PR can succeed.
  The push run's publish job consumes the Candidate that its own `prepare` job uploaded.
  The artifact check had required that run to have completed, which it can't have while it publishes.
  A push now accepts only its own run, in progress, and a manual promotion still accepts only an earlier run that completed with success.
- A release with many notify hooks or release assets runs to completion.
  The runner gave up after a fixed 128 rounds, one effect each, though nothing bounds the number of notify hooks.
  It now makes up to one attempt for each effect that its first plan lists.
- A version bump that would carry a component past `u64::MAX`, and a prerelease number past it, is an error instead of a wrapped smaller version or a panic.
  Kani proves the lifecycle and version arithmetic of the new dependency-free `release-glz-core` crate for every input, and shipping assurance runs those proofs.
- Updating the Release PR considers only a pull request on a branch with the release prefix whose marker names that same branch.
  The update could otherwise pick, close, and replace a pull request that copied a Release PR body onto another branch.
- Repairing a stale Release PR marker keeps its intent only when the head stays the same.
  A marker moved to a new head carried the old head's intent, and the binding then refused the new head's Candidate.
- Closing a stale Release PR deletes its branch through a compare-and-swap on the verified generated commit and only then closes the pull request.
  A commit that someone pushes after the check now keeps both the branch and the open pull request.
- Binding an intent reads the Release PR again just before it writes, and writes nothing over a head or body that a newer run replaced.
- `release-pr` fails before any write when `[repository]` spells the slug differently from GitHub, including letter case.
  OIDC and the Actions run checks compare the slug exactly, so such a configuration used to fail only at publication.
- `release-pr` looks up the pull requests of at most 200 commits since the baseline.
  Over that, as on a first release over a long history, it lists every commit by subject and reports `changes_listed_by_commit`.
- `release-glz prerelease stable` no longer writes an empty `[tools.release-glz]` table into a manifest that has none, so `init` still accepts that manifest afterward.
- A plan's `hex_url` names a package page only once the planned version is on the registry.
  It points at the Organization page for a Hex.pm Organization package and stays empty for a Hex-compatible registry, which serves no package pages.
- A failed write of the artifact baseline cache is reported instead of ignored.
- Commit messages that contain ASCII record or unit separators no longer corrupt the change list.
- `release-pr` no longer fails with "No such file or directory" when the manifest path names no directory and the changelog doesn't exist yet.
- The Release PR branch always holds one generated commit on the current default branch tip.
  When the tip moves, `release-pr` rebuilds that commit on the new tip, so the merged commit carries the content that the bound intent describes.
  It moves the branch only through a compare-and-swap from the generated commit it last wrote.
- `release-pr` writes or closes the Release PR only when its checkout is the default branch tip that GitHub reports.
  A run behind the tip reports `release_pr_superseded` and writes nothing.
- Requests for the repository itself no longer end in a slash, which GitHub answers with 404, so `doctor --online` can read the repository settings.
- At the merge commit of the Release PR for the planned version, `release-pr` opens no second Release PR for that version.
  It reports `release_pr_merged` with the merged Release PR while publication waits for approval.
