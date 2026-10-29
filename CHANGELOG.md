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

### Security

- Archive validation refuses, on every host, a path that some supported OS can't store under the same name, and two entries that collide once letter case no longer counts.
  That covers a colon, a character or device name that Windows forbids, such as `aux.html`, and a component that ends in a dot or a space.
  A package, documentation archive, or source snapshot with such a path now fails instead of extracting into a different tree on macOS or Windows.
- No configured hook may take the id `release-glz`, which marks the SBOM and provenance that release-glz builds itself.
  Such a hook's output used to count as built-in evidence.
- The files digest of a Release PR commit starts from a domain tag and puts a length before every path and content.
  Two different file sets could hash the same input before, and an open Release PR gets one rebuilt commit under the new digest.
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

- The `update` command, which ran the same code as `release-pr`; use `release-glz release-pr`.
- `HexRegistry::default` and `Planner::default`, which no command used and which read registry locations from `RELEASE_GLZ_HEX_*` variables.
  Build a registry from the manifest configuration instead.
- The undocumented `RELEASE_GLZ_POLL_ATTEMPTS` and `RELEASE_GLZ_POLL_INTERVAL_MS` variables, which changed how long publication waited for the registry.
  A library caller sets `VisibilityPoll` through `HexRegistry::with_visibility_poll` instead.
- `GitHubClient::create_release`, which published a Release in one request and let GitHub create a missing tag.
  It bypassed the draft and its checks.
- `GitRepo::create_tag`, `GitRepo::create_annotated_tag`, and `GitRepo::push_tag`, which wrote and pushed tags with the local git.
  release-glz creates its tag through the GitHub Git Data API, and nothing outside the tests called them.

### Fixed

- A `--candidate` path that isn't a directory exits 2 as a usage error instead of 4 as a conflict.
  Offline `verify --candidate` and `status --candidate` no longer need a manifest in the working directory, and the exit code table describes partial releases and inspection commands.
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
