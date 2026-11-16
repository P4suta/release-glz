# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `release-glz plan` decides the next version of one Gleam package from its latest Hex release, its Conventional Commits, its normalized publication contents, and its public API.
  It prints a `plan/v1` result and changes neither external state nor tracked files.
- Version selection joins the requirements of the publication contents, the commits, the public API, and an explicit version by `none < patch < minor < major`.
  It compares versions by semantic version precedence, makes a breaking change in a 0.x package a minor release, and refuses a version that doesn't follow the published one.
- `prerelease` moves a version through the `alpha`, `beta`, and `rc` channels, and `set-version` raises the planned version without lowering the required one.
- A version-scoped `api_exceptions` entry with a baseline ref, a reason, and an expiry date lets a release proceed when the baseline API can't be reconstructed.
- `release-pr` keeps one rolling Release PR as a single generated commit on the default branch tip, with the version, the changelog, and a marker that records the release intent.
  It writes only the rendered files that differ from the tip, rebuilds the commit when the tip moves, and closes the Release PR when no release is required.
  It writes nothing and reports `release_files_current`, `release_pr_superseded`, or `release_pr_merged` when the tip already holds its files, the checkout is behind the tip, or the checkout is the merge commit of the Release PR for the version.
  Over 200 commits since the baseline, it lists every commit by subject and reports `changes_listed_by_commit`.
- `plan --out <FILE>` hands its plan to `release-pr --plan <FILE>`, which writes the Release PR without running the compiler.
  The writing job refuses a file that isn't a `plan/v1` document of at most 4 MiB, carries an unknown field, names a Release PR, describes another package or manifest version, or has a baseline outside the checked-out history.
- `rehearse --ref <SHA> --out <DIR>` builds one committed snapshot with the configured compiler, runs the verify and sidecar hooks, and seals a `candidate/v1` with an `intent_digest` and a `candidate_digest`.
- `release-pr --candidate <DIR>` binds the Candidate's intent digest to the Release PR at its source commit and reports `intent_binding`.
- `verify`, `status`, and `release` check a sealed Candidate, observe Hex, HexDocs, git, and GitHub, and publish the tag, the draft GitHub Release, the package, the docs, the assets, and the notifications in that order.
  An existing object with other contents stops the release as a conflict, and a run never replaces an object.
  Once a run has published part of a release, every failure it reports is `partially_released` with exit code 7, and a rerun with the same Candidate resumes.
- `doctor` checks the local configuration, compiler, and workflow.
  `doctor --online` audits registry credentials and GitHub protections, and `doctor --candidate-build` builds `HEAD` with isolated caches and no credentials.
- `init` previews or writes a strictly typed `[tools.release-glz]` table and the managed workflow for a public Hex.pm, Hex.pm Organization, or Hex-compatible private registry package.
  It refuses to overwrite a managed workflow that changed after generation.
- `completion` generates bash, zsh, fish, and PowerShell completion source.
- Every command can print a `command/v1` JSON envelope whose result names its format, and each format has a published JSON Schema under `docs/`.
- Exit codes distinguish usage, policy, conflict, temporary external failure, hook failure, and partial release.
- The GitHub Action downloads the release-glz binary, verifies its checksum and provenance, and runs it without a shell.
  It keeps the original exit code and exposes the state, version, digests, Release PR, and next action of the result as outputs.
- Release archives for Linux musl x86_64 and aarch64, macOS x86_64 and arm64, and Windows x86_64 and arm64 come with checksums, licenses, a CycloneDX SBOM, provenance, and GitHub artifact attestations.
- The publication, run, approval, and version decisions live in the dependency-free `release-glz-core` crate, where Kani proves them.
  A Quint model checks the release protocol together with its world.

### Security

- No job of the generated workflow both runs the compiler and holds a write permission.
  The compiler and the dependency builds it runs receive only the variables that locate executables, home and cache directories, temporary space, the locale, proxies, and certificates.
- A push release needs both the merged Release PR whose marker records the approved intent digest and the protected GitHub Environment, which approves the sealed `candidate_digest`.
  A verified approval identity comes only from the signature of the GitHub OIDC token, whose repository, Environment, workflow, event, ref, run, and source SHA claims must all match.
- Publication takes its policy from the source commit and refuses a Candidate whose registry, credential variable, hooks, approval policy, or release notes differ from it.
- A Release PR counts only when its head branch lives in the repository, it targets the default branch, and its one generated commit has a server-verified signature, one parent, and files that match the digest its message records.
  Its body must end in exactly one complete marker, and every move or deletion of its branch is a compare-and-swap on that commit.
- Archive validation refuses traversal, links, duplicate entries, paths that some supported OS can't store, and paths that collide when letter case and Unicode normalization are ignored, before anything extracts.
- Candidate verification rechecks each sealed file through the handle it opened and bounds every read, and no sealed artifact may declare a size over the archive limit.
- Redaction removes every occurrence of every secret from error messages and logs, including secrets that overlap.
- A hook is an argv array, never shell source.
  It receives only allowlisted variables, and never the registry credential, GitHub or OIDC tokens, or runner command files.
  On Windows, a hook runs in a job object, so a timeout ends every process it started.
- Registry, GitHub API, and download URLs need HTTPS or plain HTTP to a numeric loopback address, and redirects stay on the configured origin.
  Responses have time and size limits, and a `Retry-After` header counts only as digits and for at most one minute.
- The Action pauses workflow commands with an unpredictable token while release-glz runs, refuses cross-origin redirects, and ends a download after an idle minute or ten minutes in total.
- The distribution of release-glz itself compares every GitHub Release asset with the run's own build, by digest and byte for byte, before it finalizes the Release.
  Its attestations require `distribute.yml` at the release tag.
