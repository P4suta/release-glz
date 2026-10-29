# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial Hex-native release planner, rolling Release PR manager, resumable publisher, GitHub Action, and cross-platform binary distribution workflows.

### Security

- A merged or open Release PR counts only when its head branch lives in the repository itself and it targets the default branch, so a fork's pull request can't stand in for a managed Release PR.
- A generated Release PR commit must have exactly one parent in addition to its server-verified signature and digest trailer.
- A managed Release PR body must end in exactly one complete marker, and the reasons and API summaries it renders can no longer contain one.
- A remote tag lookup accepts only the exact tag ref, so a tag whose name merely ends in the release tag can't answer for it.
- Git children pass refs after `--end-of-options` and never wait for a credential prompt.
- The Gleam compiler, and every dependency build it runs, receives only the variables that locate executables, home and cache directories, temporary space, the locale, proxies, and certificates.
  GitHub and Actions tokens, OIDC request values, Action inputs, runner command files, and registry credentials no longer reach dependency code.
- Hooks can't receive `GITHUB_STATE`, like the other runner command files.

### Removed

- The `update` command, which ran the same code as `release-pr`; use `release-glz release-pr`.

### Fixed

- `release-glz prerelease stable` no longer writes an empty `[tools.release-glz]` table into a manifest that has none, so `init` still accepts that manifest afterward.
- A plan's `hex_url` names a package page only once the planned version is on the registry.
  It points at the Organization page for a Hex.pm Organization package and stays empty for a Hex-compatible registry, which serves no package pages.
- A failed write of the artifact baseline cache is reported instead of ignored.
- Commit messages that contain ASCII record or unit separators no longer corrupt the change list.
