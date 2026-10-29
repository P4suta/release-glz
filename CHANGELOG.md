# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial Hex-native release planner, rolling Release PR manager, resumable
  publisher, GitHub Action, and cross-platform binary distribution workflows.

### Removed

- The `update` command, which ran the same code as `release-pr`; use `release-glz release-pr`.

### Fixed

- `release-glz prerelease stable` no longer writes an empty `[tools.release-glz]` table into a manifest that has none, so `init` still accepts that manifest afterward.
- A plan's `hex_url` names a package page only once the planned version is on the registry.
  It points at the Organization page for a Hex.pm Organization package and stays empty for a Hex-compatible registry, which serves no package pages.
- A failed write of the artifact baseline cache is reported instead of ignored.
