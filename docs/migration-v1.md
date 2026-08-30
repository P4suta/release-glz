# Migrating to v1 schema 2

Legacy flat schema 1 remains readable during v1.x so that planning and the
migration preview can explain existing settings. Candidate creation and
publication require schema 2.

## Preview and apply

Commit or back up the repository, then run:

```console
release-glz migrate --check
release-glz migrate --diff
release-glz migrate --update
release-glz doctor
release-glz init --diff
release-glz init --update
release-glz doctor --online
release-glz doctor --candidate-build
```

`migrate --check` exits with the policy code when migration is required.
`migrate --diff` does not write. `migrate --update` first records the exact
installed Gleam compiler version, then writes only after validating the complete
generated schema 2 configuration. It refuses races or conflicting backup/note
files. Because schema 1 has no compiler field, migration fails with an actionable
error if the intended supported Gleam executable cannot be observed.

The original manifest is preserved byte-for-byte at
`.release-glz/legacy-gleam.toml`. An existing different backup is never
replaced. The original CHANGELOG remains in place. Each classified bullet under
its legacy Unreleased section becomes a deterministic
`.release-glz/notes/legacy-unreleased-####.toml` note (a single bullet uses
`legacy-unreleased.toml`), without truncating long content.

## Field mapping

| schema 1 field | schema 2 location |
|---|---|
| `changelog_path` | `changelog.path` |
| `release_branch_prefix` | top-level `release_branch_prefix` |
| `allow_version_zero` | top-level `allow_version_zero` |
| `prerelease` | top-level `prerelease` |
| `baseline_refs` | top-level `baseline_refs` |
| `allow_unknown_api_for` | migration pauses until each version is replaced by an `api_exceptions` record with baseline, reason, and expiry |

The legacy override cannot be converted losslessly because it does not contain
the schema 2 audit fields; migration therefore never drops it or invents those
fields. Migration also materializes the exact compiler, registry identity, approval
policy, outputs, hooks, and changelog policy so defaults cannot drift after a
Candidate is approved.

## Machine output

JSON schema v1 command output is end-of-life at the v1 boundary. Automation
must consume the `command/v2` envelope and the independently versioned
`plan/v2`, `candidate/v1`, `state/v1`, and `hook/v1` schemas. Field names and
repository-relative `/` paths should be treated as data, not reconstructed from
human output.
