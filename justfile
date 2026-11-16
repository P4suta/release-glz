set windows-shell := ["pwsh.exe", "-NoLogo", "-NoProfile", "-Command"]

default:
    @just --list

# mise's paranoid mode loads this checkout's configuration only after a trust that records its current contents.
[private]
trust:
    mise trust --quiet {{ quote(justfile_directory() / "mise.toml") }}

# Formatting, lints, the tests, the documentation, the dependency policy, the Action, and the workflows.
check: trust
    mise x -- cargo xtask check

# The quick staged-file checks the pre-commit hook runs.
check-staged: trust
    mise x -- cargo xtask check --staged

# The checks whose outcome depends on the operating system.
check-platform: trust
    mise x -- cargo xtask check --platform

# The boundary of the proved core and the edges between the crates, outside the findings that `DEBT` holds.
structure: trust
    mise x -- cargo xtask structure

# The platform checks on the Linux host over the current files, uncommitted edits included.
check-linux:
    domyjob run linux --wait -- /bin/bash -lc 'export MISE_TRUSTED_CONFIG_PATHS="$PWD"; mise x -- cargo xtask check --platform'

# The platform checks on the Windows host over the current files, uncommitted edits included.
check-win:
    domyjob run win --wait -- powershell.exe -NoProfile -Command '$env:MISE_TRUSTED_CONFIG_PATHS=(Get-Location).Path; mise x -- cargo xtask check --platform; exit $LASTEXITCODE'

# Every Kani harness and negative control, each in its own bounded run in the pinned image.
proofs: trust
    mise x -- cargo xtask proofs

# The Lean model of publication and its refinement of the core crate, in the pinned image.
lean: trust
    mise x -- cargo xtask lean

# The Quint model of the release protocol and its traces, in the pinned image.
quint: trust
    mise x -- cargo xtask quint

# The mutants of the core crates through the Kani harnesses, optionally one shard: `just proof-mutants --shard K --of N`.
proof-mutants *args: trust
    mise x -- cargo xtask proof-mutants {{ args }}

# The fast gate, every proof, and the committed mutation receipt, for a release candidate.
release-check: check proofs lean quint
    mise x -- cargo xtask proof-mutants check
