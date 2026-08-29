# v1 architecture

release-glz separates decisions, sealed inputs, and observed effects so that an
approval cannot accidentally authorize different bytes.

## Three layers

`ReleasePlan` is pure release intent. Planning reads the selected manifest,
committed history, registry metadata/artifacts, pull requests, and public API.
It joins independent requirements with `none < patch < minor < major` and
returns `plan/v2`. It does not change external state or tracked files.

`Candidate` is one immutable package release. Rehearsal validates a full commit
SHA, exports that commit with `git archive`, builds with the exact configured
Gleam compiler, inventories the Hex and docs archives, executes sealed hooks,
and writes `candidate/v1` plus exact artifacts. `Candidate::verify` rejects
missing, unexpected, renamed, or changed files before any online operation.

`ReleaseState` (`state/v1`) is freshly observed external state. The reconciler
compares every existing object with the Candidate and returns only missing
effects. That makes interruption and retry normal operation rather than a
rollback problem.

```text
committed source + registry/API history
                 │
                 ▼
            ReleasePlan ── intent_digest ── Release PR
                 │
      rehearse exact SHA with exact compiler
                 ▼
             Candidate ── candidate_digest ── Environment
                 │
      verify bytes + observe external systems
                 ▼
           ReleaseState ── monotonic effects ── released
```

## Digest boundary

Hex tar output is not byte-deterministic when equivalent dependency metadata is
ordered differently. The PR therefore approves a semantic `intent_digest`
derived from normalized package/API/docs content. The Environment approves the
`candidate_digest`, which binds the exact raw tar and docs checksums, source
SHA, policy, hook evidence, and sidecars. Publication consumes those raw files
directly and never invokes a compiler.

Canonical values use sorted, duplicate-free JSON object keys, JSON-safe
numbers/strings, and SHA-256. Digests do not rely on filesystem enumeration
order or timestamps.

## Boundaries

Registry and forge access sit behind observable adapters. Production supports
Hex.pm, `/repos/ORG`, standard Hex-compatible endpoints, and GitHub.com. Tests
use loopback fake services, local bare git repositories, and fake argv-based
hooks; no test publishes a real user package.

Registry credentials are allowed on reads because private package metadata and
artifacts require them. Redirects must remain on the configured origin. HTTPS
is mandatory except for explicit loopback tests. Responses have time and size
limits, retry `Retry-After` where safe, and redact credentials from errors.

## Monotonic reconciler

After all preflight validation and required verify hooks, effects are ordered:
annotated tag, GitHub draft, package, docs, release assets/finalization, and
notifications. Every invocation observes before applying. If an existing
package checksum, docs checksum, tag target, release Candidate digest, or asset
checksum differs, reconciliation ends in `conflict`; it never replaces it.

An unknown package POST result transitions into observation/polling. It cannot
authorize a second POST until absence is established. Required notify failure
does not roll back earlier public effects and is reported as
`partially_released`. Optional notify failure is diagnostic only.

## Approval boundary

The Candidate job has no publication secret. Normal authorization binds the
server-side merged managed PR head to `intent_digest`. The Environment job
downloads an Actions artifact by immutable artifact ID and digest, verifies the
Candidate again, and binds `candidate_digest`. OIDC validation restricts the
repository, Environment, workflow ref, run identity, event path, source SHA,
and allowed manual ref.

Private package core artifacts remain inside the Actions artifact. Only
sidecars marked public by explicit output policy can become GitHub Release
assets.

## Extensibility

Hooks are executable plus argv, never shell source. They receive JSON on stdin
and return versioned JSON on stdout. Environment propagation is allowlisted.
Verify hooks cannot modify the snapshot. Sidecar hooks can add sealed evidence
but cannot alter core package/docs bytes. Notify hooks implement observe/apply
with a Candidate-derived idempotency key.

## Compatibility

Machine output is wrapped in `command/v2`; domain data versions independently.
Within a schema, removing or changing a field is forbidden. Repository paths
use `/` regardless of host OS. Exit codes distinguish usage, policy, conflict,
temporary external failure, hook failure, and partial release.
