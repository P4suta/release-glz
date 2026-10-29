# Threat model

release-glz protects the integrity and authorization of one immutable package release.
It assumes GitHub, the configured registry, the configured compiler distribution, and repository administrators are trusted within their stated roles.
It does not make a compromised maintainer machine or registry reversible.

## Protected assets

- exact package and docs bytes associated with a source commit;
- Release PR intent and Environment approval;
- registry and GitHub secret values;
- tags, releases, provenance, SBOMs, signatures, and notifications;
- the ability to resume without replacing an already published object.

## Main threats and controls

| Threat | Control |
|---|---|
| Dirty or malicious working tree content | Rehearsal accepts a full commit SHA and builds a `git archive` snapshot; the working tree is never the Candidate source. |
| Archive path traversal or resource exhaustion | Inventory rejects absolute/parent paths, links, devices, duplicate entries, excessive counts, and expansion beyond limits before extraction. |
| Credential theft by redirect | URLs cannot embed credentials; authenticated requests reject cross-origin redirects and redact secret values from errors and JSON. |
| Fork or alternate-workflow publication | The secret-free Candidate job is separated from the Environment job; OIDC claims bind repository, environment, workflow, event, ref, run, and SHA. A fork cannot satisfy that identity. |
| A fork's pull request posing as the Release PR | A merged or open Release PR counts only when its head branch lives in the repository itself and it targets the default branch. Its head must be a server-verified single-parent commit that carries the files digest, and its body must end in exactly one complete marker that rendered summaries can't forge. |
| Dependency build code reading tokens | The compiler, and every dependency build it runs, receives only the variables that locate executables, home and cache directories, temporary space, the locale, proxies, and certificates. GitHub and Actions tokens, OIDC request values, Action inputs, runner command files, and registry credentials stay out. |
| Approval substitution | The PR binds semantic `intent_digest`; the Environment and Actions artifact identity bind exact `candidate_digest`. Both are verified again before effects. |
| Compiler or source drift | The Candidate seals an exact compiler version and committed source SHA. Release performs no rebuild. |
| Registry race or ambiguous response | Every stage observes first; unknown POST results are polled by checksum instead of automatically repeated. |
| Replacement of immutable public state | Existing package, docs, tag, GitHub Release, and asset values must match exactly; no replace, clobber, or automatic revert operation exists. |
| Hook command injection or release-credential theft | Hooks are argv arrays with timeouts, JSON I/O, environment allowlists, sealed definitions, and phase-specific capabilities; shell strings are rejected. Registry publication credentials, GitHub/OIDC authorization tokens, and GitHub control-file paths cannot be forwarded even when explicitly named. |
| Private artifact disclosure | Raw private Candidate artifacts stay in Actions storage; only explicitly allowed evidence/sidecars can be public assets. |
| Mutable workflow dependency | Generated and project workflows pin third-party Actions to full commit SHAs and use least job permissions with checkout credentials disabled. |

## Archive limits

Hex package, documentation, and source snapshot archives pass the same bounded reader.
Unless a caller sets tighter limits, the reader refuses an archive that exceeds any of these values.

| Limit | Default |
|---|---|
| Entries in one archive | 20,000 |
| Expanded size of one entry | 64 MiB |
| Expanded size of one archive | 256 MiB |
| Compressed size of one archive | 128 MiB |

## Gleam 1.18.1 Windows packaging compatibility

Gleam 1.18.1 has a native Windows path regression in `export hex-tarball` ([gleam-lang/gleam#6184](https://github.com/gleam-lang/gleam/issues/6184)).
release-glz attempts the normal compiler export first.
It uses its compatibility path only on Windows, only for exactly Gleam 1.18.1, and only when both known upstream error fragments identify that regression.
The compiler validations and build have already completed at that point.

The compatibility path calls `export package-information`, inventories the compiler outputs, validates Hex-only dependencies, and constructs a deterministic Hex v3 package.
The ordinary strict archive validator then checks the complete result before it can become a Candidate.
It does not relax source, size, path, file-type, dependency, or checksum policy.
All other errors fail closed.

## Availability and residual risk

Registry, GitHub, runner, and network outages can leave a partial release.
The monotonic reconciler makes this recoverable with the same Candidate but cannot make multiple external services atomic.
A registry that lies about checksums, a compromised allowed compiler or pinned Action commit, a malicious repository administrator, and theft of an Environment credential remain trust-boundary risks.
Artifact attestation, provenance verification, protected branches, strict separation, short-lived credentials, and independent review reduce but do not eliminate them.

No telemetry is collected.
Logs and hook output should still be treated as sensitive, because redaction can protect known credentials but cannot identify arbitrary application secrets.
