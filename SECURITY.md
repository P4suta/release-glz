# Security policy

Report suspected vulnerabilities privately through GitHub Security Advisories
for this repository. Do not include Hex, private-registry, GitHub, signing, or
hook credentials in a public issue.

release-glz separates a secret-free Candidate build from the protected publish
Environment. Publication verifies the sealed Candidate, Actions artifact ID and
digest, Release PR intent where applicable, and GitHub OIDC identity before any
effect. Registry credentials are named by configuration but their values are
not written to configuration, Candidate JSON, error chains, or command output.

Use an Environment-scoped, least-privilege registry token; pin release-glz and
all third-party Actions to reviewed full commit SHAs; disable persisted checkout
credentials; protect allowed refs; and review generated workflow diffs. Strict
separation should require a different reviewer and prevent self-review. Rotate
any credential that may have reached a log, artifact, hook, or untrusted runner.

The Node Action verifies checksums and provenance policy, limits downloads and
archive inventory, rejects cross-origin redirects, streams child output, and
cleans temporary files. The Rust Candidate verifier rejects unexpected files,
unsafe archives, checksum changes, and mismatched policy or hook evidence.

The complete trust boundaries, threats, and residual risks are documented in
[docs/threat-model.md](docs/threat-model.md). Operational response for an
interrupted immutable release is in [docs/recovery.md](docs/recovery.md).
