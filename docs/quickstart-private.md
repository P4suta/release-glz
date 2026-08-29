# Hex-compatible private registry quickstart

Use this path only for a registry implementing the standard Hex API, repository,
package tarball, and docs endpoints. Non-standard publish protocols are not
adapted by v1.

```toml
[tools.release-glz]
schema = 2
compiler = "1.18.1"

[tools.release-glz.registry]
provider = "hex-compatible"
api_url = "https://hex.example.test/api"
repository_url = "https://hex.example.test/repo"
docs_url = "https://hex.example.test/docs"
credential_env = "PRIVATE_HEX_TOKEN"
auth = "bearer"

[tools.release-glz.approval]
normal = "release-pr-and-environment"
manual = "environment"
environment = "release"
separation = "solo"
manual_refs = ["refs/heads/main"]

[tools.release-glz.outputs]
docs = true
github_release = true
sbom = true
provenance = true
signature = false
allow_private_evidence_upload = false
```

All URLs must be HTTPS and credentials in URLs are rejected. The API,
repository, and docs origins should be stable; authenticated redirects may not
cross origin. `repository` is intentionally omitted for `hex-compatible`.

Create a repository-level `PRIVATE_HEX_TOKEN` that can only read package and
docs metadata; it is used by trusted push planning and is never passed to the
Candidate or pull-request job. Store a separate publish-capable token under the
same name in the protected GitHub Environment, whose value overrides the read
token only for publication. Raw private package and docs Candidate artifacts
remain in the short-lived Actions artifact. By default no private core artifact
or evidence is uploaded to a GitHub Release. Set
`allow_private_evidence_upload = true` only after reviewing the contents of
every built-in and hook-produced sidecar.

Some GitHub plans do not support required Environment reviewers for private
repositories. release-glz never weakens approval automatically. In solo mode,
an explicit `private_repository_fallback = "workflow-dispatch-digest"` permits
a separate manual promotion that requires the Candidate digest. Strict mode
cannot use that fallback. Run `release-glz doctor` before the first rehearsal.
