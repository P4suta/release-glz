# Hex-compatible private registry quickstart

Use this path only for a registry implementing the standard Hex API, repository,
package tarball, and docs endpoints. Non-standard publish protocols are not
adapted by v1.

Generate the complete schema 2 configuration with all registry values explicit:

```console
release-glz init --profile private \
  --api-url https://hex.example.test/api \
  --repository-url https://hex.example.test/repo \
  --docs-url https://hex.example.test/docs \
  --credential-env PRIVATE_HEX_TOKEN --auth bearer --diff
release-glz init --profile private \
  --api-url https://hex.example.test/api \
  --repository-url https://hex.example.test/repo \
  --docs-url https://hex.example.test/docs \
  --credential-env PRIVATE_HEX_TOKEN --auth bearer --update
release-glz doctor --candidate-build
```

The generated registry section is:

```toml
[tools.release-glz.registry]
provider = "hex-compatible"
api_url = "https://hex.example.test/api"
repository_url = "https://hex.example.test/repo"
docs_url = "https://hex.example.test/docs"
credential_env = "PRIVATE_HEX_TOKEN"
auth = "bearer"
```

All URLs must be HTTPS and credentials in URLs are rejected. The API,
repository, and docs origins should be stable; authenticated redirects may not
cross origin. `repository` is intentionally omitted for `hex-compatible`.

Store a publish-capable `PRIVATE_HEX_TOKEN` only in the protected GitHub
Environment. Planning, Candidate preparation, and pull-request authorization
never receive it. Raw private package and docs Candidate artifacts
remain in the short-lived Actions artifact. By default no private core artifact
or evidence is uploaded to a GitHub Release. Set
`allow_private_evidence_upload = true` only after reviewing the contents of
every built-in and hook-produced sidecar.

The v1 Candidate boundary requires every dependency to build without
credentials. A private publication target is supported; private dependencies
are not. `doctor --candidate-build` removes all credentials and uses isolated
caches so this incompatibility is reported before a release run. Replace or
vendor the dependency, use a public source, or choose a publication path outside
v1; release-glz does not contain a private dependency resolver.

Some GitHub plans do not support required Environment reviewers for private
repositories. release-glz never weakens approval automatically. In solo mode,
an explicit `private_repository_fallback = "workflow-dispatch-digest"` permits
the separate `prepare` then `promote` flow. Promotion requires the Candidate digest,
prepare run ID, artifact ID, artifact digest, source SHA, and reason.
Strict mode cannot use that fallback. Run `release-glz doctor --online` before
the first rehearsal.
