# Hex.pm Organization quickstart

A Hex.pm Organization uses the normal Hex API but reads and publishes package
artifacts through `/repos/ORG`. Replace `acme` with the exact Organization
repository name:

```toml
[tools.release-glz]
schema = 2
compiler = "1.18.1"

[tools.release-glz.registry]
provider = "hexpm"
repository = "acme"
api_url = "https://hex.pm/api"
repository_url = "https://repo.hex.pm/repos/acme"
docs_url = "https://repo.hex.pm/repos/acme/docs"
credential_env = "HEXPM_API_KEY"
auth = "hex-token"

[tools.release-glz.approval]
normal = "release-pr-and-environment"
manual = "environment"
environment = "release"
separation = "solo"
manual_refs = ["refs/heads/main"]
```

The token must have API write permission and read access to the configured
Organization repository. release-glz sends it on private reads as well as the
publish request, but only to the configured origin. `release-glz doctor`
distinguishes an invalid token, missing API write permission, and missing
repository read permission.

Generate the workflow with `release-glz init --update` and configure the
protected `release` Environment. Store a repository-level read-only
`HEXPM_API_KEY` for trusted push planning, and an Environment secret of the same
name with publish permission. GitHub applies the Environment value only to the
publish job. Neither credential enters the Candidate or pull-request job.
Candidate artifacts are private Actions artifacts; GitHub Release uploads are
limited by the Candidate's evidence policy.
