# Hex.pm Organization quickstart

A Hex.pm Organization uses the normal Hex API but reads and publishes package
artifacts through `/repos/ORG`. Replace `acme` with the exact Organization
repository name and generate all three explicit endpoints:

```console
release-glz init --profile organization --organization acme --diff
release-glz init --profile organization --organization acme --update
release-glz doctor --online
release-glz doctor --candidate-build
```

The generated registry section is:

```toml
[tools.release-glz.registry]
provider = "hexpm"
repository = "acme"
api_url = "https://hex.pm/api"
repository_url = "https://repo.hex.pm/repos/acme"
docs_url = "https://repo.hex.pm/repos/acme/docs"
credential_env = "HEXPM_API_KEY"
auth = "hex-token"
```

The token must have API write permission and read access to the configured
Organization repository. release-glz sends it on private reads as well as the
publish request, but only to the configured origin. `release-glz doctor`
distinguishes an invalid token, missing API write permission, and missing
repository read permission.

Configure the protected `release` Environment and store `HEXPM_API_KEY` there
with publish and Organization-read permission. GitHub applies it only to the publish job.
Planning, Candidate preparation, and pull-request authorization
receive no credential.
Candidate artifacts are private Actions artifacts; GitHub Release uploads are
limited by the Candidate's evidence policy.
