# Public Hex.pm quickstart

This path publishes one public package to Hex.pm and HexDocs.

## Configure the package

Add the following to `gleam.toml`, choosing the exact Gleam compiler used by
your project:

```toml
[repository]
type = "github"
user = "acme"
repo = "widget"

[tools.release-glz]
schema = 2
compiler = "1.18.1"
release_branch_prefix = "release-glz/"
allow_version_zero = true

[tools.release-glz.registry]
provider = "hexpm"
api_url = "https://hex.pm/api"
repository_url = "https://repo.hex.pm"
docs_url = "https://repo.hex.pm/docs"
credential_env = "HEXPM_API_KEY"
auth = "hex-token"

[tools.release-glz.approval]
normal = "release-pr-and-environment"
manual = "environment"
environment = "release"
separation = "solo"
manual_refs = ["refs/heads/main"]
```

Run `release-glz doctor`, review `release-glz init --diff`, then apply
`release-glz init --update`. Commit the manifest and generated workflow.

## Configure GitHub

Create the `release` Environment, restrict it to the protected default branch,
and add an approval rule. Store a Hex API key with write permission as the
Environment secret `HEXPM_API_KEY`; do not put it in repository variables or
the Candidate job.

For strict separation set `separation = "strict"`, enable prevent-self-review,
and require a reviewer other than the release author. Run `doctor` again to
verify the effective server-side policy and registry permission.

## Operate

Push ordinary changes. release-glz updates one managed Release PR. Review its
version, API changes, changelog, and `intent_digest`, merge it, then approve the
Environment deployment for the sealed `candidate_digest`. Use
`release-glz status --candidate <DIR> --online` when recovering a stopped run.
