# Public Hex.pm quickstart

This path publishes one public package to Hex.pm and HexDocs.

## Configure the package

Preview and generate the complete configuration and managed workflow. The CLI
detects the exact installed Gleam compiler and git default branch:

```console
release-glz init --profile public --diff
release-glz init --profile public --update
release-glz doctor
release-glz doctor --online
release-glz doctor --candidate-build
```

The generated registry section is:

```toml
[tools.release-glz.registry]
provider = "hexpm"
api_url = "https://hex.pm/api"
repository_url = "https://repo.hex.pm"
docs_url = "https://repo.hex.pm/docs"
credential_env = "HEXPM_API_KEY"
auth = "hex-token"

```

Packages already on schema 2 omit `--profile` when refreshing the workflow.
For a deliberate 0.x package add `--allow-version-zero` to both init commands.
Commit the manifest and generated workflow.

## Configure GitHub

Create the `release` Environment, restrict it to the protected default branch,
and add an approval rule. Store a Hex API key with write permission as the
Environment secret `HEXPM_API_KEY`; do not put it in repository variables or
the Candidate job.

For strict separation set `separation = "strict"`, enable prevent-self-review,
and require a reviewer other than the release author. Run `doctor --online` again to
verify the effective server-side policy and registry permission.

## Operate

Push ordinary changes. release-glz updates one managed Release PR. Review its
version, API changes, changelog, and `intent_digest`, merge it, then approve the
Environment deployment for the sealed `candidate_digest`. Use
`release-glz status --candidate <DIR> --online` when recovering a stopped run.
