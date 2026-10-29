# Repository rulesets

The repository protections are checked in as importable GitHub rulesets:

- `.github/rulesets/main.json` protects the default branch.
- `.github/rulesets/release-tags.json` makes every `v*` release tag immutable after creation.

Each file records the live ruleset of the same name.
Import a file from **Settings → Rules → Rulesets → New ruleset → Import a ruleset**, and the imported ruleset is active immediately.
After any change, fetch `GET /repos/P4suta/release-glz/rulesets` and compare each returned ruleset with its file.

## Default branch policy

The `main` ruleset rejects deletion and force pushes, requires linear history, and permits only squash merges through pull requests.
A new push dismisses earlier reviews, and unresolved review threads block merging.
The repository is operable by its sole maintainer, so it requires no separate human approval.

The `required` check is the one required status.
It is the CI job that aggregates every check that a pull request selects, and it is bound to the GitHub Actions app, so a same-named status from another source cannot satisfy it.
CI selects the Rust job for every change to a file that a Rust test reads, and the `required` job fails when a selected check fails or is skipped without cause.
Shipping assurance is not a pull request check.
Its compatibility matrix, coverage, fuzzing, dependency audit, and mutation jobs run before a release and on a manual dispatch.

There are no bypass actors.
The owner follows the same pull request, status-check, linear-history, and thread-resolution rules as every contributor, but does not need a second maintainer merely to provide an approval click.

Every commit on `main` must carry a signature.
GitHub signs the squash commit it writes when merging a pull request, so the pull request path, including Renovate updates, satisfies this without an extra step.
A commit pushed from a workstation carries that maintainer's own signature.
The rule records that guarantee rather than introducing it.
Release identity remains protected by the annotated-tag checklist and the immutable `v*` tag ruleset.

GitHub's own signatures are PGP.
A workstation that signs with SSH still needs `gpg` installed, and GitHub's `web-flow` public key in its keyring, for `git verify-commit` to confirm them locally.

## Accepted solo-maintainer risk

While this remains a one-person project, the owner explicitly accepts that merges have no independent human approval.
Requiring one would make normal operation impossible rather than add a usable control.
The compensating controls are a mandatory pull request, the source-bound `required` check, resolved review threads, squash-only linear history, and immutable release tags.
Revisit the approval count when a second maintainer with write access is available.

## Release tag policy

The `release tags` ruleset allows the first creation of a matching tag, then rejects deletion, updates, and non-fast-forward moves.
GitHub rulesets do not distinguish annotated from lightweight tag creation, so the annotated-tag check remains an explicit item in the release-readiness checklist.
