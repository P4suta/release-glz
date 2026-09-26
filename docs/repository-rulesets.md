# Repository rulesets

The canonical repository protections are checked in as importable GitHub
rulesets:

- `.github/rulesets/main.json` protects the default branch.
- `.github/rulesets/release-tags.json` makes every `v*` release tag immutable
  after creation.

Import both files from **Settings → Rules → Rulesets → New ruleset → Import a
ruleset**. The imported rulesets are active immediately. After importing, fetch
`GET /repos/P4suta/release-glz/rulesets` and compare the returned rules and
conditions with the files above.

## Default branch policy

`Protect main` rejects deletion and force pushes, requires linear history, and
permits squash merges only through pull requests. The repository is
intentionally operable by its sole maintainer, so it requires no separate human
approval. Unresolved review threads still block merging. `Required CI` and
`CodeRabbit` are bound to their GitHub App IDs so a same-named status from
another source cannot satisfy the rule.

`Required CI` is the stable aggregate job for the complete supported
OS/compiler matrix and lints. Shipping assurance is intentionally not a normal
PR merge check: its coverage, fuzzing, dependency audit, and mutation jobs run
manually before a release and once after changes reach `main`. This avoids
restarting the expensive mutation matrix after every review fix.

There are no bypass actors. The owner follows the same PR, status-check,
linear-history, and thread-resolution rules as every contributor, but does not
need a second maintainer merely to provide an approval click.

Every commit on `main` must carry a signature.
GitHub signs the squash commit it writes when merging a pull request, so the pull request path — including Renovate updates — satisfies this without any extra step, and a commit pushed from a workstation carries that maintainer's own signature.
The rule records that guarantee rather than introducing it.
Release identity remains protected by the annotated-tag checklist and the immutable `v*` tag ruleset.

Note for maintainers: GitHub's own signatures are PGP. A workstation that
signs with SSH still needs `gpg` installed, and GitHub's `web-flow` public key
in its keyring, for `git verify-commit` to confirm them locally.

## Accepted solo-maintainer risk

While this remains a one-person project, the owner explicitly accepts that
merges have no independent human approval. Requiring one would make normal
operation impossible rather than add a usable control. The compensating
controls are a mandatory pull request, source-bound `Required CI` and
`CodeRabbit` checks, resolved review threads, squash-only linear history, and
immutable release tags. Revisit the approval count when a second maintainer
with write access is available.

## Release tag policy

`Protect release tags` allows the first creation of a matching tag, then rejects
deletion and non-fast-forward updates. GitHub rulesets do not distinguish
annotated from lightweight tag creation, so the annotated-tag check remains an
explicit item in the release-readiness checklist.
