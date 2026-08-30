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

`Protect main` rejects deletion and force pushes, requires signed linear
history, and permits squash merges only through pull requests. The repository
requires one independent approval, dismisses that approval after a new push,
and blocks unresolved review threads. `Required CI` and `CodeRabbit` are bound
to their GitHub App IDs so a same-named status from another source cannot
satisfy the rule.

`Required CI` is the stable aggregate job for the complete supported
OS/compiler matrix and lints. Shipping assurance is intentionally not a normal
PR merge check: its coverage, fuzzing, dependency audit, and mutation jobs run
manually before a release and once after changes reach `main`. This avoids
restarting the expensive mutation matrix after every review fix.

The repository owner is the only bypass actor, and the bypass mode is limited
to pull requests. This keeps the solo-maintainer recovery path in the PR audit
trail without allowing direct pushes to `main`. Use the bypass only when no
independent maintainer is available, and record the reason in the PR.

## Release tag policy

`Protect release tags` allows the first creation of a matching tag, then rejects
deletion and non-fast-forward updates. GitHub rulesets do not distinguish
annotated from lightweight tag creation, so the annotated-tag check remains an
explicit item in the release-readiness checklist.
