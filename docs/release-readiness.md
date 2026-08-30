# v1 release readiness

This is the final, fail-closed checklist for publishing the first immutable
release-glz version. Complete it from a clean protected branch. Do not create a
GitHub Release, move a tag, or publish any package while an item is unresolved.

## 0. Confirm repository protections

- Confirm the active repository rulesets match
  [the checked-in ruleset contract](repository-rulesets.md).
- Confirm `Protect main` requires the `Required CI` and `CodeRabbit` checks,
  thread resolution, and no separate approval or bypass actor.
- Confirm `Protect release tags` covers `refs/tags/v*` before creating the first
  release tag.

## 1. Prepare reproducible archives

- Run **Distribute binaries** manually with the exact stable `vX.Y.Z` in its
  `version` input. This invokes the checksum-preparation path only.
- Confirm all six matrix builds succeeded: Linux musl x86_64/aarch64, macOS
  x86_64/arm64, and Windows x86_64/arm64.
- Download the checksum preparation artifact by the run ID and artifact ID
  shown in the workflow summary. Verify its server-reported artifact digest.
- Confirm `action/checksums.json` contains exactly the six expected archive
  names, six distinct real SHA-256 values where appropriate, and no all-zero
  placeholder.
- Replace only `action/checksums.json`. The distribution workflow deliberately
  rejects a tag commit whose parent diff contains any other file. Because the
  binary no longer embeds its Action commit, this checksum-only commit cannot
  change the compiled program; the tag run must nevertheless reproduce all six
  prepared archive checksums byte-for-byte.

## 2. Review and tag

- Re-run formatting, Clippy with warnings denied, Rustdoc with warnings denied,
  all Rust and Node tests, actionlint, zizmor, dependency policy/audit, line and
  branch coverage, critical mutation shards, and every fuzz smoke target.
- Confirm `Cargo.toml`, `action/package.json`, the requested version, and the
  checksum manifest all name the same stable version.
- Confirm every external Action reference is a full reviewed commit SHA.
- Create an **annotated** `vX.Y.Z` tag on the checksum-only commit. Never use a
  lightweight tag and never move or recreate the tag.

## 3. Verify release evidence before finalization

- The tag workflow must regenerate and compare all six archive checksums with
  `action/checksums.json` before any Release mutation.
- Require a CycloneDX `release-glz.cdx.json`,
  `THIRD_PARTY_LICENSES.json`, `SHA256SUMS`, and one in-toto provenance JSONL
  statement per archive.
- Require GitHub artifact attestations for every archive and the SBOM
  attestation. Verify each downloaded archive with `gh attestation verify`
  against `P4suta/release-glz`.
- Keep the GitHub Release in draft state while assets are uploaded. Existing
  assets must have the exact server SHA-256 digest; never clobber or replace an
  asset.
- Re-download every asset from the draft, run `sha256sum --check SHA256SUMS`,
  re-verify all attestations and provenance subjects, and confirm the inventory
  contains no extra or missing file.
- Finalize the draft only after every check above succeeds. Then test one clean
  installation for each documented operating-system family and run
  `release-glz --version`.

The checksum manifest intentionally remains fail-closed until the external
preparation run is complete. Producing the real six-platform archives and the
single checksum-only commit are the only expected external steps before v1.
