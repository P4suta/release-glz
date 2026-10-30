# Partial release recovery

Never regenerate an approved release.
Keep and use the same Candidate artifact and its `candidate_digest` for every retry.

Start with:

```console
release-glz verify --candidate .release-glz/candidate
release-glz status --candidate .release-glz/candidate --online
release-glz release --candidate .release-glz/candidate --dry-run
```

The online observer compares all existing objects by checksum, target SHA, and Candidate digest.
A match is a completed no-op, and a mismatch is a hard immutable conflict.
Resolve credentials or availability, then rerun the non-dry release only when you expect the effects that the dry run reports.

| Stage | Safe recovery |
|---|---|
| `verify_hooks` | Fix the hook environment or policy; verify the unchanged snapshot and sealed definitions again. |
| `prepare_git_tag` | An absent tag can be prepared; an existing tag must be annotated and point to the Candidate source SHA. |
| `prepare_github_draft` | Resume the matching draft; never replace a release carrying another Candidate digest. |
| `publish_package` | If the response timed out, poll the registry for the exact outer checksum and never re-POST merely because the response was ambiguous. |
| `publish_docs` | Publish only when absent; existing docs must match the sealed docs checksum. |
| `finalize_github_release` | Upload only missing matching sidecars, verify them, then finalize the existing draft without clobbering assets. |
| `notify_hooks` | Re-observe with the Candidate-derived idempotency key, then apply only incomplete notifications. |

A run knows that the release has started once an observation showed a published object or one of its own effects landed.
From then on, every failure it reports is `partially_released` and exits with code 7.
That includes a failed observation, a required notification hook that fails after the GitHub Release is final, and a run that stops without converging.
The run rolls nothing back.
A conflicting package, docs object, tag, release, or asset exits with code 4 and requires human investigation.
Before the release has started, a temporary remote failure exits with code 5, and a verify hook failure exits with code 6.
A run whose first observation fails reports `blocked`, since it can't tell whether an earlier run published anything.

If the Actions artifact expired, don't rebuild it and treat the rebuild as the same approval.
Re-run the approval path to create and approve a new Candidate, or restore the exact archived Candidate bytes through an explicitly controlled incident procedure.

## Unfinished release assets

An upload that breaks off can leave an asset that GitHub reports in a state other than `uploaded`, such as `starter`.
GitHub keeps that asset's name, so no upload can use the name until someone deletes the asset.
When the Candidate seals the asset and the Candidate's own draft holds it, the next `release` run completes it.
That run reads the Release again, deletes the unfinished asset, and uploads the sealed bytes under the same name.
It deletes the asset only while that read still shows the Candidate's draft with the asset unfinished.
It never deletes an asset that GitHub reports as uploaded, and it never changes a published Release.

On the Candidate's own Release, two cases stop the release as a conflict with code 4 until a person acts:

- An unfinished asset that the Candidate doesn't seal: delete it from the Release on GitHub, then run `release` again.
- An unfinished asset on the published Release: delete it on GitHub, upload `sidecars/<hook>/<name>` from the Candidate directory under the same name, and run `release` again.

## Asset names that GitHub keeps

GitHub renames an asset whose name has special characters or a leading or trailing `.`, so the upload would fail after Hex holds the package.
`rehearse` and `verify` refuse such a name before anything publishes.
An asset name may use only ASCII letters, digits, `.`, `-`, and `_`, and it can't start or end with `.`.
Change the name that the sidecar hook returns, then rehearse a new Candidate.
The built-in SBOM and provenance names hold the version, and build metadata puts a `+` in it.
To release a version with build metadata, set `sbom` and `provenance` to `false` under `[tools.release-glz.outputs]`.
