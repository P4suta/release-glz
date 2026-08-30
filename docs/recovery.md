# Partial release recovery

Never regenerate an approved release. Keep and use the same Candidate artifact
and its `candidate_digest` for every retry.

Start with:

```console
release-glz verify --candidate .release-glz/candidate
release-glz status --candidate .release-glz/candidate --online
release-glz release --candidate .release-glz/candidate --dry-run
```

The online observer compares all existing objects by checksum, target SHA, and
Candidate digest. A match is a completed no-op; a mismatch is a hard immutable
conflict. Resolve credentials or availability and rerun the non-dry release
only when the reported effects are expected.

| Stage | Safe recovery |
|---|---|
| `verify_hooks` | Fix the hook environment or policy; verify the unchanged snapshot and sealed definitions again. |
| `prepare_git_tag` | An absent tag can be prepared; an existing tag must be annotated and point to the Candidate source SHA. |
| `prepare_github_draft` | Resume the matching draft; never replace a release carrying another Candidate digest. |
| `publish_package` | If the response timed out, poll the registry for the exact outer checksum and never re-POST merely because the response was ambiguous. |
| `publish_docs` | Publish only when absent; existing docs must match the sealed docs checksum. |
| `finalize_github_release` | Upload only missing matching sidecars, verify them, then finalize the existing draft without clobbering assets. |
| `notify_hooks` | Re-observe with the Candidate-derived idempotency key, then apply only incomplete notifications. |

A failure after any public effect is `partially_released` and exits with code 7;
it is not rolled back. A conflicting package, docs object, tag, release, or
asset exits with code 4 and requires human investigation. A temporary remote
failure exits with code 5. Required hook failures use code 6.

If the Actions artifact expired, do not rebuild and pretend it is the same
approval. Re-run the approval path to create and approve a new Candidate, or
restore the exact archived Candidate bytes through an explicitly controlled
incident procedure.
