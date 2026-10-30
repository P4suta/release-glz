# Assurance

This map ties each release and security property of release-glz to the proofs, models, and tests that check it.
`cargo xtask trace` and a test in the fast gate refuse a citation that names nothing and a property without evidence.
They also refuse a Kani harness, Lean theorem, Quint invariant or model test, or fuzz target that no property cites.

## What each verifier shows

- Kani proves a harness for every input that its assumptions admit, up to the bounds the property names.
  `cargo xtask proofs` admits a harness only from an audited report, together with a negative control that has to fail on its expected assertion.
- Lean proves a theorem about a model for inputs of every size.
  Generated vectors tie the model to the core crate on small inputs, and the audit refuses any axiom outside Lean's standard three.
- Quint's explicit-state model checker visits every state of the release protocol model for releases of up to three objects and two runs.
  Its traces replay through the production run machine on every pull request.
- A fuzz target runs a parser on generated input and replays its committed corpus in the fast gate.
- A test checks the behavior it names on the inputs it builds, and it proves nothing beyond them.

## Trust

- The proofs trust Kani and its model checker, Lean's kernel, and Quint's translation to the model checker.
- The protocol model trusts the registry and GitHub to refuse to replace an object that exists, and it trusts GitHub to sign the identity that approval reads.
- No proof covers the network adapters, the compiler, or the operating system, so their tests and the boundary checks carry those properties.

## Properties

### A release never replaces a published object

The release creates an object only when the world lacks it or holds it pending, and an object that exists outside the Candidate's description stops the release.
Kani proves the decision for every object and for lists of up to three objects, and Lean proves the list properties for every length.

- Kani: `publication::proofs::an_effect_concerns_only_an_object_the_world_lacks`
- Kani: `publication::proofs::an_object_that_differs_ends_in_a_conflict`
- Kani: `publication::proofs::a_conflict_anywhere_stops_the_release`
- Lean: `ReleaseGlz.create_means_missing`
- Lean: `ReleaseGlz.conflict_iff_differs`
- Lean: `ReleaseGlz.effect_concerns_missing_object`
- Lean: `ReleaseGlz.differing_object_conflicts`
- Lean: `ReleaseGlz.Refinement.decision_refines_rust`
- Lean: `ReleaseGlz.Refinement.reconcile_refines_rust`
- Quint: `aRaceStopsTheReleaseTest`
- Test: `tests/release_executor.rs::crash_after_docs_resumes_without_republishing_candidate_bytes`
- Test: `tests/release_executor.rs::an_invalid_candidate_and_an_existing_checksum_conflict_keep_their_exact_states`
- Test: `tests/registry_contract.rs::ambiguous_publish_is_reported_without_reposting`

### A release publishes nothing without verified approval

An approval has to bind the Candidate digest, the intent digest, and a run identity that GitHub signed, and a push never rests on the inputs of a manual release.

- Kani: `publication::proofs::no_effect_leaves_without_approval`
- Kani: `approval::proofs::an_approval_needs_every_conjunct_of_its_path`
- Kani: `approval::proofs::a_push_approval_never_rests_on_manual_inputs`
- Lean: `ReleaseGlz.no_effect_without_approval`
- Quint: `approvalFirst`
- Quint: `anUnapprovedRunAppliesNothingTest`
- Test: `tests/release_executor.rs::a_run_without_verified_approval_applies_nothing`
- Test: `tests/approval_evidence.rs::a_push_without_a_merged_release_pr_has_no_approval`
- Test: `tests/approval_evidence.rs::a_job_value_that_disagrees_with_the_merged_release_pr_never_approves_a_push`
- Test: `tests/oidc_authorization.rs::every_security_boundary_is_fail_closed`
- Test: `tests/oidc_authorization.rs::signed_compact_token_is_verified_before_github_claims_are_returned`

### A release publishes in order

The tag, the draft Release, the package, the documentation, the assets, the final Release, and the notifications follow publication order.
A run applies an effect only when no earlier object still needs one, apart from optional effects it already attempted, so a Release becomes final only after its assets exist.

- Kani: `run::proofs::a_run_applies_only_owed_effects_in_publication_order`
- Kani: `run::proofs::every_step_keeps_the_record_that_bounds_a_run`
- Quint: `ordered`
- Quint: `publishesInOrderTest`
- Quint: `skipsAheadTest`
- Test: `tests/run_replay.rs::every_committed_trace_replays_through_the_run_machine`

### A release counts as released exactly when no blocking effect remains

An optional notification that fails leaves the release released, and a required one leaves it in `partially_released`.

- Kani: `publication::proofs::the_release_is_released_once_no_blocking_effect_remains`
- Kani: `run::proofs::a_run_stops_only_when_nothing_but_attempted_optional_effects_remains`
- Lean: `ReleaseGlz.released_iff_no_blocking_effect`
- Quint: `releasedHoldsTheCandidate`
- Quint: `aFailedOptionalEffectIsPassedOverTest`
- Test: `tests/release_executor.rs::optional_notify_is_attempted_once_but_failure_does_not_make_release_partial`

### Every run stops, and a run whose effects land ends released

The first plan that lists an effect fixes how many attempts a run may make, and publishing an effect removes exactly that effect from the plan.

- Kani: `publication::proofs::publishing_an_effect_removes_exactly_that_effect`
- Kani: `run::proofs::a_run_attempts_each_optional_effect_once_within_its_first_plan`
- Kani: `run::proofs::a_run_whose_effects_land_ends_released`
- Lean: `ReleaseGlz.effects_within_objects`
- Lean: `ReleaseGlz.publishing_removes_exactly_that_effect`
- Lean: `ReleaseGlz.publishing_shortens_the_plan`
- Quint: `aWorldThatNeverShowsTheEffectDivergesTest`
- Quint: `aSecondRunResumesTheReleaseTest`
- Test: `tests/release_executor.rs::a_target_that_never_records_success_stops_after_the_effects_of_its_first_plan`
- Test: `tests/release_executor.rs::a_release_with_more_notify_hooks_than_any_fixed_round_limit_completes`

### A failed call counts as published only once the world holds it

A failed blocking effect that the world still lacks stops the run, and an observation that fails after it reports the state that the run can vouch for.

- Kani: `run::proofs::a_failed_effect_counts_only_once_the_world_holds_it`
- Kani: `run::proofs::a_run_stops_when_the_number_of_objects_changes`
- Quint: `aLandedFailureCountsTest`
- Quint: `anUnshownCommitStopsTheRunTest`
- Quint: `aFailedObservationAfterAFailedCallKeepsThePlanTest`
- Quint: `aFailedFirstObservationBlocksTest`
- Test: `tests/release_executor.rs::unknown_publish_response_is_reobserved_before_any_retry`
- Test: `tests/release_executor.rs::an_observation_failure_after_an_ambiguous_effect_preserves_the_pre_effect_state`
- Test: `tests/release_executor.rs::a_required_notification_failure_is_partial_and_is_never_rolled_back`
- Test: `tests/run_replay.rs::a_trace_that_decides_otherwise_fails_the_replay`

### Release states move forward, and a terminal state never changes

- Kani: `lifecycle::proofs::every_state_may_repeat`
- Kani: `lifecycle::proofs::a_terminal_state_never_changes`
- Kani: `lifecycle::proofs::normal_states_form_one_forward_chain`
- Kani: `lifecycle::proofs::advancing_is_transitive`
- Kani: `lifecycle::proofs::an_unfinished_release_can_always_end_in_conflict_or_blocked`
- Test: `tests/v1_domain.rs::release_state_is_monotonic_except_terminal_diagnostics`
- Test: `tests/v1_domain.rs::release_state_property_covers_every_pair_in_the_monotonic_lattice`

### Version arithmetic never wraps, and the larger bump wins

- Kani: `version::proofs::the_join_of_two_bumps_is_the_larger_one`
- Kani: `version::proofs::an_increment_adds_one_or_reports_the_largest_value`
- Kani: `version::proofs::a_bump_raises_the_core_or_reports_an_overflow`
- Test: `tests/v1_domain.rs::zero_major_breaking_changes_require_a_minor_release`
- Test: `tests/v1_domain.rs::prerelease_channels_only_move_forward_on_the_same_core`

### A Candidate publishes exactly the bytes it sealed

- Test: `tests/v1_candidate.rs::candidate_seals_and_verifies_the_exact_publish_bytes`
- Test: `tests/v1_candidate.rs::candidate_verification_detects_any_raw_artifact_change`
- Test: `tests/v1_candidate.rs::candidate_verification_rejects_every_manifest_identity_and_digest_tamper`
- Test: `tests/registry_contract.rs::organization_registry_uses_repos_prefix_and_publishes_exact_bytes`

### Unpacking an archive writes only portable relative paths

- Fuzz: `archive`
- Test: `tests/artifact_security.rs::archive_paths_reject_every_ambiguous_or_traversing_form`
- Test: `tests/artifact_security.rs::archive_paths_reject_entries_that_collide_once_letter_case_no_longer_counts`
- Test: `tests/artifact_security.rs::unpacking_uses_only_validated_relative_regular_files`

### Parsers refuse malformed input without panicking

- Fuzz: `api_interface`
- Fuzz: `config`
- Fuzz: `identifiers`
- Fuzz: `pr_marker`
- Test: `tests/fuzz_corpus.rs::every_fuzz_target_runs_shared_invariants_that_this_suite_replays`

### No job that compiles dependencies holds a write token

Dependency builds may run code, so the jobs that compile hold read permissions only, and hooks receive only the environment they declare.

- Test: `tests/workflow_permissions.rs::no_job_that_compiles_holds_a_write_permission`
- Test: `tests/workflow_permissions.rs::the_check_finds_a_write_job_that_would_compile`
- Test: `tests/hooks_contract.rs::undeclared_environment_is_not_forwarded`

### Proof evidence counts only from an audited run

The proof gate admits a run only when every listed harness verified and no other ran, and a negative control only when it failed exactly its expected assertion.

- Kani: `proofs::a_proof_run_is_admitted_only_when_every_expected_harness_verified`
- Kani: `proofs::a_control_run_is_admitted_only_when_exactly_its_assertion_failed`
- Test: `xtask/src/proof_report.rs::the_recorded_runs_are_admitted`
- Test: `xtask/src/proof_report.rs::a_negative_control_must_fail_only_its_expected_assertion`
- Test: `xtask/src/inventory.rs::every_harness_has_its_own_negative_control`

### The harnesses detect every viable mutant of the core decisions

`cargo xtask proof-mutants` runs each mutant of the core crates through the harnesses on an owner machine, and the release gate checks that its committed receipt covers the current core sources.
A survivor needs an entry with a reason in `verification/equivalent-mutants.json`.

- Test: `xtask/src/proof_mutants.rs::an_outcome_comes_from_the_report_and_never_from_the_exit_alone`
- Test: `xtask/src/proof_mutants.rs::the_campaign_leaves_out_harnesses_and_negative_controls`
- Test: `xtask/src/proof_mutants.rs::the_gate_refuses_a_stale_or_unexplained_receipt`
