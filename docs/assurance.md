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
The live observation looks for docs even when the Candidate has none, so docs that contradict the Candidate stop the release too.
It records each notification under the key that the Candidate derives, so a notification with another key reaches the reconciler only from another `ReleaseTarget`.

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
- Test: `tests/live_release_contract.rs::docs_for_a_candidate_without_docs_stop_the_release_in_a_conflict`

### A release publishes nothing without verified approval

An approval has to bind the Candidate digest, the intent digest, and a run identity that GitHub signed, and a push never rests on the inputs of a manual release.
Kani proves the approval decision for every combination of its conjuncts and the publication decision for lists of up to three objects, and Lean proves it for every length.
The Quint model covers three objects and two runs.

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

### Approval trusts only a token that's valid now and that GitHub's own hosts serve

A token counts only before it expires, and only while neither its issue time nor the start of its validity lies more than thirty seconds ahead.
That check can't overflow at any time.
A run ID is one or more ASCII digits, and a run attempt is a positive decimal number in ASCII digits, so `+3` isn't attempt 3.
The verifier reads the discovery document and the key set only from `token.actions.githubusercontent.com` over HTTPS.
It requests a runner token only from `actions.githubusercontent.com` or a host inside it.
Kani proves the window for every pair of times, and the run numbers for texts of up to three bytes and the two 20-digit texts around 2^64.
It proves the hosts for every host whose length reaches a boundary of the rule, because the rule reads only the last 30 bytes of a longer host.
The adapter parses each URL, decides whether a host is a loopback address, and verifies the token's signature before the core decides.

- Kani: `oidc::proofs::a_token_is_valid_exactly_while_its_window_holds_now`
- Kani: `oidc::proofs::run_numbers_are_exactly_decimal_digits`
- Kani: `oidc::proofs::an_oidc_url_trusts_no_host_but_githubs_own`
- Test: `tests/oidc_authorization.rs::every_security_boundary_is_fail_closed`
- Test: `tests/oidc_authorization.rs::claim_values_that_match_textually_still_require_canonical_safe_shapes`
- Test: `src/authorization.rs::oidc_urls_are_origin_pinned_and_test_http_is_numeric_loopback_only`

### A publish job consumes only the Candidate that its trigger permits

A push consumes only the Candidate of its own run while that run is in progress.
A manual promotion consumes only the Candidate of another run that completed with success.
Kani proves it for every event name of up to 18 bytes, status of up to 12 bytes, and conclusion of up to 8 bytes.

- Kani: `candidate_choice::proofs::a_push_consumes_only_its_own_run_and_a_promotion_only_another_successful_one`
- Test: `tests/github_release_contract.rs::a_push_publishes_only_its_own_candidate_and_a_promotion_only_an_earlier_one`
- Test: `tests/github_release_contract.rs::a_candidate_from_the_current_run_requires_that_run_to_be_in_progress`
- Test: `tests/github_release_contract.rs::actions_artifact_run_requires_the_managed_successful_repository_source`

### Every request and every wait for a release ends within a stated time

A request to the registry or to GitHub waits only when another attempt follows.
A busy response never makes it wait longer than a minute for the registry or thirty seconds for GitHub.
In all, a registry request waits at most two minutes between its attempts, and a GitHub read at most one minute.
A wait for a published release sleeps only between two polls, and it ends at the first poll that lists the version with the docs it needs.
A `Retry-After` header names a wait only in digits, so a sign or a date leaves the policy's default wait, and both clients use exactly the shipped policies.
Kani proves each wait for every policy, attempt, and answer, and it pins the wait after a transport failure for the first nine attempts.
It proves the whole wait of the two shipped policies for every sequence of answers.
It proves the reading of `Retry-After` for every text of up to three bytes and for the 20-digit texts on both sides of 2^64.
The time that each attempt itself takes falls under the client's request timeouts, which no proof covers.

- Kani: `wait::proofs::a_request_waits_only_before_another_attempt_and_only_as_long_as_its_answer_allows`
- Kani: `wait::proofs::the_shipped_policies_bound_the_whole_wait_of_a_request`
- Kani: `wait::proofs::a_wait_sleeps_only_before_another_poll_and_ends_at_the_first_visible_one`
- Kani: `wait::proofs::a_retry_after_header_names_a_delay_only_in_digits`
- Test: `src/forge.rs::a_busy_read_waits_only_as_long_as_digits_ask`
- Test: `src/registry.rs::retry_after_and_checksums_validate_all_boundaries`
- Test: `tests/registry_contract.rs::get_and_credential_audit_retries_are_bounded_and_never_change_method`
- Test: `tests/registry_contract.rs::transport_failures_and_redirect_loops_exhaust_a_fixed_read_budget`
- Test: `tests/registry_contract.rs::wait_for_reports_its_timeout_without_sleeping_after_the_last_poll`
- Test: `tests/registry_contract.rs::wait_for_stops_after_its_attempts`
- Test: `tests/github_release_contract.rs::github_get_retries_retry_after_without_reposting_and_bounds_json_bodies`
- Test: `tests/github_release_contract.rs::github_get_retries_a_transport_failure_without_reposting`
- Test: `src/registry.rs::retry_after_and_checksums_validate_all_boundaries`

### A release publishes in order

The tag, the draft Release, the package, the documentation, the assets, the final Release, and the notifications follow publication order.
A run applies an effect only when no earlier object still needs one, apart from optional effects it already attempted, so a Release becomes final only after its assets exist.
The run harness covers releases of at most three objects over four observations, and the Quint model covers three objects and two runs.
The step harness covers one step from any record of at most five objects.
The order thus holds at every step of a run of any length over at most five objects.
A default release has seven objects, which no proof of this property covers, so for it the order rests on the tests.

- Kani: `run::proofs::a_run_applies_only_owed_effects_in_publication_order`
- Kani: `run::proofs::every_step_keeps_the_record_that_bounds_a_run`
- Quint: `ordered`
- Quint: `publishesInOrderTest`
- Quint: `skipsAheadTest`
- Test: `tests/run_replay.rs::every_committed_trace_replays_through_the_run_machine`

### A release counts as released exactly when no blocking effect remains

An optional notification that fails leaves the release released, and a required one leaves it in `partially_released`.
Kani proves it for lists and runs of at most three objects, and Lean proves the plan's rule for every length.

- Kani: `publication::proofs::the_release_is_released_once_no_blocking_effect_remains`
- Kani: `run::proofs::a_run_stops_only_when_nothing_but_attempted_optional_effects_remains`
- Lean: `ReleaseGlz.released_iff_no_blocking_effect`
- Quint: `releasedHoldsTheCandidate`
- Quint: `aFailedOptionalEffectIsPassedOverTest`
- Test: `tests/release_executor.rs::optional_notify_is_attempted_once_but_failure_does_not_make_release_partial`

### Every run stops, and a run whose effects land ends released

The first plan that lists an effect fixes how many attempts a run may make, and publishing an effect removes exactly that effect from the plan.
The run harnesses cover releases of at most three objects over four observations.
The step harness carries the attempt bound to runs of any length over at most five objects.
Lean proves the plan's rules for every length.

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
The run harnesses cover releases of at most three objects over four observations, and the Quint model covers three objects and two runs.

- Kani: `run::proofs::a_failed_effect_counts_only_once_the_world_holds_it`
- Kani: `run::proofs::a_run_stops_when_the_number_of_objects_changes`
- Quint: `aLandedFailureCountsTest`
- Quint: `aFailedCallThatNeverLandedStopsTheRunTest`
- Quint: `anUnshownCommitStopsTheRunTest`
- Quint: `aFailedObservationAfterAFailedCallKeepsThePlanTest`
- Quint: `aFailedFirstObservationBlocksTest`
- Test: `tests/release_executor.rs::unknown_publish_response_is_reobserved_before_any_retry`
- Test: `tests/release_executor.rs::an_observation_failure_after_an_ambiguous_effect_preserves_the_pre_effect_state`
- Test: `tests/release_executor.rs::a_required_notification_failure_is_partial_and_is_never_rolled_back`
- Test: `tests/run_replay.rs::a_trace_that_decides_otherwise_fails_the_replay`

### A run that knows the release started never reports less than a partial release

Once a run knows the release started, because an observation showed a published object or one of its effects landed, every state it reports is `partially_released` or `released`.
A later observation that lags behind can't lower the report.
That holds when the run stops, when an effect fails, when an observation fails, and when the run stops without converging, and `partially_released` exits with code 7.
A conflict keeps its own state.
The run harnesses cover releases of at most three objects and four observations, and the Quint model covers three objects and two runs.

- Kani: `run::proofs::a_run_never_reports_less_than_partially_released_once_the_release_started`
- Quint: `floored`
- Quint: `aFailedObservationAfterALandedCallIsPartialTest`
- Quint: `forgetsWhatItPublishedTest`
- Test: `tests/release_executor.rs::an_observation_failure_after_a_published_package_is_a_partial_release`
- Test: `tests/release_executor.rs::a_failed_notification_observation_after_finalization_is_a_partial_release`
- Test: `tests/release_executor.rs::a_target_that_never_records_success_stops_after_the_effects_of_its_first_plan`
- Test: `tests/run_replay.rs::every_committed_trace_replays_through_the_run_machine`

### Release states move forward, and a terminal state never changes

Within one approved run, every state that the run reports may follow the state of its first plan in the release lifecycle.
The proof assumes a world that never loses an object it showed and never shows one that differs from the Candidate.
A world that replaces an object, or shows one that differs, can end the run in `conflict` after any plan, which the conflict property covers.
Kani proves the lifecycle's rules for every pair of states, and it proves the run's reports for releases of at most three objects over four observations.
A new run starts from a fresh observation, so `blocked` ends a run but not a release, and a later run can still end `released`.

- Kani: `run::proofs::a_run_reports_states_in_lifecycle_order`
- Kani: `lifecycle::proofs::every_state_may_repeat`
- Kani: `lifecycle::proofs::a_terminal_state_never_changes`
- Kani: `lifecycle::proofs::normal_states_form_one_forward_chain`
- Kani: `lifecycle::proofs::advancing_is_transitive`
- Kani: `lifecycle::proofs::an_unfinished_release_can_always_end_in_conflict_or_blocked`
- Test: `tests/v1_domain.rs::release_state_is_monotonic_except_terminal_diagnostics`
- Test: `tests/v1_domain.rs::release_state_property_covers_every_pair_in_the_monotonic_lattice`

### Version arithmetic never wraps, and the larger bump wins

An increment adds exactly one or reports the largest value, and a bump raises the component it names, resets the smaller ones, or reports an overflow.
Kani proves these rules for every bump and every version core, with each component any `u64`.

- Kani: `version::proofs::the_join_of_two_bumps_is_the_larger_one`
- Kani: `version::proofs::an_increment_adds_one_or_reports_the_largest_value`
- Kani: `version::proofs::a_bump_raises_the_core_or_reports_an_overflow`
- Test: `tests/v1_domain.rs::zero_major_breaking_changes_require_a_minor_release`
- Test: `tests/v1_domain.rs::prerelease_channels_only_move_forward_on_the_same_core`

### A selected version always follows the published one

The selection never names a version that Hex already holds or a lower one.
A computed version reaches the core that the required step demands, and the selection refuses an explicit version below the required one.
Kani proves it for every core and train number over versions that are stable or on a train, which is how the core reads every `<channel>.<number>` prerelease.

- Kani: `selection::proofs::a_selected_version_follows_the_published_one`
- Kani: `selection::proofs::a_selection_reaches_the_core_the_required_step_demands`
- Kani: `selection::proofs::an_explicit_version_below_the_required_one_is_refused`
- Test: `src/version.rs::version_selection_never_moves_below_or_onto_the_published_version`
- Test: `src/version.rs::select_version_covers_stable_prerelease_and_explicit_boundaries`
- Test: `src/version.rs::explicit_core_authority_has_exact_boundaries`
- Test: `src/planner.rs::the_requested_version_is_an_explicit_choice_only_when_read_and_ahead`

### A release train only moves forward

A train counts up within its channel or moves on to a later channel, a move back needs an explicitly higher core, and a first release joins the configured train.
A refused move back names the missing explicit core whenever the required step alone raises the core.
On a train, the selection takes an explicit version on the train as written and starts the train at the core of a stable explicit version.
It refuses any other explicit version as off the train.
Kani proves it for every core, channel, and train number over versions that are stable or on a train.

- Kani: `selection::proofs::a_train_moves_forward_or_counts_up_within_its_channel`
- Kani: `selection::proofs::an_explicit_version_decides_the_selection_on_a_train`
- Kani: `selection::proofs::the_first_release_joins_the_configured_train`
- Kani: `precedence::proofs::a_train_counts_up_and_moves_through_its_channels_in_precedence`
- Test: `src/version.rs::backward_channel_moves_require_an_explicitly_higher_core`
- Test: `src/version.rs::a_first_release_joins_the_configured_train_and_keeps_its_build_metadata`
- Test: `src/planner.rs::a_first_release_keeps_its_prerelease_unless_the_plan_asks_for_a_stable_one`

### Versions compare by semantic version precedence

The core decides before the prerelease, a stable release follows every prerelease of its core, and build metadata never changes precedence.
A train compares, parses, and names its channel exactly as the text `<label>.<number>` that spells it, and the prerelease grammar is the one semantic versioning states.
Kani covers prerelease text of at most three bytes for one version and two bytes for each of a pair.
It compares trains with one-digit numbers to any valid text of at most two bytes.
It compares a train with any number to its own label and any valid one-byte identifier, which reaches the comparison of the number.
It parses any text of at most eight bytes, and it checks the grammar of any text of at most four bytes.
The differential tests and the fuzz target compare the core with the `semver` crate on longer text.

- Kani: `precedence::proofs::a_version_equals_itself_and_order_flips_with_its_operands`
- Kani: `precedence::proofs::a_stable_release_follows_every_prerelease_of_its_core`
- Kani: `precedence::proofs::the_core_decides_before_the_prerelease`
- Kani: `precedence::proofs::a_train_compares_like_the_text_that_spells_it`
- Kani: `precedence::proofs::a_train_meets_its_own_label_by_its_number`
- Kani: `precedence::proofs::text_parses_as_a_train_exactly_when_it_spells_one`
- Kani: `precedence::proofs::the_prerelease_grammar_is_the_one_semantic_versioning_states`
- Fuzz: `prerelease`
- Test: `tests/version_precedence.rs::core_precedence_agrees_with_semver_on_every_pair`
- Test: `tests/version_precedence.rs::a_train_compares_like_the_prerelease_that_spells_it`
- Test: `tests/version_precedence.rs::parse_reads_every_train_spelling_as_its_train`
- Test: `tests/version_precedence.rs::build_metadata_never_changes_precedence`
- Test: `tests/version_precedence.rs::the_prerelease_grammar_agrees_with_semver_on_every_short_text`
- Test: `tests/fuzz_corpus.rs::prerelease_seeds_reach_trains_text_comparison_and_refusal`

### The required step follows the commits and the rules for versions below 1.0

A breaking marker asks for a major release, and otherwise the commit type decides the step in any letter case.
Only a marker that starts a body line counts, so a marker inside a line leaves the step to the type.
Below 1.0 a breaking change is a minor release, a release needs its acknowledgement, and the step between two versions names the highest component that changed.
The commit proofs cover three symbolic ASCII bytes around each marker and unknown types of at most four bytes.
Kani proves the rules below 1.0 for every major number and step.
It proves the step between versions for every core and train number over versions that are stable or on a train.

- Kani: `commit::proofs::a_breaking_marker_always_asks_for_a_major_release`
- Kani: `commit::proofs::the_commit_type_decides_the_step_without_a_breaking_marker`
- Kani: `commit::proofs::only_a_marker_that_starts_a_line_breaks_the_release`
- Kani: `selection::proofs::a_breaking_change_below_one_is_a_minor_release`
- Kani: `selection::proofs::a_zero_major_release_needs_its_acknowledgement`
- Kani: `selection::proofs::the_step_between_versions_names_the_highest_changed_component`
- Test: `src/git.rs::commit_types_match_in_any_letter_case_but_breaking_change_only_in_uppercase`
- Test: `tests/v1_domain.rs::zero_major_breaking_changes_require_a_minor_release`

### A Candidate publishes exactly the bytes it sealed

A digest or a commit id counts only when it has its exact length and nothing but lowercase hexadecimal digits, so one value never has two spellings.
Kani proves the digit check for every byte and the identity checks for every value of an identity's length.
It proves the refusal of every other length for values of up to three bytes, and for all-digit values one byte too short or too long.

- Kani: `hex::proofs::a_hex_digit_is_exactly_a_lowercase_hexadecimal_digit`
- Kani: `hex::proofs::hex_identities_check_every_byte`
- Kani: `hex::proofs::hex_identities_refuse_every_other_length`
- Test: `tests/v1_candidate.rs::candidate_seals_and_verifies_the_exact_publish_bytes`
- Test: `tests/v1_candidate.rs::candidate_verification_detects_any_raw_artifact_change`
- Test: `tests/v1_candidate.rs::candidate_verification_rejects_every_manifest_identity_and_digest_tamper`
- Test: `tests/registry_contract.rs::organization_registry_uses_repos_prefix_and_publishes_exact_bytes`

### Two different file sets or notifications never feed SHA-256 the same bytes

The files digest and the notification key frame their inputs injectively, so only a SHA-256 collision could give two of them one digest, and collision resistance is an assumption.
Kani proves the framing of one file and of one notification for parts of a few bytes, and Lean proves both framings for every length.

- Kani: `framing::proofs::the_files_framing_is_injective`
- Kani: `framing::proofs::the_notification_framing_is_injective`
- Lean: `ReleaseGlz.Framing.fromBe8_be8`
- Lean: `ReleaseGlz.Framing.the_files_framing_is_injective`
- Lean: `ReleaseGlz.Framing.the_notification_framing_is_injective`
- Lean: `ReleaseGlz.Refinement.files_framing_refines_rust`
- Lean: `ReleaseGlz.Refinement.notification_framing_refines_rust`
- Test: `tests/github_release_contract.rs::different_file_sets_never_share_a_files_digest`
- Test: `tests/github_release_contract.rs::the_files_digest_format_is_pinned`
- Test: `tests/v1_reconciler.rs::notification_key_is_a_domain_separated_binding_of_candidate_and_hook`

### Canonical JSON sorts member names by their 16-bit code units

The order equals the order of UTF-16 code units and is a strict total order, so a digest over canonical JSON doesn't depend on insertion order.
Kani proves it for names of at most one character, and longer names compare by the first character in which they differ.

- Kani: `key_order::proofs::member_names_sort_by_utf16_code_units`
- Kani: `key_order::proofs::member_names_have_a_strict_total_order`
- Test: `tests/v1_canonical.rs::canonical_json_follows_utf16_property_order`
- Test: `tests/v1_canonical.rs::canonical_digest_is_independent_of_object_insertion_order`

### Unpacking an archive writes only portable relative paths

An accepted path is relative, and none of its components is empty, `.`, or `..`.
No component is a name that Windows reserves for a device or holds a character that some supported OS forbids.
Two entries whose paths fold to the same file or directory once letter case and Unicode normalization no longer count never both stand.
Kani proves the character rules for every byte and every byte pair, and the device names for every stem of up to eight bytes.
It proves where a stem ends for components of up to six bytes and what an accepted component may hold for components of up to eight bytes.
It proves the collision rule for pairs of folded paths of up to five bytes, which nest two directories deep.
It proves that a path passes exactly when each of its components does for every path of three bytes over `a`, `.`, and `/`.
It proves the trimming of trailing slashes for every path of up to two bytes over those bytes.
It proves which directories hold a folded path for every folded path of up to four bytes, and it pins reading a path from its text on fixed paths.
Symbolic bytes across a whole path exhaust the solver.
The shell decodes each path as UTF-8 before the core reads it.
The shell also keeps the folded paths of the entries so far in its maps, which no proof covers, and the tests check that bookkeeping.
The shell folds a path through canonical decomposition, Unicode's lowercase mapping, and canonical decomposition again.
That fold rests on `icu_normalizer` and the tests, and it approximates the default macOS file system's own folding.

- Kani: `archive_path::proofs::a_component_refuses_exactly_the_characters_windows_forbids`
- Kani: `archive_path::proofs::a_stem_names_a_device_exactly_when_it_is_reserved`
- Kani: `archive_path::proofs::a_stem_ends_at_the_first_dot_without_trailing_spaces`
- Kani: `archive_path::proofs::an_accepted_archive_path_stays_inside_its_destination`
- Kani: `archive_path::proofs::two_accepted_entries_never_collide_once_case_no_longer_counts`
- Kani: `archive_path::proofs::entries_two_directories_deep_never_collide_once_case_no_longer_counts`
- Kani: `archive_path::proofs::a_path_passes_exactly_when_each_component_does`
- Kani: `archive_path::proofs::an_archive_path_is_its_text_without_trailing_slashes`
- Kani: `archive_path::proofs::the_directories_above_a_path_are_its_prefixes_before_each_slash`
- Fuzz: `archive`
- Test: `tests/artifact_security.rs::archive_paths_reject_every_ambiguous_or_traversing_form`
- Test: `tests/artifact_security.rs::archive_paths_reject_entries_that_collide_once_letter_case_no_longer_counts`
- Test: `tests/artifact_security.rs::archive_paths_reject_entries_that_differ_only_in_unicode_normalization`
- Test: `tests/artifact_security.rs::names_that_differ_beyond_normalization_still_pass`
- Test: `tests/artifact_security.rs::unpacking_uses_only_validated_relative_regular_files`

### Parsers refuse malformed input without panicking

No proof covers these parsers.
Fuzzing checks them, and every pull request replays the committed corpus of each fuzz target.

- Fuzz: `api_interface`
- Fuzz: `config`
- Fuzz: `identifiers`
- Fuzz: `pr_marker`
- Fuzz: `prerelease`
- Test: `tests/fuzz_corpus.rs::every_fuzz_target_runs_shared_invariants_that_this_suite_replays`

### A Release PR body carries exactly the marker that release-glz wrote

A rendered marker after inert text is the one marker that ends the body, its fields give back every value, and a body with an earlier marker has no marker.
Kani proves inert text for texts of at most three bytes and the byte search for haystacks of at most four bytes with needles of at most two.
It proves reading one field for fields of at most nine bytes, and Lean proves the marker for bodies of every length.
Kani also pins writing a marker for values of one byte each and for empty values.
It proves finding the block that ends a body for every body of up to five bytes with one-byte opening and closing texts.
It pins finding the marker itself on an empty body and on the shortest marker.
It pins reading the fields of a marker in two orders and with a key missing.
The adapter trims trailing whitespace and splits the fields at Unicode whitespace before the core reads them.
That split agrees with the model's split at spaces, because no value that release-glz writes holds whitespace.

- Kani: `marker::proofs::inert_text_replaces_each_less_than_sign`
- Kani: `marker::proofs::the_first_occurrence_is_the_earliest_match`
- Kani: `marker::proofs::the_last_occurrence_is_the_latest_match`
- Kani: `marker::proofs::a_field_is_recorded_only_under_a_new_known_key`
- Kani: `marker::proofs::a_marker_writes_each_key_and_value_in_order`
- Kani: `marker::proofs::the_marker_that_ends_a_body_is_found_after_inert_text`
- Kani: `marker::proofs::the_marker_is_found_with_its_own_texts`
- Kani: `marker::proofs::the_fields_of_a_marker_give_back_each_value`
- Lean: `ReleaseGlz.Marker.inert_holds_no_less_than`
- Lean: `ReleaseGlz.Marker.a_rendered_marker_ends_the_body`
- Lean: `ReleaseGlz.Marker.an_earlier_marker_is_refused`
- Lean: `ReleaseGlz.Marker.the_fields_give_back_every_value`
- Lean: `ReleaseGlz.Marker.the_marker_round_trips`
- Lean: `ReleaseGlz.Refinement.inert_refines_rust`
- Lean: `ReleaseGlz.Refinement.render_refines_rust`
- Lean: `ReleaseGlz.Refinement.marker_start_refines_rust`
- Lean: `ReleaseGlz.Refinement.marker_values_refines_rust`
- Test: `src/forge.rs::managed_marker_round_trips`
- Test: `src/forge.rs::replacing_the_marker_keeps_the_body_and_its_single_marker`
- Test: `src/forge.rs::release_pr_explains_that_merge_approves_intent_not_publication_bytes`
- Test: `tests/fuzz_corpus.rs::marker_seeds_reach_managed_and_unmanaged_bodies`

### Redaction removes every byte that a secret covers, and nothing else

Redaction covers a byte exactly when an occurrence of a non-empty secret spans it, replaces each maximal covered run once, and never splits a UTF-8 character.
Kani proves it for texts of at most three bytes with two secrets of at most two bytes, and Lean proves the coverage and the runs for every length.

- Kani: `redaction::proofs::each_step_reaches_exactly_the_occurrences_that_start_there`
- Kani: `redaction::proofs::redaction_covers_exactly_the_bytes_of_secret_occurrences`
- Kani: `redaction::proofs::redaction_replaces_each_maximal_covered_run_once`
- Kani: `redaction::proofs::redaction_never_splits_a_character`
- Lean: `ReleaseGlz.Redaction.reach_decides_coverage`
- Lean: `ReleaseGlz.Redaction.coverage_is_the_definition`
- Lean: `ReleaseGlz.Redaction.segments_cover_every_byte_once`
- Lean: `ReleaseGlz.Redaction.segments_are_nonempty`
- Lean: `ReleaseGlz.Redaction.neighboring_segments_differ`
- Lean: `ReleaseGlz.Refinement.redaction_refines_rust`
- Test: `src/secrets.rs::every_short_text_loses_exactly_the_characters_its_secrets_cover`
- Test: `src/secrets.rs::secrets_that_overlap_in_the_text_become_one_redaction`
- Test: `src/secrets.rs::redaction_keeps_multibyte_characters_whole`
- Test: `tests/standard_secret_redaction.rs::every_standard_credential_in_the_environment_is_redacted`

### No job that compiles dependencies holds a write token

Dependency builds may run code, so the jobs that compile hold read permissions only, and hooks receive only the environment they declare.
Tests check the generated workflows and the hook environment, and no proof covers them.

- Test: `tests/workflow_permissions.rs::no_job_that_compiles_holds_a_write_permission`
- Test: `tests/workflow_permissions.rs::the_check_finds_a_write_job_that_would_compile`
- Test: `tests/hooks_contract.rs::undeclared_environment_is_not_forwarded`

### Proof evidence counts only from an audited run

The proof gate admits a run only when every listed harness verified and no other ran, and a negative control only when it failed exactly its expected assertion.
Kani proves both rules for every exit code and every combination of the counts and flags in a run's report.

- Kani: `proofs::a_proof_run_is_admitted_only_when_every_expected_harness_verified`
- Kani: `proofs::a_control_run_is_admitted_only_when_exactly_its_assertion_failed`
- Test: `xtask/src/proof_report.rs::the_recorded_runs_are_admitted`
- Test: `xtask/src/proof_report.rs::a_negative_control_must_fail_only_its_expected_assertion`
- Test: `xtask/src/inventory.rs::every_harness_has_its_own_negative_control`
