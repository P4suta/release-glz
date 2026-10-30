//! The committed inventory of Kani harnesses and negative controls that the release gate expects.
//!
//! A test without the solver keeps it equal to the harnesses and negative-control features in the sources, so drift fails on every pull request.

/// One harness that a run of every proof has to verify.
#[derive(Debug, Clone, Copy)]
pub struct Harness {
    /// The name Kani reports, which is the harness's module path inside its crate.
    pub name: &'static str,
    /// The cover properties it declares, each of which the run has to satisfy.
    pub covers: usize,
}

/// One negative control: a feature that breaks a decision, and the assertion of the harness that has to fail.
#[derive(Debug, Clone, Copy)]
pub struct Control {
    /// The package whose feature it is.
    pub package: &'static str,
    /// The feature that breaks the decision.
    pub feature: &'static str,
    /// The harness that has to fail.
    pub harness: &'static str,
    /// The description of the only assertion that may fail.
    pub assertion: &'static str,
}

/// The packages whose harnesses the release gate proves.
pub const PACKAGES: [&str; 2] = ["release-glz-core", "assurance-core"];

const fn harness(name: &'static str, covers: usize) -> Harness {
    Harness { name, covers }
}

const fn control(
    package: &'static str,
    feature: &'static str,
    harness: &'static str,
    assertion: &'static str,
) -> Control {
    Control {
        package,
        feature,
        harness,
        assertion,
    }
}

/// Every harness of the proof packages, with its cover count.
pub const HARNESSES: [Harness; 60] = [
    harness(
        "proofs::a_proof_run_is_admitted_only_when_every_expected_harness_verified",
        2,
    ),
    harness(
        "proofs::a_control_run_is_admitted_only_when_exactly_its_assertion_failed",
        2,
    ),
    harness(
        "approval::proofs::an_approval_needs_every_conjunct_of_its_path",
        2,
    ),
    harness(
        "approval::proofs::a_push_approval_never_rests_on_manual_inputs",
        1,
    ),
    harness(
        "commit::proofs::a_breaking_marker_always_asks_for_a_major_release",
        2,
    ),
    harness(
        "commit::proofs::the_commit_type_decides_the_step_without_a_breaking_marker",
        1,
    ),
    harness("framing::proofs::the_files_framing_is_injective", 1),
    harness("framing::proofs::the_notification_framing_is_injective", 1),
    harness(
        "key_order::proofs::member_names_sort_by_utf16_code_units",
        1,
    ),
    harness(
        "key_order::proofs::member_names_have_a_strict_total_order",
        1,
    ),
    harness("lifecycle::proofs::every_state_may_repeat", 1),
    harness("lifecycle::proofs::a_terminal_state_never_changes", 2),
    harness("lifecycle::proofs::normal_states_form_one_forward_chain", 2),
    harness("lifecycle::proofs::advancing_is_transitive", 1),
    harness(
        "lifecycle::proofs::an_unfinished_release_can_always_end_in_conflict_or_blocked",
        2,
    ),
    harness("marker::proofs::inert_text_replaces_each_less_than_sign", 1),
    harness(
        "marker::proofs::the_first_occurrence_is_the_earliest_match",
        1,
    ),
    harness("marker::proofs::the_last_occurrence_is_the_latest_match", 1),
    harness(
        "marker::proofs::a_field_is_recorded_only_under_a_new_known_key",
        1,
    ),
    harness(
        "precedence::proofs::a_version_equals_itself_and_order_flips_with_its_operands",
        2,
    ),
    harness(
        "precedence::proofs::a_stable_release_follows_every_prerelease_of_its_core",
        1,
    ),
    harness(
        "precedence::proofs::the_core_decides_before_the_prerelease",
        1,
    ),
    harness(
        "precedence::proofs::a_train_counts_up_and_moves_through_its_channels_in_precedence",
        1,
    ),
    harness(
        "publication::proofs::an_effect_concerns_only_an_object_the_world_lacks",
        2,
    ),
    harness(
        "publication::proofs::an_object_that_differs_ends_in_a_conflict",
        2,
    ),
    harness("publication::proofs::no_effect_leaves_without_approval", 1),
    harness(
        "publication::proofs::a_conflict_anywhere_stops_the_release",
        1,
    ),
    harness(
        "publication::proofs::publishing_an_effect_removes_exactly_that_effect",
        1,
    ),
    harness(
        "publication::proofs::the_release_is_released_once_no_blocking_effect_remains",
        3,
    ),
    harness(
        "redaction::proofs::each_step_reaches_exactly_the_occurrences_that_start_there",
        1,
    ),
    harness(
        "redaction::proofs::redaction_covers_exactly_the_bytes_of_secret_occurrences",
        1,
    ),
    harness(
        "redaction::proofs::redaction_replaces_each_maximal_covered_run_once",
        1,
    ),
    harness("redaction::proofs::redaction_never_splits_a_character", 1),
    harness(
        "selection::proofs::a_selected_version_follows_the_published_one",
        4,
    ),
    harness(
        "selection::proofs::a_selection_reaches_the_core_the_required_step_demands",
        1,
    ),
    harness(
        "selection::proofs::a_train_moves_forward_or_counts_up_within_its_channel",
        2,
    ),
    harness(
        "selection::proofs::an_explicit_version_below_the_required_one_is_refused",
        2,
    ),
    harness(
        "selection::proofs::the_first_release_joins_the_configured_train",
        1,
    ),
    harness(
        "selection::proofs::a_breaking_change_below_one_is_a_minor_release",
        1,
    ),
    harness(
        "selection::proofs::the_step_between_versions_names_the_highest_changed_component",
        1,
    ),
    harness(
        "selection::proofs::a_zero_major_release_needs_its_acknowledgement",
        1,
    ),
    harness(
        "version::proofs::the_join_of_two_bumps_is_the_larger_one",
        1,
    ),
    harness(
        "version::proofs::an_increment_adds_one_or_reports_the_largest_value",
        2,
    ),
    harness(
        "version::proofs::a_bump_raises_the_core_or_reports_an_overflow",
        2,
    ),
    harness(
        "run::proofs::a_run_applies_only_owed_effects_in_publication_order",
        1,
    ),
    harness(
        "run::proofs::a_run_attempts_each_optional_effect_once_within_its_first_plan",
        2,
    ),
    harness(
        "run::proofs::a_failed_effect_counts_only_once_the_world_holds_it",
        2,
    ),
    harness(
        "run::proofs::a_run_stops_only_when_nothing_but_attempted_optional_effects_remains",
        1,
    ),
    harness("run::proofs::a_run_whose_effects_land_ends_released", 1),
    harness(
        "run::proofs::every_step_keeps_the_record_that_bounds_a_run",
        2,
    ),
    harness(
        "run::proofs::a_run_stops_when_the_number_of_objects_changes",
        1,
    ),
    harness(
        "hex::proofs::a_hex_digit_is_exactly_a_lowercase_hexadecimal_digit",
        2,
    ),
    harness("hex::proofs::hex_identities_check_every_byte", 2),
    harness("hex::proofs::hex_identities_refuse_every_other_length", 2),
    harness(
        "archive_path::proofs::a_component_refuses_exactly_the_characters_windows_forbids",
        2,
    ),
    harness(
        "archive_path::proofs::a_stem_names_a_device_exactly_when_it_is_reserved",
        4,
    ),
    harness(
        "archive_path::proofs::a_stem_ends_at_the_first_dot_without_trailing_spaces",
        1,
    ),
    harness(
        "archive_path::proofs::an_accepted_archive_path_stays_inside_its_destination",
        2,
    ),
    harness(
        "archive_path::proofs::two_accepted_entries_never_collide_once_case_no_longer_counts",
        2,
    ),
    harness(
        "archive_path::proofs::entries_two_directories_deep_never_collide_once_case_no_longer_counts",
        2,
    ),
];

const CORE: &str = "release-glz-core";
const ASSURANCE: &str = "assurance-core";

/// Every negative control, each of which has to fail exactly its harness's assertion.
pub const CONTROLS: [Control; 62] = [
    control(
        ASSURANCE,
        "negative-control-incomplete-run",
        "proofs::a_proof_run_is_admitted_only_when_every_expected_harness_verified",
        "a proof run must complete before admission",
    ),
    control(
        ASSURANCE,
        "negative-control-extra-failure",
        "proofs::a_control_run_is_admitted_only_when_exactly_its_assertion_failed",
        "a negative control must fail only its expected assertion",
    ),
    control(
        CORE,
        "negative-control-approval",
        "approval::proofs::an_approval_needs_every_conjunct_of_its_path",
        "an approval must cover the Candidate digest",
    ),
    control(
        CORE,
        "negative-control-substitution",
        "approval::proofs::a_push_approval_never_rests_on_manual_inputs",
        "a push approval must not rest on manual inputs",
    ),
    control(
        CORE,
        "negative-control-breaking-footer",
        "commit::proofs::a_breaking_marker_always_asks_for_a_major_release",
        "a breaking-change footer must ask for a major release",
    ),
    control(
        CORE,
        "negative-control-commit-type-case",
        "commit::proofs::the_commit_type_decides_the_step_without_a_breaking_marker",
        "a commit type must decide the step in any letter case",
    ),
    control(
        CORE,
        "negative-control-unframed-files",
        "framing::proofs::the_files_framing_is_injective",
        "the files framing must be injective",
    ),
    control(
        CORE,
        "negative-control-unframed-notification",
        "framing::proofs::the_notification_framing_is_injective",
        "the notification framing must be injective",
    ),
    control(
        CORE,
        "negative-control-utf8-key-order",
        "key_order::proofs::member_names_sort_by_utf16_code_units",
        "member names must sort by UTF-16 code units",
    ),
    control(
        CORE,
        "negative-control-first-unit-key-order",
        "key_order::proofs::member_names_have_a_strict_total_order",
        "member names must compare equal only when they are equal",
    ),
    control(
        CORE,
        "negative-control-no-repeat",
        "lifecycle::proofs::every_state_may_repeat",
        "every state must be able to repeat",
    ),
    control(
        CORE,
        "negative-control-reopen",
        "lifecycle::proofs::a_terminal_state_never_changes",
        "a terminal state must never change",
    ),
    control(
        CORE,
        "negative-control-backward",
        "lifecycle::proofs::normal_states_form_one_forward_chain",
        "distinct normal states must be ordered one way only",
    ),
    control(
        CORE,
        "negative-control-no-skip",
        "lifecycle::proofs::advancing_is_transitive",
        "advancing must be transitive",
    ),
    control(
        CORE,
        "negative-control-unstoppable",
        "lifecycle::proofs::an_unfinished_release_can_always_end_in_conflict_or_blocked",
        "an unfinished release must be able to stop",
    ),
    control(
        CORE,
        "negative-control-inert-less-than",
        "marker::proofs::inert_text_replaces_each_less_than_sign",
        "inert text must replace each less-than sign and keep every other byte",
    ),
    control(
        CORE,
        "negative-control-search-skips-start",
        "marker::proofs::the_first_occurrence_is_the_earliest_match",
        "the first occurrence must be the earliest match",
    ),
    control(
        CORE,
        "negative-control-search-stops-short",
        "marker::proofs::the_last_occurrence_is_the_latest_match",
        "the last occurrence must be the latest match",
    ),
    control(
        CORE,
        "negative-control-duplicate-keys",
        "marker::proofs::a_field_is_recorded_only_under_a_new_known_key",
        "a field must be recorded only under a new known key",
    ),
    control(
        CORE,
        "negative-control-equal-prereleases",
        "precedence::proofs::a_version_equals_itself_and_order_flips_with_its_operands",
        "a version must equal itself",
    ),
    control(
        CORE,
        "negative-control-stable-before-prerelease",
        "precedence::proofs::a_stable_release_follows_every_prerelease_of_its_core",
        "a stable release must follow every prerelease of its core",
    ),
    control(
        CORE,
        "negative-control-prerelease-first",
        "precedence::proofs::the_core_decides_before_the_prerelease",
        "the core must decide before the prerelease",
    ),
    control(
        CORE,
        "negative-control-reverse-numbers",
        "precedence::proofs::a_train_counts_up_and_moves_through_its_channels_in_precedence",
        "a train's next number must follow it",
    ),
    control(
        CORE,
        "negative-control-republish",
        "publication::proofs::an_effect_concerns_only_an_object_the_world_lacks",
        "an effect must concern an object the world lacks",
    ),
    control(
        CORE,
        "negative-control-overwrite",
        "publication::proofs::an_object_that_differs_ends_in_a_conflict",
        "an object that differs must end in a conflict",
    ),
    control(
        CORE,
        "negative-control-unapproved",
        "publication::proofs::no_effect_leaves_without_approval",
        "no effect may leave without approval",
    ),
    control(
        CORE,
        "negative-control-overwrite",
        "publication::proofs::a_conflict_anywhere_stops_the_release",
        "an object that differs must end in a conflict",
    ),
    control(
        CORE,
        "negative-control-republish",
        "publication::proofs::publishing_an_effect_removes_exactly_that_effect",
        "publishing an effect must remove exactly that effect",
    ),
    control(
        CORE,
        "negative-control-optional-blocks",
        "publication::proofs::the_release_is_released_once_no_blocking_effect_remains",
        "a release must be released exactly when no blocking effect remains",
    ),
    control(
        CORE,
        "negative-control-redaction-partial",
        "redaction::proofs::each_step_reaches_exactly_the_occurrences_that_start_there",
        "a step must reach exactly the occurrences that start at its byte",
    ),
    control(
        CORE,
        "negative-control-redaction-overreach",
        "redaction::proofs::redaction_covers_exactly_the_bytes_of_secret_occurrences",
        "every byte of every secret occurrence must be redacted, and no other",
    ),
    control(
        CORE,
        "negative-control-redaction-split",
        "redaction::proofs::redaction_replaces_each_maximal_covered_run_once",
        "each maximal covered run must be one segment",
    ),
    control(
        CORE,
        "negative-control-redaction-midchar",
        "redaction::proofs::redaction_never_splits_a_character",
        "a character must be redacted or kept as a whole",
    ),
    control(
        CORE,
        "negative-control-reselect",
        "selection::proofs::a_selected_version_follows_the_published_one",
        "a selected version must follow the published one",
    ),
    control(
        CORE,
        "negative-control-understep",
        "selection::proofs::a_selection_reaches_the_core_the_required_step_demands",
        "a selection must reach the core of the required step",
    ),
    control(
        CORE,
        "negative-control-backward-train",
        "selection::proofs::a_train_moves_forward_or_counts_up_within_its_channel",
        "a train must not move back without an explicitly higher core",
    ),
    control(
        CORE,
        "negative-control-override-floor",
        "selection::proofs::an_explicit_version_below_the_required_one_is_refused",
        "an explicit version below the required one must be refused",
    ),
    control(
        CORE,
        "negative-control-initial-train",
        "selection::proofs::the_first_release_joins_the_configured_train",
        "a first release must join the configured train",
    ),
    control(
        CORE,
        "negative-control-zero-major",
        "selection::proofs::a_breaking_change_below_one_is_a_minor_release",
        "a breaking change below 1.0 must be a minor release",
    ),
    control(
        CORE,
        "negative-control-bump-between",
        "selection::proofs::the_step_between_versions_names_the_highest_changed_component",
        "a change of the prerelease alone must be a patch step",
    ),
    control(
        CORE,
        "negative-control-version-zero",
        "selection::proofs::a_zero_major_release_needs_its_acknowledgement",
        "a release below 1.0 must need its acknowledgement",
    ),
    control(
        CORE,
        "negative-control-join",
        "version::proofs::the_join_of_two_bumps_is_the_larger_one",
        "the join of two bumps must be the larger one",
    ),
    control(
        CORE,
        "negative-control-increment",
        "version::proofs::an_increment_adds_one_or_reports_the_largest_value",
        "an increment must add exactly one",
    ),
    control(
        CORE,
        "negative-control-increment",
        "version::proofs::a_bump_raises_the_core_or_reports_an_overflow",
        "a bump must raise the version core",
    ),
    control(
        CORE,
        "negative-control-skip-ahead",
        "run::proofs::a_run_applies_only_owed_effects_in_publication_order",
        "a run must apply effects in publication order",
    ),
    control(
        CORE,
        "negative-control-unbudgeted",
        "run::proofs::a_run_attempts_each_optional_effect_once_within_its_first_plan",
        "a run must attempt at most as many effects as its first plan listed",
    ),
    control(
        CORE,
        "negative-control-retry-optional",
        "run::proofs::a_run_attempts_each_optional_effect_once_within_its_first_plan",
        "a run must attempt each optional effect at most once",
    ),
    control(
        CORE,
        "negative-control-trust-failure",
        "run::proofs::a_failed_effect_counts_only_once_the_world_holds_it",
        "a failed blocking effect that the world lacks must stop the run",
    ),
    control(
        CORE,
        "negative-control-forget-failure",
        "run::proofs::a_failed_effect_counts_only_once_the_world_holds_it",
        "a run that can't observe must report the state of the plan that chose its failed effect",
    ),
    control(
        CORE,
        "negative-control-stall",
        "run::proofs::a_run_stops_only_when_nothing_but_attempted_optional_effects_remains",
        "a run must stop only when nothing but optional effects it attempted remains",
    ),
    control(
        CORE,
        "negative-control-stall",
        "run::proofs::a_run_whose_effects_land_ends_released",
        "a run whose effects land must end released",
    ),
    control(
        CORE,
        "negative-control-unbudgeted",
        "run::proofs::every_step_keeps_the_record_that_bounds_a_run",
        "a step must spend exactly one attempt",
    ),
    control(
        CORE,
        "negative-control-reshape",
        "run::proofs::a_run_stops_when_the_number_of_objects_changes",
        "a run must stop when the number of objects changes",
    ),
    control(
        CORE,
        "negative-control-hex-case",
        "hex::proofs::a_hex_digit_is_exactly_a_lowercase_hexadecimal_digit",
        "a hex digit must be a lowercase hexadecimal digit",
    ),
    control(
        CORE,
        "negative-control-hex-any-byte",
        "hex::proofs::hex_identities_check_every_byte",
        "a hex identity must check every byte",
    ),
    control(
        CORE,
        "negative-control-hex-length",
        "hex::proofs::hex_identities_refuse_every_other_length",
        "a hex identity must refuse every other length",
    ),
    control(
        CORE,
        "negative-control-path-colon",
        "archive_path::proofs::a_component_refuses_exactly_the_characters_windows_forbids",
        "a component must refuse every character that Windows forbids",
    ),
    control(
        CORE,
        "negative-control-device-case",
        "archive_path::proofs::a_stem_names_a_device_exactly_when_it_is_reserved",
        "a stem must name a device exactly when it is reserved",
    ),
    control(
        CORE,
        "negative-control-device-stem",
        "archive_path::proofs::a_stem_ends_at_the_first_dot_without_trailing_spaces",
        "the stem of a component must end at its first dot",
    ),
    control(
        CORE,
        "negative-control-path-traversal",
        "archive_path::proofs::an_accepted_archive_path_stays_inside_its_destination",
        "an accepted path must stay inside its destination",
    ),
    control(
        CORE,
        "negative-control-case-collision",
        "archive_path::proofs::two_accepted_entries_never_collide_once_case_no_longer_counts",
        "two accepted entries must not collide once letter case no longer counts",
    ),
    control(
        CORE,
        "negative-control-case-collision",
        "archive_path::proofs::entries_two_directories_deep_never_collide_once_case_no_longer_counts",
        "two accepted entries must not collide once letter case no longer counts",
    ),
];

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{CONTROLS, HARNESSES, PACKAGES};

    fn repository() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    fn package_directory(package: &str) -> PathBuf {
        repository().join("crates").join(package)
    }

    /// Every `#[kani::proof]` function of `package`, named as Kani reports it, with the source of its body.
    fn harnesses_in(package: &str) -> BTreeMap<String, String> {
        let mut harnesses = BTreeMap::new();
        let source = package_directory(package).join("src");
        for entry in fs::read_dir(&source).unwrap() {
            let path = entry.unwrap().path();
            let module = path.file_stem().unwrap().to_str().unwrap().to_owned();
            let prefix = if module == "lib" {
                "proofs::".to_owned()
            } else {
                format!("{module}::proofs::")
            };
            let text = fs::read_to_string(&path).unwrap();
            for piece in text.split("#[kani::proof]").skip(1) {
                let name = piece
                    .split_once("fn ")
                    .and_then(|(_, rest)| rest.split_once('('))
                    .map(|(name, _)| name.trim().to_owned())
                    .unwrap();
                harnesses.insert(format!("{prefix}{name}"), piece.to_owned());
            }
        }
        harnesses
    }

    /// The negative-control features that `package` declares.
    fn features_of(package: &str) -> BTreeSet<String> {
        fs::read_to_string(package_directory(package).join("Cargo.toml"))
            .unwrap()
            .lines()
            .filter_map(|line| line.split_once(" = "))
            .map(|(name, _)| name.trim().to_owned())
            .filter(|name| name.starts_with("negative-control-"))
            .collect()
    }

    #[test]
    fn the_inventory_lists_every_harness_of_the_proof_packages_once() {
        let mut found = BTreeMap::new();
        for package in PACKAGES {
            found.extend(harnesses_in(package));
        }
        let listed = HARNESSES
            .iter()
            .map(|harness| harness.name.to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(listed.len(), HARNESSES.len(), "a harness is listed twice");
        assert_eq!(
            found.keys().cloned().collect::<BTreeSet<_>>(),
            listed,
            "the inventory and the sources name different harnesses"
        );
        for harness in HARNESSES {
            let body = &found[harness.name];
            assert_eq!(
                body.matches("kani::cover!").count(),
                harness.covers,
                "{} declares another number of covers",
                harness.name
            );
        }
    }

    #[test]
    fn every_negative_control_breaks_a_declared_feature_and_a_listed_harness() {
        let mut found = BTreeMap::new();
        for package in PACKAGES {
            found.extend(harnesses_in(package));
        }
        for package in PACKAGES {
            let declared = features_of(package);
            let controlled = CONTROLS
                .iter()
                .filter(|control| control.package == package)
                .map(|control| control.feature.to_owned())
                .collect::<BTreeSet<_>>();
            assert_eq!(
                declared, controlled,
                "{package} declares other negative controls than the inventory runs"
            );
        }
        for control in CONTROLS {
            let body = found
                .get(control.harness)
                .unwrap_or_else(|| panic!("{} names no harness", control.feature));
            assert!(
                body.contains(&format!("\"{}\"", control.assertion)),
                "{} asserts no {:?}",
                control.harness,
                control.assertion
            );
            let sources = fs::read_dir(package_directory(control.package).join("src"))
                .unwrap()
                .map(|entry| fs::read_to_string(entry.unwrap().path()).unwrap())
                .collect::<String>();
            assert!(
                sources.contains(&format!("feature = \"{}\"", control.feature)),
                "{} breaks nothing",
                control.feature
            );
        }
    }

    #[test]
    fn every_harness_has_its_own_negative_control() {
        let controlled = CONTROLS
            .iter()
            .map(|control| control.harness)
            .collect::<BTreeSet<_>>();
        for harness in HARNESSES {
            assert!(
                controlled.contains(harness.name),
                "{} has no negative control",
                harness.name
            );
        }
        let pairs = CONTROLS
            .iter()
            .map(|control| (control.feature, control.harness))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            pairs.len(),
            CONTROLS.len(),
            "a negative control is listed twice"
        );
    }
}
