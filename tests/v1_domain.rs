use release_glz::model::{
    CommandEnvelope, Diagnostic, DiagnosticLevel, NextAction, ReleaseStage, ReleaseState,
};
use release_glz::version::{effective_bump, next_prerelease_with_core};
use release_glz::{Bump, PrereleaseChannel};
use semver::Version;
use serde_json::json;

fn v(input: &str) -> Version {
    input.parse().unwrap()
}

#[test]
fn zero_major_breaking_changes_require_a_minor_release() {
    assert_eq!(effective_bump(&v("0.4.2"), Bump::Major), Bump::Minor);
    assert_eq!(effective_bump(&v("0.4.2"), Bump::Minor), Bump::Minor);
    assert_eq!(effective_bump(&v("0.4.2"), Bump::Patch), Bump::Patch);
    assert_eq!(effective_bump(&v("1.4.2"), Bump::Major), Bump::Major);
}

#[test]
fn prerelease_channels_only_move_forward_on_the_same_core() {
    assert_eq!(
        next_prerelease_with_core(
            &v("1.2.0-alpha.4"),
            &v("1.2.0"),
            PrereleaseChannel::Beta,
            false,
        )
        .unwrap(),
        v("1.2.0-beta.1")
    );
    assert!(
        next_prerelease_with_core(
            &v("1.2.0-rc.2"),
            &v("1.2.0"),
            PrereleaseChannel::Beta,
            false,
        )
        .is_err()
    );
    assert_eq!(
        next_prerelease_with_core(
            &v("1.2.0-rc.2"),
            &v("1.3.0"),
            PrereleaseChannel::Alpha,
            true,
        )
        .unwrap(),
        v("1.3.0-alpha.1")
    );
}

#[test]
fn release_state_is_monotonic_except_terminal_diagnostics() {
    assert!(ReleaseState::Planned.can_advance_to(ReleaseState::CandidateReady));
    assert!(ReleaseState::CandidateReady.can_advance_to(ReleaseState::AwaitingApproval));
    assert!(ReleaseState::PartiallyReleased.can_advance_to(ReleaseState::Released));
    assert!(!ReleaseState::Released.can_advance_to(ReleaseState::Planned));
    assert!(ReleaseState::CandidateReady.can_advance_to(ReleaseState::Conflict));
    assert!(ReleaseState::CandidateReady.can_advance_to(ReleaseState::Blocked));
}

#[test]
fn command_envelope_v2_has_one_stable_shape() {
    let envelope = CommandEnvelope::success(
        "plan",
        json!({"schema": "plan/v2", "state": "planned"}),
        vec![Diagnostic {
            code: "version_zero".into(),
            level: DiagnosticLevel::Warning,
            message: "Gleam recommends starting at 1.0.0".into(),
            detail: None,
        }],
        vec![NextAction {
            argv: vec![
                "release-glz".into(),
                "rehearse".into(),
                "--ref".into(),
                "deadbeef".into(),
                "--out".into(),
                "candidate".into(),
            ],
            command: "rehearse --ref deadbeef --out candidate".into(),
            description: "Seal the approved source".into(),
        }],
    );
    let value = serde_json::to_value(envelope).unwrap();
    assert_eq!(value["schema"], "command/v2");
    assert_eq!(value["ok"], true);
    assert_eq!(value["command"], "plan");
    assert_eq!(value["result"]["schema"], "plan/v2");
    assert_eq!(value["diagnostics"][0]["level"], "warning");
    assert_eq!(
        value["next_actions"][0]["command"],
        "rehearse --ref deadbeef --out candidate"
    );
}

#[test]
fn next_action_argv_preserves_spaces_and_newlines_without_shell_reparsing() {
    let candidate = "candidate path\nsecond line";
    let action = NextAction::executable(
        ["release-glz", "verify", "--candidate", candidate],
        "Verify the Candidate.",
    );
    assert_eq!(
        action.argv,
        ["release-glz", "verify", "--candidate", candidate]
    );
    assert!(!action.command.contains('\n'));
    assert!(action.command.contains("\\n"));
}

#[test]
fn every_public_state_and_stage_has_a_stable_wire_name() {
    let states = [
        ReleaseState::UpToDate,
        ReleaseState::Planned,
        ReleaseState::CandidateReady,
        ReleaseState::AwaitingApproval,
        ReleaseState::PartiallyReleased,
        ReleaseState::Released,
        ReleaseState::Conflict,
        ReleaseState::Blocked,
    ];
    assert_eq!(
        serde_json::to_value(states).unwrap(),
        json!([
            "up_to_date",
            "planned",
            "candidate_ready",
            "awaiting_approval",
            "partially_released",
            "released",
            "conflict",
            "blocked"
        ])
    );

    let stages = [
        ReleaseStage::VerifyHooks,
        ReleaseStage::PrepareGitTag,
        ReleaseStage::PrepareGithubDraft,
        ReleaseStage::PublishPackage,
        ReleaseStage::PublishDocs,
        ReleaseStage::FinalizeGithubRelease,
        ReleaseStage::NotifyHooks,
    ];
    assert_eq!(
        serde_json::to_value(stages).unwrap(),
        json!([
            "verify_hooks",
            "prepare_git_tag",
            "prepare_github_draft",
            "publish_package",
            "publish_docs",
            "finalize_github_release",
            "notify_hooks"
        ])
    );
}

#[test]
fn release_state_property_covers_every_pair_in_the_monotonic_lattice() {
    let states = [
        ReleaseState::UpToDate,
        ReleaseState::Planned,
        ReleaseState::CandidateReady,
        ReleaseState::AwaitingApproval,
        ReleaseState::PartiallyReleased,
        ReleaseState::Released,
        ReleaseState::Conflict,
        ReleaseState::Blocked,
    ];
    for (from_index, from) in states.into_iter().enumerate() {
        for (to_index, to) in states.into_iter().enumerate() {
            let expected = if from == to {
                true
            } else if matches!(to, ReleaseState::Conflict | ReleaseState::Blocked) {
                !matches!(
                    from,
                    ReleaseState::Released | ReleaseState::Conflict | ReleaseState::Blocked
                )
            } else {
                to_index >= from_index
                    && !matches!(
                        from,
                        ReleaseState::Released | ReleaseState::Conflict | ReleaseState::Blocked
                    )
            };
            assert_eq!(from.can_advance_to(to), expected, "{from:?} -> {to:?}");
        }
    }
}

#[test]
fn bump_and_prerelease_wire_helpers_cover_every_variant_and_invalid_input() {
    let bumps = [Bump::None, Bump::Patch, Bump::Minor, Bump::Major];
    assert_eq!(
        bumps.map(|bump| bump.to_string()),
        ["none", "patch", "minor", "major"]
    );
    for left in bumps {
        for right in bumps {
            assert_eq!(left.max(right), std::cmp::max(left, right));
        }
    }

    for (wire, expected) in [
        ("alpha", PrereleaseChannel::Alpha),
        ("beta", PrereleaseChannel::Beta),
        ("rc", PrereleaseChannel::Rc),
    ] {
        assert_eq!(wire.parse::<PrereleaseChannel>().unwrap(), expected);
        assert_eq!(expected.as_str(), wire);
    }
    assert_eq!(
        "preview".parse::<PrereleaseChannel>().unwrap_err(),
        "unknown prerelease channel `preview`"
    );
}
