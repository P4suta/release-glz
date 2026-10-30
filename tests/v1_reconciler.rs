use std::collections::{BTreeMap, BTreeSet};

use release_glz::authorization::{
    GithubOidcClaims, JwkSet, OidcAudience, OidcExpectation, RsaJwk, VerifiedGithubOidc,
    verify_github_oidc_token,
};
use release_glz::model::ReleaseState;
use release_glz::reconciler::{
    ApprovalEvidence, ExternalReleaseState, NotifyHookIntent, NotifyObservation, ObservedArtifact,
    ObservedGithubRelease, ObservedTag, ReconcileEffect, ReleaseAsset, ReleaseIntent,
    notification_key, preview, reconcile,
};
use release_glz_test_support::oidc;
use semver::Version;

fn intent() -> ReleaseIntent {
    ReleaseIntent {
        package: "widget".into(),
        version: Version::new(1, 2, 3),
        source_sha: "a".repeat(40),
        tag: "v1.2.3".into(),
        intent_digest: "1".repeat(64),
        candidate_digest: "2".repeat(64),
        approval_environment: "release".into(),
        manual_refs: vec!["refs/heads/main".into()],
        github_repository: "owner/widget".into(),
        workflow_path: ".github/workflows/release-glz.yml".into(),
        github_release: true,
        package_sha256: "3".repeat(64),
        docs_sha256: Some("4".repeat(64)),
        release_assets: vec![],
        notify_hooks: vec![NotifyHookIntent {
            id: "announce".into(),
            required: true,
        }],
    }
}

#[test]
fn release_assets_upload_to_the_draft_once_and_conflict_instead_of_replacing() {
    let mut target = intent();
    target.release_assets = vec![ReleaseAsset {
        hook_id: "sbom".into(),
        name: "sbom.cdx.json".into(),
        media_type: "application/vnd.cyclonedx+json".into(),
        sha256: "5".repeat(64),
        size: 123,
    }];
    let plan = reconcile(&target, &ExternalReleaseState::default(), &approved()).unwrap();
    let upload = ReconcileEffect::UploadGithubAsset {
        hook_id: "sbom".into(),
        name: "sbom.cdx.json".into(),
        sha256: "5".repeat(64),
    };
    assert_eq!(
        serde_json::to_value(&upload).unwrap()["hook_id"],
        "sbom",
        "asset effects must preserve the sealed sidecar identity"
    );
    assert!(plan.effects.contains(&upload));
    assert!(
        plan.effects
            .iter()
            .position(|effect| effect == &upload)
            .unwrap()
            < plan
                .effects
                .iter()
                .position(|effect| effect == &ReconcileEffect::FinalizeGithubRelease)
                .unwrap()
    );

    let matching = ExternalReleaseState {
        release_assets: BTreeMap::from([(
            "sbom.cdx.json".into(),
            ObservedArtifact {
                sha256: "5".repeat(64),
            },
        )]),
        ..ExternalReleaseState::default()
    };
    assert!(
        !reconcile(&target, &matching, &approved())
            .unwrap()
            .effects
            .contains(&upload)
    );

    let conflicting = ExternalReleaseState {
        release_assets: BTreeMap::from([(
            "sbom.cdx.json".into(),
            ObservedArtifact {
                sha256: "f".repeat(64),
            },
        )]),
        ..ExternalReleaseState::default()
    };
    assert_eq!(
        reconcile(&target, &conflicting, &approved())
            .unwrap_err()
            .state(),
        ReleaseState::Conflict
    );
}

/// The released world of `target` except its assets, with the GitHub Release still a draft when `draft` holds.
fn released_but_assets(target: &ReleaseIntent, draft: bool) -> ExternalReleaseState {
    ExternalReleaseState {
        package: Some(ObservedArtifact {
            sha256: target.package_sha256.clone(),
        }),
        docs: Some(ObservedArtifact {
            sha256: target.docs_sha256.clone().unwrap(),
        }),
        tag: Some(ObservedTag {
            target_sha: target.source_sha.clone(),
            annotated: true,
        }),
        github_release: Some(ObservedGithubRelease {
            target_sha: target.source_sha.clone(),
            candidate_digest: target.candidate_digest.clone(),
            draft,
        }),
        ..ExternalReleaseState::default()
    }
}

/// An asset that a failed upload left unfinished on the Candidate's draft is pending, so the plan uploads it again before it finalizes the Release.
#[test]
fn an_unfinished_sealed_asset_on_the_draft_is_uploaded_again_before_finalizing() {
    let mut target = intent();
    target.notify_hooks.clear();
    target.release_assets = vec![ReleaseAsset {
        hook_id: "sbom".into(),
        name: "sbom.cdx.json".into(),
        media_type: "application/vnd.cyclonedx+json".into(),
        sha256: "5".repeat(64),
        size: 12,
    }];
    let observed = ExternalReleaseState {
        unfinished_release_assets: BTreeSet::from(["sbom.cdx.json".to_owned()]),
        ..released_but_assets(&target, true)
    };
    let plan = reconcile(&target, &observed, &approved()).unwrap();
    assert_eq!(plan.state, ReleaseState::PartiallyReleased);
    assert_eq!(
        plan.effects,
        vec![
            ReconcileEffect::UploadGithubAsset {
                hook_id: "sbom".into(),
                name: "sbom.cdx.json".into(),
                sha256: "5".repeat(64),
            },
            ReconcileEffect::FinalizeGithubRelease,
        ]
    );
    assert_eq!(preview(&target, &observed).unwrap(), plan);
}

/// An unfinished asset that the release can't complete stops it, as an uploaded asset outside the Candidate does.
#[test]
fn an_unfinished_asset_the_release_cant_complete_is_a_conflict() {
    let mut target = intent();
    target.release_assets = vec![ReleaseAsset {
        hook_id: "sbom".into(),
        name: "sbom.cdx.json".into(),
        media_type: "application/vnd.cyclonedx+json".into(),
        sha256: "5".repeat(64),
        size: 12,
    }];
    let unfinished = |draft: bool, name: &str| ExternalReleaseState {
        unfinished_release_assets: BTreeSet::from([name.to_owned()]),
        ..released_but_assets(&target, draft)
    };
    let both = ExternalReleaseState {
        release_assets: BTreeMap::from([(
            "sbom.cdx.json".into(),
            ObservedArtifact {
                sha256: "5".repeat(64),
            },
        )]),
        ..unfinished(true, "sbom.cdx.json")
    };
    for (observed, message) in [
        (
            unfinished(true, "stray.json"),
            "GitHub Release contains unsealed asset `stray.json`",
        ),
        (
            unfinished(false, "sbom.cdx.json"),
            "GitHub Release asset `sbom.cdx.json` differs from the Candidate",
        ),
        (
            both,
            "GitHub Release reports asset `sbom.cdx.json` both as uploaded and as unfinished",
        ),
    ] {
        let error = reconcile(&target, &observed, &approved()).unwrap_err();
        assert_eq!(error.state(), ReleaseState::Conflict, "{message}");
        assert_eq!(error.to_string(), message);
    }
}

fn approved() -> ApprovalEvidence {
    ApprovalEvidence {
        approved_intent_digest: Some("1".repeat(64)),
        environment_candidate_digest: Some("2".repeat(64)),
        source_sha: None,
        manual_reason: None,
        github_oidc: Some(oidc_identity("push")),
    }
}

/// The identity in `claims`, signed and then verified, since no other path yields a verified identity.
fn signed_identity(
    claims: GithubOidcClaims,
    expected: &OidcExpectation,
    now: i64,
) -> anyhow::Result<VerifiedGithubOidc> {
    let key = RsaJwk {
        key_type: "RSA".into(),
        key_id: Some(oidc::KEY_ID.into()),
        algorithm: Some("RS256".into()),
        usage: Some("sig".into()),
        modulus: oidc::MODULUS.into(),
        exponent: oidc::EXPONENT.into(),
    };
    verify_github_oidc_token(
        &oidc::sign_rs256(&claims),
        &JwkSet { keys: vec![key] },
        expected,
        now,
    )
}

fn oidc_identity(event_name: &str) -> release_glz::authorization::VerifiedGithubOidc {
    oidc_identity_for_ref(event_name, "refs/heads/main")
}

fn oidc_identity_for_ref(
    event_name: &str,
    git_ref: &str,
) -> release_glz::authorization::VerifiedGithubOidc {
    oidc_identity_with(
        event_name,
        "owner/widget",
        "release",
        ".github/workflows/release-glz.yml",
        &"a".repeat(40),
        git_ref,
    )
}

fn oidc_identity_with(
    event_name: &str,
    repository: &str,
    environment: &str,
    workflow_path: &str,
    source_sha: &str,
    git_ref: &str,
) -> release_glz::authorization::VerifiedGithubOidc {
    let now = 1_800_000_000;
    signed_identity(
        GithubOidcClaims {
            issuer: "https://token.actions.githubusercontent.com".into(),
            audience: OidcAudience::One("release-glz".into()),
            subject: format!("repo:{repository}:environment:{environment}"),
            repository: repository.into(),
            environment: Some(environment.into()),
            workflow_ref: format!("{repository}/{workflow_path}@{git_ref}"),
            git_ref: git_ref.into(),
            source_sha: source_sha.into(),
            run_id: "42".into(),
            run_attempt: "1".into(),
            event_name: event_name.into(),
            issued_at: now - 1,
            not_before: Some(now - 1),
            expires_at: now + 60,
        },
        &OidcExpectation {
            repository: repository.into(),
            environment: environment.into(),
            workflow_path: workflow_path.into(),
            source_sha: source_sha.into(),
            run_id: Some("42".into()),
        },
        now,
    )
    .unwrap()
}

#[test]
fn a_preview_lists_what_reconcile_withholds_without_approval_and_still_checks_the_world() {
    let observed = ExternalReleaseState::default();
    let withheld = reconcile(&intent(), &observed, &ApprovalEvidence::default()).unwrap();
    assert_eq!(withheld.state, ReleaseState::AwaitingApproval);
    assert!(withheld.effects.is_empty());
    assert_eq!(
        preview(&intent(), &observed).unwrap(),
        reconcile(&intent(), &observed, &approved()).unwrap()
    );

    let conflicting = ExternalReleaseState {
        package: Some(ObservedArtifact {
            sha256: "0".repeat(64),
        }),
        ..ExternalReleaseState::default()
    };
    assert_eq!(
        preview(&intent(), &conflicting).unwrap_err().to_string(),
        reconcile(&intent(), &conflicting, &approved())
            .unwrap_err()
            .to_string()
    );
}

#[test]
fn a_new_release_has_the_fixed_effect_order() {
    let plan = reconcile(&intent(), &ExternalReleaseState::default(), &approved()).unwrap();
    assert_eq!(plan.state, ReleaseState::CandidateReady);
    assert_eq!(
        plan.effects,
        vec![
            ReconcileEffect::PrepareAnnotatedTag,
            ReconcileEffect::PrepareGithubDraft,
            ReconcileEffect::PublishPackage,
            ReconcileEffect::PublishDocs,
            ReconcileEffect::FinalizeGithubRelease,
            ReconcileEffect::Notify {
                hook_id: "announce".into(),
                idempotency_key: plan
                    .effects
                    .last()
                    .unwrap()
                    .idempotency_key()
                    .unwrap()
                    .into(),
                required: true,
            },
        ]
    );
}

#[test]
fn matching_partial_state_resumes_and_never_repeats_completed_effects() {
    let target = intent();
    let observed = ExternalReleaseState {
        schema: "state/v1".into(),
        package: Some(ObservedArtifact {
            sha256: target.package_sha256.clone(),
        }),
        docs: None,
        tag: Some(ObservedTag {
            target_sha: target.source_sha.clone(),
            annotated: true,
        }),
        github_release: Some(ObservedGithubRelease {
            target_sha: target.source_sha.clone(),
            candidate_digest: target.candidate_digest.clone(),
            draft: true,
        }),
        release_assets: BTreeMap::new(),
        unfinished_release_assets: BTreeSet::new(),
        notifications: BTreeMap::new(),
    };
    let plan = reconcile(&target, &observed, &approved()).unwrap();
    assert_eq!(plan.state, ReleaseState::PartiallyReleased);
    assert_eq!(
        plan.effects,
        vec![
            ReconcileEffect::PublishDocs,
            ReconcileEffect::FinalizeGithubRelease,
            ReconcileEffect::Notify {
                hook_id: "announce".into(),
                idempotency_key: plan
                    .effects
                    .last()
                    .unwrap()
                    .idempotency_key()
                    .unwrap()
                    .into(),
                required: true,
            },
        ]
    );
}

#[test]
fn any_existing_object_with_different_identity_is_a_hard_conflict() {
    let target = intent();
    let states = [
        ExternalReleaseState {
            package: Some(ObservedArtifact {
                sha256: "f".repeat(64),
            }),
            ..ExternalReleaseState::default()
        },
        ExternalReleaseState {
            tag: Some(ObservedTag {
                target_sha: "b".repeat(40),
                annotated: true,
            }),
            ..ExternalReleaseState::default()
        },
        ExternalReleaseState {
            github_release: Some(ObservedGithubRelease {
                target_sha: target.source_sha.clone(),
                candidate_digest: "e".repeat(64),
                draft: true,
            }),
            ..ExternalReleaseState::default()
        },
    ];
    for state in states {
        let error = reconcile(&target, &state, &approved()).unwrap_err();
        assert_eq!(error.state(), ReleaseState::Conflict);
    }
}

#[test]
fn authorization_is_bound_to_both_digests_and_the_signed_environment() {
    let target = intent();
    for evidence in [
        ApprovalEvidence {
            approved_intent_digest: None,
            ..approved()
        },
        ApprovalEvidence {
            environment_candidate_digest: Some("0".repeat(64)),
            ..approved()
        },
        ApprovalEvidence {
            github_oidc: Some(oidc_identity_with(
                "push",
                "owner/widget",
                "staging",
                ".github/workflows/release-glz.yml",
                &target.source_sha,
                "refs/heads/main",
            )),
            ..approved()
        },
        ApprovalEvidence {
            github_oidc: None,
            ..approved()
        },
    ] {
        let plan = reconcile(&target, &ExternalReleaseState::default(), &evidence).unwrap();
        assert_eq!(plan.state, ReleaseState::AwaitingApproval);
        assert!(plan.effects.is_empty());
    }
}

#[test]
fn authorization_rejects_each_oidc_identity_field_independently() {
    let target = intent();
    let identities = [
        oidc_identity_with(
            "push",
            "other/widget",
            "release",
            ".github/workflows/release-glz.yml",
            &target.source_sha,
            "refs/heads/main",
        ),
        oidc_identity_with(
            "push",
            "owner/widget",
            "staging",
            ".github/workflows/release-glz.yml",
            &target.source_sha,
            "refs/heads/main",
        ),
        oidc_identity_with(
            "push",
            "owner/widget",
            "release",
            ".github/workflows/release-glz.yml",
            &"b".repeat(40),
            "refs/heads/main",
        ),
        oidc_identity_with(
            "push",
            "owner/widget",
            "release",
            ".github/workflows/other.yml",
            &target.source_sha,
            "refs/heads/main",
        ),
    ];
    for identity in identities {
        let evidence = ApprovalEvidence {
            github_oidc: Some(identity),
            ..approved()
        };
        let plan = reconcile(&target, &ExternalReleaseState::default(), &evidence).unwrap();
        assert_eq!(plan.state, ReleaseState::AwaitingApproval);
        assert!(plan.effects.is_empty());
    }
}

#[test]
fn completed_notifications_are_keyed_by_candidate_and_hook() {
    let target = intent();
    let first = reconcile(&target, &ExternalReleaseState::default(), &approved()).unwrap();
    let key = first
        .effects
        .last()
        .unwrap()
        .idempotency_key()
        .unwrap()
        .to_owned();
    let observed = ExternalReleaseState {
        schema: "state/v1".into(),
        package: Some(ObservedArtifact {
            sha256: target.package_sha256.clone(),
        }),
        docs: Some(ObservedArtifact {
            sha256: target.docs_sha256.clone().unwrap(),
        }),
        tag: Some(ObservedTag {
            target_sha: target.source_sha.clone(),
            annotated: true,
        }),
        github_release: Some(ObservedGithubRelease {
            target_sha: target.source_sha.clone(),
            candidate_digest: target.candidate_digest.clone(),
            draft: false,
        }),
        release_assets: BTreeMap::new(),
        unfinished_release_assets: BTreeSet::new(),
        notifications: BTreeMap::from([(
            "announce".into(),
            NotifyObservation {
                idempotency_key: key,
                complete: true,
            },
        )]),
    };
    let plan = reconcile(&target, &observed, &approved()).unwrap();
    assert_eq!(plan.state, ReleaseState::Released);
    assert!(plan.effects.is_empty());
}

#[test]
fn incomplete_matching_notification_is_retried_and_marks_the_release_partial() {
    let target = intent();
    let key = notification_key(&target.candidate_digest, "announce");
    let observed = ExternalReleaseState {
        notifications: BTreeMap::from([(
            "announce".into(),
            NotifyObservation {
                idempotency_key: key.clone(),
                complete: false,
            },
        )]),
        ..ExternalReleaseState::default()
    };

    let plan = reconcile(&target, &observed, &approved()).unwrap();
    assert_eq!(plan.state, ReleaseState::PartiallyReleased);
    assert!(plan.effects.contains(&ReconcileEffect::Notify {
        hook_id: "announce".into(),
        idempotency_key: key,
        required: true,
    }));
}

#[test]
fn notification_key_is_a_domain_separated_binding_of_candidate_and_hook() {
    let candidate = "2".repeat(64);
    let key = notification_key(&candidate, "announce");
    assert_eq!(key.len(), 64);
    assert!(
        key.bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    );
    assert_ne!(key, notification_key(&"3".repeat(64), "announce"));
    assert_ne!(key, notification_key(&candidate, "audit"));
    // `printf 'release-glz-notify-v1\0%s\0announce' "$candidate" | shasum -a 256` gives the same value, which changes only when the framing does.
    assert_eq!(
        key,
        "474fda2d6d36b965fe2ef090d334f7e5cf7423feff59281dbb846c0da11ba4df"
    );
}

#[test]
fn optional_notifications_are_planned_but_do_not_make_a_published_core_partial() {
    let mut target = intent();
    target.notify_hooks = vec![NotifyHookIntent {
        id: "best-effort".into(),
        required: false,
    }];
    let observed = ExternalReleaseState {
        package: Some(ObservedArtifact {
            sha256: target.package_sha256.clone(),
        }),
        docs: Some(ObservedArtifact {
            sha256: target.docs_sha256.clone().unwrap(),
        }),
        tag: Some(ObservedTag {
            target_sha: target.source_sha.clone(),
            annotated: true,
        }),
        github_release: Some(ObservedGithubRelease {
            target_sha: target.source_sha.clone(),
            candidate_digest: target.candidate_digest.clone(),
            draft: false,
        }),
        ..ExternalReleaseState::default()
    };

    let plan = reconcile(&target, &observed, &approved()).unwrap();
    assert_eq!(plan.state, ReleaseState::Released);
    assert!(matches!(
        plan.effects.as_slice(),
        [ReconcileEffect::Notify {
            hook_id,
            required: false,
            ..
        }] if hook_id == "best-effort"
    ));
}

#[test]
fn push_and_manual_workflow_approvals_cannot_be_substituted_for_each_other() {
    let target = intent();
    let missing_intent = ApprovalEvidence {
        approved_intent_digest: None,
        source_sha: Some(target.source_sha.clone()),
        manual_reason: Some("Emergency release after incident review".into()),
        github_oidc: Some(oidc_identity("workflow_dispatch")),
        ..approved()
    };
    assert_eq!(
        reconcile(&target, &ExternalReleaseState::default(), &missing_intent)
            .unwrap()
            .state,
        ReleaseState::AwaitingApproval
    );

    let wrong_intent = ApprovalEvidence {
        approved_intent_digest: Some("0".repeat(64)),
        ..missing_intent.clone()
    };
    assert_eq!(
        reconcile(&target, &ExternalReleaseState::default(), &wrong_intent)
            .unwrap()
            .state,
        ReleaseState::AwaitingApproval
    );

    let manual = ApprovalEvidence {
        approved_intent_digest: Some(target.intent_digest.clone()),
        ..missing_intent
    };
    assert_ne!(
        reconcile(&target, &ExternalReleaseState::default(), &manual)
            .unwrap()
            .state,
        ReleaseState::AwaitingApproval
    );

    let wrong_ref = ApprovalEvidence {
        github_oidc: Some(oidc_identity_for_ref(
            "workflow_dispatch",
            "refs/heads/unapproved",
        )),
        ..manual.clone()
    };
    assert_eq!(
        reconcile(&target, &ExternalReleaseState::default(), &wrong_ref)
            .unwrap()
            .state,
        ReleaseState::AwaitingApproval
    );

    let dispatch_with_pr_only = ApprovalEvidence {
        source_sha: None,
        manual_reason: None,
        github_oidc: Some(oidc_identity("workflow_dispatch")),
        ..approved()
    };
    assert_eq!(
        reconcile(
            &target,
            &ExternalReleaseState::default(),
            &dispatch_with_pr_only
        )
        .unwrap()
        .state,
        ReleaseState::AwaitingApproval
    );

    let push_with_manual_only = ApprovalEvidence {
        approved_intent_digest: None,
        source_sha: Some(target.source_sha.clone()),
        manual_reason: Some("not valid on push".into()),
        ..approved()
    };
    assert_eq!(
        reconcile(
            &target,
            &ExternalReleaseState::default(),
            &push_with_manual_only
        )
        .unwrap()
        .state,
        ReleaseState::AwaitingApproval
    );
}

#[test]
fn github_release_output_policy_removes_draft_and_finalize_effects() {
    let mut target = intent();
    target.github_release = false;
    let plan = reconcile(&target, &ExternalReleaseState::default(), &approved()).unwrap();
    assert!(!plan.effects.contains(&ReconcileEffect::PrepareGithubDraft));
    assert!(
        !plan
            .effects
            .contains(&ReconcileEffect::FinalizeGithubRelease)
    );
    assert!(plan.effects.contains(&ReconcileEffect::PrepareAnnotatedTag));
    assert!(plan.effects.contains(&ReconcileEffect::PublishPackage));

    let observed = ExternalReleaseState {
        github_release: Some(ObservedGithubRelease {
            target_sha: target.source_sha.clone(),
            candidate_digest: target.candidate_digest.clone(),
            draft: true,
        }),
        ..ExternalReleaseState::default()
    };
    assert_eq!(
        reconcile(&target, &observed, &approved())
            .unwrap_err()
            .state(),
        ReleaseState::Conflict
    );
}

#[test]
fn every_immutable_external_identity_mismatch_is_a_hard_conflict() {
    let mut target = intent();
    target.release_assets = vec![ReleaseAsset {
        hook_id: "sbom".into(),
        name: "sbom.cdx.json".into(),
        media_type: "application/vnd.cyclonedx+json".into(),
        sha256: "5".repeat(64),
        size: 12,
    }];
    let release = |target_sha: String, candidate_digest: String| {
        Some(ObservedGithubRelease {
            target_sha,
            candidate_digest,
            draft: true,
        })
    };
    let cases = [
        (
            ExternalReleaseState {
                schema: "state/v2".into(),
                ..ExternalReleaseState::default()
            },
            "unsupported external state schema `state/v2`",
        ),
        (
            ExternalReleaseState {
                package: Some(ObservedArtifact {
                    sha256: "f".repeat(64),
                }),
                ..ExternalReleaseState::default()
            },
            "the published package checksum differs from the Candidate",
        ),
        (
            ExternalReleaseState {
                docs: Some(ObservedArtifact {
                    sha256: "f".repeat(64),
                }),
                ..ExternalReleaseState::default()
            },
            "the published documentation checksum differs from the Candidate",
        ),
        (
            ExternalReleaseState {
                tag: Some(ObservedTag {
                    target_sha: target.source_sha.clone(),
                    annotated: false,
                }),
                ..ExternalReleaseState::default()
            },
            "the existing git tag has a different immutable identity",
        ),
        (
            ExternalReleaseState {
                github_release: release("b".repeat(40), target.candidate_digest.clone()),
                ..ExternalReleaseState::default()
            },
            "the existing GitHub Release differs from the Candidate",
        ),
        (
            ExternalReleaseState {
                github_release: release(target.source_sha.clone(), "e".repeat(64)),
                ..ExternalReleaseState::default()
            },
            "the existing GitHub Release differs from the Candidate",
        ),
        (
            ExternalReleaseState {
                release_assets: BTreeMap::from([(
                    "surprise.bin".into(),
                    ObservedArtifact {
                        sha256: "f".repeat(64),
                    },
                )]),
                ..ExternalReleaseState::default()
            },
            "GitHub Release contains unsealed asset `surprise.bin`",
        ),
        (
            ExternalReleaseState {
                release_assets: BTreeMap::from([(
                    "sbom.cdx.json".into(),
                    ObservedArtifact {
                        sha256: "f".repeat(64),
                    },
                )]),
                ..ExternalReleaseState::default()
            },
            "GitHub Release asset `sbom.cdx.json` differs from the Candidate",
        ),
        (
            ExternalReleaseState {
                notifications: BTreeMap::from([(
                    "announce".into(),
                    NotifyObservation {
                        idempotency_key: "wrong".into(),
                        complete: true,
                    },
                )]),
                ..ExternalReleaseState::default()
            },
            "notify hook `announce` completed under a different idempotency key",
        ),
    ];
    for (observed, message) in cases {
        let error = reconcile(&target, &observed, &approved()).unwrap_err();
        assert_eq!(error.state(), ReleaseState::Conflict, "{message}");
        assert_eq!(error.to_string(), message);
        assert_eq!(
            preview(&target, &observed).unwrap_err().to_string(),
            message,
            "an inspection must refuse the same world"
        );
    }
}

/// When the world contradicts the Candidate in more than one object, the first object in publication order names the conflict.
#[test]
fn the_first_object_in_publication_order_names_the_conflict() {
    let target = intent();
    let observed = ExternalReleaseState {
        package: Some(ObservedArtifact {
            sha256: "f".repeat(64),
        }),
        tag: Some(ObservedTag {
            target_sha: "b".repeat(40),
            annotated: true,
        }),
        ..ExternalReleaseState::default()
    };
    assert_eq!(
        reconcile(&target, &observed, &approved())
            .unwrap_err()
            .to_string(),
        "the existing git tag has a different immutable identity"
    );
}

/// A notification record for a hook that the Candidate doesn't have is no object of this release.
#[test]
fn a_record_for_a_hook_outside_the_candidate_neither_conflicts_nor_starts_the_release() {
    let target = intent();
    let observed = ExternalReleaseState {
        notifications: BTreeMap::from([(
            "retired".into(),
            NotifyObservation {
                idempotency_key: "any".into(),
                complete: true,
            },
        )]),
        ..ExternalReleaseState::default()
    };
    let plan = reconcile(&target, &observed, &approved()).unwrap();
    assert_eq!(plan.state, ReleaseState::CandidateReady);
}

#[test]
fn output_policy_and_candidate_asset_identity_fail_closed_before_effects() {
    let mut no_docs = intent();
    no_docs.docs_sha256 = None;
    let unexpected_docs = ExternalReleaseState {
        docs: Some(ObservedArtifact {
            sha256: "4".repeat(64),
        }),
        ..ExternalReleaseState::default()
    };
    assert_eq!(
        reconcile(&no_docs, &unexpected_docs, &approved())
            .unwrap_err()
            .to_string(),
        "documentation exists but the Candidate contains none"
    );

    let mut no_release = intent();
    no_release.github_release = false;
    let unexpected_release = ExternalReleaseState {
        github_release: Some(ObservedGithubRelease {
            target_sha: no_release.source_sha.clone(),
            candidate_digest: no_release.candidate_digest.clone(),
            draft: false,
        }),
        ..ExternalReleaseState::default()
    };
    assert_eq!(
        reconcile(&no_release, &unexpected_release, &approved())
            .unwrap_err()
            .to_string(),
        "a GitHub Release exists but the Candidate disables it"
    );

    let mut disabled = intent();
    disabled.github_release = false;
    disabled.release_assets = vec![ReleaseAsset {
        hook_id: "sbom".into(),
        name: "sbom.cdx.json".into(),
        media_type: "application/vnd.cyclonedx+json".into(),
        sha256: "5".repeat(64),
        size: 12,
    }];
    assert_eq!(
        reconcile(&disabled, &ExternalReleaseState::default(), &approved())
            .unwrap_err()
            .to_string(),
        "the Candidate requests release assets while GitHub Releases are disabled"
    );

    let mut duplicate = intent();
    let asset = ReleaseAsset {
        hook_id: "evidence".into(),
        name: "same.bin".into(),
        media_type: "application/octet-stream".into(),
        sha256: "6".repeat(64),
        size: 1,
    };
    duplicate.release_assets = vec![asset.clone(), asset];
    assert_eq!(
        reconcile(&duplicate, &ExternalReleaseState::default(), &approved())
            .unwrap_err()
            .to_string(),
        "duplicate Candidate release asset `same.bin`"
    );
}

#[test]
fn state_machine_property_never_repeats_an_observed_matching_stage() {
    let target = intent();
    for mask in 0_u8..16 {
        let package = (mask & 1 != 0).then(|| ObservedArtifact {
            sha256: target.package_sha256.clone(),
        });
        let docs = (mask & 2 != 0).then(|| ObservedArtifact {
            sha256: target.docs_sha256.clone().unwrap(),
        });
        let tag = (mask & 4 != 0).then(|| ObservedTag {
            target_sha: target.source_sha.clone(),
            annotated: true,
        });
        let github_release = (mask & 8 != 0).then(|| ObservedGithubRelease {
            target_sha: target.source_sha.clone(),
            candidate_digest: target.candidate_digest.clone(),
            draft: true,
        });
        let observed = ExternalReleaseState {
            package,
            docs,
            tag,
            github_release,
            ..ExternalReleaseState::default()
        };
        let plan = reconcile(&target, &observed, &approved()).unwrap();
        assert_eq!(
            plan.effects.contains(&ReconcileEffect::PublishPackage),
            mask & 1 == 0,
            "mask {mask:04b}"
        );
        assert_eq!(
            plan.effects.contains(&ReconcileEffect::PublishDocs),
            mask & 2 == 0,
            "mask {mask:04b}"
        );
        assert_eq!(
            plan.effects.contains(&ReconcileEffect::PrepareAnnotatedTag),
            mask & 4 == 0,
            "mask {mask:04b}"
        );
        assert_eq!(
            plan.effects.contains(&ReconcileEffect::PrepareGithubDraft),
            mask & 8 == 0,
            "mask {mask:04b}"
        );
        assert_eq!(
            plan.state,
            if mask == 0 {
                ReleaseState::CandidateReady
            } else {
                ReleaseState::PartiallyReleased
            }
        );
    }

    assert_eq!(ReconcileEffect::PublishPackage.idempotency_key(), None);
}
