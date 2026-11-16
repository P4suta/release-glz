//! Failure classes shared by the CLI exit status and the `command/v1` error code, and the reasons that name typed refusals within a class.

use std::fmt;

use anyhow::Error;
use serde::{Deserialize, Serialize};

/// Stable classes shared by the CLI exit status and machine-readable error code.
///
/// The error type carries the class, so message text can never change the exit status.
/// Each discriminant is the class's exit status, a public contract documented in the README; callers branch on it, so a code can never be reused for another class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(i32)]
pub enum FailureClass {
    /// A defect, or a boundary error that carries no more precise class.
    Internal = 1,
    /// Invalid arguments, manifest, or repository state that the caller has to correct.
    UsageOrConfig = 2,
    /// A policy, approval, or authorization requirement that is not met.
    PolicyOrApproval = 3,
    /// An already published object differs from what this run would write.
    ///
    /// Republishing is never attempted; the conflict is reported instead.
    ImmutableStateConflict = 4,
    /// A transient registry, GitHub, or network failure that may be retried.
    TemporaryExternal = 5,
    /// A configured hook failed, timed out, or produced invalid evidence.
    Hook = 6,
    /// Publication stopped part way and can be resumed monotonically.
    PartialRelease = 7,
}

impl FailureClass {
    /// Every class, in the order of its exit status.
    pub const ALL: [Self; 7] = [
        Self::Internal,
        Self::UsageOrConfig,
        Self::PolicyOrApproval,
        Self::ImmutableStateConflict,
        Self::TemporaryExternal,
        Self::Hook,
        Self::PartialRelease,
    ];

    /// The process exit status for this class.
    pub const fn exit_code(self) -> i32 {
        self as i32
    }

    /// The stable diagnostic code emitted in `command/v1` output.
    pub const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::Internal => "internal_failure",
            Self::UsageOrConfig => "usage_or_config",
            Self::PolicyOrApproval => "policy_or_approval",
            Self::ImmutableStateConflict => "immutable_state_conflict",
            Self::TemporaryExternal => "temporary_external_failure",
            Self::Hook => "hook_failure",
            Self::PartialRelease => "partial_release",
        }
    }
}

/// Declares [`RefusalReason`] from one list, so its variants, [`RefusalReason::ALL`], and both exhaustive matches can't drift apart.
macro_rules! refusal_reasons {
    ($($(#[doc = $meaning:literal])+ $reason:ident => $code:literal, $class:ident;)+) => {
        /// A refusal that release-glz names, so a consumer tells refusals of one class apart without reading the message.
        ///
        /// The reason decides the class, and its code is the `code` of the error diagnostic in `command/v1`.
        /// Codes are public and stable: a code is never reused for another refusal.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum RefusalReason {
            $($(#[doc = $meaning])+ $reason,)+
        }

        impl RefusalReason {
            /// Every reason, in declaration order.
            pub const ALL: &[Self] = &[$(Self::$reason),+];

            /// The stable `snake_case` code of the error diagnostic.
            pub const fn code(self) -> &'static str {
                match self {
                    $(Self::$reason => $code,)+
                }
            }

            /// The class, and so the exit status, of this refusal.
            pub const fn class(self) -> FailureClass {
                match self {
                    $(Self::$reason => FailureClass::$class,)+
                }
            }
        }
    };
}

refusal_reasons! {
    /// The manifest has no `[tools.release-glz]` table.
    ConfigMissing => "config_missing", UsageOrConfig;
    /// The `[tools.release-glz]` table sets a `schema` other than 2.
    ConfigSchemaUnsupported => "config_schema_unsupported", UsageOrConfig;
    /// The `[tools.release-glz]` table has an unknown key, lacks a required key, or holds a value of the wrong type.
    ConfigTableInvalid => "config_table_invalid", UsageOrConfig;
    /// The manifest changed on disk after release-glz read it, so it isn't replaced.
    ManifestChanged => "manifest_changed", ImmutableStateConflict;
    /// A package name isn't one Hex accepts.
    PackageNameInvalid => "package_name_invalid", UsageOrConfig;
    /// A configured path is empty or not `/`-separated.
    PathNotRelative => "path_not_relative", UsageOrConfig;
    /// A configured path leaves the repository.
    PathOutsideRepository => "path_outside_repository", UsageOrConfig;
    /// A git ref is unsafe, or git itself would refuse it.
    GitRefUnsafe => "git_ref_unsafe", UsageOrConfig;
    /// A ref prefix, such as the release branch prefix, could produce an unsafe ref.
    GitRefPrefixUnsafe => "git_ref_prefix_unsafe", UsageOrConfig;
    /// A hook id isn't a safe name.
    HookIdUnsafe => "hook_id_unsafe", UsageOrConfig;
    /// A hook takes the id of the evidence that release-glz builds itself.
    HookIdReserved => "hook_id_reserved", UsageOrConfig;
    /// A hook argv is empty or holds an empty or NUL-containing argument.
    HookArgvInvalid => "hook_argv_invalid", UsageOrConfig;
    /// A hook timeout lies outside the permitted range.
    HookTimeoutOutOfRange => "hook_timeout_out_of_range", UsageOrConfig;
    /// A hook allows an environment variable whose name is invalid.
    HookEnvInvalid => "hook_env_invalid", UsageOrConfig;
    /// A hook allows a credential or a GitHub control file that no hook may receive.
    HookEnvProtected => "hook_env_protected", UsageOrConfig;
    /// The registry credential setting isn't the name of an environment variable.
    CredentialEnvInvalid => "credential_env_invalid", UsageOrConfig;
    /// The Hex organization isn't a safe single path segment.
    RegistryRepositoryInvalid => "registry_repository_invalid", UsageOrConfig;
    /// A configured URL carries credentials.
    UrlCredentials => "url_credentials", UsageOrConfig;
    /// A configured URL isn't absolute and hierarchical.
    UrlNotHierarchical => "url_not_hierarchical", UsageOrConfig;
    /// A configured URL carries a query or a fragment.
    UrlQueryOrFragment => "url_query_or_fragment", UsageOrConfig;
    /// A configured URL uses neither HTTPS nor HTTP to a numeric loopback address.
    UrlTransportUntrusted => "url_transport_untrusted", UsageOrConfig;
    /// The approval Environment name is empty or spans lines.
    ApprovalEnvironmentInvalid => "approval_environment_invalid", UsageOrConfig;
    /// An approval path names a mode other than its fixed one.
    ApprovalModeFixed => "approval_mode_fixed", UsageOrConfig;
    /// The private repository fallback names an unsupported value.
    ApprovalFallbackUnsupported => "approval_fallback_unsupported", UsageOrConfig;
    /// A manual release ref names neither a branch nor a tag.
    ManualRefKindUnsupported => "manual_ref_kind_unsupported", UsageOrConfig;
    /// A manual release ref is listed twice.
    ManualRefDuplicate => "manual_ref_duplicate", UsageOrConfig;
    /// Two API exceptions name the same version.
    ApiExceptionDuplicate => "api_exception_duplicate", UsageOrConfig;
    /// An API exception gives no reason.
    ApiExceptionReasonMissing => "api_exception_reason_missing", UsageOrConfig;
    /// An API exception expiry isn't a `YYYY-MM-DD` date.
    ApiExceptionExpiryInvalid => "api_exception_expiry_invalid", UsageOrConfig;
    /// A GitHub repository isn't an `owner/name` that GitHub accepts.
    GithubRepositoryInvalid => "github_repository_invalid", UsageOrConfig;
    /// A command that writes to GitHub has neither `GITHUB_TOKEN` nor `GH_TOKEN`.
    GithubTokenMissing => "github_token_missing", TemporaryExternal;
    /// The GitHub Environment to audit has an empty name.
    GithubEnvironmentEmpty => "github_environment_empty", UsageOrConfig;
    /// GitHub reports no default branch for the repository.
    GithubDefaultBranchMissing => "github_default_branch_missing", UsageOrConfig;
    /// The managed Release PR at the Candidate head describes another release.
    ReleasePrMarkerMismatch => "release_pr_marker_mismatch", TemporaryExternal;
    /// The managed Release PR head isn't the generated commit that GitHub verified.
    ReleasePrHeadUnverified => "release_pr_head_unverified", TemporaryExternal;
    /// The managed Release PR is already bound to another Candidate intent.
    ReleasePrIntentConflict => "release_pr_intent_conflict", TemporaryExternal;
    /// The managed Release PR changed while its intent was being bound.
    ReleasePrChanged => "release_pr_changed", TemporaryExternal;
    /// A push publishes a Candidate that another run prepared.
    CandidateRunFromAnotherPush => "candidate_run_from_another_push", PolicyOrApproval;
    /// A manual promotion names a Candidate from its own run.
    CandidateRunPromotesItself => "candidate_run_promotes_itself", PolicyOrApproval;
    /// An event other than a push or a manual promotion publishes a Candidate.
    CandidateRunEventUnsupported => "candidate_run_event_unsupported", PolicyOrApproval;
    /// The release approval can't verify its Actions artifact without `GITHUB_TOKEN` or `GH_TOKEN`.
    ApprovalGithubTokenMissing => "approval_github_token_missing", PolicyOrApproval;
    /// The Actions artifact ID or digest that the approval names is malformed.
    ActionsArtifactIdentityInvalid => "actions_artifact_identity_invalid", PolicyOrApproval;
    /// The Actions run ID that the approval names isn't a canonical number.
    ActionsRunIdInvalid => "actions_run_id_invalid", PolicyOrApproval;
    /// The Candidate's Actions artifact has expired.
    ActionsArtifactExpired => "actions_artifact_expired", PolicyOrApproval;
    /// The Actions artifact doesn't match its sealed run, source, and digest.
    ActionsArtifactMismatch => "actions_artifact_mismatch", PolicyOrApproval;
    /// The Actions run doesn't match the repository, managed workflow, source, and required state.
    ActionsRunMismatch => "actions_run_mismatch", PolicyOrApproval;
    /// An annotated tag on GitHub targets something other than a commit.
    GithubTagTargetNotCommit => "github_tag_target_not_commit", TemporaryExternal;
    /// A tag ref on GitHub points at an unsupported object type.
    GithubTagObjectUnsupported => "github_tag_object_unsupported", TemporaryExternal;
    /// GitHub created an annotated tag object other than the one requested.
    GithubTagCreationUnexpected => "github_tag_creation_unexpected", TemporaryExternal;
    /// Two or more GitHub Releases have the Candidate's tag.
    GithubReleaseTagAmbiguous => "github_release_tag_ambiguous", ImmutableStateConflict;
    /// A Release asset upload targets a Release that is no longer a draft.
    ReleaseAssetDraftRequired => "release_asset_draft_required", TemporaryExternal;
    /// A Release asset name is unsafe.
    ReleaseAssetNameUnsafe => "release_asset_name_unsafe", TemporaryExternal;
    /// A Release asset media type is invalid.
    ReleaseAssetMediaTypeInvalid => "release_asset_media_type_invalid", TemporaryExternal;
    /// GitHub's Release upload URL is malformed.
    ReleaseUploadUrlMalformed => "release_upload_url_malformed", TemporaryExternal;
    /// GitHub's Release upload URL has an untrusted origin.
    ReleaseUploadUrlUntrusted => "release_upload_url_untrusted", TemporaryExternal;
    /// GitHub's Release upload URL names another repository or Release.
    ReleaseUploadUrlMismatch => "release_upload_url_mismatch", TemporaryExternal;
    /// GitHub reports an uploaded Release asset whose identity differs from the bytes sent.
    ReleaseAssetUploadUnexpected => "release_asset_upload_unexpected", TemporaryExternal;
    /// A Release asset to delete belongs to a published Release.
    ReleaseAssetOnPublishedRelease => "release_asset_on_published_release", TemporaryExternal;
    /// A Release asset to delete is already uploaded.
    ReleaseAssetUploaded => "release_asset_uploaded", TemporaryExternal;
    /// The Release has no asset of the name to delete.
    ReleaseAssetMissing => "release_asset_missing", TemporaryExternal;
    /// The Release has two assets of the name to delete.
    ReleaseAssetDuplicate => "release_asset_duplicate", TemporaryExternal;
    /// A Release asset to delete has no id.
    ReleaseAssetIdMissing => "release_asset_id_missing", TemporaryExternal;
    /// A `--candidate` path isn't a directory.
    CandidateNotDirectory => "candidate_not_directory", UsageOrConfig;
    /// The Candidate destination already exists, and a sealed Candidate is never replaced.
    CandidateDestinationExists => "candidate_destination_exists", ImmutableStateConflict;
    /// The Candidate source commit isn't a commit ID of 40 lowercase hexadecimal digits.
    CandidateSourceCommitInvalid => "candidate_source_commit_invalid", UsageOrConfig;
    /// The Candidate tag is a full ref or a peeled ref.
    CandidateTagUnsafe => "candidate_tag_unsafe", UsageOrConfig;
    /// The Candidate tag doesn't end with the Candidate version.
    CandidateTagVersionMismatch => "candidate_tag_version_mismatch", UsageOrConfig;
    /// The Candidate release notes hold a NUL or exceed 1 MiB.
    CandidateReleaseNotesInvalid => "candidate_release_notes_invalid", UsageOrConfig;
    /// The Candidate lists no manual release ref.
    ManualRefsEmpty => "manual_refs_empty", UsageOrConfig;
    /// Two hooks share an id.
    HookIdDuplicate => "hook_id_duplicate", UsageOrConfig;
    /// A notify hook id is empty or listed twice.
    NotifyHookIdInvalid => "notify_hook_id_invalid", UsageOrConfig;
    /// The sealed notify hook definitions don't match the ordered notify hook ids.
    NotifyHooksMismatch => "notify_hooks_mismatch", UsageOrConfig;
    /// The documentation archive's presence contradicts `outputs.docs`.
    CandidateDocsPolicyMismatch => "candidate_docs_policy_mismatch", UsageOrConfig;
    /// The package interface exceeds the archive size limit.
    CandidateInterfaceTooLarge => "candidate_interface_too_large", UsageOrConfig;
    /// The Candidate manifest names an unsupported schema.
    CandidateSchemaUnsupported => "candidate_schema_unsupported", ImmutableStateConflict;
    /// The Candidate manifest isn't the strict JSON that a seal writes.
    CandidateManifestInvalid => "candidate_manifest_invalid", ImmutableStateConflict;
    /// A Candidate file isn't a regular file.
    CandidateFileNotRegular => "candidate_file_not_regular", ImmutableStateConflict;
    /// A Candidate file exceeds its size limit.
    CandidateFileTooLarge => "candidate_file_too_large", ImmutableStateConflict;
    /// A Candidate artifact sits at a path other than its fixed one.
    CandidateArtifactPathUnexpected => "candidate_artifact_path_unexpected", ImmutableStateConflict;
    /// A checksum that the Candidate records isn't a lowercase SHA-256 digest.
    CandidateChecksumMalformed => "candidate_checksum_malformed", ImmutableStateConflict;
    /// A Candidate file's size or SHA-256 differs from what the Candidate records.
    CandidateChecksumMismatch => "candidate_checksum_mismatch", ImmutableStateConflict;
    /// The Candidate directory holds files or directories other than the sealed ones.
    CandidateInventoryMismatch => "candidate_inventory_mismatch", ImmutableStateConflict;
    /// An archive's semantic checksum differs from what the Candidate records.
    CandidateSemanticChecksumMismatch => "candidate_semantic_checksum_mismatch", ImmutableStateConflict;
    /// The Candidate's intent digest differs from the intent it records.
    CandidateIntentDigestMismatch => "candidate_intent_digest_mismatch", ImmutableStateConflict;
    /// The Candidate digest differs from the manifest it records.
    CandidateDigestMismatch => "candidate_digest_mismatch", ImmutableStateConflict;
    /// Hook evidence names an unsupported schema, or an empty or duplicate id.
    CandidateHookEvidenceInvalid => "candidate_hook_evidence_invalid", ImmutableStateConflict;
    /// A required hook did not succeed.
    CandidateHookFailed => "candidate_hook_failed", ImmutableStateConflict;
    /// Hook evidence doesn't match the configured verify and sidecar hooks.
    CandidateHookEvidenceMismatch => "candidate_hook_evidence_mismatch", ImmutableStateConflict;
    /// A sidecar artifact comes from a hook that the Candidate doesn't declare.
    CandidateSidecarProducerUndeclared => "candidate_sidecar_producer_undeclared", ImmutableStateConflict;
    /// The Candidate carries more sidecar artifacts than the limit.
    CandidateSidecarsTooMany => "candidate_sidecars_too_many", ImmutableStateConflict;
    /// A sidecar artifact path is invalid or duplicated.
    CandidateSidecarPathInvalid => "candidate_sidecar_path_invalid", ImmutableStateConflict;
    /// The sidecar artifacts exceed their size limit.
    CandidateSidecarsTooLarge => "candidate_sidecars_too_large", ImmutableStateConflict;
    /// A public sidecar artifact needs `outputs.github_release`.
    CandidateSidecarReleaseDisabled => "candidate_sidecar_release_disabled", ImmutableStateConflict;
    /// A public sidecar artifact of a private package needs `outputs.allow_private_evidence_upload`.
    CandidateSidecarPrivateUploadForbidden => "candidate_sidecar_private_upload_forbidden", ImmutableStateConflict;
    /// Two public sidecar artifacts share a GitHub Release asset name.
    CandidateSidecarNameDuplicate => "candidate_sidecar_name_duplicate", ImmutableStateConflict;
    /// The built-in SBOM or provenance evidence contradicts the output policy.
    CandidateEvidencePolicyMismatch => "candidate_evidence_policy_mismatch", ImmutableStateConflict;
    /// `outputs.signature` is set, and no signature sidecar artifact is sealed.
    CandidateSignatureMissing => "candidate_signature_missing", ImmutableStateConflict;
    /// A sidecar artifact names an unsafe hook id.
    SidecarHookIdUnsafe => "sidecar_hook_id_unsafe", Hook;
    /// A sidecar artifact name isn't one that GitHub keeps as it is.
    SidecarNameUnsafe => "sidecar_name_unsafe", Hook;
    /// A sidecar artifact media type is invalid.
    SidecarMediaTypeInvalid => "sidecar_media_type_invalid", Hook;
    /// The checkout isn't at the Candidate's source commit.
    CandidateSourceMismatch => "candidate_source_mismatch", ImmutableStateConflict;
    /// The Candidate's policy differs from the configuration at its source commit.
    CandidatePolicyDiffers => "candidate_policy_differs", ImmutableStateConflict;
    /// A private registry's credential variable is not set.
    RegistryCredentialMissing => "registry_credential_missing", PolicyOrApproval;
    /// A GitHub OIDC URL is malformed, carries credentials or a fragment, or has an origin other than GitHub's.
    OidcUrlUntrusted => "oidc_url_untrusted", PolicyOrApproval;
    /// The GitHub OIDC token isn't a well-formed RS256 compact JWS that one key of the issuer's key set verifies.
    OidcTokenUnverified => "oidc_token_unverified", PolicyOrApproval;
    /// The GitHub OIDC claims don't canonically name the trusted issuer, the release-glz audience, the sealed Candidate's repository, Environment, workflow, ref, and commit, the publishing run, and an authorized event.
    OidcClaimsMismatch => "oidc_claims_mismatch", PolicyOrApproval;
    /// The GitHub OIDC token has expired, was issued in the future, or isn't valid yet.
    OidcTokenOutsideValidity => "oidc_token_outside_validity", PolicyOrApproval;
    /// A release step or prerelease train would pass the largest number that a version component holds.
    VersionNumberExhausted => "version_number_exhausted", UsageOrConfig;
    /// A prerelease train would move backwards, stay behind the published core, or not sort after the published version, without an explicitly higher core version.
    PrereleaseTrainBackward => "prerelease_train_backward", UsageOrConfig;
    /// An explicit version is below the version that the changes require, or doesn't belong to the configured prerelease train.
    ExplicitVersionRefused => "explicit_version_refused", UsageOrConfig;
    /// The selected version doesn't follow the published version, so there is nothing new to release.
    VersionNotAfterPublished => "version_not_after_published", UsageOrConfig;
    /// The structured changelog notes path isn't a directory, holds more note files than the limit, or holds a note that isn't a regular file within the size limit.
    ChangelogNotesLayoutInvalid => "changelog_notes_layout_invalid", Internal;
    /// A structured changelog note has an unsafe id or one other than its filename, text other than one trimmed line within the length limit, or a zero pull request.
    ChangelogNoteInvalid => "changelog_note_invalid", Internal;
    /// The installed Gleam compiler is older than the oldest one that release-glz supports.
    GleamCompilerUnsupported => "gleam_compiler_unsupported", UsageOrConfig;
    /// The package `repository` names an unsupported type, or lacks the user, repository, host, or URL that its type needs.
    GleamRepositoryInvalid => "gleam_repository_invalid", UsageOrConfig;
    /// The managed Release PR body doesn't end in exactly one release-glz marker.
    ReleasePrMarkerNotTrailing => "release_pr_marker_not_trailing", TemporaryExternal;
    /// A value that the generated workflow embeds holds characters that are unsafe in YAML, or names the default branch as a full ref.
    WorkflowInputUnsafe => "workflow_input_unsafe", UsageOrConfig;
    /// The release-glz Action pin isn't a full lowercase commit SHA.
    ActionShaInvalid => "action_sha_invalid", UsageOrConfig;
    /// The managed workflow lacks a valid managed-state record or changed after generation, so it isn't overwritten.
    WorkflowModified => "workflow_modified", ImmutableStateConflict;
    /// The registry's release response isn't valid JSON, or names an invalid version, a release other than the one observed, or a checksum that isn't a SHA-256 digest.
    RegistryReleaseInvalid => "registry_release_invalid", TemporaryExternal;
    /// A published release didn't appear on the registry within the visibility poll.
    RegistryReleaseNotVisible => "registry_release_not_visible", TemporaryExternal;
    /// An archive exceeds its compressed size, entry count, per-entry size, or expanded size limit.
    ArchiveLimitExceeded => "archive_limit_exceeded", UsageOrConfig;
    /// An archive entry path isn't a safe relative UTF-8 path that every supported OS can represent.
    ArchivePathUnsafe => "archive_path_unsafe", UsageOrConfig;
    /// An archive entry, or a file that a package publishes, isn't a regular file, or a directory entry has content.
    ArchiveEntryNotRegular => "archive_entry_not_regular", UsageOrConfig;
    /// Two archive entries name the same path, also once letter case and Unicode normalization no longer count.
    ArchiveEntryDuplicate => "archive_entry_duplicate", UsageOrConfig;
    /// An archive carries a global or link extension header, or a path extension header that is malformed, unsupported, consecutive, or dangling.
    ArchiveExtensionHeaderInvalid => "archive_extension_header_invalid", UsageOrConfig;
    /// A Hex package's `CHECKSUM` doesn't match its `VERSION`, `metadata.config`, and `contents.tar.gz`.
    HexInnerChecksumMismatch => "hex_inner_checksum_mismatch", UsageOrConfig;
    /// A verify or sidecar hook changed the snapshot that it ran against.
    HookSnapshotModified => "hook_snapshot_modified", Hook;
    /// A hook ran past its timeout and was terminated.
    HookTimedOut => "hook_timed_out", Hook;
    /// A required verify or sidecar hook, or a notify hook delivering its notification, exited unsuccessfully or reported failure.
    HookReportedFailure => "hook_reported_failure", Hook;
    /// A required notify hook exited unsuccessfully or reported failure while observing whether its notification was delivered.
    HookObservationFailed => "hook_observation_failed", Hook;
    /// A hook wrote more to stdout or stderr than its limit.
    HookOutputLimitExceeded => "hook_output_limit_exceeded", Hook;
    /// A hook's output isn't strict `hook/v1` JSON with a non-empty summary and object evidence, or a notify hook's observation lacks a boolean `complete`.
    HookOutputInvalid => "hook_output_invalid", Hook;
    /// A sidecar hook's evidence isn't a list of artifacts with only known fields and base64 content, or names one artifact twice.
    SidecarArtifactsInvalid => "sidecar_artifacts_invalid", Hook;
    /// Sidecar hooks returned more artifacts, or more bytes, than a Candidate holds.
    SidecarArtifactsLimitExceeded => "sidecar_artifacts_limit_exceeded", Hook;
    /// The snapshot that hooks run against holds an entry that is neither a regular file nor a directory.
    HookSnapshotEntryNotRegular => "hook_snapshot_entry_not_regular", Hook;
    /// The commit SHA that a rehearsal seals names no commit, or git resolves it as a ref to another commit.
    SourceCommitUnresolved => "source_commit_unresolved", UsageOrConfig;
    /// The installed Gleam compiler isn't the version that the configuration pins.
    GleamCompilerMismatch => "gleam_compiler_mismatch", UsageOrConfig;
    /// An explicit version is below the manifest version of a package that has no release yet.
    VersionLoweringForbidden => "version_lowering_forbidden", PolicyOrApproval;
    /// The manifest or explicit version is behind the latest release on the registry.
    ManifestVersionBehindPublished => "manifest_version_behind_published", PolicyOrApproval;
    /// A configured baseline ref, or the baseline of an API exception, names no commit.
    BaselineRefUnresolved => "baseline_ref_unresolved", UsageOrConfig;
    /// The API exception for the published version has expired.
    ApiExceptionExpired => "api_exception_expired", PolicyOrApproval;
    /// No tag, `baseline_refs` entry, or commit within the bounded history search matches the published Hex artifact.
    BaselineNotFound => "baseline_not_found", PolicyOrApproval;
    /// The manifest or changelog that a Release PR writes lies outside the repository.
    ReleaseFileOutsideRepository => "release_file_outside_repository", Internal;
    /// The registry's package response isn't valid JSON, or lists an invalid version.
    RegistryPackageInvalid => "registry_package_invalid", TemporaryExternal;
    /// A registry redirect leaves the origin that the request was sent to.
    RegistryRedirectCrossOrigin => "registry_redirect_cross_origin", TemporaryExternal;
    /// A registry request was redirected more times than the redirect limit.
    RegistryRedirectLimitExceeded => "registry_redirect_limit_exceeded", TemporaryExternal;
    /// A registry redirect has no `Location` header, or one that isn't ASCII.
    RegistryRedirectLocationInvalid => "registry_redirect_location_invalid", TemporaryExternal;
    /// A registry response exceeds its download limit.
    RegistryResponseTooLarge => "registry_response_too_large", TemporaryExternal;
    /// A GitHub Release asset is unfinished where a release can't complete it: the Candidate doesn't seal it, or its Release is published or isn't the Candidate's draft.
    ReleaseAssetUnfinished => "release_asset_unfinished", ImmutableStateConflict;
    /// The publishing job's environment lacks a variable that release approval checks.
    ApprovalRequestIncomplete => "approval_request_incomplete", PolicyOrApproval;
    /// A push release has no server-verified merged managed Release PR for its Candidate.
    ApprovalReleasePrMissing => "approval_release_pr_missing", PolicyOrApproval;
    /// The repository that a rehearsal builds from names its objects with a hash other than SHA-1, so GitHub can't serve its commits.
    RepositoryObjectFormatUnsupported => "repository_object_format_unsupported", UsageOrConfig;
}

/// An error that names its refusal, whose reason decides the class.
#[derive(Debug)]
pub struct Refusal {
    reason: RefusalReason,
    message: String,
}

impl Refusal {
    /// Pair a reason with the message that will be shown for it.
    pub fn new(reason: RefusalReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }

    /// The reason this refusal was constructed with.
    pub const fn reason(&self) -> RefusalReason {
        self.reason
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Refusal {}

/// A typed refusal as an [`anyhow::Error`], keeping every context and cause of `message` like [`classified`].
pub fn refused(reason: RefusalReason, message: impl fmt::Display) -> Error {
    Error::new(Refusal::new(reason, format!("{message:#}")))
}

/// Return early with a typed refusal, as `anyhow::bail!` returns with an untyped error.
#[macro_export]
macro_rules! refuse {
    ($reason:ident, $($message:tt)+) => {
        return Err($crate::failure::refused(
            $crate::failure::RefusalReason::$reason,
            format_args!($($message)+),
        ))
    };
}

/// An error that carries its class instead of leaving it to message text.
#[derive(Debug)]
pub struct ClassifiedFailure {
    class: FailureClass,
    message: String,
}

impl ClassifiedFailure {
    /// Pair a class with the message that will be shown for it.
    pub fn new(class: FailureClass, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
        }
    }

    /// The class this failure was constructed with.
    pub const fn class(&self) -> FailureClass {
        self.class
    }
}

impl fmt::Display for ClassifiedFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ClassifiedFailure {}

/// Wrap any displayable error so its class survives conversion to [`anyhow::Error`].
///
/// The message keeps every context and cause of an `anyhow::Error`, which its alternate form lists.
pub fn classified(class: FailureClass, error: impl fmt::Display) -> Error {
    Error::new(ClassifiedFailure::new(class, format!("{error:#}")))
}

/// Classify `error` at a boundary like [`classified`], keeping its refusal reason when that reason already has `class`.
///
/// The message is flattened as [`classified`] flattens it, so only the reason survives, and the class is `class` either way.
pub fn classified_keeping_reason(class: FailureClass, error: Error) -> Error {
    match decide(&error) {
        Decision::Refusal(reason) if reason.class() == class => refused(reason, error),
        _ => classified(class, error),
    }
}

/// Attach a boundary-specific class without replacing a more precise class already carried by the source error.
///
/// A typed refusal always carries its class, so the fallback never replaces it.
pub fn with_default_class(error: Error, fallback: FailureClass) -> Error {
    if decide(&error) == Decision::Class(FailureClass::Internal)
        && error.downcast_ref::<ClassifiedFailure>().is_none()
    {
        classified(fallback, error)
    } else {
        error
    }
}

/// What decided the class of an error: a typed refusal, whose reason determines the class, or a class alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Refusal(RefusalReason),
    Class(FailureClass),
}

impl Decision {
    const fn class(self) -> FailureClass {
        match self {
            Self::Refusal(reason) => reason.class(),
            Self::Class(class) => class,
        }
    }
}

/// The typed source error that decides the class of `error`.
///
/// Only typed source errors are inspected.
/// Message wording never selects a class or a reason, so rephrasing an error cannot change an exit status or a diagnostic code.
fn decide(error: &Error) -> Decision {
    if let Some(classified) = error.downcast_ref::<ClassifiedFailure>() {
        return Decision::Class(classified.class());
    }
    if let Some(release) = error.downcast_ref::<crate::release::ReleaseRunError>() {
        return Decision::Class(release.failure_class());
    }
    if let Some(refusal) = error.downcast_ref::<Refusal>() {
        return Decision::Refusal(refusal.reason());
    }
    if error
        .downcast_ref::<crate::config::MissingReleaseConfig>()
        .is_some()
    {
        return Decision::Refusal(RefusalReason::ConfigMissing);
    }
    if let Some(error) = error.downcast_ref::<reqwest::Error>()
        && (error.is_timeout() || error.is_connect())
    {
        return Decision::Class(FailureClass::TemporaryExternal);
    }
    Decision::Class(FailureClass::Internal)
}

/// Recover the class of an error, defaulting to [`FailureClass::Internal`].
///
/// A typed refusal's reason decides its class.
pub fn classify(error: &Error) -> FailureClass {
    decide(error).class()
}

/// The reason of the typed refusal that decides the class of `error`, if one does.
pub fn refusal_reason(error: &Error) -> Option<RefusalReason> {
    match decide(error) {
        Decision::Refusal(reason) => Some(reason),
        Decision::Class(_) => None,
    }
}

/// The `code` of the error diagnostic for `error`: the reason of a typed refusal, and otherwise the code of its class.
pub fn diagnostic_code(error: &Error) -> &'static str {
    match decide(error) {
        Decision::Refusal(reason) => reason.code(),
        Decision::Class(class) => class.diagnostic_code(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_failure_class_has_a_stable_machine_contract() {
        let cases = [
            (FailureClass::Internal, 1, "internal_failure"),
            (FailureClass::UsageOrConfig, 2, "usage_or_config"),
            (FailureClass::PolicyOrApproval, 3, "policy_or_approval"),
            (
                FailureClass::ImmutableStateConflict,
                4,
                "immutable_state_conflict",
            ),
            (
                FailureClass::TemporaryExternal,
                5,
                "temporary_external_failure",
            ),
            (FailureClass::Hook, 6, "hook_failure"),
            (FailureClass::PartialRelease, 7, "partial_release"),
        ];

        for (class, exit_code, diagnostic_code) in cases {
            assert_eq!(class.exit_code(), exit_code);
            assert_eq!(class.diagnostic_code(), diagnostic_code);
        }
    }

    #[test]
    fn message_words_never_select_a_failure_class() {
        for message in [
            "hook approval conflict timed out invalid TOML",
            "connection policy checksum mismatch",
        ] {
            assert_eq!(classify(&anyhow::anyhow!(message)), FailureClass::Internal);
        }
        let failure = classified(FailureClass::UsageOrConfig, "an unrelated message");
        assert_eq!(classify(&failure), FailureClass::UsageOrConfig);
        let preserved = with_default_class(failure, FailureClass::TemporaryExternal);
        assert_eq!(classify(&preserved), FailureClass::UsageOrConfig);
        let defaulted = with_default_class(
            anyhow::anyhow!("untyped boundary error"),
            FailureClass::TemporaryExternal,
        );
        assert_eq!(classify(&defaulted), FailureClass::TemporaryExternal);
    }

    #[test]
    fn a_manifest_without_release_configuration_is_a_usage_failure_on_every_path() {
        let missing = Error::new(crate::config::MissingReleaseConfig);
        assert_eq!(classify(&missing), FailureClass::UsageOrConfig);
        assert_eq!(diagnostic_code(&missing), "config_missing");
        let explained = missing.context("while binding the Candidate to its source");
        assert_eq!(classify(&explained), FailureClass::UsageOrConfig);
        let kept = with_default_class(explained, FailureClass::PolicyOrApproval);
        assert_eq!(classify(&kept), FailureClass::UsageOrConfig);
        assert_eq!(refusal_reason(&kept), Some(RefusalReason::ConfigMissing));
    }

    #[test]
    fn every_refusal_reason_has_a_unique_snake_case_code_outside_the_class_codes() {
        let class_codes = FailureClass::ALL.map(FailureClass::diagnostic_code);
        let mut codes = std::collections::BTreeSet::new();
        for reason in RefusalReason::ALL {
            let code = reason.code();
            assert!(
                code.split('_').all(|word| !word.is_empty()
                    && word
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()))
                    && code.starts_with(|first: char| first.is_ascii_lowercase()),
                "{reason:?} has the code `{code}`, which is not snake_case"
            );
            assert!(
                !class_codes.contains(&code),
                "{reason:?} reuses the class code `{code}`"
            );
            assert!(codes.insert(code), "{reason:?} reuses the code `{code}`");
        }
    }

    #[test]
    fn a_boundary_keeps_only_the_reason_of_a_refusal_of_its_own_class() {
        let boundary = FailureClass::ImmutableStateConflict;
        let matching = refused(RefusalReason::CandidateChecksumMismatch, "checksum differs")
            .context("while verifying the Candidate");
        let kept = classified_keeping_reason(boundary, matching);
        assert_eq!(
            refusal_reason(&kept),
            Some(RefusalReason::CandidateChecksumMismatch)
        );
        assert_eq!(classify(&kept), boundary);
        assert_eq!(
            format!("{kept:#}"),
            "while verifying the Candidate: checksum differs"
        );
        assert_eq!(kept.chain().count(), 1);

        let mismatched = refused(RefusalReason::ConfigMissing, "no release table");
        let reclassified = classified_keeping_reason(boundary, mismatched);
        assert_eq!(refusal_reason(&reclassified), None);
        assert_eq!(classify(&reclassified), boundary);
        assert_eq!(format!("{reclassified:#}"), "no release table");

        let untyped = classified_keeping_reason(boundary, anyhow::anyhow!("unreadable"));
        assert_eq!(refusal_reason(&untyped), None);
        assert_eq!(classify(&untyped), boundary);
        assert_eq!(format!("{untyped:#}"), "unreadable");
    }

    #[test]
    fn a_refusal_takes_the_class_and_code_of_its_reason_through_every_boundary() {
        for &reason in RefusalReason::ALL {
            let refusal = refused(reason, "message text is not classification")
                .context("while checking the release");
            assert_eq!(classify(&refusal), reason.class(), "{reason:?}");
            assert_eq!(diagnostic_code(&refusal), reason.code(), "{reason:?}");
            let fallback = FailureClass::ALL
                .into_iter()
                .find(|&class| class != reason.class() && class != FailureClass::Internal)
                .unwrap();
            let kept = with_default_class(refusal, fallback);
            assert_eq!(refusal_reason(&kept), Some(reason), "{reason:?}");
            assert_eq!(classify(&kept), reason.class(), "{reason:?}");
            let overridden = classified(fallback, kept);
            assert_eq!(refusal_reason(&overridden), None, "{reason:?}");
            assert_eq!(diagnostic_code(&overridden), fallback.diagnostic_code());
        }
    }
}
