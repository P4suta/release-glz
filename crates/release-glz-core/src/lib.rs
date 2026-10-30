//! Release decisions of release-glz that depend on nothing but their inputs.
//!
//! The crate has no dependency outside `core` and `alloc`, so a model checker can prove its functions for every admitted input.
//! The main crate adapts them to the wire format and to the outside world.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

mod approval;
mod archive_path;
mod candidate_choice;
mod commit;
mod framing;
mod hex;
mod key_order;
mod lifecycle;
mod marker;
mod oidc;
mod precedence;
mod publication;
mod redaction;
mod run;
mod selection;
mod version;
mod wait;

pub use approval::{Approval, RunIdentity, Trigger};
pub use archive_path::{archive_path, collision, directories_above};
pub use candidate_choice::{CandidateRun, RunRefusal, candidate_run};
pub use commit::conventional_bump;
pub use framing::{FILES_DOMAIN, NOTIFICATION_DOMAIN, frame_file, notification_frame};
pub use hex::{
    OBJECT_HEX_LEN, SHA256_HEX_LEN, is_commit_id, is_object_id, is_sha256_hex, lowercase_hex,
};
pub use key_order::utf16_cmp;
pub use lifecycle::ReleaseState;
pub use marker::{
    MARKER_KEYS, MARKER_PREFIX, MARKER_SUFFIX, marker_start, marker_values, write_inert,
    write_marker,
};
pub use oidc::{
    CLOCK_SKEW_SECONDS, OIDC_ISSUER_HOST, OidcUrlKind, OriginRefusal, RUNNER_TOKEN_ZONE,
    TokenTimes, WindowRefusal, is_run_id, oidc_origin, run_attempt, token_window,
};
pub use precedence::{Channel, Pre, Version, compare};
pub use publication::{Decision, Effects, Object, Outcome, Presence, reconcile};
pub use redaction::{Segment, redaction_segments};
pub use run::{Run, Step};
pub use selection::{
    Computed, Initial, Refusal, Selection, bump_between, effective_bump, initial_version,
    next_prerelease, select_version, version_zero_refused,
};
pub use version::{Bump, VersionCore, increment};
pub use wait::{
    AfterPoll, Answer, BusyDefault, GITHUB_READS, Next, REGISTRY_RETRIES, RetryPolicy, after_poll,
    another_attempt_follows, delay_seconds, release_ready,
};
