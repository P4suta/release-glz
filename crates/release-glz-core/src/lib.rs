//! Release decisions of release-glz that depend on nothing but their inputs.
//!
//! The crate has no dependency outside `core`, so a model checker can prove its functions for every admitted input.
//! The main crate adapts them to the wire format and to the outside world.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod approval;
mod commit;
mod framing;
mod key_order;
mod lifecycle;
mod marker;
mod precedence;
mod publication;
mod redaction;
mod run;
mod selection;
mod version;

pub use approval::{Approval, RunIdentity, Trigger};
pub use commit::conventional_bump;
pub use framing::{FILES_DOMAIN, NOTIFICATION_DOMAIN, frame_file, notification_frame};
pub use key_order::utf16_cmp;
pub use lifecycle::ReleaseState;
pub use marker::{
    MARKER_KEYS, MARKER_PREFIX, MARKER_SUFFIX, marker_start, marker_values, write_inert,
    write_marker,
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
