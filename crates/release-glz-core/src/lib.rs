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
mod commit;
mod framing;
mod hex;
mod key_order;
mod lifecycle;
mod precedence;
mod publication;
mod redaction;
mod run;
mod selection;
mod version;

pub use approval::{Approval, RunIdentity, Trigger};
pub use archive_path::{Collision, FoldedPaths, PathRefusal, archive_path};
pub use commit::conventional_bump;
pub use framing::{FILES_DOMAIN, NOTIFICATION_DOMAIN, frame_file, notification_frame};
pub use hex::{
    OBJECT_HEX_LEN, SHA256_HEX_LEN, is_commit_id, is_object_id, is_sha256_hex, lowercase_hex,
};
pub use key_order::utf16_cmp;
pub use lifecycle::ReleaseState;
pub use precedence::{Channel, Pre, Version, compare};
pub use publication::{Decision, Effects, Object, Outcome, Presence, reconcile};
pub use redaction::{Segment, redaction_segments};
pub use run::{Run, Step};
pub use selection::{
    Computed, Initial, Refusal, Selection, bump_between, effective_bump, initial_version,
    next_prerelease, select_version, version_zero_refused,
};
pub use version::{Bump, VersionCore, increment};
