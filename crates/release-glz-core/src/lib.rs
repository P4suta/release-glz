//! Release decisions of release-glz that depend on nothing but their inputs.
//!
//! The crate has no dependency outside `core`, so a model checker can prove its functions for every admitted input.
//! The main crate adapts them to the wire format and to the outside world.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod approval;
mod framing;
mod key_order;
mod lifecycle;
mod publication;
mod redaction;
mod run;
mod version;

pub use approval::{Approval, RunIdentity, Trigger};
pub use framing::{FILES_DOMAIN, NOTIFICATION_DOMAIN, frame_file, notification_frame};
pub use key_order::utf16_cmp;
pub use lifecycle::ReleaseState;
pub use publication::{Decision, Effects, Object, Outcome, Presence, reconcile};
pub use redaction::{Segment, redaction_segments};
pub use run::{Run, Step};
pub use version::{Bump, VersionCore, increment};
