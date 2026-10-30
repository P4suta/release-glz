//! Release decisions of release-glz that depend on nothing but their inputs.
//!
//! The crate has no dependency outside `core`, so a model checker can prove its functions for every admitted input.
//! The main crate adapts them to the wire format and to the outside world.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod approval;
mod commit;
mod lifecycle;
mod precedence;
mod publication;
mod run;
mod selection;
mod version;

pub use approval::{Approval, RunIdentity, Trigger};
pub use commit::conventional_bump;
pub use lifecycle::ReleaseState;
pub use precedence::{Channel, Pre, Version, compare};
pub use publication::{Decision, Effects, Object, Outcome, Presence, reconcile};
pub use run::{Run, Step};
pub use selection::{
    Computed, Initial, Refusal, Selection, bump_between, effective_bump, initial_version,
    next_prerelease, select_version, version_zero_refused,
};
pub use version::{Bump, VersionCore, increment};
