//! Release decisions of release-glz that depend on nothing but their inputs.
//!
//! The crate has no dependency outside `core`, so a model checker can prove its functions for every admitted input.
//! The main crate adapts them to the wire format and to the outside world.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod lifecycle;
mod version;

pub use lifecycle::ReleaseState;
pub use version::{Bump, VersionCore, increment};
