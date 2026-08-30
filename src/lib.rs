//! Release engine for `release-glz`.
//!
//! The crate keeps release decisions separate from the CLI so the same stable
//! [`ReleasePlan`] can eventually be consumed by other front ends.

pub mod api;
pub mod artifact;
pub mod authorization;
pub mod candidate;
pub mod canonical;
pub mod changelog;
pub mod config;
pub mod doctor;
pub mod forge;
pub mod git;
pub mod gleam;
pub mod hooks;
pub mod migrate;
pub mod model;
pub mod planner;
pub mod reconciler;
pub mod registry;
pub mod rehearse;
pub mod release;
pub mod secrets;
mod sidecar;
pub mod version;
pub mod workflow;

pub use config::{Manifest, ReleaseConfig};
pub use model::{Bump, PrereleaseChannel, ReleasePlan};
pub use planner::{PlanOptions, Planner};
