//! Properties that every fuzz target checks and that `cargo test` replays over the committed corpora.

pub mod api_interface;
pub mod api_responses;
pub mod archive;
pub mod candidate;
pub mod changelog_notes;
pub mod config;
pub mod git_log;
pub mod handoff;
pub mod hook_output;
pub mod identifiers;
pub mod oidc;
pub mod pr_marker;
pub mod prerelease;
