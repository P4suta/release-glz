//! Properties that every fuzz target checks and that `cargo test` replays over the committed corpora.

pub mod api_interface;
pub mod archive;
pub mod config;
pub mod identifiers;
pub mod pr_marker;
