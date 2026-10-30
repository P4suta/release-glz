//! Repository tasks that drive the pinned verification images.
//!
//! `cargo xtask lean` proves the Lean model of publication and its refinement of the core crate.

mod container;
mod lean;

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(root) = Path::new(env!("CARGO_MANIFEST_DIR")).parent() else {
        eprintln!("xtask lives outside the repository");
        return ExitCode::FAILURE;
    };
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let outcome = match arguments.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["lean"] => lean::run(root),
        _ => {
            eprintln!("usage: cargo xtask lean");
            return ExitCode::from(2);
        }
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("{failure}");
            ExitCode::FAILURE
        }
    }
}
