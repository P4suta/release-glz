//! Repository tasks that drive the pinned verification images.
//!
//! `cargo xtask proofs` proves every Kani harness, one module at a time, and every negative control, and audits each run.
//! `cargo xtask lean` proves the Lean model of publication and its refinement of the core crate.
//! `cargo xtask quint` model-checks the release protocol and writes the traces that the replay test reads.
//! `cargo xtask trace` checks that `docs/assurance.md` maps every property to evidence that exists, and every check to a property.

mod container;
mod inventory;
mod lean;
mod proof_report;
mod proofs;
mod quint;
mod source_snapshot;
mod trace;

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(root) = Path::new(env!("CARGO_MANIFEST_DIR")).parent() else {
        eprintln!("xtask lives outside the repository");
        return ExitCode::FAILURE;
    };
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let outcome = match arguments.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["proofs"] => proofs::run(root),
        ["lean"] => lean::run(root),
        ["quint"] => quint::run(root),
        ["trace"] => trace::run(root),
        _ => {
            eprintln!("usage: cargo xtask proofs|lean|quint|trace");
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
