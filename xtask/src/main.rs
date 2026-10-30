//! Repository tasks that drive the pinned verification images.
//!
//! `cargo xtask proofs` proves every Kani harness, one module at a time, and every negative control, and audits each run.
//! `cargo xtask proof-mutants` runs every mutant of the core crates through the harnesses, `--shard K --of N` runs one part of them, `merge` joins the parts, and `check` checks the committed receipt.
//! `cargo xtask lean` proves the Lean model of publication and its refinement of the core crate.
//! `cargo xtask quint` model-checks the release protocol and writes the traces that the replay test reads.
//! `cargo xtask trace` checks that `docs/assurance.md` maps every property to evidence that exists, and every check to a property.

mod container;
mod inventory;
mod lean;
mod proof_mutants;
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
        ["proof-mutants"] => proof_mutants::run(root, None),
        ["proof-mutants", "--shard", index, "--of", count] => {
            match (index.parse::<usize>(), count.parse::<usize>()) {
                (Ok(index), Ok(count)) => proof_mutants::Shard::new(index, count)
                    .and_then(|shard| proof_mutants::run(root, Some(shard))),
                _ => Err(container::Failure::new(
                    "a shard is two numbers: `--shard K --of N`",
                )),
            }
        }
        ["proof-mutants", "merge", ref receipts @ ..] if !receipts.is_empty() => {
            proof_mutants::merge(root, receipts)
        }
        ["proof-mutants", "check"] => proof_mutants::check(root),
        ["lean"] => lean::run(root),
        ["quint"] => quint::run(root),
        ["trace"] => trace::run(root),
        _ => {
            eprintln!(
                "usage: cargo xtask proofs|proof-mutants [--shard K --of N | merge RECEIPT... | check]|lean|quint|trace"
            );
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
