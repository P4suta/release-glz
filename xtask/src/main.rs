//! The command line of the repository tasks.
//!
//! `cargo xtask check` runs the fast gate, `--staged` checks only the staged files, and `--platform` runs the checks that depend on the operating system.
//! `cargo xtask commit-msg MESSAGE` refuses a commit message without a Conventional Commit type, and a fix without a staged test.
//! `cargo xtask proofs` proves every Kani harness, one module at a time, and every negative control, and audits each run.
//! `cargo xtask proof-mutants` runs every mutant of the core crates through the harnesses, `--shard K --of N` runs one part of them, `merge` joins the parts, and `check` checks the committed receipt.
//! `cargo xtask lean` proves the Lean model of publication and its refinement of the core crate.
//! `cargo xtask quint` model-checks the release protocol and writes the traces that the replay test reads.
//! `cargo xtask trace` checks that `docs/assurance.md` maps every property to evidence that exists, and every check to a property.

use std::path::Path;
use std::process::ExitCode;
use xtask::container::Failure;
use xtask::{check, commit_msg, lean, proof_mutants, proofs, quint, trace};

const USAGE: &str = "usage: cargo xtask check [--staged | --platform]|commit-msg MESSAGE|proofs|proof-mutants [--shard K --of N | merge RECEIPT... | check]|lean|quint|trace";

fn run(root: &Path, arguments: &[&str]) -> Option<Result<(), Failure>> {
    Some(match *arguments {
        ["check"] => check::run(root, check::Scope::Everything),
        ["check", "--staged"] => check::run(root, check::Scope::Staged),
        ["check", "--platform"] => check::run(root, check::Scope::Platform),
        ["commit-msg", message] => commit_msg::check(root, Path::new(message)),
        ["proofs"] => proofs::run(root),
        ["proof-mutants"] => proof_mutants::run(root, None),
        ["proof-mutants", "--shard", index, "--of", count] => {
            match (index.parse::<usize>(), count.parse::<usize>()) {
                (Ok(index), Ok(count)) => proof_mutants::Shard::new(index, count)
                    .and_then(|shard| proof_mutants::run(root, Some(shard))),
                _ => Err(Failure::new("a shard is two numbers: `--shard K --of N`")),
            }
        }
        ["proof-mutants", "merge", ref receipts @ ..] if !receipts.is_empty() => {
            proof_mutants::merge(root, receipts)
        }
        ["proof-mutants", "check"] => proof_mutants::check(root),
        ["lean"] => lean::run(root),
        ["quint"] => quint::run(root),
        ["trace"] => trace::run(root),
        _ => return None,
    })
}

fn main() -> ExitCode {
    let Some(root) = Path::new(env!("CARGO_MANIFEST_DIR")).parent() else {
        eprintln!("xtask lives outside the repository");
        return ExitCode::FAILURE;
    };
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    match run(root, &arguments) {
        Some(Ok(())) => ExitCode::SUCCESS,
        Some(Err(failure)) => {
            eprintln!("{failure}");
            ExitCode::FAILURE
        }
        None => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
