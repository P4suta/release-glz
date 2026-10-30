//! Whether the release gate may rely on a recorded verification run.
//!
//! The audit of a run's report reduces what it found to counts and findings, and these functions decide from those alone.
//! Kani proves them, so the gate that admits every other proof is itself proven.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// The exit status of a Kani run in which every harness verified.
pub const VERIFIED_EXIT: i32 = 0;

/// The exit status of a Kani run in which a harness failed.
pub const FAILED_EXIT: i32 = 1;

/// What the audit found in the report of a run of every proof harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct ProofRun {
    /// Harnesses the committed inventory expects.
    pub expected: usize,
    /// Harnesses the report counts.
    pub total: usize,
    /// Harnesses the report says ran.
    pub executed: usize,
    /// Harnesses the report says verified.
    pub verified: usize,
    /// Harnesses the report says failed.
    pub failed: usize,
    /// The report says the run completed.
    pub completed: bool,
    /// Every section of the report names exactly the expected harnesses, once each.
    pub inventory_matches: bool,
    /// Every owned assertion succeeded, every cover the inventory expects was satisfied, and the tool versions and target are the pinned ones.
    pub properties_valid: bool,
    /// No log names a construct the verifier doesn't support.
    pub logs_supported: bool,
    /// The source didn't change while the run read it.
    pub source_matches: bool,
}

/// What the audit found in the report of a run of one negative control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct ControlRun {
    /// Harnesses the report counts.
    pub total: usize,
    /// Harnesses the report says failed.
    pub failed: usize,
    /// The report says the run completed.
    pub completed: bool,
    /// The run checked the harness the negative control names, and no other.
    pub harness_matches: bool,
    /// Every failed check is the assertion the negative control expects, owned by its harness, and at least one failed.
    pub failed_as_expected: bool,
    /// No check ended undetermined or in a solver error.
    pub checks_resolved: bool,
    /// The tool versions and target are the pinned ones.
    pub tools_valid: bool,
    /// No log names a construct the verifier doesn't support.
    pub logs_supported: bool,
    /// The source didn't change while the run read it.
    pub source_matches: bool,
}

/// Why the gate refuses a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The inventory expects no harness, so the run would prove nothing.
    EmptyInventory,
    /// Kani exited with another status than the run calls for.
    UnexpectedExit,
    /// The report says the run didn't complete.
    IncompleteRun,
    /// The counts in the report differ from what the run calls for.
    CountMismatch,
    /// The report names other harnesses than the inventory.
    InventoryMismatch,
    /// An owned check, a cover, or a tool identity is not what the run calls for.
    InvalidProperties,
    /// A log names a construct the verifier doesn't support.
    UnsupportedConstruct,
    /// The source changed while the run read it.
    SourceChanged,
}

/// Whether the gate may rely on a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The run proves what the gate claims.
    Admit,
    /// The run doesn't, for this reason.
    Refuse(Refusal),
}

/// Admit a run of every proof harness only when Kani verified exactly the inventory and nothing in the report or the logs undermines it.
pub const fn admit_proofs(exit_code: Option<i32>, run: ProofRun) -> Admission {
    #[cfg(feature = "negative-control-incomplete-run")]
    let run = negative_control_incomplete_run(run);
    if run.expected == 0 {
        return Admission::Refuse(Refusal::EmptyInventory);
    }
    if !matches!(exit_code, Some(VERIFIED_EXIT)) {
        return Admission::Refuse(Refusal::UnexpectedExit);
    }
    if !run.completed {
        return Admission::Refuse(Refusal::IncompleteRun);
    }
    if run.total != run.expected
        || run.executed != run.expected
        || run.verified != run.expected
        || run.failed != 0
    {
        return Admission::Refuse(Refusal::CountMismatch);
    }
    if !run.inventory_matches {
        return Admission::Refuse(Refusal::InventoryMismatch);
    }
    if !run.properties_valid {
        return Admission::Refuse(Refusal::InvalidProperties);
    }
    if !run.logs_supported {
        return Admission::Refuse(Refusal::UnsupportedConstruct);
    }
    if !run.source_matches {
        return Admission::Refuse(Refusal::SourceChanged);
    }
    Admission::Admit
}

/// Admit a run of one negative control only when Kani failed exactly its harness, on exactly the expected assertion.
pub const fn admit_control(exit_code: Option<i32>, run: ControlRun) -> Admission {
    #[cfg(feature = "negative-control-extra-failure")]
    let run = negative_control_extra_failure(run);
    if !matches!(exit_code, Some(FAILED_EXIT)) {
        return Admission::Refuse(Refusal::UnexpectedExit);
    }
    if !run.completed {
        return Admission::Refuse(Refusal::IncompleteRun);
    }
    if run.total != 1 || run.failed != 1 {
        return Admission::Refuse(Refusal::CountMismatch);
    }
    if !run.harness_matches {
        return Admission::Refuse(Refusal::InventoryMismatch);
    }
    if !run.failed_as_expected || !run.checks_resolved || !run.tools_valid {
        return Admission::Refuse(Refusal::InvalidProperties);
    }
    if !run.logs_supported {
        return Admission::Refuse(Refusal::UnsupportedConstruct);
    }
    if !run.source_matches {
        return Admission::Refuse(Refusal::SourceChanged);
    }
    Admission::Admit
}

/// Admits a proof run that didn't complete.
#[cfg(feature = "negative-control-incomplete-run")]
const fn negative_control_incomplete_run(run: ProofRun) -> ProofRun {
    ProofRun {
        completed: true,
        ..run
    }
}

/// Admits a negative control run in which another check failed too.
#[cfg(feature = "negative-control-extra-failure")]
const fn negative_control_extra_failure(run: ControlRun) -> ControlRun {
    ControlRun {
        failed_as_expected: true,
        ..run
    }
}

#[cfg(kani)]
mod proofs {
    use super::{
        Admission, ControlRun, FAILED_EXIT, ProofRun, VERIFIED_EXIT, admit_control, admit_proofs,
    };

    /// A proof run is admitted exactly when Kani verified every expected harness, and no other, from an unchanged source.
    #[kani::proof]
    fn a_proof_run_is_admitted_only_when_every_expected_harness_verified() {
        let exit_code: Option<i32> = kani::any();
        let run: ProofRun = kani::any();
        let admitted = admit_proofs(exit_code, run) == Admission::Admit;
        if admitted {
            kani::assert(run.completed, "a proof run must complete before admission");
        }
        let sound = run.expected > 0
            && exit_code == Some(VERIFIED_EXIT)
            && run.completed
            && run.total == run.expected
            && run.executed == run.expected
            && run.verified == run.expected
            && run.failed == 0
            && run.inventory_matches
            && run.properties_valid
            && run.logs_supported
            && run.source_matches;
        kani::assert(
            admitted == sound,
            "a proof run must be admitted exactly when every expected harness verified",
        );
        kani::cover!(admitted);
        kani::cover!(!admitted && run.completed);
    }

    /// A negative control is admitted exactly when Kani failed its one harness on the expected assertion and on nothing else.
    #[kani::proof]
    fn a_control_run_is_admitted_only_when_exactly_its_assertion_failed() {
        let exit_code: Option<i32> = kani::any();
        let run: ControlRun = kani::any();
        let admitted = admit_control(exit_code, run) == Admission::Admit;
        if admitted {
            kani::assert(
                run.failed_as_expected,
                "a negative control must fail only its expected assertion",
            );
        }
        let sound = exit_code == Some(FAILED_EXIT)
            && run.completed
            && run.total == 1
            && run.failed == 1
            && run.harness_matches
            && run.failed_as_expected
            && run.checks_resolved
            && run.tools_valid
            && run.logs_supported
            && run.source_matches;
        kani::assert(
            admitted == sound,
            "a negative control must be admitted exactly when its assertion alone failed",
        );
        kani::cover!(admitted);
        kani::cover!(!admitted && run.failed_as_expected);
    }
}
