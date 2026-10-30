//! Which run's Candidate a publish job may consume.

/// The run that may have prepared the Candidate a publish job consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum CandidateRun {
    /// The run that is publishing now, which prepared the Candidate in an earlier job and is still in progress.
    Current,
    /// Another run, which prepared the Candidate and completed with success.
    Completed,
}

/// Why a publish job may consume no Candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunRefusal {
    /// A push names a Candidate that another run prepared.
    PushFromAnotherRun,
    /// A manual promotion names a Candidate that its own run prepared.
    PromotionOfItsOwnRun,
    /// Neither a push nor a manual promotion started the job.
    OtherEvent,
}

/// The run whose Candidate a publish job that `event` started may consume, given whether the Candidate names the job's own run.
///
/// A push publishes only the Candidate that its own run prepared, and a manual promotion only one that another run prepared.
pub fn candidate_run(event: &[u8], own_run: bool) -> Result<CandidateRun, RunRefusal> {
    #[cfg(feature = "negative-control-push-from-another-run")]
    if let Some(run) = negative_control_push_from_another_run(event, own_run) {
        return run;
    }
    match (event, own_run) {
        (b"push", true) => Ok(CandidateRun::Current),
        (b"push", false) => Err(RunRefusal::PushFromAnotherRun),
        (b"workflow_dispatch", false) => Ok(CandidateRun::Completed),
        (b"workflow_dispatch", true) => Err(RunRefusal::PromotionOfItsOwnRun),
        _ => Err(RunRefusal::OtherEvent),
    }
}

impl CandidateRun {
    /// Whether a run that GitHub reports with `status` and `conclusion` can be the run this names.
    pub fn admits(self, status: &[u8], conclusion: Option<&[u8]>) -> bool {
        match self {
            Self::Current => status == b"in_progress",
            Self::Completed => status == b"completed" && conclusion == Some(b"success".as_slice()),
        }
    }
}

/// Lets a push consume the Candidate of another run.
#[cfg(feature = "negative-control-push-from-another-run")]
fn negative_control_push_from_another_run(
    event: &[u8],
    own_run: bool,
) -> Option<Result<CandidateRun, RunRefusal>> {
    (event == b"push" && !own_run).then_some(Ok(CandidateRun::Completed))
}

#[cfg(kani)]
mod proofs {
    use super::{RunRefusal, candidate_run};

    /// Symbolic text of at most `N` bytes.
    fn text<const N: usize>(bytes: &[u8; N]) -> &[u8] {
        &bytes[..kani::any_where(|length: &usize| *length <= N)]
    }

    /// A push consumes only the Candidate of its own run while that run is in progress, and a manual promotion only the Candidate of another run that completed with success.
    ///
    /// Every event name of at most 18 bytes, status of at most 12 bytes, and conclusion of at most 8 bytes or none.
    #[kani::proof]
    #[kani::unwind(20)]
    fn a_push_consumes_only_its_own_run_and_a_promotion_only_another_successful_one() {
        let event_bytes: [u8; 18] = kani::any();
        let status_bytes: [u8; 12] = kani::any();
        let conclusion_bytes: [u8; 8] = kani::any();
        let event = text(&event_bytes);
        let status = text(&status_bytes);
        let conclusion = kani::any::<bool>().then(|| text(&conclusion_bytes));
        let own_run: bool = kani::any();
        let push = event == b"push";
        let promotion = event == b"workflow_dispatch";
        let expected = match (push, promotion, own_run) {
            (true, _, true) => Ok(status == b"in_progress"),
            (true, _, false) => Err(RunRefusal::PushFromAnotherRun),
            (_, true, false) => {
                Ok(status == b"completed" && conclusion.is_some_and(|value| value == b"success"))
            }
            (_, true, true) => Err(RunRefusal::PromotionOfItsOwnRun),
            _ => Err(RunRefusal::OtherEvent),
        };
        let consumed = candidate_run(event, own_run).map(|run| run.admits(status, conclusion));
        kani::assert(
            consumed == expected,
            "a publish job must consume only its own push run or another successful run",
        );
        kani::cover!(push && consumed == Ok(true));
        kani::cover!(promotion && consumed == Ok(true));
    }
}
