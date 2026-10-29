//! The externally visible lifecycle of one package release.

/// The externally visible lifecycle of one package release.
///
/// Normal states only move forward.
/// `conflict` and `blocked` are terminal observations rather than rollback states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case")
)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum ReleaseState {
    /// The published release already matches the manifest.
    UpToDate,
    /// A release is required and a version has been selected.
    Planned,
    /// A Candidate has been sealed and passes offline verification.
    CandidateReady,
    /// The Candidate is waiting for the approvals the manifest requires.
    AwaitingApproval,
    /// Some publication stages succeeded and the rest can be resumed.
    PartiallyReleased,
    /// Every required stage completed; the release is immutable.
    Released,
    /// A published object differs from what this Candidate would write.
    Conflict,
    /// A policy, API, or configuration requirement prevents release.
    Blocked,
}

impl ReleaseState {
    /// Whether `next` is a legal successor of this state.
    ///
    /// A state may always repeat itself, which is what makes resuming a partial release safe.
    pub fn can_advance_to(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        if self.is_terminal() {
            return false;
        }
        match (position(self), position(next)) {
            (Some(from), Some(to)) => to > from,
            _ => true,
        }
    }

    /// Whether the state never changes again.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Released | Self::Conflict | Self::Blocked)
    }
}

/// The normal states in the order a release moves through them.
const LIFECYCLE: [ReleaseState; 6] = [
    ReleaseState::UpToDate,
    ReleaseState::Planned,
    ReleaseState::CandidateReady,
    ReleaseState::AwaitingApproval,
    ReleaseState::PartiallyReleased,
    ReleaseState::Released,
];

/// Position in [`LIFECYCLE`], or `None` for `conflict` and `blocked`.
fn position(state: ReleaseState) -> Option<usize> {
    LIFECYCLE.iter().position(|normal| *normal == state)
}

#[cfg(kani)]
mod proofs {
    use super::ReleaseState;

    fn normal(state: ReleaseState) -> bool {
        !matches!(state, ReleaseState::Conflict | ReleaseState::Blocked)
    }

    #[kani::proof]
    fn every_state_may_repeat() {
        let state: ReleaseState = kani::any();
        assert!(state.can_advance_to(state));
        kani::cover!(state.is_terminal());
    }

    #[kani::proof]
    fn a_terminal_state_never_changes() {
        let from: ReleaseState = kani::any();
        let to: ReleaseState = kani::any();
        kani::assume(from.is_terminal() && from != to);
        assert!(!from.can_advance_to(to));
        kani::cover!(from == ReleaseState::Released);
        kani::cover!(from == ReleaseState::Conflict);
    }

    /// Distinct normal states are ordered one way only, so the normal lifecycle is a single chain.
    #[kani::proof]
    fn normal_states_form_one_forward_chain() {
        let a: ReleaseState = kani::any();
        let b: ReleaseState = kani::any();
        kani::assume(normal(a) && normal(b) && a != b);
        assert!(a.can_advance_to(b) != b.can_advance_to(a));
        kani::cover!(a.can_advance_to(b));
        kani::cover!(b.can_advance_to(a));
    }

    #[kani::proof]
    fn advancing_is_transitive() {
        let a: ReleaseState = kani::any();
        let b: ReleaseState = kani::any();
        let c: ReleaseState = kani::any();
        kani::assume(a.can_advance_to(b) && b.can_advance_to(c));
        assert!(a.can_advance_to(c));
        kani::cover!(a != b && b != c && a != c);
    }

    #[kani::proof]
    fn an_unfinished_release_can_always_end_in_conflict_or_blocked() {
        let state: ReleaseState = kani::any();
        kani::assume(!state.is_terminal());
        assert!(state.can_advance_to(ReleaseState::Conflict));
        assert!(state.can_advance_to(ReleaseState::Blocked));
        assert!(state.can_advance_to(ReleaseState::Released));
        kani::cover!(state == ReleaseState::UpToDate);
        kani::cover!(state == ReleaseState::PartiallyReleased);
    }
}
