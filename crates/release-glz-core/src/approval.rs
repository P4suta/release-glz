//! Whether a publication is approved, decided from evidence that was already compared with the Candidate.

/// The event that started the publishing run, as its verified OIDC claims name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Trigger {
    /// A push of the merged Release PR.
    Push,
    /// A manual dispatch that promotes an earlier Candidate.
    ManualDispatch,
    /// Any other event, which never publishes.
    Other,
}

/// The verified OIDC claims of the publishing run, compared with the Candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct RunIdentity {
    /// The claims name the Candidate's repository.
    pub repository: bool,
    /// The claims name the Environment that has to release the publish job.
    pub environment: bool,
    /// The claims name the Candidate's source commit.
    pub source: bool,
    /// The claims name the managed workflow of that repository.
    pub workflow: bool,
    /// The event that started the run.
    pub trigger: Trigger,
    /// The run's ref is one that a manual release may start from.
    pub manual_ref: bool,
}

/// The approval evidence of a publication, compared with the Candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Approval {
    /// The approved Candidate digest is the Candidate's.
    pub candidate: bool,
    /// The approved intent digest is the Candidate's.
    pub intent: bool,
    /// The verified identity of the publishing run, when there is one.
    pub identity: Option<RunIdentity>,
    /// The source commit that a manual release names is the Candidate's.
    pub manual_source: bool,
    /// A manual release gives a reason.
    pub manual_reason: bool,
}

impl Approval {
    /// Whether the evidence approves the publication.
    ///
    /// Every publication needs the Candidate digest and a verified run of the managed workflow in the Candidate's repository, Environment, and commit.
    /// A push also needs the approved intent, and a manual dispatch needs the intent, its own source commit and reason, and an allowed ref.
    pub fn approves(self) -> bool {
        let Some(identity) = self.identity else {
            return false;
        };
        let run =
            identity.repository && identity.environment && identity.source && identity.workflow;
        let path = match identity.trigger {
            #[cfg(feature = "negative-control-substitution")]
            Trigger::Push => self.intent || (self.manual_source && self.manual_reason),
            #[cfg(not(feature = "negative-control-substitution"))]
            Trigger::Push => self.intent,
            Trigger::ManualDispatch => {
                self.intent && self.manual_source && self.manual_reason && identity.manual_ref
            }
            Trigger::Other => false,
        };
        #[cfg(feature = "negative-control-approval")]
        return run && path;
        #[cfg(not(feature = "negative-control-approval"))]
        return self.candidate && run && path;
    }
}

#[cfg(kani)]
mod proofs {
    use super::{Approval, Trigger};

    /// An approval holds exactly when every conjunct of its path holds.
    #[kani::proof]
    fn an_approval_needs_every_conjunct_of_its_path() {
        let approval: Approval = kani::any();
        let expected = approval.candidate
            && approval.identity.is_some_and(|identity| {
                identity.repository
                    && identity.environment
                    && identity.source
                    && identity.workflow
                    && match identity.trigger {
                        Trigger::Push => approval.intent,
                        Trigger::ManualDispatch => {
                            approval.intent
                                && approval.manual_source
                                && approval.manual_reason
                                && identity.manual_ref
                        }
                        Trigger::Other => false,
                    }
            });
        // Kani stops a path at its first failed assertion, so the conjunct that the negative control drops comes first.
        if approval.approves() {
            kani::assert(
                approval.candidate,
                "an approval must cover the Candidate digest",
            );
        }
        kani::assert(
            approval.approves() == expected,
            "an approval must hold exactly when every conjunct of its path holds",
        );
        kani::cover!(
            approval.approves()
                && approval
                    .identity
                    .is_some_and(|identity| identity.trigger == Trigger::Push)
        );
        kani::cover!(
            approval.approves()
                && approval
                    .identity
                    .is_some_and(|identity| identity.trigger == Trigger::ManualDispatch)
        );
    }

    /// The manual inputs never decide a push, so neither path can stand in for the other.
    #[kani::proof]
    fn a_push_approval_never_rests_on_manual_inputs() {
        let push: Approval = kani::any();
        kani::assume(
            push.identity
                .is_some_and(|identity| identity.trigger == Trigger::Push),
        );
        let mut manual = push;
        manual.manual_source = kani::any();
        manual.manual_reason = kani::any();
        if let Some(identity) = manual.identity.as_mut() {
            identity.manual_ref = kani::any();
        }
        kani::assert(
            push.approves() == manual.approves(),
            "a push approval must not rest on manual inputs",
        );
        kani::cover!(push.approves());
    }
}
