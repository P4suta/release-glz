//! What a release still has to publish, decided from what the world already holds.
//!
//! The reconciler describes each object a release publishes as an [`Object`], in publication order, and these functions decide what happens to each one.
//! An object that exists is never replaced, so a resumed release completes what is missing rather than publishing anything again.

use crate::ReleaseState;

/// How the observed world holds one object that a release publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Presence {
    /// The object doesn't exist.
    Absent,
    /// The object exists in an unfinished form that the release completes, such as a draft GitHub Release or an incomplete notification.
    Pending,
    /// The object exists exactly as the Candidate describes it.
    Matches,
    /// The object exists with an identity other than the one the Candidate describes.
    Differs,
}

/// What the reconciler does about one object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decision {
    /// Publish the object, or complete it.
    Create,
    /// Leave the object as it is.
    Keep,
    /// Stop, because the object exists and publishing the Candidate would have to replace it.
    Conflict,
}

/// One object of a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Object {
    /// Whether the Candidate publishes this object.
    pub wanted: bool,
    /// How the observed world holds it.
    pub presence: Presence,
    /// Whether its effect has to finish before the release counts as released.
    pub blocking: bool,
}

impl Object {
    /// What the reconciler does about this object.
    ///
    /// The release creates or completes only an object it wants that is missing or pending, and any object that exists outside the Candidate's description is a conflict.
    pub fn decision(self) -> Decision {
        #[cfg(feature = "negative-control-overwrite")]
        if let Some(decision) = negative_control_overwrite(self) {
            return decision;
        }
        #[cfg(feature = "negative-control-republish")]
        if let Some(decision) = negative_control_republish(self) {
            return decision;
        }
        match (self.wanted, self.presence) {
            (_, Presence::Differs) | (false, Presence::Pending | Presence::Matches) => {
                Decision::Conflict
            }
            (true, Presence::Absent | Presence::Pending) => Decision::Create,
            (true, Presence::Matches) | (false, Presence::Absent) => Decision::Keep,
        }
    }

    fn blocks(self) -> bool {
        #[cfg(feature = "negative-control-optional-blocks")]
        if let Some(blocks) = negative_control_optional_blocks() {
            return blocks;
        }
        self.blocking
    }
}

/// Keeps a wanted object that differs instead of reporting a conflict.
#[cfg(feature = "negative-control-overwrite")]
fn negative_control_overwrite(object: Object) -> Option<Decision> {
    match (object.wanted, object.presence) {
        (true, Presence::Differs) => Some(Decision::Keep),
        _ => None,
    }
}

/// Publishes a wanted object again although it already matches.
#[cfg(feature = "negative-control-republish")]
fn negative_control_republish(object: Object) -> Option<Decision> {
    match (object.wanted, object.presence) {
        (true, Presence::Matches) => Some(Decision::Create),
        _ => None,
    }
}

/// Lets every effect block completion, optional ones included.
#[cfg(feature = "negative-control-optional-blocks")]
fn negative_control_optional_blocks() -> Option<bool> {
    Some(true)
}

/// Treats every run as approved.
#[cfg(feature = "negative-control-unapproved")]
fn negative_control_unapproved(_approved: bool) -> bool {
    true
}

/// The result of reconciling the objects of one release.
#[derive(Debug, Clone)]
pub enum Outcome<'a> {
    /// The object at this index exists, and publishing the Candidate would replace it.
    Conflict(usize),
    /// The release publishes nothing until it is approved.
    AwaitingApproval,
    /// The release is in `state`, and `effects` lists what it still has to publish.
    Proceed {
        /// The state the release is in.
        state: ReleaseState,
        /// The objects that still need an effect.
        effects: Effects<'a>,
    },
}

/// Reconcile `objects`, given in publication order, under `approved`.
///
/// A conflict outranks approval, so an unapproved run still reports a world that contradicts the Candidate.
pub fn reconcile(objects: &[Object], approved: bool) -> Outcome<'_> {
    if let Some(index) = objects
        .iter()
        .position(|object| object.decision() == Decision::Conflict)
    {
        return Outcome::Conflict(index);
    }
    #[cfg(feature = "negative-control-unapproved")]
    let approved = negative_control_unapproved(approved);
    if !approved {
        return Outcome::AwaitingApproval;
    }
    let blocking = objects
        .iter()
        .any(|object| object.decision() == Decision::Create && object.blocks());
    let started = objects
        .iter()
        .any(|object| object.presence != Presence::Absent);
    let state = if !blocking {
        ReleaseState::Released
    } else if started {
        ReleaseState::PartiallyReleased
    } else {
        ReleaseState::CandidateReady
    };
    Outcome::Proceed {
        state,
        effects: Effects {
            objects: objects.iter().enumerate(),
        },
    }
}

/// The indices of the objects that still need an effect, in publication order.
#[derive(Debug, Clone)]
pub struct Effects<'a> {
    objects: core::iter::Enumerate<core::slice::Iter<'a, Object>>,
}

impl Iterator for Effects<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        self.objects
            .find(|(_, object)| object.decision() == Decision::Create)
            .map(|(index, _)| index)
    }
}

#[cfg(kani)]
mod proofs {
    use super::{Decision, Object, Outcome, Presence, reconcile};
    use crate::ReleaseState;

    /// The number of objects that the list proofs cover, so their results hold for releases of at most this many objects.
    const OBJECTS: usize = 3;

    fn differs(object: Object) -> bool {
        object.presence == Presence::Differs
            || (!object.wanted && object.presence != Presence::Absent)
    }

    #[kani::proof]
    fn an_effect_concerns_only_an_object_the_world_lacks() {
        let object: Object = kani::any();
        if object.decision() == Decision::Create {
            kani::assert(
                object.wanted && matches!(object.presence, Presence::Absent | Presence::Pending),
                "an effect must concern an object the world lacks",
            );
        }
        kani::cover!(object.decision() == Decision::Create && object.presence == Presence::Absent);
        kani::cover!(object.decision() == Decision::Create && object.presence == Presence::Pending);
    }

    /// An object conflicts exactly when it exists and doesn't match what the Candidate wants of it.
    #[kani::proof]
    fn an_object_that_differs_ends_in_a_conflict() {
        let object: Object = kani::any();
        kani::assert(
            (object.decision() == Decision::Conflict) == differs(object),
            "an object that differs must end in a conflict",
        );
        kani::cover!(object.wanted && object.presence == Presence::Differs);
        kani::cover!(!object.wanted && object.presence == Presence::Matches);
    }

    #[kani::proof]
    #[kani::unwind(5)]
    fn no_effect_leaves_without_approval() {
        let objects: [Object; OBJECTS] = kani::any();
        let outcome = reconcile(&objects, false);
        kani::assert(
            !matches!(outcome, Outcome::Proceed { .. }),
            "no effect may leave without approval",
        );
        kani::cover!(matches!(outcome, Outcome::AwaitingApproval));
    }

    /// The first object that differs stops the release, whatever the approval and the other objects.
    #[kani::proof]
    #[kani::unwind(5)]
    fn a_conflict_anywhere_stops_the_release() {
        let objects: [Object; OBJECTS] = kani::any();
        let approved: bool = kani::any();
        let first = objects.iter().position(|object| differs(*object));
        let outcome = reconcile(&objects, approved);
        kani::assert(
            match first {
                Some(index) => matches!(outcome, Outcome::Conflict(found) if found == index),
                None => !matches!(outcome, Outcome::Conflict(_)),
            },
            "an object that differs must end in a conflict",
        );
        kani::cover!(first == Some(OBJECTS - 1));
    }

    /// An approved plan lists each missing object once, in publication order, and publishing one removes exactly that effect.
    ///
    /// The runner gives a release as many attempts as its first plan has effects, so a release whose effects all apply finishes within that budget.
    #[kani::proof]
    #[kani::unwind(5)]
    fn publishing_an_effect_removes_exactly_that_effect() {
        let mut objects: [Object; OBJECTS] = kani::any();
        let Outcome::Proceed { effects, .. } = reconcile(&objects, true) else {
            return;
        };
        let mut before = [false; OBJECTS];
        let mut count = 0;
        let mut previous = None;
        for index in effects {
            assert!(previous.is_none_or(|previous| previous < index));
            assert!(objects[index].decision() == Decision::Create);
            before[index] = true;
            previous = Some(index);
            count += 1;
        }
        let published: usize = kani::any();
        kani::assume(published < OBJECTS && before[published]);
        objects[published].presence = Presence::Matches;
        let Outcome::Proceed { effects, .. } = reconcile(&objects, true) else {
            panic!("publishing an effect made the release conflict");
        };
        let mut after = [false; OBJECTS];
        for index in effects {
            after[index] = true;
        }
        for index in 0..OBJECTS {
            kani::assert(
                after[index] == (before[index] && index != published),
                "publishing an effect must remove exactly that effect",
            );
        }
        kani::cover!(count == OBJECTS);
    }

    /// A release counts as released once no blocking effect remains, and it reports partial progress only when something already exists.
    #[kani::proof]
    #[kani::unwind(5)]
    fn the_release_is_released_once_no_blocking_effect_remains() {
        let objects: [Object; OBJECTS] = kani::any();
        let Outcome::Proceed { state, .. } = reconcile(&objects, true) else {
            return;
        };
        let creates = |object: &Object| object.decision() == Decision::Create;
        let blocking = objects
            .iter()
            .any(|object| creates(object) && object.blocking);
        let started = objects
            .iter()
            .any(|object| object.presence != Presence::Absent);
        kani::assert(
            (state == ReleaseState::Released) == !blocking,
            "a release must be released exactly when no blocking effect remains",
        );
        if blocking {
            assert!(
                state
                    == if started {
                        ReleaseState::PartiallyReleased
                    } else {
                        ReleaseState::CandidateReady
                    }
            );
        }
        kani::cover!(state == ReleaseState::Released && objects.iter().any(creates));
        kani::cover!(state == ReleaseState::PartiallyReleased);
        kani::cover!(state == ReleaseState::CandidateReady);
    }
}
