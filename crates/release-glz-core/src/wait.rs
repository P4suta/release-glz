//! How often a request repeats and how long it waits first, and when a wait for a release to become visible polls again.

/// The milliseconds in one second.
const MILLISECONDS_PER_SECOND: u64 = 1000;

/// What an attempt of a request got that may let the request repeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Answer {
    /// A response that asks the client to repeat the request, with the seconds that its `Retry-After` header names when it names a number.
    Busy(Option<u64>),
    /// No response, because the connection or the transfer failed.
    Unreachable,
}

/// How long a request waits after a busy response that names no wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum BusyDefault {
    /// The same number of milliseconds after every attempt.
    Fixed(u64),
    /// One second after the first attempt, and twice as long after each later one.
    Doubling,
}

/// How often one request may be attempted, and how long it waits before it repeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct RetryPolicy {
    /// The attempts that one request makes at most.
    pub attempts: usize,
    /// The milliseconds by which each wait after a transport failure grows.
    pub transport_step_ms: u64,
    /// The wait after a busy response that names none.
    pub busy_default: BusyDefault,
    /// The longest wait, in milliseconds, after a busy response.
    pub busy_cap_ms: u64,
}

/// Registry requests: three attempts, a quarter of a second when a busy response names no wait, and at most a minute when it names one.
pub const REGISTRY_RETRIES: RetryPolicy = RetryPolicy {
    attempts: 3,
    transport_step_ms: 100,
    busy_default: BusyDefault::Fixed(250),
    busy_cap_ms: 60_000,
};

/// GitHub reads: three attempts, a wait that doubles from one second when a busy response names none, and at most thirty seconds.
pub const GITHUB_READS: RetryPolicy = RetryPolicy {
    attempts: 3,
    transport_step_ms: 100,
    busy_default: BusyDefault::Doubling,
    busy_cap_ms: 30_000,
};

/// What a request does after an attempt that may let it repeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Keep what the attempt got: its response, or its failure.
    Stop,
    /// Wait this many milliseconds, then attempt the request again.
    Retry(u64),
}

/// Whether another attempt follows the attempt with index `attempt`, counted from zero, of a request that makes at most `attempts`.
pub fn another_attempt_follows(attempt: usize, attempts: usize) -> bool {
    attempt < attempts.saturating_sub(1)
}

impl RetryPolicy {
    /// What a request does after its attempt with index `attempt`, counted from zero, got `answer`.
    ///
    /// It waits only when another attempt follows.
    pub fn after(&self, attempt: usize, answer: Answer) -> Next {
        #[cfg(feature = "negative-control-retry-after-last-attempt")]
        if let Some(next) = negative_control_retry_after_last_attempt(self, attempt, answer) {
            return next;
        }
        if !another_attempt_follows(attempt, self.attempts) {
            return Next::Stop;
        }
        Next::Retry(self.wait(attempt, answer))
    }

    fn wait(&self, attempt: usize, answer: Answer) -> u64 {
        match answer {
            Answer::Busy(asked) => self.busy_wait(attempt, asked),
            Answer::Unreachable => self.transport_wait(attempt),
        }
    }

    /// The milliseconds to wait after a busy response to the attempt with index `attempt` that asked for `asked` seconds, which never exceed the cap.
    pub fn busy_wait(&self, attempt: usize, asked: Option<u64>) -> u64 {
        let wait = match (asked, self.busy_default) {
            (Some(seconds), _) => seconds.saturating_mul(MILLISECONDS_PER_SECOND),
            (None, BusyDefault::Fixed(milliseconds)) => milliseconds,
            (None, BusyDefault::Doubling) => {
                doubled(attempt).saturating_mul(MILLISECONDS_PER_SECOND)
            }
        };
        capped(wait, self.busy_cap_ms)
    }

    /// The milliseconds to wait after the attempt with index `attempt` failed in transport: one step for each attempt so far.
    pub fn transport_wait(&self, attempt: usize) -> u64 {
        u64::try_from(attempt)
            .map_or(u64::MAX, |attempt| attempt.saturating_add(1))
            .saturating_mul(self.transport_step_ms)
    }
}

fn capped(wait: u64, cap: u64) -> u64 {
    #[cfg(feature = "negative-control-uncapped-busy-wait")]
    if let Some(wait) = negative_control_uncapped_busy_wait(wait) {
        return wait;
    }
    wait.min(cap)
}

/// Two to the power of `attempt`, or the largest number when that doesn't fit.
fn doubled(attempt: usize) -> u64 {
    u32::try_from(attempt)
        .ok()
        .and_then(|shift| 1_u64.checked_shl(shift))
        .unwrap_or(u64::MAX)
}

/// What a wait for a release to become visible does after a poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterPoll {
    /// The poll shows the release, so the wait ends with it.
    Visible,
    /// Wait the poll interval, then poll again.
    PollAgain,
    /// No poll may follow, so the wait ends without the release.
    TimedOut,
}

/// What a wait that polls at most `attempts` times does after its poll with index `poll`, counted from zero, which showed the release when `visible` holds.
pub fn after_poll(poll: usize, attempts: usize, visible: bool) -> AfterPoll {
    #[cfg(feature = "negative-control-sleep-after-last-poll")]
    if let Some(after) = negative_control_sleep_after_last_poll(visible) {
        return after;
    }
    if visible {
        AfterPoll::Visible
    } else if another_attempt_follows(poll, attempts) {
        AfterPoll::PollAgain
    } else {
        AfterPoll::TimedOut
    }
}

/// Whether a poll shows a release as visible: the registry lists its version, with docs when `require_docs` asks for them.
///
/// `listed` holds whether the registry has docs for the version, when it lists the version at all.
pub fn release_ready(listed: Option<bool>, require_docs: bool) -> bool {
    #[cfg(feature = "negative-control-ready-without-docs")]
    if let Some(ready) = negative_control_ready_without_docs(listed) {
        return ready;
    }
    listed.is_some_and(|has_docs| has_docs || !require_docs)
}

/// Waits after the last attempt too, so a request sleeps before it gives up.
#[cfg(feature = "negative-control-retry-after-last-attempt")]
fn negative_control_retry_after_last_attempt(
    policy: &RetryPolicy,
    attempt: usize,
    answer: Answer,
) -> Option<Next> {
    Some(Next::Retry(policy.wait(attempt, answer)))
}

/// Waits as long as a busy response asks, however long that is.
#[cfg(feature = "negative-control-uncapped-busy-wait")]
fn negative_control_uncapped_busy_wait(wait: u64) -> Option<u64> {
    Some(wait)
}

/// Polls again after every poll that doesn't show the release, so a wait sleeps after its last poll too.
#[cfg(feature = "negative-control-sleep-after-last-poll")]
fn negative_control_sleep_after_last_poll(visible: bool) -> Option<AfterPoll> {
    (!visible).then_some(AfterPoll::PollAgain)
}

/// Counts a listed version as visible even when the docs it needs are missing.
#[cfg(feature = "negative-control-ready-without-docs")]
fn negative_control_ready_without_docs(listed: Option<bool>) -> Option<bool> {
    Some(listed.is_some())
}

#[cfg(kani)]
mod proofs {
    use super::{
        AfterPoll, Answer, BusyDefault, GITHUB_READS, Next, REGISTRY_RETRIES, RetryPolicy,
        after_poll, release_ready,
    };

    /// A request waits only when another attempt follows, after a busy response as long as it asks or its default says but never beyond the cap, and after a transport failure one step for each attempt so far.
    ///
    /// Every policy, attempt index, and answer, including every number of seconds that a `Retry-After` header can name.
    /// The wait after a transport failure is pinned for the first nine attempts, and saturating arithmetic bounds it beyond them.
    #[kani::proof]
    fn a_request_waits_only_before_another_attempt_and_only_as_long_as_its_answer_allows() {
        let policy: RetryPolicy = kani::any();
        let attempt: usize = kani::any();
        let answer: Answer = kani::any();
        let next = policy.after(attempt, answer);
        let follows = attempt as u128 + 1 < policy.attempts as u128;
        kani::assert(
            matches!(next, Next::Retry(_)) == follows,
            "a request must wait only before another attempt",
        );
        let allowed = match answer {
            Answer::Busy(asked) => {
                let asked = match (asked, policy.busy_default) {
                    (Some(seconds), _) => u128::from(seconds) * 1000,
                    (None, BusyDefault::Fixed(milliseconds)) => u128::from(milliseconds),
                    (None, BusyDefault::Doubling) if attempt < 64 => (1_u128 << attempt) * 1000,
                    (None, BusyDefault::Doubling) => u128::MAX,
                };
                Some(asked.min(u128::from(policy.busy_cap_ms)))
            }
            Answer::Unreachable if attempt < 9 => {
                Some((attempt as u128 + 1) * u128::from(policy.transport_step_ms))
            }
            Answer::Unreachable => None,
        };
        if let (Next::Retry(wait), Some(allowed)) = (next, allowed) {
            kani::assert(
                u128::from(wait) == allowed.min(u128::from(u64::MAX)),
                "a wait must be as long as its answer allows",
            );
        }
        kani::cover!(
            matches!(answer, Answer::Busy(Some(seconds)) if u128::from(seconds) * 1000 > u128::from(policy.busy_cap_ms))
                && next == Next::Retry(policy.busy_cap_ms)
        );
        kani::cover!(
            answer == Answer::Unreachable && matches!(next, Next::Retry(wait) if wait > 0)
        );
    }

    /// The whole wait of one request, whatever each of its attempts gets.
    fn whole_wait(policy: RetryPolicy) -> u128 {
        let mut total = 0;
        for attempt in 0..policy.attempts {
            if let Next::Retry(wait) = policy.after(attempt, kani::any()) {
                total += u128::from(wait);
            }
        }
        total
    }

    /// A registry request waits at most two minutes in all, and a GitHub read at most one minute, whatever its attempts get.
    ///
    /// Every sequence of answers to the three attempts of each policy, including every number of seconds that a `Retry-After` header can name.
    #[kani::proof]
    #[kani::unwind(4)]
    fn the_shipped_policies_bound_the_whole_wait_of_a_request() {
        let registry = whole_wait(REGISTRY_RETRIES);
        let github = whole_wait(GITHUB_READS);
        kani::assert(
            registry <= 120_000 && github <= 60_000,
            "a request must wait at most two minutes for the registry and one for GitHub",
        );
        kani::cover!(registry == 120_000);
        kani::cover!(github == 60_000);
    }

    /// A wait polls again only when the release is missing and another poll may follow, ends with the release exactly at a poll that shows it, and a poll shows it exactly when the registry lists its version with the docs it needs.
    ///
    /// Every poll index, attempt count, listing, and docs requirement.
    #[kani::proof]
    fn a_wait_sleeps_only_before_another_poll_and_ends_at_the_first_visible_one() {
        let poll: usize = kani::any();
        let attempts: usize = kani::any();
        let listed: Option<bool> = kani::any();
        let require_docs: bool = kani::any();
        let ready = release_ready(listed, require_docs);
        kani::assert(
            ready
                == match listed {
                    Some(has_docs) => has_docs || !require_docs,
                    None => false,
                },
            "a release must count as visible exactly when the registry lists it with the docs it needs",
        );
        let after = after_poll(poll, attempts, ready);
        kani::assert(
            (after == AfterPoll::PollAgain) == (!ready && poll as u128 + 1 < attempts as u128),
            "a wait must sleep only before another poll",
        );
        kani::assert(
            (after == AfterPoll::Visible) == ready,
            "a wait must end with the release exactly when a poll shows it",
        );
        kani::cover!(after == AfterPoll::PollAgain);
        kani::cover!(after == AfterPoll::TimedOut && attempts > 0);
    }
}
