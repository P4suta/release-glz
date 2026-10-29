//! Spawning child processes that tolerate a concurrent `fork`.
//!
//! A file that one thread has just written stays open for writing in a process another thread forks until that process execs, and running the file in that window fails with `ETXTBSY`.
//! The condition clears on its own,
//! so a spawn retries it a bounded number of times instead of failing.

use std::io::{self, ErrorKind};
use std::process::{Command, Output};
use std::time::Duration;

/// Attempts made to spawn a process before the failure is reported.
pub(crate) const SPAWN_ATTEMPTS: usize = 3;

/// Milliseconds added to the wait before each further spawn attempt.
const SPAWN_RETRY_STEP_MS: u64 = 10;

/// Whether a spawn error means no process can have started, so retrying it cannot run anything twice.
pub(crate) fn retryable_spawn_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::ExecutableFileBusy
    )
}

/// The wait before the spawn attempt that follows `attempt` failed ones.
pub(crate) fn spawn_retry_delay(attempt: usize) -> Duration {
    let attempt = u64::try_from(attempt).unwrap_or(u64::MAX);
    Duration::from_millis(SPAWN_RETRY_STEP_MS.saturating_mul(attempt))
}

/// Run a command to completion, retrying only spawns that cannot have started.
pub(crate) fn output(command: &mut Command) -> io::Result<Output> {
    let mut attempt = 1;
    loop {
        match command.output() {
            Err(error) if retryable_spawn_error(&error) && attempt < SPAWN_ATTEMPTS => {
                std::thread::sleep(spawn_retry_delay(attempt));
                attempt += 1;
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawns_retry_only_errors_that_cannot_have_started_a_process() {
        for kind in [
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
            ErrorKind::ExecutableFileBusy,
        ] {
            assert!(retryable_spawn_error(&io::Error::from(kind)), "{kind:?}");
        }
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::PermissionDenied,
            ErrorKind::Other,
        ] {
            assert!(!retryable_spawn_error(&io::Error::from(kind)), "{kind:?}");
        }
    }

    #[test]
    fn retry_delay_grows_with_each_attempt_and_saturates() {
        assert_eq!(spawn_retry_delay(1), Duration::from_millis(10));
        assert_eq!(spawn_retry_delay(2), Duration::from_millis(20));
        assert_eq!(
            spawn_retry_delay(usize::MAX),
            Duration::from_millis(u64::MAX)
        );
    }

    #[cfg(unix)]
    #[test]
    fn output_reports_a_missing_program_without_retrying_it() {
        let error = output(&mut Command::new("/nonexistent/release-glz-program")).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::NotFound);
    }
}
