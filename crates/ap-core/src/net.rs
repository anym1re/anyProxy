//! Accepting connections without spinning when a host runs short (0101).

use std::io;
use std::time::Duration;

/// How long a listener waits before accepting again after a refusal that will
/// repeat until something is freed.
///
/// At most ten attempts a second while the resource is gone, which costs no
/// processor, and a descriptor that comes free is taken within a tenth of a
/// second.
pub const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

/// What a listener does after `accept` failed: go straight on, or wait first.
///
/// A client that went away before it was taken is its own affair, and the next
/// connection in the queue does not depend on it; waiting there would let a
/// stream of connections reset in the queue throttle how fast real ones are
/// taken. Anything else — out of descriptors, out of kernel memory — fails
/// again the instant it is retried, because the connection that caused it is
/// still waiting in the backlog. A listener that retries at once spends a
/// whole core doing nothing: measured at 100 % on a node at its descriptor
/// limit.
pub fn pause_after_accept(error: &io::Error) -> Option<Duration> {
    match error.kind() {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::Interrupted => None,
        _ => Some(ACCEPT_PAUSE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_client_gone_before_it_was_taken_costs_no_wait() {
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::Interrupted,
        ] {
            assert_eq!(pause_after_accept(&io::Error::from(kind)), None, "{kind:?}");
        }
    }

    #[test]
    fn running_out_of_descriptors_waits_before_trying_again() {
        // EMFILE and ENFILE on Linux: the process and the system are out of
        // descriptors. Neither has an ErrorKind of its own, which is why the
        // rule is written as "everything but", not as a list of shortages.
        for code in [24, 23] {
            assert_eq!(
                pause_after_accept(&io::Error::from_raw_os_error(code)),
                Some(ACCEPT_PAUSE),
                "os error {code}"
            );
        }
        assert_eq!(
            pause_after_accept(&io::Error::from(io::ErrorKind::OutOfMemory)),
            Some(ACCEPT_PAUSE)
        );
    }
}
