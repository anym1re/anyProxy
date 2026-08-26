use std::time::Duration;

/// Where the doubling stops.
const CEILING_SECS: u64 = 60;

/// How long to wait before the next attempt, before jitter.
///
/// A node that lost the panel keeps trying for as long as it exists: there is
/// no attempt count at which giving up is better than waiting a minute more.
pub fn base(attempt: u32) -> Duration {
    let seconds = 1u64
        .checked_shl(attempt.min(63))
        .unwrap_or(CEILING_SECS)
        .min(CEILING_SECS);
    Duration::from_secs(seconds)
}

/// Spreads the wait over the half-interval below it.
///
/// Every node that lost the same panel would otherwise come back at the same
/// instant and lose it again.
pub fn jittered(attempt: u32) -> Duration {
    let base = base(attempt);
    let half = base / 2;
    let spread = rand::random_range(0..=half.as_millis().max(1) as u64);
    half + Duration::from_millis(spread)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_doubles_and_then_stops_growing() {
        assert_eq!(base(0), Duration::from_secs(1));
        assert_eq!(base(1), Duration::from_secs(2));
        assert_eq!(base(2), Duration::from_secs(4));
        assert_eq!(base(5), Duration::from_secs(32));
        assert_eq!(base(6), Duration::from_secs(60));
        assert_eq!(base(1000), Duration::from_secs(60));
    }

    #[test]
    fn the_wait_never_leaves_its_half_interval() {
        for attempt in 0..8 {
            let base = base(attempt);
            for _ in 0..50 {
                let waited = jittered(attempt);
                assert!(waited >= base / 2, "{waited:?} is below half of {base:?}");
                assert!(waited <= base, "{waited:?} is above {base:?}");
            }
        }
    }

    #[test]
    fn two_nodes_do_not_come_back_together() {
        let draws: std::collections::HashSet<_> = (0..50).map(|_| jittered(6)).collect();
        assert!(
            draws.len() > 1,
            "every attempt waited exactly the same time"
        );
    }
}
