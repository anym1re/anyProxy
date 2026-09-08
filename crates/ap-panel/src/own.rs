//! What the panel's own process is using (0073).
//!
//! The processes card is a summary over the whole fleet, and the panel is part
//! of it. Read from `/proc/self`, which exists where the panel runs; elsewhere
//! there is nothing to read and nothing is said.

use std::sync::atomic::{AtomicU64, Ordering};

/// Resident memory in megabytes, when it can be read.
pub fn memory_mb() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = text.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4096 / (1024 * 1024))
}

/// Processor time used since boot, in clock ticks.
fn ticks() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/stat").ok()?;
    // The name sits in brackets and may hold spaces, so the fields are counted
    // from the closing bracket rather than from the start.
    let rest = text.rsplit_once(')')?.1;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let user: u64 = fields.get(11)?.parse().ok()?;
    let system: u64 = fields.get(12)?.parse().ok()?;
    Some(user + system)
}

/// What was read last time, so a share can be worked out from the next.
static LAST_TICKS: AtomicU64 = AtomicU64::new(u64::MAX);
static LAST_AT: AtomicU64 = AtomicU64::new(0);

/// Share of one processor the panel is using, in percent.
///
/// A rate, so the first call after a start has nothing to measure against and
/// says nothing rather than saying zero.
pub fn cpu_percent() -> Option<f64> {
    // Every Linux this runs on counts a hundred ticks a second; the figure is
    // not readable without libc, and being wrong here would only scale a
    // percentage.
    const TICKS_A_SECOND: f64 = 100.0;
    let now = ticks()?;
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let before = LAST_TICKS.swap(now, Ordering::Relaxed);
    let then = LAST_AT.swap(at, Ordering::Relaxed);
    if before == u64::MAX || at <= then {
        return None;
    }
    let seconds = (at - then) as f64;
    let grew = now.checked_sub(before)? as f64;
    Some(grew * 100.0 / (TICKS_A_SECOND * seconds))
}
