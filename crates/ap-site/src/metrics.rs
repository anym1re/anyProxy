//! Counters, and nothing about who was counted.

use std::sync::atomic::{AtomicU64, Ordering};

/// Requests by status and feed fetches by outcome. Atomic numbers in memory:
/// no addresses, no paths, no history (0095).
#[derive(Debug, Default)]
pub struct Counters {
    ok: AtomicU64,
    moved: AtomicU64,
    found: AtomicU64,
    missing: AtomicU64,
    refused: AtomicU64,
    feed_ok: AtomicU64,
    feed_error: AtomicU64,
}

impl Counters {
    /// Counts one answered request by its status.
    pub fn answered(&self, status: u16) {
        let counter = match status {
            200 => &self.ok,
            301 => &self.moved,
            302 => &self.found,
            404 => &self.missing,
            _ => &self.refused,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a feed that was taken.
    pub fn feed_ok(&self) {
        self.feed_ok.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts a feed that was not.
    pub fn feed_error(&self) {
        self.feed_error.fetch_add(1, Ordering::Relaxed);
    }

    /// The counters in the text form Prometheus reads.
    pub fn render(&self, links: usize, age_seconds: Option<u64>) -> String {
        let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let mut out = String::new();
        out.push_str("# TYPE site_requests_total counter\n");
        for (status, counter) in [
            ("200", &self.ok),
            ("301", &self.moved),
            ("302", &self.found),
            ("404", &self.missing),
            ("405", &self.refused),
        ] {
            out.push_str(&format!(
                "site_requests_total{{status=\"{status}\"}} {}\n",
                read(counter)
            ));
        }
        out.push_str("# TYPE site_feed_fetches_total counter\n");
        out.push_str(&format!(
            "site_feed_fetches_total{{outcome=\"ok\"}} {}\n",
            read(&self.feed_ok)
        ));
        out.push_str(&format!(
            "site_feed_fetches_total{{outcome=\"error\"}} {}\n",
            read(&self.feed_error)
        ));
        out.push_str("# TYPE site_links gauge\n");
        out.push_str(&format!("site_links {links}\n"));
        out.push_str("# TYPE site_feed_age_seconds gauge\n");
        match age_seconds {
            Some(age) => out.push_str(&format!("site_feed_age_seconds {age}\n")),
            None => out.push_str("site_feed_age_seconds NaN\n"),
        }
        out
    }
}
