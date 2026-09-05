use std::collections::BTreeMap;

use ap_engine::metrics::{Counters, Reading};
use ap_proto::{DeviceCount, Health, Telemetry, TrafficDelta};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AgentError;

/// What one access used on one day.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Used {
    bytes_in: i64,
    bytes_out: i64,
}

/// Counts what the node used and hands it upward.
///
/// No client address passes through here, and none can: what the engine gives
/// out is counts. The addresses those counts were derived from stay in the
/// engine's memory, and the control client removes them from every reply
/// before this ever sees one.
#[derive(Debug, Default)]
pub struct Meter {
    /// The last reading, so the next one can be turned into a difference.
    seen: BTreeMap<Uuid, Counters>,
    /// What has been used and not yet acknowledged, by access and day.
    owed: BTreeMap<(Uuid, String), Used>,
    /// The highest device count seen for an access in a period.
    devices: BTreeMap<(Uuid, String), i64>,
    /// The delivery that is out and unanswered.
    outstanding: Option<Telemetry>,
}

impl Meter {
    /// Starts with nothing owed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes a reading and adds what it says was used since the last one.
    ///
    /// A counter that went down means the engine started again from zero, so
    /// the whole of the new value is what has been used since; treating it as
    /// a difference would produce a negative one, and a node that restarts
    /// would appear to give traffic back.
    pub fn observe(&mut self, reading: &Reading, now: OffsetDateTime) -> Result<(), AgentError> {
        let day = day_of(now)?;
        let period = day.clone();

        for (access, counters) in &reading.by_access {
            let before = self.seen.get(access).copied().unwrap_or_default();
            let used = Used {
                bytes_in: since(before.bytes_in, counters.bytes_in),
                bytes_out: since(before.bytes_out, counters.bytes_out),
            };
            self.seen.insert(*access, *counters);

            if used.bytes_in != 0 || used.bytes_out != 0 {
                let owed = self.owed.entry((*access, day.clone())).or_default();
                owed.bytes_in += used.bytes_in;
                owed.bytes_out += used.bytes_out;
            }

            // A gauge, not a counter: the most seen in the period is what the
            // period is worth reporting.
            let devices = self.devices.entry((*access, period.clone())).or_default();
            *devices = (*devices).max(counters.devices);
        }

        // An access the engine no longer reports has gone away. Its baseline
        // goes with it, so if it comes back it starts from nothing rather than
        // from a number that is no longer true.
        self.seen
            .retain(|access, _| reading.by_access.contains_key(access));
        Ok(())
    }

    /// The delivery to send, if there is anything to say.
    ///
    /// The same delivery comes back until it is acknowledged: the panel
    /// applies one delivery once, by its identifier, so repeating it is safe
    /// and losing it is not.
    pub fn delivery(&mut self, health: Health, now: OffsetDateTime) -> Option<Telemetry> {
        if let Some(outstanding) = &self.outstanding {
            return Some(outstanding.clone());
        }
        if self.owed.is_empty() && self.devices.is_empty() {
            return None;
        }

        let deltas = self
            .owed
            .iter()
            .map(|((access, day), used)| TrafficDelta {
                access_id: *access,
                day: day.clone(),
                bytes_in: used.bytes_in,
                bytes_out: used.bytes_out,
            })
            .collect();
        let devices = self
            .devices
            .iter()
            .map(|((access, period), unique)| DeviceCount {
                access_id: *access,
                period: period.clone(),
                unique: *unique,
            })
            .collect();

        let telemetry = Telemetry {
            revision: Uuid::now_v7(),
            sent_at: ap_core::time::format_rfc3339(now).ok()?,
            deltas,
            devices,
            health,
            // Filled in by whoever sends it: the machine is read at that
            // moment, and a repeated delivery carries a fresh reading.
            machine: None,
        };
        self.outstanding = Some(telemetry.clone());
        Some(telemetry)
    }

    /// A report with nothing in it, to keep the conversation going.
    ///
    /// The panel answers what a node says and never speaks first, so a node
    /// with no traffic to report would say nothing and be told nothing. The
    /// node with nothing to report is exactly the one whose last access has
    /// just been withdrawn — the one that most needs to hear that it has
    /// nothing left to serve.
    ///
    /// Not kept for retry, unlike a delivery: there is nothing in it to lose.
    pub fn heartbeat(&self, health: Health, now: OffsetDateTime) -> Option<Telemetry> {
        Some(Telemetry {
            revision: Uuid::now_v7(),
            sent_at: ap_core::time::format_rfc3339(now).ok()?,
            deltas: Vec::new(),
            devices: Vec::new(),
            health,
            machine: None,
        })
    }

    /// Marks the outstanding delivery as received.
    ///
    /// An acknowledgement for something else is ignored rather than clearing
    /// what is owed: a stale one arriving late would otherwise drop traffic
    /// nobody counted.
    pub fn acknowledged(&mut self, revision: Uuid) -> bool {
        let Some(outstanding) = &self.outstanding else {
            return false;
        };
        if outstanding.revision != revision {
            return false;
        }
        self.outstanding = None;
        self.owed.clear();
        self.devices.clear();
        true
    }

    /// Whether a delivery is out and unanswered.
    pub fn waiting(&self) -> bool {
        self.outstanding.is_some()
    }
}

/// What was used between two readings of one counter.
fn since(before: i64, now: i64) -> i64 {
    if now < before {
        now.max(0)
    } else {
        now - before
    }
}

/// The day a reading belongs to, in UTC.
fn day_of(now: OffsetDateTime) -> Result<String, AgentError> {
    let date = now.date();
    Ok(format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_health() -> Health {
        Health {
            engine: "up".to_owned(),
            site: "up".to_owned(),
            reach: "open".to_owned(),
            cert_not_after: None,
        }
    }

    fn a_reading(access: Uuid, bytes_in: i64, bytes_out: i64, devices: i64) -> Reading {
        let mut by_access = BTreeMap::new();
        by_access.insert(
            access,
            Counters {
                bytes_in,
                bytes_out,
                devices,
                connections: 0,
            },
        );
        Reading {
            by_access,
            unread: 0,
        }
    }

    fn at(day: u8) -> OffsetDateTime {
        ap_core::time::parse_rfc3339(&format!("2026-08-{day:02}T12:00:00Z")).unwrap()
    }

    #[test]
    fn what_was_used_between_two_readings_is_the_difference() {
        let access = Uuid::now_v7();
        let mut meter = Meter::new();

        meter
            .observe(&a_reading(access, 1000, 100, 1), at(26))
            .unwrap();
        meter
            .observe(&a_reading(access, 2500, 400, 2), at(26))
            .unwrap();

        let delivery = meter.delivery(a_health(), at(26)).unwrap();
        assert_eq!(delivery.deltas.len(), 1);
        assert_eq!(delivery.deltas[0].bytes_in, 2500);
        assert_eq!(delivery.deltas[0].bytes_out, 400);
    }

    #[test]
    fn an_engine_that_started_again_does_not_give_traffic_back() {
        let access = Uuid::now_v7();
        let mut meter = Meter::new();

        meter
            .observe(&a_reading(access, 5000, 900, 1), at(26))
            .unwrap();
        // The engine restarted: its counters begin at zero and climb again.
        meter
            .observe(&a_reading(access, 200, 30, 1), at(26))
            .unwrap();

        let delivery = meter.delivery(a_health(), at(26)).unwrap();
        let delta = &delivery.deltas[0];
        assert!(
            delta.bytes_in >= 0 && delta.bytes_out >= 0,
            "a restart produced a negative delta: {delta:?}"
        );
        // The whole of the new value is what has been used since the restart.
        assert_eq!(delta.bytes_in, 5000 + 200);
        assert_eq!(delta.bytes_out, 900 + 30);
    }

    #[test]
    fn a_delivery_that_was_not_acknowledged_comes_back_unchanged() {
        let access = Uuid::now_v7();
        let mut meter = Meter::new();
        meter
            .observe(&a_reading(access, 1000, 100, 1), at(26))
            .unwrap();

        let first = meter.delivery(a_health(), at(26)).unwrap();
        let again = meter.delivery(a_health(), at(26)).unwrap();
        assert_eq!(first.revision, again.revision);
        assert_eq!(first.deltas, again.deltas);
        assert!(meter.waiting());
    }

    #[test]
    fn an_acknowledged_delivery_is_not_sent_twice() {
        let access = Uuid::now_v7();
        let mut meter = Meter::new();
        meter
            .observe(&a_reading(access, 1000, 100, 1), at(26))
            .unwrap();

        let sent = meter.delivery(a_health(), at(26)).unwrap();
        assert!(meter.acknowledged(sent.revision));
        assert!(!meter.waiting());
        assert!(meter.delivery(a_health(), at(26)).is_none());
    }

    #[test]
    fn an_acknowledgement_for_something_else_drops_nothing() {
        let access = Uuid::now_v7();
        let mut meter = Meter::new();
        meter
            .observe(&a_reading(access, 1000, 100, 1), at(26))
            .unwrap();

        let sent = meter.delivery(a_health(), at(26)).unwrap();
        assert!(!meter.acknowledged(Uuid::now_v7()), "a stale ack was taken");
        assert!(meter.waiting());

        let again = meter.delivery(a_health(), at(26)).unwrap();
        assert_eq!(again.revision, sent.revision);
    }

    #[test]
    fn what_is_used_after_an_acknowledgement_starts_a_new_delivery() {
        let access = Uuid::now_v7();
        let mut meter = Meter::new();
        meter
            .observe(&a_reading(access, 1000, 100, 1), at(26))
            .unwrap();
        let first = meter.delivery(a_health(), at(26)).unwrap();
        meter.acknowledged(first.revision);

        meter
            .observe(&a_reading(access, 1600, 250, 1), at(26))
            .unwrap();
        let second = meter.delivery(a_health(), at(26)).unwrap();
        assert_ne!(second.revision, first.revision);
        assert_eq!(second.deltas[0].bytes_in, 600);
        assert_eq!(second.deltas[0].bytes_out, 150);
    }

    #[test]
    fn traffic_is_kept_apart_by_day() {
        let access = Uuid::now_v7();
        let mut meter = Meter::new();
        meter
            .observe(&a_reading(access, 1000, 100, 1), at(26))
            .unwrap();
        meter
            .observe(&a_reading(access, 1500, 200, 1), at(27))
            .unwrap();

        let delivery = meter.delivery(a_health(), at(27)).unwrap();
        assert_eq!(delivery.deltas.len(), 2, "{:?}", delivery.deltas);
        let days: Vec<_> = delivery
            .deltas
            .iter()
            .map(|delta| delta.day.as_str())
            .collect();
        assert!(days.contains(&"2026-08-26") && days.contains(&"2026-08-27"));
    }

    #[test]
    fn the_device_count_is_the_most_seen_in_the_period() {
        let access = Uuid::now_v7();
        let mut meter = Meter::new();
        meter
            .observe(&a_reading(access, 100, 10, 1), at(26))
            .unwrap();
        meter
            .observe(&a_reading(access, 200, 20, 3), at(26))
            .unwrap();
        // Two of the three went away; the period still saw three.
        meter
            .observe(&a_reading(access, 300, 30, 1), at(26))
            .unwrap();

        let delivery = meter.delivery(a_health(), at(26)).unwrap();
        assert_eq!(delivery.devices.len(), 1);
        assert_eq!(delivery.devices[0].unique, 3);
    }

    #[test]
    fn a_delivery_carries_no_field_that_names_an_address() {
        let access = Uuid::now_v7();
        let mut meter = Meter::new();
        meter
            .observe(&a_reading(access, 1000, 100, 2), at(26))
            .unwrap();

        let delivery = meter.delivery(a_health(), at(26)).unwrap();
        let payload = serde_json::to_value(&delivery).unwrap();

        // The same check the panel makes when the frame arrives.
        assert!(
            ap_proto::guard::refuse_address_fields(&payload).is_ok(),
            "the delivery names an address: {payload}"
        );
        assert!(!payload.to_string().contains("203.0.113"));
    }

    #[test]
    fn nothing_used_is_nothing_to_send() {
        let mut meter = Meter::new();
        assert!(meter.delivery(a_health(), at(26)).is_none());

        let access = Uuid::now_v7();
        meter.observe(&a_reading(access, 0, 0, 0), at(26)).unwrap();
        assert!(
            meter.delivery(a_health(), at(26)).is_some(),
            "a device count of zero is still a period worth reporting"
        );
    }

    #[test]
    fn an_access_that_went_away_and_came_back_starts_from_nothing() {
        let access = Uuid::now_v7();
        let mut meter = Meter::new();
        meter
            .observe(&a_reading(access, 4000, 400, 1), at(26))
            .unwrap();

        // Withdrawn: the engine stops reporting it.
        meter
            .observe(
                &Reading {
                    by_access: BTreeMap::new(),
                    unread: 0,
                },
                at(26),
            )
            .unwrap();

        // Granted again, under the same identifier, from zero.
        meter
            .observe(&a_reading(access, 700, 70, 1), at(26))
            .unwrap();

        let delivery = meter.delivery(a_health(), at(26)).unwrap();
        let delta = &delivery.deltas[0];
        assert_eq!(delta.bytes_in, 4000 + 700);
        assert!(delta.bytes_in >= 0 && delta.bytes_out >= 0);
    }
}
