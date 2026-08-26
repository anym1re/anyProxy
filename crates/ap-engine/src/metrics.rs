use std::collections::BTreeMap;

use uuid::Uuid;

/// What the engine reported about one access.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// Bytes the client received, counted by the engine as sent to it.
    pub bytes_in: i64,
    /// Bytes the client sent, counted by the engine as received from it.
    pub bytes_out: i64,
    /// Distinct addresses currently using the access.
    pub devices: i64,
    /// Connections currently open.
    pub connections: i64,
}

/// One reading of the engine's metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reading {
    /// Counters by access.
    pub by_access: BTreeMap<Uuid, Counters>,
    /// Lines that were not understood.
    ///
    /// Kept rather than swallowed: a response cut off mid-line leaves one, and
    /// a response that changed shape entirely leaves many. The difference
    /// matters, so the caller is told the number.
    pub unread: usize,
}

/// Reads a Prometheus exposition body into counters per access.
///
/// A line that cannot be read is skipped rather than failing the whole
/// reading: a truncated body still carries everything before the cut, and
/// throwing it away would lose traffic that was really used.
pub fn read(body: &str) -> Reading {
    let mut reading = Reading::default();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((head, value)) = line.rsplit_once(' ') else {
            reading.unread += 1;
            continue;
        };
        let Some((name, labels)) = split_name(head) else {
            reading.unread += 1;
            continue;
        };

        let field = match name {
            "telemt_user_octets_to_client" => Field::BytesIn,
            "telemt_user_octets_from_client" => Field::BytesOut,
            "telemt_user_unique_ips_current" => Field::Devices,
            "telemt_user_connections_current" => Field::Connections,
            // Everything else the engine reports is not ours to carry.
            _ => continue,
        };

        let Some(user) = label(labels, "user") else {
            reading.unread += 1;
            continue;
        };
        let Some(access) = crate::config::access_of(&user) else {
            reading.unread += 1;
            continue;
        };
        let Some(value) = number(value) else {
            reading.unread += 1;
            continue;
        };

        let counters = reading.by_access.entry(access).or_default();
        match field {
            Field::BytesIn => counters.bytes_in = value,
            Field::BytesOut => counters.bytes_out = value,
            Field::Devices => counters.devices = value,
            Field::Connections => counters.connections = value,
        }
    }

    reading
}

enum Field {
    BytesIn,
    BytesOut,
    Devices,
    Connections,
}

/// Splits `name{labels}` into its two parts. A name with no labels has none.
fn split_name(head: &str) -> Option<(&str, &str)> {
    match head.split_once('{') {
        Some((name, rest)) => rest.strip_suffix('}').map(|labels| (name, labels)),
        None => Some((head, "")),
    }
}

/// The value of one label, if it is there.
fn label(labels: &str, wanted: &str) -> Option<String> {
    for pair in labels.split(',') {
        let (name, value) = pair.split_once('=')?;
        if name.trim() != wanted {
            continue;
        }
        let value = value.trim();
        let value = value.strip_prefix('"')?.strip_suffix('"')?;
        return Some(value.replace("\\\"", "\"").replace("\\\\", "\\"));
    }
    None
}

/// A counter as a whole number.
///
/// The exposition format allows floating point, and counters arrive as whole
/// numbers written that way. A value that is not finite is not a count.
fn number(text: &str) -> Option<i64> {
    if let Ok(value) = text.parse::<i64>() {
        // A counter that went backwards is not a count of anything.
        return (value >= 0).then_some(value);
    }
    let value = text.parse::<f64>().ok()?;
    if !value.is_finite() || value < 0.0 {
        return None;
    }
    Some(value.trunc() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::user_of;

    fn a_body(user: &str) -> String {
        format!(
            "# HELP telemt_user_octets_to_client Per-user bytes sent\n\
             # TYPE telemt_user_octets_to_client counter\n\
             telemt_user_octets_to_client{{user=\"{user}\"}} 4096\n\
             telemt_user_octets_from_client{{user=\"{user}\"}} 1024\n\
             telemt_user_unique_ips_current{{user=\"{user}\"}} 2\n\
             telemt_user_connections_current{{user=\"{user}\"}} 5\n\
             telemt_connections_total 91\n"
        )
    }

    #[test]
    fn a_reading_carries_each_direction_the_way_the_panel_counts_it() {
        let access = Uuid::now_v7();
        let reading = read(&a_body(&user_of(access)));

        let counters = reading.by_access.get(&access).unwrap();
        // The engine counts from its own side: what it sent to the client is
        // what the client received.
        assert_eq!(counters.bytes_in, 4096);
        assert_eq!(counters.bytes_out, 1024);
        assert_eq!(counters.devices, 2);
        assert_eq!(counters.connections, 5);
        assert_eq!(reading.unread, 0);
    }

    #[test]
    fn an_empty_body_reads_as_nothing_used() {
        let reading = read("");
        assert!(reading.by_access.is_empty());
        assert_eq!(reading.unread, 0);
    }

    #[test]
    fn a_body_of_only_comments_reads_as_nothing_used() {
        let reading = read("# HELP telemt_build_info Build\n# TYPE telemt_build_info gauge\n");
        assert!(reading.by_access.is_empty());
        assert_eq!(reading.unread, 0);
    }

    #[test]
    fn lines_that_are_not_ours_are_passed_over_rather_than_counted_as_faults() {
        let reading = read(
            "telemt_connections_total 91\n\
             telemt_me_writers_total 4\n\
             telemt_build_info{version=\"3.5.3\"} 1\n",
        );
        assert!(reading.by_access.is_empty());
        assert_eq!(reading.unread, 0, "another metric was read as a fault");
    }

    #[test]
    fn a_body_cut_off_mid_line_keeps_everything_before_the_cut() {
        let access = Uuid::now_v7();
        let full = a_body(&user_of(access));
        let cut = &full[..full.len() - 30];

        let reading = read(cut);
        let counters = reading.by_access.get(&access).unwrap();
        assert_eq!(counters.bytes_in, 4096);
        assert_eq!(counters.bytes_out, 1024);
    }

    #[test]
    fn a_line_with_no_value_is_counted_as_unread() {
        let reading = read("telemt_user_octets_to_client{user=\"whoever\"}\n");
        assert!(reading.by_access.is_empty());
        assert_eq!(reading.unread, 1);
    }

    #[test]
    fn a_user_that_is_not_an_access_is_counted_as_unread() {
        let reading = read("telemt_user_octets_to_client{user=\"nobody\"} 12\n");
        assert!(reading.by_access.is_empty());
        assert_eq!(reading.unread, 1);
    }

    #[test]
    fn a_value_that_is_not_a_count_is_refused() {
        for value in ["NaN", "+Inf", "-1", "-12.5", "banana"] {
            let reading = read(&format!(
                "telemt_user_octets_to_client{{user=\"{}\"}} {value}\n",
                user_of(Uuid::now_v7())
            ));
            assert!(
                reading.by_access.is_empty() && reading.unread == 1,
                "{value} was read as a count"
            );
        }
    }

    #[test]
    fn a_count_written_as_a_decimal_is_read() {
        let access = Uuid::now_v7();
        let reading = read(&format!(
            "telemt_user_octets_to_client{{user=\"{}\"}} 4096.0\n",
            user_of(access)
        ));
        assert_eq!(reading.by_access.get(&access).unwrap().bytes_in, 4096);
    }

    #[test]
    fn the_user_label_is_found_among_others() {
        let access = Uuid::now_v7();
        let reading = read(&format!(
            "telemt_user_octets_to_client{{listener=\"443\",user=\"{}\"}} 7\n",
            user_of(access)
        ));
        assert_eq!(reading.by_access.get(&access).unwrap().bytes_in, 7);
    }

    #[test]
    fn two_accesses_are_kept_apart() {
        let first = Uuid::now_v7();
        let second = Uuid::now_v7();
        let body = format!(
            "telemt_user_octets_to_client{{user=\"{}\"}} 10\n\
             telemt_user_octets_to_client{{user=\"{}\"}} 20\n",
            user_of(first),
            user_of(second)
        );
        let reading = read(&body);
        assert_eq!(reading.by_access.get(&first).unwrap().bytes_in, 10);
        assert_eq!(reading.by_access.get(&second).unwrap().bytes_in, 20);
    }
}
