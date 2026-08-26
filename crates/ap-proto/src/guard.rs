use crate::ProtoError;

/// Field-name segments that would name a client address.
///
/// Matched on whole segments split by underscore, not as substrings: the
/// letters of "ip" sit inside "description" and "recipient", and a check that
/// fires on those would be turned off within a week.
const ADDRESS_SEGMENTS: &[&str] = &[
    "ip",
    "ips",
    "addr",
    "addrs",
    "address",
    "addresses",
    "host",
    "hosts",
    "peer",
    "peers",
    "endpoint",
    "endpoints",
];

fn names_an_address(key: &str) -> bool {
    key.split('_')
        .any(|segment| ADDRESS_SEGMENTS.contains(&segment.to_ascii_lowercase().as_str()))
}

/// Refuses a telemetry payload carrying a field that names a client address.
///
/// Unknown fields are otherwise tolerated, because the protocol adds optional
/// fields as it grows. This one class is not tolerated: a node that reports an
/// address has broken the rule the whole design rests on, and parsing the rest
/// of the frame would leave that unnoticed.
pub fn refuse_address_fields(payload: &serde_json::Value) -> Result<(), ProtoError> {
    match payload {
        serde_json::Value::Object(fields) => {
            for (key, value) in fields {
                if names_an_address(key) {
                    return Err(ProtoError::AddressInTelemetry { field: key.clone() });
                }
                refuse_address_fields(value)?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for item in items {
                refuse_address_fields(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Takes out every field that names a client address, and says how many.
///
/// The engine keeps the addresses it is tracking, because tracking them is its
/// job. The agent has no use for them and no right to hold them, so they are
/// removed where the two meet rather than remembered not to be used: a caller
/// that logs the whole reply then has nothing to leak.
pub fn strip_address_fields(payload: &mut serde_json::Value) -> usize {
    match payload {
        serde_json::Value::Object(fields) => {
            let named: Vec<String> = fields
                .keys()
                .filter(|key| names_an_address(key))
                .cloned()
                .collect();
            let mut taken = named.len();
            for key in named {
                fields.remove(&key);
            }
            for value in fields.values_mut() {
                taken += strip_address_fields(value);
            }
            taken
        }
        serde_json::Value::Array(items) => items.iter_mut().map(strip_address_fields).sum(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(text: &str) -> serde_json::Value {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn a_client_address_is_refused_wherever_it_hides() {
        for text in [
            r#"{"client_ip": "203.0.113.7"}"#,
            r#"{"deltas": [{"peer_addr": "x"}]}"#,
            r#"{"health": {"remote_host": "x"}}"#,
            r#"{"ip": "x"}"#,
            r#"{"addresses": []}"#,
            r#"{"a": {"b": {"c": {"endpoint": "x"}}}}"#,
        ] {
            assert!(
                refuse_address_fields(&json(text)).is_err(),
                "accepted {text}"
            );
        }
    }

    #[test]
    fn ordinary_fields_pass() {
        for text in [
            r#"{"unique": 3}"#,
            r#"{"bytes_in": 1, "bytes_out": 2}"#,
            r#"{"description": "recipient of multiple"}"#,
            r#"{"access_id": "x", "day": "2026-08-26"}"#,
            r#"{"gossip": 1, "zipper": 2, "chip": 3}"#,
            r#"{"health": {"engine": "up", "site": "up"}}"#,
        ] {
            assert!(refuse_address_fields(&json(text)).is_ok(), "refused {text}");
        }
    }

    #[test]
    fn the_offending_field_is_named() {
        let error = refuse_address_fields(&json(r#"{"deltas":[{"client_ip":"x"}]}"#)).unwrap_err();
        assert_eq!(
            error,
            ProtoError::AddressInTelemetry {
                field: "client_ip".to_owned()
            }
        );
    }

    #[test]
    fn stripping_takes_out_the_addresses_and_leaves_the_rest() {
        let mut payload = json(
            r#"{"username":"abc","current_connections":2,
                "active_unique_ips_list":["203.0.113.7"],
                "recent_unique_ips_list":["203.0.113.8"],
                "active_unique_ips":1}"#,
        );
        let taken = strip_address_fields(&mut payload);

        assert_eq!(taken, 3, "a field naming an address was left behind");
        assert!(refuse_address_fields(&payload).is_ok());
        assert_eq!(payload["username"], "abc");
        assert_eq!(payload["current_connections"], 2);
        assert!(!payload.to_string().contains("203.0.113"));
    }

    #[test]
    fn stripping_reaches_inside_arrays_and_nested_objects() {
        let mut payload = json(
            r#"{"users":[{"username":"a","active_unique_ips_list":["203.0.113.7"]},
                         {"username":"b","peer":"203.0.113.8"}],
                "node":{"health":{"host":"cover.example.com"}}}"#,
        );
        let taken = strip_address_fields(&mut payload);

        assert_eq!(taken, 3);
        assert!(!payload.to_string().contains("203.0.113"));
        assert!(!payload.to_string().contains("cover.example.com"));
        assert_eq!(payload["users"][0]["username"], "a");
    }

    #[test]
    fn stripping_a_payload_with_nothing_to_take_changes_nothing() {
        let before = json(r#"{"username":"abc","current_connections":2}"#);
        let mut payload = before.clone();
        assert_eq!(strip_address_fields(&mut payload), 0);
        assert_eq!(payload, before);
    }
}
