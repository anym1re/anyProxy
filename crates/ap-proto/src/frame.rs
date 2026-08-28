use crate::ProtoError;
use crate::guard::refuse_address_fields;
use crate::message::{Message, PROTOCOL_VERSION};

/// Bytes of length that precede every payload.
pub const HEADER_LEN: usize = 4;

/// Largest payload a frame may declare.
pub const MAX_PAYLOAD: usize = 1024 * 1024;

/// Writes a message as a frame.
pub fn encode(message: &Message) -> Result<Vec<u8>, ProtoError> {
    let payload =
        serde_json::to_vec(message).map_err(|error| ProtoError::Malformed(error.to_string()))?;
    if payload.len() > MAX_PAYLOAD {
        return Err(ProtoError::FrameTooLarge {
            declared: payload.len(),
            ceiling: MAX_PAYLOAD,
        });
    }
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Reads one frame from the front of a buffer.
///
/// Returns the message and how many bytes it consumed, or `None` when the
/// buffer does not yet hold a whole frame. The declared length is checked
/// against the ceiling before anything is reserved, so a frame claiming four
/// gigabytes costs four bytes of reading.
pub fn decode(buffer: &[u8]) -> Result<Option<(Message, usize)>, ProtoError> {
    let Some(header) = buffer.get(..HEADER_LEN) else {
        return Ok(None);
    };
    let declared = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;

    if declared > MAX_PAYLOAD {
        return Err(ProtoError::FrameTooLarge {
            declared,
            ceiling: MAX_PAYLOAD,
        });
    }

    let total = HEADER_LEN + declared;
    let Some(payload) = buffer.get(HEADER_LEN..total) else {
        return Ok(None);
    };

    let value: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|error| ProtoError::Malformed(error.to_string()))?;

    if value.get("t").and_then(serde_json::Value::as_str) == Some("telemetry") {
        refuse_address_fields(&value)?;
    }

    let message: Message =
        serde_json::from_value(value).map_err(|error| ProtoError::Malformed(error.to_string()))?;

    if let Some(theirs) = message.declared_version()
        && theirs > PROTOCOL_VERSION
    {
        return Err(ProtoError::UnsupportedVersion {
            theirs,
            ours: PROTOCOL_VERSION,
        });
    }

    Ok(Some((message, total)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::*;
    use uuid::Uuid;

    fn hello() -> Message {
        Message::Hello(Hello {
            proto: PROTOCOL_VERSION,
            node_id: Uuid::now_v7(),
            agent_version: "0.0.0".to_owned(),
            applied_revision: None,
        })
    }

    fn every_message() -> Vec<Message> {
        vec![
            hello(),
            Message::Welcome(Welcome {
                proto: PROTOCOL_VERSION,
                cache_key: "00".repeat(32),
                heartbeat_secs: 30,
                cache_ttl_secs: 259_200,
            }),
            Message::Enroll(Enroll {
                proto: PROTOCOL_VERSION,
                code: "code".to_owned(),
                csr: "-----BEGIN CERTIFICATE REQUEST-----".to_owned(),
                agent_version: "0.0.0".to_owned(),
            }),
            Message::Enrolled(Enrolled {
                node_id: Uuid::now_v7(),
                certificate: "pem".to_owned(),
                ca: "pem".to_owned(),
                not_after: "2026-12-31T23:59:59Z".to_owned(),
            }),
            Message::Config(Config {
                revision: Uuid::now_v7(),
                issued_at: "2026-08-26T00:00:00Z".to_owned(),
                node: NodeShape {
                    kind: "faketls".to_owned(),
                    domain: Some("cover.example.com".to_owned()),
                    ad_tag: None,
                },
                listeners: vec![Listener {
                    method: "faketls".to_owned(),
                    bind: "0.0.0.0:443".to_owned(),
                }],
                accesses: vec![WireAccess {
                    id: Uuid::now_v7(),
                    method: "faketls".to_owned(),
                    credential: WireCredential::Secret {
                        hex: "00".repeat(16),
                    },
                    max_devices: Some(5),
                    state: "active".to_owned(),
                }],
                policy: Policy {
                    log_level: "minimal".to_owned(),
                    carrier_mode: "https".to_owned(),
                },
            }),
            Message::Applied(Applied {
                revision: Uuid::now_v7(),
                status: "ok".to_owned(),
                detail: None,
            }),
            Message::Telemetry(Telemetry {
                revision: Uuid::now_v7(),
                sent_at: "2026-08-26T00:00:00Z".to_owned(),
                deltas: vec![TrafficDelta {
                    access_id: Uuid::now_v7(),
                    day: "2026-08-26".to_owned(),
                    bytes_in: 1,
                    bytes_out: 2,
                }],
                devices: vec![DeviceCount {
                    access_id: Uuid::now_v7(),
                    period: "2026-08-26".to_owned(),
                    unique: 3,
                }],
                health: Health {
                    engine: "up".to_owned(),
                    site: "up".to_owned(),
                    cert_not_after: None,
                },
            }),
            Message::Ack(Ack {
                revision: Uuid::now_v7(),
            }),
            Message::Command(Command {
                id: Uuid::now_v7(),
                action: "reload".to_owned(),
                args: serde_json::json!({}),
            }),
            Message::Result(CommandResult {
                id: Uuid::now_v7(),
                status: "ok".to_owned(),
                detail: None,
            }),
        ]
    }

    #[test]
    fn every_message_survives_a_round_trip() {
        for message in every_message() {
            let frame = encode(&message).unwrap();
            let (read, consumed) = decode(&frame).unwrap().unwrap();
            assert_eq!(read, message);
            assert_eq!(consumed, frame.len());
        }
    }

    #[test]
    fn all_ten_kinds_are_covered() {
        assert_eq!(every_message().len(), 10);
    }

    #[test]
    fn a_frame_is_read_out_of_a_longer_buffer() {
        let first = encode(&hello()).unwrap();
        let second = encode(&hello()).unwrap();
        let mut buffer = first.clone();
        buffer.extend_from_slice(&second);

        let (_, consumed) = decode(&buffer).unwrap().unwrap();
        assert_eq!(consumed, first.len());
        assert!(decode(&buffer[consumed..]).unwrap().is_some());
    }

    #[test]
    fn a_partial_frame_asks_for_more() {
        let frame = encode(&hello()).unwrap();
        for cut in 0..frame.len() {
            assert_eq!(decode(&frame[..cut]).unwrap(), None, "cut at {cut}");
        }
    }

    #[test]
    fn an_empty_payload_is_malformed_not_a_panic() {
        let frame = [0u8, 0, 0, 0];
        assert!(matches!(decode(&frame), Err(ProtoError::Malformed(_))));
    }

    #[test]
    fn the_ceiling_is_enforced_on_the_header_alone() {
        let mut frame = ((MAX_PAYLOAD + 1) as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(b"{}");
        assert_eq!(
            decode(&frame),
            Err(ProtoError::FrameTooLarge {
                declared: MAX_PAYLOAD + 1,
                ceiling: MAX_PAYLOAD
            })
        );
    }

    // A frame claiming four gigabytes must cost four bytes of reading. If the
    // length were used to reserve before being checked, this test would take
    // the machine down rather than fail.
    #[test]
    fn a_huge_declared_length_reserves_nothing() {
        let frame = u32::MAX.to_be_bytes();
        assert_eq!(
            decode(&frame),
            Err(ProtoError::FrameTooLarge {
                declared: u32::MAX as usize,
                ceiling: MAX_PAYLOAD
            })
        );
    }

    #[test]
    fn a_payload_at_the_ceiling_is_accepted() {
        let filler = "x".repeat(MAX_PAYLOAD - 200);
        let message = Message::Applied(Applied {
            revision: Uuid::now_v7(),
            status: "rejected".to_owned(),
            detail: Some(filler),
        });
        let frame = encode(&message).unwrap();
        assert!(frame.len() <= HEADER_LEN + MAX_PAYLOAD);
        assert_eq!(decode(&frame).unwrap().unwrap().0, message);
    }

    #[test]
    fn rubbish_payloads_are_malformed_not_panics() {
        for payload in [
            &b"not json"[..],
            b"{}",
            br#"{"t": "unknown"}"#,
            br#"{"t": 7}"#,
            br#"{"t": "hello"}"#,
            br#"[1,2,3]"#,
            b"null",
            &[0xff, 0xfe, 0xfd],
        ] {
            let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(payload);
            assert!(
                matches!(decode(&frame), Err(ProtoError::Malformed(_))),
                "unexpected result for {payload:?}"
            );
        }
    }

    #[test]
    fn a_newer_protocol_is_refused_by_name() {
        let message = Message::Hello(Hello {
            proto: PROTOCOL_VERSION + 1,
            node_id: Uuid::now_v7(),
            agent_version: "0.0.0".to_owned(),
            applied_revision: None,
        });
        let frame = encode(&message).unwrap();
        assert_eq!(
            decode(&frame),
            Err(ProtoError::UnsupportedVersion {
                theirs: PROTOCOL_VERSION + 1,
                ours: PROTOCOL_VERSION
            })
        );
    }

    #[test]
    fn telemetry_carrying_an_address_is_refused() {
        let payload = br#"{"t":"telemetry","revision":"018f0000-0000-7000-8000-000000000000",
            "sent_at":"2026-08-26T00:00:00Z","deltas":[{"access_id":"018f0000-0000-7000-8000-000000000001",
            "day":"2026-08-26","bytes_in":1,"bytes_out":2,"client_ip":"203.0.113.7"}],
            "devices":[],"health":{"engine":"up","site":"up","cert_not_after":null}}"#;
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(payload);
        assert_eq!(
            decode(&frame),
            Err(ProtoError::AddressInTelemetry {
                field: "client_ip".to_owned()
            })
        );
    }

    #[test]
    fn telemetry_with_a_device_count_is_accepted() {
        let message = every_message()
            .into_iter()
            .find(|message| matches!(message, Message::Telemetry(_)))
            .unwrap();
        let frame = encode(&message).unwrap();
        assert_eq!(decode(&frame).unwrap().unwrap().0, message);
    }

    // Only telemetry is scanned. A future field naming the panel's own host
    // in a welcome frame is legitimate and must not be caught by the rule
    // meant for client addresses.
    #[test]
    fn other_frames_are_not_scanned_for_address_fields() {
        let payload =
            br#"{"t":"ack","revision":"018f0000-0000-7000-8000-000000000000","panel_host":"x"}"#;
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(payload);
        assert!(decode(&frame).unwrap().is_some());
    }
}
