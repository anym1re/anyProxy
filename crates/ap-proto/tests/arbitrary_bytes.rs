//! Feeds arbitrary bytes to the decoder.
//!
//! In Rust a malformed frame does not corrupt memory. It does two other
//! things: a panic is a denial of service, and a divergence in parsing is a
//! signal a censor can measure. Both are what this looks for.

// An integration test is a separate build target and does not inherit the
// relaxations in clippy.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ap_proto::{MAX_PAYLOAD, ProtoError, decode};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = decode(&bytes);
    }

    #[test]
    fn a_declared_length_never_drives_an_allocation(declared in any::<u32>()) {
        let frame = declared.to_be_bytes();
        match decode(&frame) {
            Ok(None) => prop_assert!((declared as usize) <= MAX_PAYLOAD),
            Err(ProtoError::FrameTooLarge { .. }) => {
                prop_assert!((declared as usize) > MAX_PAYLOAD)
            }
            other => prop_assert!(false, "unexpected {other:?}"),
        }
    }

    #[test]
    fn arbitrary_text_in_a_frame_never_panics(text in ".{0,512}") {
        let payload = text.as_bytes();
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(payload);
        let _ = decode(&frame);
    }

    #[test]
    fn truncating_a_frame_anywhere_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 4..512),
        cut in 0usize..512,
    ) {
        let cut = cut.min(bytes.len());
        let _ = decode(&bytes[..cut]);
    }
}
