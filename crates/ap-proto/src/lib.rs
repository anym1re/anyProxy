//! Wire format between the panel and node agents.
//!
//! Bytes in, messages out. Nothing here touches a socket: the channel lives in
//! the panel and the agent, and keeping this crate free of I/O is what lets a
//! malformed frame be tested without a network.

mod error;
mod frame;
pub mod guard;
mod message;

pub use error::ProtoError;
pub use frame::{HEADER_LEN, MAX_PAYLOAD, decode, encode};
pub use message::{
    Ack, Applied, Command, CommandResult, Config, DeviceCount, Enroll, Enrolled, Health, Hello,
    Listener, Message, NodeShape, PROTOCOL_VERSION, Policy, Telemetry, TrafficDelta, Welcome,
    WireAccess, WireCredential,
};
