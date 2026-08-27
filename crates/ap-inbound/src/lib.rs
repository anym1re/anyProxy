//! SOCKS5 and HTTP CONNECT listeners for open nodes.
//!
//! Nothing here writes down a client's address or where it asked to go. The
//! registry holds digests taken with a salt drawn once per process, so what it
//! can report is how many distinct devices used an access and nothing that
//! could be turned back into one of them.

mod error;
pub mod http;
pub mod registry;
pub mod serve;
pub mod socks5;

pub use error::InboundError;
pub use registry::{Method, Registry};
pub use serve::serve;
