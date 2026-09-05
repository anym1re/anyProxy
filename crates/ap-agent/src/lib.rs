//! Node-side daemon: panel channel, config cache, engine control.

pub mod backoff;
pub mod cache;
pub mod engine;
mod error;
pub mod host;
pub mod identity;
pub mod link;
pub mod meter;
pub mod only_one;
pub mod pin;
pub mod posture;
pub mod probe;
pub mod say;
pub mod session;
pub mod through;

pub use error::AgentError;

/// What the agent tells the panel it is.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
