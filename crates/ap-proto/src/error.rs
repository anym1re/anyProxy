/// What can be wrong with a frame.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtoError {
    /// A frame declaring more than the ceiling allows.
    ///
    /// The length is checked before anything is reserved, so a frame claiming
    /// four gigabytes costs four bytes of reading and nothing else.
    #[error("frame declares {declared} bytes, the ceiling is {ceiling}")]
    FrameTooLarge {
        /// What the header claimed.
        declared: usize,
        /// What is allowed.
        ceiling: usize,
    },

    /// The payload is not JSON, or not the shape a message takes.
    #[error("payload is not a message: {0}")]
    Malformed(String),

    /// The peer speaks a version this build does not know.
    #[error("peer speaks protocol {theirs}, this build knows up to {ours}")]
    UnsupportedVersion {
        /// Version the peer asked for.
        theirs: u32,
        /// Highest version this build implements.
        ours: u32,
    },

    /// A telemetry frame carrying something shaped like a client address.
    ///
    /// Refused outright rather than parsed and ignored: a field that should
    /// never exist is a protocol violation, not a value to work around.
    #[error("telemetry carries a field named '{field}', which looks like a client address")]
    AddressInTelemetry {
        /// The offending field name.
        field: String,
    },
}
