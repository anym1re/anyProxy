/// What can stop an inbound.
#[derive(Debug, thiserror::Error)]
pub enum InboundError {
    /// The socket could not be opened or read.
    #[error("{0}")]
    Io(#[from] std::io::Error),

    /// The client did not speak the protocol this listener serves.
    #[error("the client did not speak {0}")]
    Protocol(&'static str),

    /// The client offered credentials this node does not serve.
    ///
    /// One variant for every way of failing: a wrong name, a wrong password,
    /// a disabled access and one belonging to another method must not be
    /// distinguishable from outside.
    #[error("refused")]
    Refused,

    /// The access is at its device limit and this is a new device.
    #[error("too many devices")]
    TooManyDevices,
}
