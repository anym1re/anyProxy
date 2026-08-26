/// What can stop the agent.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// A file could not be read or written.
    #[error("{0}: {1}")]
    File(String, std::io::Error),

    /// A file the agent must be alone in reading was readable by others.
    #[error("{0} is readable beyond its owner")]
    Exposed(String),

    /// The panel did not present the certificate the operator pinned.
    #[error("the panel presented a certificate that is not the pinned one")]
    WrongPanel,

    /// The panel refused, or the exchange did not reach it.
    #[error("panel: {0}")]
    Panel(String),

    /// A frame did not belong where it arrived.
    #[error("unexpected frame: {0}")]
    Unexpected(&'static str),

    /// A value the agent produced or received did not hold up.
    #[error("{0}")]
    Refused(String),

    /// The cache could not be opened with the key the panel sent.
    #[error("the cache does not open with this key")]
    Cache,
}

impl AgentError {
    /// Wraps an input or output failure with the path it happened on.
    pub fn file(path: impl std::fmt::Display, error: std::io::Error) -> Self {
        Self::File(path.to_string(), error)
    }
}
