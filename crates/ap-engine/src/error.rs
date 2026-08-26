/// What can go wrong between the agent and the engine.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The pinned build could not be read or does not look like one.
    #[error("engine pin: {0}")]
    Pin(String),

    /// A value the panel sent is not one this engine serves.
    #[error("{0}")]
    Refused(String),

    /// The control API did not answer, or answered with a failure.
    #[error("engine control: {0}")]
    Control(String),

    /// A file could not be read or written.
    #[error("{0}: {1}")]
    File(String, std::io::Error),
}

impl EngineError {
    /// Wraps an input or output failure with the path it happened on.
    pub fn file(path: impl std::fmt::Display, error: std::io::Error) -> Self {
        Self::File(path.to_string(), error)
    }
}
