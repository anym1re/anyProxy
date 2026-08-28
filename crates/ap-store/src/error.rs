/// What can go wrong between the panel and its database.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database refused or could not answer.
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),

    /// A row held a value no domain type accepts.
    #[error("stored row does not map to a domain value: {0}")]
    Domain(#[from] ap_core::Error),

    /// A migration would not apply.
    #[error("migration: {0}")]
    Migration(String),

    /// A row the schema should not have allowed.
    #[error("stored row is not one the schema permits: {0}")]
    Impossible(String),
}

impl StoreError {
    /// Whether the database refused the write because a constraint said no,
    /// as opposed to being unreachable.
    pub fn is_constraint_violation(&self) -> bool {
        match self {
            Self::Database(sqlx::Error::Database(error)) => {
                matches!(error.code().as_deref(), Some(code) if code.starts_with("23"))
            }
            _ => false,
        }
    }

    /// Whether the database refused the write for lack of privilege.
    pub fn is_permission_denied(&self) -> bool {
        match self {
            Self::Database(sqlx::Error::Database(error)) => {
                error.code().as_deref() == Some("42501")
            }
            _ => false,
        }
    }
}
