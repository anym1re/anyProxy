use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::StoreError;

/// One recorded administrative action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// Identifier of the entry.
    pub id: Uuid,
    /// Who acted, when known.
    pub actor_id: Option<Uuid>,
    /// What was done.
    pub action: String,
    /// What it was done to.
    pub target: Option<String>,
    /// When it happened.
    pub at: OffsetDateTime,
    /// Anything else worth keeping.
    pub details: serde_json::Value,
}

/// Appends to and reads the audit log.
///
/// The application role holds only insert and select on this table: a
/// compromised administrator must not be able to erase their own trail.
pub struct AuditRepo;

impl AuditRepo {
    /// Records an action.
    pub async fn record(
        pool: &PgPool,
        actor_id: Option<Uuid>,
        action: &str,
        target: Option<&str>,
        at: OffsetDateTime,
        details: serde_json::Value,
    ) -> Result<Uuid, StoreError> {
        let id = Uuid::now_v7();
        sqlx::query(
            "insert into audit_log (id, actor_id, action, target, at, details) \
             values ($1, $2, $3, $4, $5, $6)",
        )
        .bind(id)
        .bind(actor_id)
        .bind(action)
        .bind(target)
        .bind(at)
        .bind(details)
        .execute(pool)
        .await?;
        Ok(id)
    }

    /// The most recent entries, newest first.
    pub async fn recent(pool: &PgPool, limit: i64) -> Result<Vec<AuditEntry>, StoreError> {
        let rows = sqlx::query(
            "select id, actor_id, action, target, at, details from audit_log \
             order by at desc, id desc limit $1",
        )
        .bind(limit)
        .fetch_all(pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(AuditEntry {
                    id: row.try_get("id")?,
                    actor_id: row.try_get("actor_id")?,
                    action: row.try_get("action")?,
                    target: row.try_get("target")?,
                    at: row.try_get("at")?,
                    details: row.try_get("details")?,
                })
            })
            .collect()
    }
}
