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
        Self::page(pool, limit, 0, None, None)
            .await
            .map(|page| page.0)
    }

    /// A page of the journal, and how many entries the filter matches (0067).
    ///
    /// The filter is a prefix of the action name — `node.` for everything
    /// done to nodes — and a point in time to start from. Both are optional
    /// and neither is a search: the screen asks for a kind and a window,
    /// which is what it was drawn with.
    pub async fn page(
        pool: &PgPool,
        limit: i64,
        offset: i64,
        prefixes: Option<&[String]>,
        since: Option<OffsetDateTime>,
    ) -> Result<(Vec<AuditEntry>, i64), StoreError> {
        // A group on the screen can be more than one kind of record — what is
        // done to accesses is done under two names — so the filter is a list
        // of beginnings and an entry matches if it starts with any of them.
        let patterns: Option<Vec<String>> =
            prefixes.map(|list| list.iter().map(|one| format!("{one}%")).collect());
        let where_clause = "where ($1::text[] is null or action like any($1)) \
             and ($2::timestamptz is null or at >= $2)";
        let rows = sqlx::query(&format!(
            "select id, actor_id, action, target, at, details from audit_log \
             {where_clause} order by at desc, id desc limit $3 offset $4"
        ))
        .bind(patterns.as_deref())
        .bind(since)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
        let total: i64 = sqlx::query(&format!(
            "select count(*)::bigint as total from audit_log {where_clause}"
        ))
        .bind(patterns.as_deref())
        .bind(since)
        .fetch_one(pool)
        .await?
        .try_get("total")?;
        let entries: Result<Vec<_>, StoreError> = rows
            .into_iter()
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
            .collect();
        Ok((entries?, total))
    }

    /// How many entries of each action there are since a point in time.
    ///
    /// What the screen makes of them — which actions belong under «nodes» and
    /// which under «accesses» — is the screen's business (0067).
    pub async fn counts(
        pool: &PgPool,
        since: OffsetDateTime,
    ) -> Result<Vec<(String, i64)>, StoreError> {
        let rows = sqlx::query(
            "select action, count(*)::bigint as many from audit_log \
             where at >= $1 group by action order by action",
        )
        .bind(since)
        .fetch_all(pool)
        .await?;
        rows.into_iter()
            .map(|row| Ok((row.try_get("action")?, row.try_get("many")?)))
            .collect()
    }
}
