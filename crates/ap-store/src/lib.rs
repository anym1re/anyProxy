//! PostgreSQL persistence for the panel.
//!
//! Queries are checked by integration tests against a real schema rather than
//! at compile time: the offline data compile-time checking needs is produced
//! by a live database, which the development machine does not have.

mod access;
mod audit;
mod client;
mod error;
mod node;
mod tag;
mod traffic;

pub use access::AccessRepo;
pub use audit::{AuditEntry, AuditRepo};
pub use client::ClientRepo;
pub use error::StoreError;
pub use node::NodeRepo;
pub use tag::TagRepo;
pub use traffic::{TrafficRepo, TrafficTotals};

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// Opens a pool against the given connection string.
pub async fn connect(url: &str, max_connections: u32) -> Result<PgPool, StoreError> {
    Ok(PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await?)
}

/// The migrations, in the order they apply, embedded in the binary.
///
/// Applied by the code below rather than by the sqlx macro: the macro lives in
/// sqlx-macros-core, which depends on the MySQL driver unconditionally, and
/// that driver brings in a crate with an unfixed timing advisory. This project
/// speaks to PostgreSQL only, so the driver is removed rather than silenced.
const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_initial",
        include_str!("../../../migrations/0001_initial.sql"),
    ),
    (
        "0002_app_role",
        include_str!("../../../migrations/0002_app_role.sql"),
    ),
];

/// Applies every migration that has not run yet. Running it twice is a no-op.
pub async fn migrate(pool: &PgPool) -> Result<(), StoreError> {
    sqlx::query(
        "create table if not exists schema_migration (             version text primary key,              applied_at timestamptz not null default now())",
    )
    .execute(pool)
    .await?;

    for (version, statements) in MIGRATIONS {
        let applied: Option<String> =
            sqlx::query_scalar("select version from schema_migration where version = $1")
                .bind(version)
                .fetch_optional(pool)
                .await?;
        if applied.is_some() {
            continue;
        }

        let mut transaction = pool.begin().await?;
        sqlx::raw_sql(statements).execute(&mut *transaction).await?;
        sqlx::query("insert into schema_migration (version) values ($1)")
            .bind(version)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
    }
    Ok(())
}
