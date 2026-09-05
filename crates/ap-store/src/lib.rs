//! PostgreSQL persistence for the panel.
//!
//! Queries are checked by integration tests against a real schema rather than
//! at compile time: the offline data compile-time checking needs is produced
//! by a live database, which the development machine does not have.

mod access;
mod admin;
mod audit;
mod channel;
mod client;
mod error;
mod node;
mod tag;
mod traffic;

pub use access::AccessRepo;
pub use admin::{AdminRepo, SessionRepo};
pub use audit::{AuditEntry, AuditRepo};
pub use channel::{EnrollmentRepo, PanelIdentity, PanelIdentityRepo, PresenceRepo};
pub use client::ClientRepo;
pub use error::StoreError;
pub use node::NodeRepo;
pub use tag::TagRepo;
pub use traffic::{DailyTraffic, TrafficRepo, TrafficTotals};

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
    (
        "0003_admin",
        include_str!("../../../migrations/0003_admin.sql"),
    ),
    (
        "0004_channel",
        include_str!("../../../migrations/0004_channel.sql"),
    ),
    (
        "0005_node_seen",
        include_str!("../../../migrations/0005_node_seen.sql"),
    ),
    (
        "0006_traffic_delta_per_access",
        include_str!("../../../migrations/0006_traffic_delta_per_access.sql"),
    ),
    (
        "0007_node_alibi",
        include_str!("../../../migrations/0007_node_alibi.sql"),
    ),
    (
        "0008_node_kinds",
        include_str!("../../../migrations/0008_node_kinds.sql"),
    ),
    (
        "0009_one_method_per_host",
        include_str!("../../../migrations/0009_one_method_per_host.sql"),
    ),
    (
        "0010_node_ad_tag",
        include_str!("../../../migrations/0010_node_ad_tag.sql"),
    ),
    (
        "0011_public_links",
        include_str!("../../../migrations/0011_public_links.sql"),
    ),
    (
        "0012_node_served_digest",
        include_str!("../../../migrations/0012_node_served_digest.sql"),
    ),
    (
        "0013_node_reach",
        include_str!("../../../migrations/0013_node_reach.sql"),
    ),
    (
        "0014_node_machine",
        include_str!("../../../migrations/0014_node_machine.sql"),
    ),
    (
        "0015_admin_totp_optional",
        include_str!("../../../migrations/0015_admin_totp_optional.sql"),
    ),
];

/// The migrations this build carries, in the order they apply.
///
/// Exposed so a test can check what was applied against what exists, rather
/// than against a list written out beside it: a list that has to be edited
/// whenever a migration is added is a list that will eventually be edited
/// without looking.
pub fn migration_versions() -> Vec<&'static str> {
    MIGRATIONS.iter().map(|(version, _)| *version).collect()
}

/// What the migrator holds while it works. The value is the project's name in
/// ASCII, so `pg_locks` says who is holding it.
const MIGRATION_LOCK: i64 = 0x616e_7970_726f_7879;

/// Applies every migration that has not run yet. Running it twice is a no-op.
///
/// Two processes may start at once — a panel and a command, or two panels
/// behind one address — and against a database nobody has migrated yet both
/// would see the same version as unapplied and both would try to apply it. The
/// lock makes them take turns, and the one that arrives second finds the work
/// already done.
///
/// Everything runs in one transaction, so the lock is released by the commit
/// and a process that dies part way through leaves neither a half-applied
/// schema nor a lock nobody will drop.
pub async fn migrate(pool: &PgPool) -> Result<(), StoreError> {
    let mut transaction = pool.begin().await?;

    sqlx::query("select pg_advisory_xact_lock($1)")
        .bind(MIGRATION_LOCK)
        .execute(&mut *transaction)
        .await?;

    sqlx::query(
        "create table if not exists schema_migration (             version text primary key,              applied_at timestamptz not null default now())",
    )
    .execute(&mut *transaction)
    .await?;

    for (version, statements) in MIGRATIONS {
        let applied: Option<String> =
            sqlx::query_scalar("select version from schema_migration where version = $1")
                .bind(version)
                .fetch_optional(&mut *transaction)
                .await?;
        if applied.is_some() {
            continue;
        }

        sqlx::raw_sql(statements).execute(&mut *transaction).await?;
        sqlx::query("insert into schema_migration (version) values ($1)")
            .bind(version)
            .execute(&mut *transaction)
            .await?;
    }

    transaction.commit().await?;
    Ok(())
}
