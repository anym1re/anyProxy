//! Migrations against a database nobody has touched yet.
//!
//! Its own target because it creates and drops databases, which is not
//! something the other tests should find happening beside them.
//! Skipped when DATABASE_URL is absent.

// An integration test is a separate build target and does not inherit the
// relaxations in clippy.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sqlx::Row;
use uuid::Uuid;

/// Points a connection string at another database on the same server.
fn pointing_at(url: &str, database: &str) -> String {
    let (server, _) = url
        .rsplit_once('/')
        .expect("a connection string with a path");
    format!("{server}/{database}")
}

/// A database created for one test and dropped after it.
struct Fresh {
    admin: String,
    name: String,
    url: String,
}

impl Fresh {
    async fn open() -> Option<Self> {
        let admin = std::env::var("DATABASE_URL").ok()?;
        let name = format!("anyproxy_migrate_{}", Uuid::now_v7().simple());
        let pool = ap_store::connect(&admin, 1).await.unwrap();
        sqlx::query(&format!("create database \"{name}\""))
            .execute(&pool)
            .await
            .unwrap();
        let url = pointing_at(&admin, &name);
        Some(Self { admin, name, url })
    }

    async fn drop_it(self) {
        let pool = ap_store::connect(&self.admin, 1).await.unwrap();
        let _ = sqlx::query(&format!(
            "drop database if exists \"{}\" with (force)",
            self.name
        ))
        .execute(&pool)
        .await;
    }
}

macro_rules! fresh {
    () => {
        match Fresh::open().await {
            Some(fresh) => fresh,
            None => return,
        }
    };
}

#[tokio::test]
async fn migrating_an_untouched_database_leaves_every_version_applied() {
    let fresh = fresh!();
    let pool = ap_store::connect(&fresh.url, 2).await.unwrap();
    ap_store::migrate(&pool).await.unwrap();

    let versions: Vec<String> =
        sqlx::query("select version from schema_migration order by version")
            .fetch_all(&pool)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.get("version"))
            .collect();
    assert_eq!(
        versions,
        vec![
            "0001_initial",
            "0002_app_role",
            "0003_admin",
            "0004_channel"
        ]
    );

    drop(pool);
    fresh.drop_it().await;
}

#[tokio::test]
async fn migrators_that_start_together_do_not_collide() {
    let fresh = fresh!();

    // A thread with a runtime of its own for each, which is what six processes
    // starting at the same moment amount to. Against an untouched database
    // they all find the same work to do.
    let racing: Vec<_> = (0..6)
        .map(|_| {
            let url = fresh.url.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let pool = ap_store::connect(&url, 2).await.unwrap();
                    ap_store::migrate(&pool)
                        .await
                        .map_err(|error| error.to_string())
                })
            })
        })
        .collect();

    for (n, started) in racing.into_iter().enumerate() {
        let outcome = started.join().unwrap();
        assert!(
            outcome.is_ok(),
            "migrator {n} failed while others were running: {outcome:?}"
        );
    }

    let pool = ap_store::connect(&fresh.url, 1).await.unwrap();
    let applied: i64 = sqlx::query("select count(*) as n from schema_migration")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("n");
    assert_eq!(applied, 4, "a migration was recorded more than once");

    drop(pool);
    fresh.drop_it().await;
}

#[tokio::test]
async fn migrating_twice_changes_nothing() {
    let fresh = fresh!();
    let pool = ap_store::connect(&fresh.url, 2).await.unwrap();

    ap_store::migrate(&pool).await.unwrap();
    let first: Vec<(String, time::OffsetDateTime)> =
        sqlx::query("select version, applied_at from schema_migration order by version")
            .fetch_all(&pool)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.get("version"), row.get("applied_at")))
            .collect();

    ap_store::migrate(&pool).await.unwrap();
    let second: Vec<(String, time::OffsetDateTime)> =
        sqlx::query("select version, applied_at from schema_migration order by version")
            .fetch_all(&pool)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.get("version"), row.get("applied_at")))
            .collect();

    assert_eq!(
        first, second,
        "the second run rewrote what the first applied"
    );

    drop(pool);
    fresh.drop_it().await;
}

#[tokio::test]
async fn the_lock_is_released_when_the_migrator_is_done() {
    let fresh = fresh!();
    let pool = ap_store::connect(&fresh.url, 2).await.unwrap();
    ap_store::migrate(&pool).await.unwrap();

    // A migrator that returned still holding its lock would stop the next one
    // for as long as its process lives.
    //
    // Counted on this database alone: every test here has one of its own, and
    // a count across the server would include locks the other tests are
    // holding at that moment.
    let held: i64 = sqlx::query(
        "select count(*) as n from pg_locks          where locktype = 'advisory' and granted            and database = (select oid from pg_database where datname = current_database())",
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .get("n");
    assert_eq!(held, 0, "the migrator kept the lock");

    drop(pool);
    fresh.drop_it().await;
}
