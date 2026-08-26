//! The panel refuses to hand out a secret it cannot record handing out.
//!
//! Its own target on purpose. Making the audit write fail means taking the
//! table away from the whole database, which any test running beside it would
//! see; cargo runs one test target at a time, so nothing else is running.
//! Skipped when DATABASE_URL is absent.

// An integration test is a separate build target and does not inherit the
// relaxations in clippy.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ap_core::Role;
use axum::http::StatusCode;

#[macro_use]
mod common;

use common::{admin, an_access, call};

// The audit entry is written before the link is produced. Renaming the table
// makes that write fail, and the secret must then not leave.
#[tokio::test]
async fn a_link_is_withheld_when_the_log_cannot_be_written() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (_, access_id) = an_access(&panel, &boss, "mtproto").await;

    let url = std::env::var("DATABASE_URL").unwrap();
    let side = ap_store::connect(&url, 1).await.unwrap();
    sqlx::query("alter table audit_log rename to audit_log_moved")
        .execute(&side)
        .await
        .unwrap();

    let reply = call(
        &panel.router,
        "POST",
        &format!("/v1/accesses/{access_id}/link"),
        Some(&boss),
        Some(serde_json::json!({ "host": "203.0.113.7", "acknowledged": true })),
    )
    .await;

    sqlx::query("alter table audit_log_moved rename to audit_log")
        .execute(&side)
        .await
        .unwrap();

    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!reply.body.contains("t.me"), "the link left anyway");
}
