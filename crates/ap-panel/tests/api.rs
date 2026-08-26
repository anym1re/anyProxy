//! Exercised against a real PostgreSQL through the router, without a socket.
//! Skipped when DATABASE_URL is absent.

// An integration test is a separate build target and does not inherit the
// relaxations in clippy.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::time::Instant;

use ap_core::Role;
use ap_panel::{AppState, Config};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

struct Panel {
    router: Router,
    state: AppState,
}

fn key_file() -> PathBuf {
    let dir = std::env::temp_dir().join("anyproxy-panel-test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("panel.key");
    if !path.exists() {
        std::fs::write(&path, [11u8; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
    }
    path
}

async fn panel() -> Option<Panel> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let config = Config::loopback(0, url, key_file());
    let state = AppState::build(&config).await.expect("state");
    Some(Panel {
        router: ap_panel::router(state.clone()),
        state,
    })
}

macro_rules! panel {
    () => {
        match panel().await {
            Some(panel) => panel,
            None => return,
        }
    };
}

fn unique(prefix: &str) -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}{}", stamp % 100_000_000)
}

struct Reply {
    status: StatusCode,
    body: String,
    retry_after: Option<String>,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

async fn call(
    router: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> Reply {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let request = match body {
        Some(value) => request
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
            .unwrap(),
        None => request.body(Body::empty()).unwrap(),
    };

    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let retry_after = response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
        retry_after,
    }
}

fn code_now(secret: &str) -> String {
    let bytes = totp_rs::Secret::Encoded(secret.to_owned())
        .to_bytes()
        .unwrap();
    totp_rs::TOTP::new(totp_rs::Algorithm::SHA1, 6, 1, 30, bytes)
        .unwrap()
        .generate_current()
        .unwrap()
}

async fn admin(panel: &Panel, role: Role) -> (String, String) {
    let login = unique("a");
    let secret = ap_panel::create_admin(&panel.state, &login, "correct horse", role)
        .await
        .expect("admin");
    let reply = call(
        &panel.router,
        "POST",
        "/v1/session",
        None,
        Some(serde_json::json!({
            "login": login, "password": "correct horse", "totp": code_now(&secret)
        })),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let token = reply.json()["token"].as_str().unwrap().to_owned();
    (login, token)
}

#[tokio::test]
async fn signing_in_needs_all_three_factors() {
    let panel = panel!();
    let login = unique("a");
    let secret = ap_panel::create_admin(&panel.state, &login, "correct horse", Role::Superadmin)
        .await
        .unwrap();

    let missing = call(
        &panel.router,
        "POST",
        "/v1/session",
        None,
        Some(serde_json::json!({ "login": login, "password": "correct horse" })),
    )
    .await;
    assert!(
        missing.status.is_client_error(),
        "a body without a second factor was accepted"
    );

    let empty = call(
        &panel.router,
        "POST",
        "/v1/session",
        None,
        Some(serde_json::json!({ "login": login, "password": "correct horse", "totp": "" })),
    )
    .await;
    assert_eq!(empty.status, StatusCode::UNAUTHORIZED);

    let good = call(
        &panel.router,
        "POST",
        "/v1/session",
        None,
        Some(serde_json::json!({
            "login": login, "password": "correct horse", "totp": code_now(&secret)
        })),
    )
    .await;
    assert_eq!(good.status, StatusCode::CREATED);
}

#[tokio::test]
async fn every_way_of_failing_to_sign_in_looks_the_same() {
    let panel = panel!();

    // A separate account per case. Sharing one would spend its five attempts
    // and turn the sixth into a refusal by rate limit, which is a different
    // answer and would hide what this test is looking at.
    let wrong_password = unique("a");
    let secret_a = ap_panel::create_admin(
        &panel.state,
        &wrong_password,
        "correct horse",
        Role::Superadmin,
    )
    .await
    .unwrap();
    let wrong_code = unique("a");
    ap_panel::create_admin(&panel.state, &wrong_code, "correct horse", Role::Superadmin)
        .await
        .unwrap();

    let cases = [
        serde_json::json!({ "login": unique("nobody"), "password": "correct horse", "totp": code_now(&secret_a) }),
        serde_json::json!({ "login": wrong_password, "password": "wrong horse", "totp": code_now(&secret_a) }),
        serde_json::json!({ "login": wrong_code, "password": "correct horse", "totp": "000000" }),
    ];

    let mut bodies = Vec::new();
    let mut medians = Vec::new();
    for case in &cases {
        let mut samples = Vec::new();
        for _ in 0..3 {
            let started = Instant::now();
            let reply = call(
                &panel.router,
                "POST",
                "/v1/session",
                None,
                Some(case.clone()),
            )
            .await;
            samples.push(started.elapsed().as_micros());
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
            bodies.push(reply.body.clone());
        }
        samples.sort_unstable();
        medians.push(samples[samples.len() / 2]);
    }

    assert!(
        bodies.windows(2).all(|pair| pair[0] == pair[1]),
        "the bodies differ: {bodies:?}"
    );

    // Argon2 dominates the time in every case, so the medians land within the
    // same order of magnitude. A branch that skipped the hash would show up
    // here as a difference of tens of times, not of tens of percent.
    let slowest = medians.iter().max().copied().unwrap_or(1);
    let fastest = medians.iter().min().copied().unwrap_or(1).max(1);
    assert!(
        slowest <= fastest * 4,
        "one path is far quicker than another: {medians:?}"
    );
}

#[tokio::test]
async fn the_sixth_attempt_is_held_back() {
    let panel = panel!();
    let login = unique("a");
    ap_panel::create_admin(&panel.state, &login, "correct horse", Role::Superadmin)
        .await
        .unwrap();

    let body = serde_json::json!({ "login": login, "password": "wrong", "totp": "000000" });
    for _ in 0..5 {
        let reply = call(
            &panel.router,
            "POST",
            "/v1/session",
            None,
            Some(body.clone()),
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }
    let reply = call(&panel.router, "POST", "/v1/session", None, Some(body)).await;
    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(reply.retry_after.is_some(), "no retry-after header");
}

#[tokio::test]
async fn a_request_without_a_token_is_refused() {
    let panel = panel!();
    for (method, path) in [
        ("GET", "/v1/clients"),
        ("GET", "/v1/nodes"),
        ("GET", "/v1/tags"),
        ("GET", "/v1/audit"),
    ] {
        let reply = call(&panel.router, method, path, None, None).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method} {path}");
    }
}

#[tokio::test]
async fn a_missing_client_and_a_foreign_one_answer_alike() {
    let panel = panel!();
    let (_, owner) = admin(&panel, Role::Reseller).await;
    let (_, stranger) = admin(&panel, Role::Reseller).await;

    let created = call(
        &panel.router,
        "POST",
        "/v1/clients",
        Some(&owner),
        Some(serde_json::json!({ "label": unique("c") })),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let id = created.json()["id"].as_str().unwrap().to_owned();

    let foreign = call(
        &panel.router,
        "GET",
        &format!("/v1/clients/{id}"),
        Some(&stranger),
        None,
    )
    .await;
    let absent = call(
        &panel.router,
        "GET",
        &format!("/v1/clients/{}", uuid::Uuid::now_v7()),
        Some(&stranger),
        None,
    )
    .await;

    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    assert_eq!(absent.status, StatusCode::NOT_FOUND);
    assert_eq!(foreign.body, absent.body);
}

#[tokio::test]
async fn a_reseller_is_told_there_are_no_nodes() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let created = call(
        &panel.router,
        "POST",
        "/v1/nodes",
        Some(&boss),
        Some(serde_json::json!({ "label": unique("n"), "kind": "open" })),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);

    let (_, reseller) = admin(&panel, Role::Reseller).await;
    let listed = call(&panel.router, "GET", "/v1/nodes", Some(&reseller), None).await;
    assert_eq!(listed.status, StatusCode::NOT_FOUND);

    let refused = call(
        &panel.router,
        "POST",
        "/v1/nodes",
        Some(&reseller),
        Some(serde_json::json!({ "label": unique("n"), "kind": "open" })),
    )
    .await;
    assert_eq!(refused.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_reseller_cannot_read_the_audit_log() {
    let panel = panel!();
    let (_, reseller) = admin(&panel, Role::Reseller).await;
    let reply = call(&panel.router, "GET", "/v1/audit", Some(&reseller), None).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_listing_without_a_limit_stops_at_fifty() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    for _ in 0..55 {
        let reply = call(
            &panel.router,
            "POST",
            "/v1/clients",
            Some(&boss),
            Some(serde_json::json!({ "label": unique("c") })),
        )
        .await;
        assert_eq!(reply.status, StatusCode::CREATED);
    }
    let listed = call(&panel.router, "GET", "/v1/clients", Some(&boss), None).await;
    assert_eq!(listed.json().as_array().unwrap().len(), 50);

    let capped = call(
        &panel.router,
        "GET",
        "/v1/clients?limit=9999",
        Some(&boss),
        None,
    )
    .await;
    assert!(capped.json().as_array().unwrap().len() <= 200);
}

async fn an_access(panel: &Panel, token: &str, method: &str) -> (String, String) {
    let node = call(
        &panel.router,
        "POST",
        "/v1/nodes",
        Some(token),
        Some(serde_json::json!({ "label": unique("n"), "kind": "open" })),
    )
    .await;
    assert_eq!(node.status, StatusCode::CREATED, "{}", node.body);
    let node_id = node.json()["id"].as_str().unwrap().to_owned();

    let client = call(
        &panel.router,
        "POST",
        "/v1/clients",
        Some(token),
        Some(serde_json::json!({ "label": unique("c") })),
    )
    .await;
    let client_id = client.json()["id"].as_str().unwrap().to_owned();

    let access = call(
        &panel.router,
        "POST",
        "/v1/accesses",
        Some(token),
        Some(serde_json::json!({
            "client_id": client_id, "node_id": node_id, "method": method
        })),
    )
    .await;
    assert_eq!(access.status, StatusCode::CREATED, "{}", access.body);
    (client_id, access.json()["id"].as_str().unwrap().to_owned())
}

#[tokio::test]
async fn a_method_the_node_does_not_serve_is_refused() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let node = call(
        &panel.router,
        "POST",
        "/v1/nodes",
        Some(&boss),
        Some(serde_json::json!({
            "label": unique("n"), "kind": "stealth",
            "domain": format!("{}.example.com", unique("d"))
        })),
    )
    .await;
    assert_eq!(node.status, StatusCode::CREATED, "{}", node.body);
    let node_id = node.json()["id"].as_str().unwrap().to_owned();

    let client = call(
        &panel.router,
        "POST",
        "/v1/clients",
        Some(&boss),
        Some(serde_json::json!({ "label": unique("c") })),
    )
    .await;
    let client_id = client.json()["id"].as_str().unwrap().to_owned();

    let refused = call(
        &panel.router,
        "POST",
        "/v1/accesses",
        Some(&boss),
        Some(serde_json::json!({
            "client_id": client_id, "node_id": node_id, "method": "socks5"
        })),
    )
    .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.json()["error"]["code"], "method_not_served");
}

#[tokio::test]
async fn no_reading_endpoint_hands_out_a_credential() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (client_id, access_id) = an_access(&panel, &boss, "mtproto").await;

    let paths = [
        "/v1/clients".to_owned(),
        format!("/v1/clients/{client_id}"),
        format!("/v1/clients/{client_id}/accesses"),
        format!("/v1/clients/{client_id}/traffic"),
        format!("/v1/accesses/{access_id}"),
        "/v1/tags".to_owned(),
        "/v1/nodes".to_owned(),
        "/v1/audit".to_owned(),
        "/v1/session".to_owned(),
    ];

    for path in paths {
        let reply = call(&panel.router, "GET", &path, Some(&boss), None).await;
        let lowered = reply.body.to_lowercase();
        for forbidden in ["secret", "credential", "password", "\"pass\"", "totp"] {
            assert!(
                !lowered.contains(forbidden),
                "{forbidden} appeared in {path}: {}",
                reply.body
            );
        }
    }
}

#[tokio::test]
async fn a_link_needs_an_acknowledgement() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (_, access_id) = an_access(&panel, &boss, "mtproto").await;

    let refused = call(
        &panel.router,
        "POST",
        &format!("/v1/accesses/{access_id}/link"),
        Some(&boss),
        Some(serde_json::json!({ "host": "203.0.113.7", "acknowledged": false })),
    )
    .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(refused.json()["error"]["code"], "acknowledgement_required");
    assert!(!refused.body.contains("t.me"));

    let given = call(
        &panel.router,
        "POST",
        &format!("/v1/accesses/{access_id}/link"),
        Some(&boss),
        Some(serde_json::json!({ "host": "203.0.113.7", "acknowledged": true })),
    )
    .await;
    assert_eq!(given.status, StatusCode::OK, "{}", given.body);
    assert!(
        given.json()["link"]
            .as_str()
            .unwrap()
            .starts_with("https://t.me/proxy?server=203.0.113.7")
    );
}

// The audit entry is written before the link is produced. Renaming the table
// makes that write fail, and the secret must then not leave. Serialised with
// the other tests by --test-threads 1.
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

#[tokio::test]
async fn a_reseller_cannot_render_a_link_for_a_foreign_client() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (_, access_id) = an_access(&panel, &boss, "mtproto").await;

    let (_, reseller) = admin(&panel, Role::Reseller).await;
    let reply = call(
        &panel.router,
        "POST",
        &format!("/v1/accesses/{access_id}/link"),
        Some(&reseller),
        Some(serde_json::json!({ "host": "203.0.113.7", "acknowledged": true })),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert!(!reply.body.contains("t.me"));
}

#[tokio::test]
async fn rendering_a_link_is_recorded() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (_, access_id) = an_access(&panel, &boss, "mtproto").await;

    call(
        &panel.router,
        "POST",
        &format!("/v1/accesses/{access_id}/link"),
        Some(&boss),
        Some(serde_json::json!({ "host": "203.0.113.7", "acknowledged": true })),
    )
    .await;

    let audit = call(
        &panel.router,
        "GET",
        "/v1/audit?limit=50",
        Some(&boss),
        None,
    )
    .await;
    let entries = audit.json();
    let found = entries
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["action"] == "access.link.rendered" && entry["target"] == access_id);
    assert!(found, "the rendering was not recorded: {}", audit.body);
    assert!(!audit.body.contains("t.me"), "the log carries the link");
}

#[tokio::test]
async fn the_panel_refuses_to_start_without_a_key() {
    if std::env::var("DATABASE_URL").is_err() {
        return;
    }
    let config = Config::loopback(
        0,
        std::env::var("DATABASE_URL").unwrap(),
        PathBuf::from("/nonexistent/panel.key"),
    );
    let outcome = AppState::build(&config).await;
    assert!(outcome.is_err(), "the panel started with no key");
}
