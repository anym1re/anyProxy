//! What every panel integration target needs to talk to the router.

// Compiled separately into each target, and each uses a subset of it.
#![allow(dead_code)]

use std::path::PathBuf;

use ap_core::Role;
use ap_panel::{AppState, Config};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

pub(crate) struct Panel {
    pub(crate) router: Router,
    pub(crate) state: AppState,
}

pub(crate) fn key_file() -> PathBuf {
    let dir = std::env::temp_dir().join("anyproxy-panel-test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("panel.key");
    if !path.exists() {
        // Test binaries share this file and one that saw it before its
        // mode was set, or before its bytes arrived, would refuse to
        // start. Assemble it under a name of its own and move it.
        let staged = path.with_extension(uuid::Uuid::now_v7().simple().to_string());
        std::fs::write(&staged, [11u8; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        std::fs::rename(&staged, &path).unwrap();
    }
    path
}

pub(crate) async fn panel() -> Option<Panel> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let config = Config::loopback(0, url, key_file());
    let state = AppState::build(&config).await.expect("state");
    Some(Panel {
        router: ap_panel::router(state.clone()),
        state,
    })
}

#[macro_export]
macro_rules! panel {
    () => {
        match $crate::common::panel().await {
            Some(panel) => panel,
            None => return,
        }
    };
}

pub(crate) fn unique(prefix: &str) -> String {
    // The first half of a version 7 identifier is a millisecond timestamp, so
    // two calls inside one millisecond share it. The second half is random.
    let id = uuid::Uuid::now_v7().simple().to_string();
    format!("{prefix}-{}", &id[16..])
}

pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) body: String,
    pub(crate) retry_after: Option<String>,
}

impl Reply {
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

pub(crate) async fn call(
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

pub(crate) fn code_now(secret: &str) -> String {
    let bytes = totp_rs::Secret::Encoded(secret.to_owned())
        .to_bytes()
        .unwrap();
    totp_rs::TOTP::new(totp_rs::Algorithm::SHA1, 6, 1, 30, bytes)
        .unwrap()
        .generate_current()
        .unwrap()
}

pub(crate) async fn admin(panel: &Panel, role: Role) -> (String, String) {
    let login = unique("a");
    let secret = ap_panel::create_admin(&panel.state, &login, "correct horse", role, true)
        .await
        .expect("admin")
        .expect("a second factor was asked for");
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

/// A client, a node that serves the given method, and an access to it.
///
/// The node's kind is the method: one method to a host, so a node that serves
/// this access serves nothing else.
pub(crate) async fn an_access(panel: &Panel, token: &str, method: &str) -> (String, String) {
    let node = call(
        &panel.router,
        "POST",
        "/v1/nodes",
        Some(token),
        Some(serde_json::json!({ "label": unique("n"), "kind": method })),
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
