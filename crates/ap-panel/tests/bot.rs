//! The bot for the users, against a real PostgreSQL and a Bot API double on
//! the loopback. Nothing here reaches Telegram. Skipped when DATABASE_URL is
//! absent.

// An integration test is a separate build target and does not inherit the
// relaxations in clippy.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use ap_core::{KeyStore, Locale, Role};
use ap_panel::bot::{BotApi, Fault, Incoming, answer, step};
use ap_panel::{AppState, Config};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Json, Router};

#[macro_use]
mod common;

use common::{admin, call, key_file, unique};

/// An account that has never written before.
fn fresh_account() -> i64 {
    // The lower half of a version 7 identifier is random.
    i64::from(uuid::Uuid::now_v7().as_u128() as u32) + 1
}

/// A client and a masked node it has an access on, so a link can be built
/// from the node's name without an agent ever having called in.
async fn a_client_with_a_link(panel: &common::Panel, token: &str) -> (String, String) {
    let node = call(
        &panel.router,
        "POST",
        "/v1/nodes",
        Some(token),
        Some(serde_json::json!({
            "label": unique("n"), "kind": "mtproto", "masked": true, "domain": "dns.google"
        })),
    )
    .await;
    assert_eq!(node.status, StatusCode::CREATED, "{}", node.body);
    let node_id = node.json()["id"].as_str().unwrap().to_owned();
    let label = unique("c");
    let client = call(
        &panel.router,
        "POST",
        "/v1/clients",
        Some(token),
        Some(serde_json::json!({ "label": label })),
    )
    .await;
    let client_id = client.json()["id"].as_str().unwrap().to_owned();
    let access = call(
        &panel.router,
        "POST",
        "/v1/accesses",
        Some(token),
        Some(serde_json::json!({ "client_id": client_id, "node_id": node_id })),
    )
    .await;
    assert_eq!(access.status, StatusCode::CREATED, "{}", access.body);
    (client_id, label)
}

async fn a_code(panel: &common::Panel, token: &str, client_id: &str) -> String {
    let issued = call(
        &panel.router,
        "POST",
        &format!("/v1/clients/{client_id}/bot-code"),
        Some(token),
        None,
    )
    .await;
    assert_eq!(issued.status, StatusCode::CREATED, "{}", issued.body);
    issued.json()["code"].as_str().unwrap().to_owned()
}

fn from(user: i64, text: &str) -> Incoming {
    Incoming {
        user_id: user,
        chat_id: user,
        locale: Locale::En,
        text: text.to_owned(),
    }
}

async fn journal(panel: &common::Panel, token: &str, prefix: &str) -> Vec<serde_json::Value> {
    let audit = call(
        &panel.router,
        "GET",
        &format!("/v1/audit?prefix={prefix}&limit=200"),
        Some(token),
        None,
    )
    .await;
    audit.json()["entries"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

#[tokio::test]
async fn a_code_ties_an_account_and_the_bot_hands_out_the_link() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (client_id, label) = a_client_with_a_link(&panel, &boss).await;
    let code = a_code(&panel, &boss, &client_id).await;
    let user = fresh_account();

    // Before the code: the bot knows nothing and says nothing about anyone.
    let said = answer(&panel.state, &from(user, "/links")).await.unwrap();
    assert_eq!(said.len(), 1);
    assert!(!said[0].contains(&label), "{}", said[0]);

    let said = answer(&panel.state, &from(user, &format!("/start {code}")))
        .await
        .unwrap();
    assert!(said[0].contains(&label), "{}", said[0]);

    let read = call(
        &panel.router,
        "GET",
        &format!("/v1/clients/{client_id}"),
        Some(&boss),
        None,
    )
    .await;
    assert!(
        read.json()["telegram_linked_at"].is_string(),
        "{}",
        read.body
    );

    let said = answer(&panel.state, &from(user, "/links")).await.unwrap();
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].contains("https://t.me/proxy?server=dns.google"),
        "{}",
        said[0]
    );

    // Handed out by the bot is handed out: the journal has it, with the bot
    // named as the one who did it, and no link in the record.
    let rendered = journal(&panel, &boss, "bot.link.rendered").await;
    let mine = rendered
        .iter()
        .find(|entry| {
            entry["target"]
                .as_str()
                .unwrap_or_default()
                .starts_with(&label)
        })
        .expect("the rendering was recorded");
    assert_eq!(mine["details"]["by"], "bot");
    assert!(mine["actor_id"].is_null());
    assert!(!mine.to_string().contains("t.me"));
    let linked = journal(&panel, &boss, "bot.linked").await;
    assert!(linked.iter().any(|entry| entry["target"] == label));

    let said = answer(&panel.state, &from(user, "/status")).await.unwrap();
    assert!(said[0].contains(&label), "{}", said[0]);

    let said = answer(&panel.state, &from(user, "/unlink")).await.unwrap();
    assert_eq!(said.len(), 1);
    let read = call(
        &panel.router,
        "GET",
        &format!("/v1/clients/{client_id}"),
        Some(&boss),
        None,
    )
    .await;
    assert!(read.json()["telegram_linked_at"].is_null(), "{}", read.body);
}

#[tokio::test]
async fn a_wrong_code_and_a_spent_code_get_one_answer() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (client_id, _) = a_client_with_a_link(&panel, &boss).await;
    let code = a_code(&panel, &boss, &client_id).await;
    let first = fresh_account();
    let second = fresh_account();

    let wrong = answer(
        &panel.state,
        &from(first, "/start 00000000000000000000000000000000"),
    )
    .await
    .unwrap();
    answer(&panel.state, &from(first, &format!("/start {code}")))
        .await
        .unwrap();
    let spent = answer(&panel.state, &from(second, &format!("/start {code}")))
        .await
        .unwrap();
    assert_eq!(wrong, spent);

    // The account that spent it is the one that holds it.
    let held = answer(&panel.state, &from(first, "/status")).await.unwrap();
    let not = answer(&panel.state, &from(second, "/status"))
        .await
        .unwrap();
    assert_ne!(held, not);
}

#[tokio::test]
async fn a_code_for_another_client_moves_the_account() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (first_id, first) = a_client_with_a_link(&panel, &boss).await;
    let (second_id, second) = a_client_with_a_link(&panel, &boss).await;
    let user = fresh_account();

    let code = a_code(&panel, &boss, &first_id).await;
    answer(&panel.state, &from(user, &code)).await.unwrap();
    let code = a_code(&panel, &boss, &second_id).await;
    answer(&panel.state, &from(user, &code)).await.unwrap();

    let said = answer(&panel.state, &from(user, "/status")).await.unwrap();
    assert!(said[0].contains(&second), "{}", said[0]);
    assert!(!said[0].contains(&first), "{}", said[0]);
    let unlinked = journal(&panel, &boss, "bot.unlinked").await;
    assert!(
        unlinked
            .iter()
            .any(|entry| entry["target"] == first && entry["details"]["moved_to"] == second),
        "{unlinked:?}"
    );
}

#[tokio::test]
async fn the_operator_can_take_the_account_off_and_a_reseller_cannot_reach_a_foreign_client() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (_, seller) = admin(&panel, Role::Reseller).await;
    let (client_id, _) = a_client_with_a_link(&panel, &boss).await;

    let foreign = call(
        &panel.router,
        "POST",
        &format!("/v1/clients/{client_id}/bot-code"),
        Some(&seller),
        None,
    )
    .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);

    let code = a_code(&panel, &boss, &client_id).await;
    let user = fresh_account();
    answer(&panel.state, &from(user, &format!("/start {code}")))
        .await
        .unwrap();

    let taken = call(
        &panel.router,
        "DELETE",
        &format!("/v1/clients/{client_id}/telegram"),
        Some(&boss),
        None,
    )
    .await;
    assert_eq!(taken.status, StatusCode::NO_CONTENT);
    let said = answer(&panel.state, &from(user, "/links")).await.unwrap();
    assert!(!said[0].contains("t.me"), "{}", said[0]);
}

#[tokio::test]
async fn the_token_is_sealed_and_never_comes_back() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let token = format!("1{}:{}", fresh_account(), unique("t"));

    let put = call(
        &panel.router,
        "PUT",
        "/v1/settings",
        Some(&boss),
        Some(serde_json::json!({ "values": { "bot_token": token } })),
    )
    .await;
    assert_eq!(put.status, StatusCode::NO_CONTENT, "{}", put.body);

    let read = call(&panel.router, "GET", "/v1/settings", Some(&boss), None).await;
    assert!(!read.body.contains(&token), "the token came back");
    let row = read.json()["settings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|one| one["name"] == "bot_token")
        .cloned()
        .unwrap();
    assert_eq!(row["secret"], true);
    assert_eq!(row["set"], true);
    assert_eq!(row["value"], "");

    // It opens under the key, and under nothing else.
    let pool = ap_store::connect(&std::env::var("DATABASE_URL").unwrap(), 2)
        .await
        .unwrap();
    let key = KeyStore::from_file(&key_file()).unwrap();
    assert_eq!(
        ap_store::SealedSettingRepo::open(&pool, "bot_token", &key)
            .await
            .unwrap()
            .as_deref(),
        Some(token.as_str())
    );
    assert!(
        ap_store::SealedSettingRepo::open(&pool, "bot_token", &KeyStore::from_bytes([3u8; 32]))
            .await
            .is_err()
    );

    // The journal names the setting and not the value.
    let changed = journal(&panel, &boss, "setting.changed").await;
    assert!(changed.iter().any(|entry| entry["target"] == "bot_token"));
    assert!(
        !changed
            .iter()
            .any(|entry| entry.to_string().contains(&token))
    );

    let cleared = call(
        &panel.router,
        "PUT",
        "/v1/settings",
        Some(&boss),
        Some(serde_json::json!({ "values": { "bot_token": "" } })),
    )
    .await;
    assert_eq!(cleared.status, StatusCode::NO_CONTENT);
    let read = call(&panel.router, "GET", "/v1/settings", Some(&boss), None).await;
    let row = read.json()["settings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|one| one["name"] == "bot_token")
        .cloned()
        .unwrap();
    assert_eq!(row["set"], false);
}

// ── a Bot API on the loopback ─────────────────────────────────────────────

/// What the double holds: updates waiting to be fetched, and everything
/// the bot sent.
#[derive(Default)]
struct Double {
    token: String,
    pending: Mutex<Vec<serde_json::Value>>,
    sent: Mutex<Vec<serde_json::Value>>,
}

async fn double_call(
    State(double): State<Arc<Double>>,
    Path((token, method)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    if token != double.token {
        return (
            StatusCode::UNAUTHORIZED,
            Json(
                serde_json::json!({ "ok": false, "error_code": 401, "description": "Unauthorized" }),
            ),
        );
    }
    let result = match method.as_str() {
        "getMe" => serde_json::json!({ "username": "anyproxy_test_bot" }),
        "getUpdates" => {
            let drained: Vec<_> = double.pending.lock().unwrap().drain(..).collect();
            serde_json::Value::Array(drained)
        }
        "sendMessage" => {
            double.sent.lock().unwrap().push(body);
            serde_json::json!({ "message_id": 1 })
        }
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(
                    serde_json::json!({ "ok": false, "error_code": 404, "description": "Not Found" }),
                ),
            );
        }
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "result": result })),
    )
}

/// Stands the double up on a free port. Its address and what it holds.
async fn a_double(token: &str) -> (String, Arc<Double>) {
    let double = Arc::new(Double {
        token: token.to_owned(),
        ..Double::default()
    });
    let app = Router::new()
        .route("/bot{token}/{method}", axum::routing::post(double_call))
        .with_state(Arc::clone(&double));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://127.0.0.1:{port}"), double)
}

#[tokio::test]
async fn the_bot_reads_its_updates_from_the_double_and_answers_them() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let token = format!("2{}:{}", fresh_account(), unique("t"));
    let (base, double) = a_double(&token).await;
    let mut config = Config::loopback(0, url.clone(), key_file());
    config.bot_api = base.clone();
    let state = AppState::build(&config).await.unwrap();
    let router = ap_panel::router(state.clone());
    let panel = common::Panel {
        router,
        state: state.clone(),
    };
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (client_id, label) = a_client_with_a_link(&panel, &boss).await;
    let code = a_code(&panel, &boss, &client_id).await;

    let api = BotApi::new(&base, &token).unwrap();
    assert_eq!(api.get_me().await.unwrap(), "anyproxy_test_bot");

    // Seconds since the epoch: later than any update a previous run left
    // the cursor at.
    let update_id = time::OffsetDateTime::now_utc().unix_timestamp();
    let user = fresh_account();
    double.pending.lock().unwrap().push(serde_json::json!({
        "update_id": update_id,
        "message": {
            "message_id": 7,
            "from": { "id": user, "is_bot": false, "first_name": "x", "language_code": "ru" },
            "chat": { "id": user, "type": "private" },
            "text": format!("/start {code}"),
        }
    }));

    assert_eq!(step(&state, &api).await.unwrap(), 1);
    let sent = double.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0]["chat_id"], user);
    let text = sent[0]["text"].as_str().unwrap();
    assert!(text.contains(&label), "{text}");
    assert!(
        text.contains("Привязано"),
        "answered in the account's language: {text}"
    );

    // The cursor moved past what was read (0087).
    let pool = ap_store::connect(&url, 2).await.unwrap();
    assert_eq!(
        ap_store::BotRepo::cursor(&pool).await.unwrap(),
        update_id + 1
    );

    // Nothing waiting: nothing answered, cursor unmoved.
    assert_eq!(step(&state, &api).await.unwrap(), 0);
    assert_eq!(
        ap_store::BotRepo::cursor(&pool).await.unwrap(),
        update_id + 1
    );
}

#[tokio::test]
async fn a_token_the_double_does_not_know_is_refused_as_such() {
    let (base, _double) = a_double("1:right").await;
    let api = BotApi::new(&base, "1:wrong").unwrap();
    assert_eq!(api.get_me().await, Err(Fault::Unauthorized));
    let api = BotApi::new(&base, "1:right").unwrap();
    assert!(api.get_me().await.is_ok());
}

#[tokio::test]
async fn a_bot_api_that_is_not_there_reads_as_unreachable() {
    let api = BotApi::new("http://127.0.0.1:9", "1:a").unwrap();
    assert_eq!(api.get_me().await, Err(Fault::Unreachable));
}
