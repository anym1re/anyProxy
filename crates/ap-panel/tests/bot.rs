//! The bot for the users, against a real PostgreSQL and a Bot API double on
//! the loopback. Nothing here reaches Telegram. Skipped when DATABASE_URL is
//! absent.

// An integration test is a separate build target and does not inherit the
// relaxations in clippy.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use ap_core::{KeyStore, Locale, Role, TelegramAccount};
use ap_panel::bot::{BotApi, Fault, Incoming, Markup, answer, step};
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
    named(user, text, None, "x")
}

/// A message from an account with a name and, when given, a username.
fn named(user: i64, text: &str, username: Option<&str>, name: &str) -> Incoming {
    Incoming {
        user_id: user,
        chat_id: user,
        locale: Locale::En,
        text: text.to_owned(),
        account: TelegramAccount::new(user, user, username, name, None, "en"),
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
    /// Chats whose person blocked the bot: Telegram answers 403 for them.
    blocked: Mutex<Vec<i64>>,
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
        "setMyCommands" => serde_json::json!(true),
        "getUpdates" => {
            let drained: Vec<_> = double.pending.lock().unwrap().drain(..).collect();
            serde_json::Value::Array(drained)
        }
        "sendMessage" => {
            let chat = body["chat_id"].as_i64().unwrap_or_default();
            if double.blocked.lock().unwrap().contains(&chat) {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "ok": false,
                        "error_code": 403,
                        "description": "Forbidden: bot was blocked by the user",
                    })),
                );
            }
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
    config.bot_signup = Some(false);
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

    assert_eq!(step(&state, &api, 0).await.unwrap(), 1);
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
    assert_eq!(step(&state, &api, 0).await.unwrap(), 0);
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

// ── the bot writes first (0102, 0103) ─────────────────────────────────────

/// The queue is one table and every test here shares it: the ones that send
/// take turns, so one test's delivery does not carry off another test's
/// messages.
static SENDING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A panel whose bot talks to a double, and the bot's view of that double.
async fn a_panel_with_a_double(url: &str) -> (common::Panel, BotApi, Arc<Double>) {
    let token = format!("3{}:{}", fresh_account(), unique("t"));
    let (base, double) = a_double(&token).await;
    let mut config = Config::loopback(0, url.to_owned(), key_file());
    config.bot_api = base.clone();
    config.bot_signup = Some(false);
    let state = AppState::build(&config).await.unwrap();
    let router = ap_panel::router(state.clone());
    let panel = common::Panel { router, state };
    (panel, BotApi::new(&base, &token).unwrap(), double)
}

/// Sends until nothing is due, and returns what reached one chat.
async fn delivered_to(
    panel: &common::Panel,
    api: &BotApi,
    double: &Double,
    chat: i64,
) -> Vec<String> {
    for _ in 0..100 {
        let delivery = ap_panel::bot::outbox::deliver(&panel.state, api)
            .await
            .unwrap();
        if !delivery.more {
            break;
        }
    }
    double
        .sent
        .lock()
        .unwrap()
        .iter()
        .filter(|sent| sent["chat_id"] == chat)
        .filter_map(|sent| sent["text"].as_str().map(str::to_owned))
        .collect()
}

/// The node a client's first access is on.
async fn node_of(panel: &common::Panel, token: &str, client_id: &str) -> String {
    let accesses = call(
        &panel.router,
        "GET",
        &format!("/v1/clients/{client_id}/accesses"),
        Some(token),
        None,
    )
    .await;
    accesses.json()[0]["node_id"].as_str().unwrap().to_owned()
}

/// Ties a fresh account to a client through the bot. The account.
async fn a_tied_account(panel: &common::Panel, token: &str, client_id: &str) -> i64 {
    let code = a_code(panel, token, client_id).await;
    let user = fresh_account();
    answer(&panel.state, &from(user, &format!("/start {code}")))
        .await
        .unwrap();
    user
}

async fn telegram_of(panel: &common::Panel, token: &str, client_id: &str) -> serde_json::Value {
    let read = call(
        &panel.router,
        "GET",
        &format!("/v1/clients/{client_id}"),
        Some(token),
        None,
    )
    .await;
    read.json()["telegram"].clone()
}

async fn message(panel: &common::Panel, token: &str, body: serde_json::Value) -> common::Reply {
    call(
        &panel.router,
        "POST",
        "/v1/bot/messages",
        Some(token),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn the_panel_knows_who_is_behind_a_tied_account_and_the_journal_does_not() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (client_id, _) = a_client_with_a_link(&panel, &boss).await;
    let code = a_code(&panel, &boss, &client_id).await;
    let user = fresh_account();
    let handle = format!("u{}", fresh_account());

    answer(
        &panel.state,
        &named(user, &format!("/start {code}"), Some(&handle), "Иван"),
    )
    .await
    .unwrap();
    let telegram = telegram_of(&panel, &boss, &client_id).await;
    assert_eq!(telegram["username"], handle.as_str(), "{telegram}");
    assert_eq!(telegram["name"], "Иван");

    // Renamed in Telegram: the next message is what the panel shows.
    let renamed = format!("{handle}_new");
    answer(
        &panel.state,
        &named(user, "/status", Some(&renamed), "Иван П"),
    )
    .await
    .unwrap();
    let telegram = telegram_of(&panel, &boss, &client_id).await;
    assert_eq!(telegram["username"], renamed.as_str(), "{telegram}");
    assert_eq!(telegram["name"], "Иван П");

    // The journal names the client, never the account.
    let lines = journal(&panel, &boss, "bot.").await;
    assert!(
        lines.iter().all(|line| !line.to_string().contains(&handle)),
        "an account name reached the journal"
    );

    answer(&panel.state, &from(user, "/unlink")).await.unwrap();
    assert!(telegram_of(&panel, &boss, &client_id).await.is_null());
}

#[tokio::test]
async fn a_renamed_node_tells_its_people_their_new_links() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let _turn = SENDING.lock().await;
    let (panel, api, double) = a_panel_with_a_double(&url).await;
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (client_id, _) = a_client_with_a_link(&panel, &boss).await;
    let user = a_tied_account(&panel, &boss, &client_id).await;
    let node = node_of(&panel, &boss, &client_id).await;

    let renamed = call(
        &panel.router,
        "POST",
        &format!("/v1/nodes/{node}/names"),
        Some(&boss),
        Some(serde_json::json!({ "domain": "dns.quad9.net" })),
    )
    .await;
    assert_eq!(renamed.status, StatusCode::NO_CONTENT, "{}", renamed.body);

    let said = delivered_to(&panel, &api, &double, user).await;
    assert_eq!(said.len(), 1, "one message with the result: {said:?}");
    assert!(said[0].contains("have changed"), "{}", said[0]);
    assert!(said[0].contains("server=dns.quad9.net"), "{}", said[0]);
    assert!(!said[0].contains("server=dns.google"), "{}", said[0]);
}

#[tokio::test]
async fn an_operator_message_reaches_whom_the_bot_can_write_to() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let _turn = SENDING.lock().await;
    let (panel, api, double) = a_panel_with_a_double(&url).await;
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (tied, tied_label) = a_client_with_a_link(&panel, &boss).await;
    let (untied, _) = a_client_with_a_link(&panel, &boss).await;
    let user = a_tied_account(&panel, &boss, &tied).await;

    let to_tied = message(
        &panel,
        &boss,
        serde_json::json!({ "text": "Обновите приложение", "client_id": tied }),
    )
    .await;
    assert_eq!(to_tied.status, StatusCode::OK, "{}", to_tied.body);
    assert_eq!(to_tied.json()["queued"], 1);
    // Queued, and the operator is told the bot is not running to send it.
    assert_eq!(to_tied.json()["bot"], "off");
    let to_untied = message(
        &panel,
        &boss,
        serde_json::json!({ "text": "x", "client_id": untied }),
    )
    .await;
    assert_eq!(
        to_untied.json()["queued"],
        0,
        "an account never tied cannot be written to"
    );

    for bad in [
        serde_json::json!({ "text": "   " }),
        serde_json::json!({ "text": "x".repeat(4001) }),
        serde_json::json!({ "text": "x", "client_id": tied, "tag_id": tied }),
    ] {
        let refused = message(&panel, &boss, bad).await;
        assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(refused.json()["error"]["code"], "message_form");
    }

    let said = delivered_to(&panel, &api, &double, user).await;
    assert_eq!(said, ["Обновите приложение"]);

    // Written down by whom it went to, and not what it said.
    let queued = journal(&panel, &boss, "bot.message.queued").await;
    let mine = queued
        .iter()
        .find(|line| line["target"] == tied_label)
        .expect("the message was recorded");
    assert_eq!(mine["details"]["count"], 1);
    assert!(!mine.to_string().contains("Обновите"));

    // A reseller reaches none of these clients, however it is addressed.
    let (_, reseller) = admin(&panel, Role::Reseller).await;
    let foreign = message(
        &panel,
        &reseller,
        serde_json::json!({ "text": "x", "client_id": tied }),
    )
    .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND);
    let everyone = message(&panel, &reseller, serde_json::json!({ "text": "x" })).await;
    assert_eq!(everyone.json()["queued"], 0, "{}", everyone.body);
}

#[tokio::test]
async fn a_person_who_blocked_the_bot_is_forgotten_until_they_write_again() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let _turn = SENDING.lock().await;
    let (panel, api, double) = a_panel_with_a_double(&url).await;
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (client_id, label) = a_client_with_a_link(&panel, &boss).await;
    let user = a_tied_account(&panel, &boss, &client_id).await;
    double.blocked.lock().unwrap().push(user);

    let queued = message(
        &panel,
        &boss,
        serde_json::json!({ "text": "x", "client_id": client_id }),
    )
    .await;
    assert_eq!(queued.json()["queued"], 1);
    assert!(delivered_to(&panel, &api, &double, user).await.is_empty());

    assert!(telegram_of(&panel, &boss, &client_id).await.is_null());
    let failed = journal(&panel, &boss, "bot.message.failed").await;
    assert!(
        failed
            .iter()
            .any(|line| line["target"] == label && line["details"]["why"] == "blocked"),
        "{failed:?}"
    );

    // Unblocked and writing again: remembered again.
    double.blocked.lock().unwrap().clear();
    answer(&panel.state, &from(user, "/status")).await.unwrap();
    assert!(!telegram_of(&panel, &boss, &client_id).await.is_null());
}

#[tokio::test]
async fn a_term_about_to_end_is_warned_of_once() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let _turn = SENDING.lock().await;
    let (panel, api, double) = a_panel_with_a_double(&url).await;
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let ends = time::OffsetDateTime::now_utc() + time::Duration::days(2);
    let client = call(
        &panel.router,
        "POST",
        "/v1/clients",
        Some(&boss),
        Some(serde_json::json!({
            "label": unique("c"),
            "expires_at": ap_core::time::format_rfc3339(ends).unwrap(),
        })),
    )
    .await;
    assert_eq!(client.status, StatusCode::CREATED, "{}", client.body);
    let client_id = client.json()["id"].as_str().unwrap().to_owned();
    let user = a_tied_account(&panel, &boss, &client_id).await;

    ap_panel::bot::outbox::scan(&panel.state).await.unwrap();
    ap_panel::bot::outbox::scan(&panel.state).await.unwrap();

    let said = delivered_to(&panel, &api, &double, user).await;
    assert_eq!(said.len(), 1, "warned once, not twice: {said:?}");
    assert!(said[0].contains("ends on"), "{}", said[0]);
}

// ── the bot is the way in (0105, 0106) ────────────────────────────────────

/// A masked node that has called in a moment ago and says it is well: the
/// kind of node the bot hands out. Its identifier and its name.
async fn a_node_in_service(panel: &common::Panel, token: &str) -> (String, String) {
    let label = unique("n");
    let node = call(
        &panel.router,
        "POST",
        "/v1/nodes",
        Some(token),
        Some(serde_json::json!({
            "label": label, "kind": "mtproto", "masked": true, "domain": "dns.google"
        })),
    )
    .await;
    assert_eq!(node.status, StatusCode::CREATED, "{}", node.body);
    let node_id = node.json()["id"].as_str().unwrap().to_owned();
    seen_now(&node_id, ("up", "up", "open")).await;
    (node_id, label)
}

/// Records, the way the agent channel does, that a node has just called in
/// and what it said about itself.
async fn seen_now(node_id: &str, health: (&str, &str, &str)) {
    let url = std::env::var("DATABASE_URL").unwrap();
    let pool = ap_store::connect(&url, 1).await.unwrap();
    ap_store::PresenceRepo::seen(
        &pool,
        node_id.parse().unwrap(),
        "test",
        Some((health.0, health.1, health.2, None)),
        time::OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();
}

/// The client an account is tied to, as the panel shows it: found by the
/// name the bot itself says in `/status`, because the list of clients is the
/// oldest two hundred and the database the tests share holds more.
async fn client_of(panel: &common::Panel, token: &str, user: i64) -> serde_json::Value {
    client_behind(panel, token, &from(user, "/status")).await
}

/// The same, asked by a message of the caller's own making. The panel keeps
/// who an account said it was in its last message, so asking as somebody
/// without a username would leave the client without one.
async fn client_behind(panel: &common::Panel, token: &str, asking: &Incoming) -> serde_json::Value {
    let status = answer(&panel.state, asking).await.unwrap();
    let label = status[0]
        .split(':')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    client_named(panel, token, &label).await
}

async fn client_named(panel: &common::Panel, token: &str, label: &str) -> serde_json::Value {
    let found = call(
        &panel.router,
        "GET",
        &format!("/v1/clients?label={label}"),
        Some(token),
        None,
    )
    .await;
    assert_eq!(found.status, StatusCode::OK, "{label}: {}", found.body);
    found.json()[0].clone()
}

/// Whether a client holds an access on a node that is not revoked.
async fn holds(panel: &common::Panel, token: &str, client_id: &str, node_id: &str) -> bool {
    let accesses = call(
        &panel.router,
        "GET",
        &format!("/v1/clients/{client_id}/accesses"),
        Some(token),
        None,
    )
    .await;
    accesses
        .json()
        .as_array()
        .unwrap()
        .iter()
        .any(|access| access["node_id"] == node_id && access["state"] != "revoked")
}

/// A panel where an account that writes to the bot is taken in.
macro_rules! open_panel {
    () => {
        match common::panel_where(true).await {
            Some(panel) => panel,
            None => return,
        }
    };
}

#[tokio::test]
async fn an_account_that_writes_is_taken_in_and_handed_its_link() {
    let panel = open_panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (node_id, node_label) = a_node_in_service(&panel, &boss).await;
    let user = fresh_account();
    let handle = format!("u{}", fresh_account());

    let said = answer(&panel.state, &named(user, "/start", Some(&handle), "Иван"))
        .await
        .unwrap();

    // Greeted with the menu, then handed the link with the button that
    // opens it.
    assert!(
        matches!(&said[0].markup, Markup::Menu(rows) if rows.concat().contains(&"Links".to_owned())),
        "{:?}",
        said[0].markup
    );
    assert!(said[0].contains("signed up"), "{}", said[0]);
    let link = said
        .iter()
        .find(|reply| reply.contains(&node_label))
        .unwrap_or_else(|| panic!("no link for the node in {said:?}"));
    assert!(
        link.contains("https://t.me/proxy?server=dns.google"),
        "{link}"
    );
    let Markup::Open(rows) = &link.markup else {
        panic!("a link without a button: {:?}", link.markup);
    };
    assert_eq!(rows[0][0].0, "Connect");
    assert!(
        rows[0][0]
            .1
            .starts_with("https://t.me/proxy?server=dns.google")
    );

    // In the panel: a client the bot made, under a name that says nothing of
    // the account, holding an access on the node.
    let asking = named(user, "/status", Some(&handle), "Иван");
    let client = client_behind(&panel, &boss, &asking).await;
    assert_eq!(client["origin"], "bot");
    assert_eq!(client["telegram"]["username"], handle.as_str());
    assert_eq!(client["telegram"]["name"], "Иван");
    let label = client["label"].as_str().unwrap();
    assert!(label.starts_with("tg-"), "{label}");
    assert!(!label.contains(&handle));
    let client_id = client["id"].as_str().unwrap();
    assert!(holds(&panel, &boss, client_id, &node_id).await);

    // The journal names the client and never the account.
    let signed = journal(&panel, &boss, "bot.signup").await;
    assert!(
        signed.iter().any(|line| line["target"] == label),
        "{signed:?}"
    );
    assert!(
        signed
            .iter()
            .all(|line| !line.to_string().contains(&handle))
    );
}

#[tokio::test]
async fn the_menu_words_ask_what_the_commands_ask() {
    let panel = open_panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (_, node_label) = a_node_in_service(&panel, &boss).await;
    let user = fresh_account();
    answer(&panel.state, &from(user, "/start")).await.unwrap();

    // A press on the menu arrives as the word on the button, in whichever
    // language the menu was drawn.
    for word in ["Links", "Ссылки"] {
        let said = answer(&panel.state, &from(user, word)).await.unwrap();
        assert!(
            said.iter().any(|reply| reply.contains(&node_label)),
            "«{word}» did not bring the links: {said:?}"
        );
    }
    let status = answer(&panel.state, &from(user, "Статус")).await.unwrap();
    assert!(status[0].contains("tg-"), "{}", status[0]);
    assert!(matches!(status[0].markup, Markup::Menu(_)));
}

#[tokio::test]
async fn the_same_account_comes_back_to_the_same_client() {
    let panel = open_panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let user = fresh_account();
    answer(&panel.state, &from(user, "/start")).await.unwrap();
    let first = client_of(&panel, &boss, user).await;
    let label = first["label"].as_str().unwrap();

    // Untied, and writing again: not a new client with a new allowance.
    answer(&panel.state, &from(user, "/unlink")).await.unwrap();
    assert!(client_named(&panel, &boss, label).await["telegram"].is_null());
    answer(&panel.state, &from(user, "/start")).await.unwrap();
    let again = client_of(&panel, &boss, user).await;
    assert_eq!(again["id"], first["id"]);
    assert!(!again["telegram"].is_null());

    // Suspended by an operator, it comes back suspended.
    let client_id = first["id"].as_str().unwrap();
    let suspended = call(
        &panel.router,
        "POST",
        &format!("/v1/clients/{client_id}/state"),
        Some(&boss),
        Some(serde_json::json!({ "state": "suspended" })),
    )
    .await;
    assert!(suspended.status.is_success(), "{}", suspended.body);
    answer(&panel.state, &from(user, "/unlink")).await.unwrap();
    let said = answer(&panel.state, &from(user, "/links")).await.unwrap();
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(said[0].contains("suspended"), "{}", said[0]);
}

#[tokio::test]
async fn a_node_that_appears_later_is_theirs_the_next_time_they_ask() {
    let panel = open_panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let user = fresh_account();
    answer(&panel.state, &from(user, "/start")).await.unwrap();
    let client = client_of(&panel, &boss, user).await;
    let client_id = client["id"].as_str().unwrap();

    let (node_id, node_label) = a_node_in_service(&panel, &boss).await;
    assert!(!holds(&panel, &boss, client_id, &node_id).await);

    let said = answer(&panel.state, &from(user, "/links")).await.unwrap();
    assert!(
        said.iter().any(|reply| reply.contains(&node_label)),
        "{said:?}"
    );
    assert!(holds(&panel, &boss, client_id, &node_id).await);

    // Asking again gives nothing more on the same node.
    answer(&panel.state, &from(user, "/links")).await.unwrap();
    let accesses = call(
        &panel.router,
        "GET",
        &format!("/v1/clients/{client_id}/accesses"),
        Some(&boss),
        None,
    )
    .await;
    let on_node = accesses
        .json()
        .as_array()
        .unwrap()
        .iter()
        .filter(|access| access["node_id"] == node_id.as_str())
        .count();
    assert_eq!(on_node, 1);
}

#[tokio::test]
async fn a_node_in_trouble_or_never_heard_from_is_not_handed_out() {
    let panel = open_panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (blocked_id, blocked_label) = a_node_in_service(&panel, &boss).await;
    seen_now(&blocked_id, ("up", "up", "blocked")).await;
    // Made in the panel, never enrolled: nobody has heard from it.
    let silent_label = unique("n");
    let silent = call(
        &panel.router,
        "POST",
        "/v1/nodes",
        Some(&boss),
        Some(serde_json::json!({
            "label": silent_label, "kind": "mtproto", "masked": true, "domain": "dns.google"
        })),
    )
    .await;
    assert_eq!(silent.status, StatusCode::CREATED, "{}", silent.body);

    let user = fresh_account();
    let said = answer(&panel.state, &from(user, "/start")).await.unwrap();
    assert!(
        said.iter()
            .all(|reply| !reply.contains(&blocked_label) && !reply.contains(&silent_label)),
        "{said:?}"
    );
}

#[tokio::test]
async fn a_client_an_operator_made_holds_what_the_operator_gave() {
    let panel = open_panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let (client_id, _) = a_client_with_a_link(&panel, &boss).await;
    let code = a_code(&panel, &boss, &client_id).await;
    let user = fresh_account();
    // A code is for the client it was issued for, also where the bot takes
    // strangers in.
    answer(&panel.state, &from(user, &format!("/start {code}")))
        .await
        .unwrap();
    let (node_id, node_label) = a_node_in_service(&panel, &boss).await;

    let said = answer(&panel.state, &from(user, "/links")).await.unwrap();
    assert!(
        said.iter().all(|reply| !reply.contains(&node_label)),
        "{said:?}"
    );
    assert!(!holds(&panel, &boss, &client_id, &node_id).await);
    let read = call(
        &panel.router,
        "GET",
        &format!("/v1/clients/{client_id}"),
        Some(&boss),
        None,
    )
    .await;
    assert_eq!(read.json()["origin"], "operator");
}

#[tokio::test]
async fn where_the_bot_is_not_the_way_in_a_stranger_is_asked_for_a_code() {
    let panel = panel!();
    let user = fresh_account();
    let said = answer(&panel.state, &from(user, "/start")).await.unwrap();
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(said[0].contains("/start"), "{}", said[0]);
    assert_eq!(said[0].markup, Markup::None);
    // Still nobody: the next thing it asks is answered the same way.
    let status = answer(&panel.state, &from(user, "/status")).await.unwrap();
    assert!(!status[0].contains("tg-"), "{}", status[0]);
}

#[tokio::test]
async fn signing_up_is_paced() {
    let panel = open_panel!();
    for _ in 0..30 {
        let said = answer(&panel.state, &from(fresh_account(), "/start"))
            .await
            .unwrap();
        assert!(said[0].contains("signed up"), "{}", said[0]);
    }
    let late = fresh_account();
    let said = answer(&panel.state, &from(late, "/start")).await.unwrap();
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(said[0].contains("Too many"), "{}", said[0]);
    // Not taken in: asked again, it is told the same.
    let status = answer(&panel.state, &from(late, "/status")).await.unwrap();
    assert!(status[0].contains("Too many"), "{}", status[0]);
}

#[tokio::test]
async fn a_web_node_takes_thirty_two_accesses_and_refuses_the_next() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;
    let node = call(
        &panel.router,
        "POST",
        "/v1/nodes",
        Some(&boss),
        Some(serde_json::json!({
            "label": unique("n"), "kind": "web",
            "domain": format!("{}.example.com", unique("w")),
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
    let give = || {
        call(
            &panel.router,
            "POST",
            "/v1/accesses",
            Some(&boss),
            Some(serde_json::json!({ "client_id": client_id, "node_id": node_id })),
        )
    };
    let mut last = String::new();
    for _ in 0..32 {
        let given = give().await;
        assert_eq!(given.status, StatusCode::CREATED, "{}", given.body);
        last = given.json()["id"].as_str().unwrap().to_owned();
    }
    let refused = give().await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    assert_eq!(refused.json()["error"]["code"], "node_full");

    // One taken back makes room for one.
    let revoked = call(
        &panel.router,
        "POST",
        &format!("/v1/accesses/{last}/state"),
        Some(&boss),
        Some(serde_json::json!({ "state": "revoked" })),
    )
    .await;
    assert!(revoked.status.is_success(), "{}", revoked.body);
    assert_eq!(give().await.status, StatusCode::CREATED);
}
