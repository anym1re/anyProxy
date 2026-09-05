//! Exercised against a real PostgreSQL through the router, without a socket.
//! Skipped when DATABASE_URL is absent.

// An integration test is a separate build target and does not inherit the
// relaxations in clippy.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::time::Instant;

use ap_core::Role;
use ap_panel::{AppState, Config};
use axum::http::StatusCode;

#[macro_use]
mod common;

use common::{admin, an_access, call, code_now, unique};

#[tokio::test]
async fn an_account_with_a_second_factor_is_not_entered_without_it() {
    let panel = panel!();
    let login = unique("a");
    let secret = ap_panel::create_admin(
        &panel.state,
        &login,
        "correct horse",
        Role::Superadmin,
        true,
    )
    .await
    .unwrap()
    .expect("a second factor was asked for");

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
        true,
    )
    .await
    .unwrap()
    .expect("a second factor was asked for");
    let wrong_code = unique("a");
    ap_panel::create_admin(
        &panel.state,
        &wrong_code,
        "correct horse",
        Role::Superadmin,
        true,
    )
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
    ap_panel::create_admin(
        &panel.state,
        &login,
        "correct horse",
        Role::Superadmin,
        true,
    )
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
        Some(serde_json::json!({ "label": unique("n"), "kind": "socks5" })),
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
        Some(serde_json::json!({ "label": unique("n"), "kind": "socks5" })),
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
            "label": unique("n"), "kind": "mtproto", "masked": true,
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

#[tokio::test]
async fn an_account_is_offered_on_the_port_its_method_is_served_on() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;

    for (method, expected) in [("socks5", 1080), ("http", 3128)] {
        let (_, access_id) = an_access(&panel, &boss, method).await;
        let reply = call(
            &panel.router,
            "POST",
            &format!("/v1/accesses/{access_id}/link"),
            Some(&boss),
            Some(serde_json::json!({ "host": "203.0.113.7", "acknowledged": true })),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);

        let answer = reply.json();
        // One port for both would send everyone holding an HTTP account to the
        // SOCKS5 listener, which refuses them for speaking the wrong protocol.
        assert_eq!(answer["port"], expected, "{method}: {}", reply.body);
        assert!(answer["user"].as_str().is_some_and(|user| !user.is_empty()));
        assert!(answer["link"].is_null(), "{method} has no link form");
    }
}

#[tokio::test]
async fn two_accesses_of_one_client_do_not_share_a_name() {
    let panel = panel!();
    let (_, boss) = admin(&panel, Role::Superadmin).await;

    let node = call(
        &panel.router,
        "POST",
        "/v1/nodes",
        Some(&boss),
        Some(serde_json::json!({ "label": unique("n"), "kind": "socks5" })),
    )
    .await;
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

    // One client, two accesses on one node. This is the case that was wrong.
    let mut names = Vec::new();
    for _ in 0..2 {
        let method = "socks5";
        let created = call(
            &panel.router,
            "POST",
            "/v1/accesses",
            Some(&boss),
            Some(serde_json::json!({
                "client_id": client_id, "node_id": node_id, "method": method
            })),
        )
        .await;
        assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
        let access_id = created.json()["id"].as_str().unwrap().to_owned();

        let reply = call(
            &panel.router,
            "POST",
            &format!("/v1/accesses/{access_id}/link"),
            Some(&boss),
            Some(serde_json::json!({ "host": "203.0.113.7", "acknowledged": true })),
        )
        .await;
        let user = reply.json()["user"].as_str().unwrap_or_default().to_owned();
        assert!(!user.is_empty(), "{method}: {}", reply.body);
        names.push(user);
    }

    // A node keys its accounts by name. Two accesses sharing one would leave
    // it serving whichever it stored last and charging the traffic to that
    // one, whoever actually used it.
    assert_ne!(names[0], names[1], "two accesses were given the same name");
}

#[tokio::test]
async fn the_interface_is_served_without_a_session() {
    let panel = panel!();
    let page = call(&panel.router, "GET", "/", None, None).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("/ui/app.js"), "{}", page.body);
    for path in ["/ui/app.js", "/ui/app.css"] {
        let file = call(&panel.router, "GET", path, None, None).await;
        assert_eq!(file.status, StatusCode::OK, "{path}");
        assert!(!file.body.is_empty(), "{path} is empty");
    }
}

#[tokio::test]
async fn the_interface_text_comes_in_the_language_asked_for() {
    let panel = panel!();
    let russian = call(&panel.router, "GET", "/v1/i18n?lang=ru", None, None).await;
    assert_eq!(russian.status, StatusCode::OK);
    assert_eq!(russian.json()["lang"], "ru");
    assert_eq!(russian.json()["messages"]["ui-nav-nodes"], "Ноды");
    // A placeable is handed over as written; the browser fills it.
    assert!(
        russian.json()["messages"]["ui-cert-until"]
            .as_str()
            .unwrap()
            .contains("{ $date }")
    );

    let english = call(&panel.router, "GET", "/v1/i18n", None, None).await;
    assert_eq!(english.json()["lang"], "en");
    assert_eq!(english.json()["messages"]["ui-nav-nodes"], "Nodes");
}

#[tokio::test]
async fn traffic_by_day_needs_a_session_and_answers_a_series() {
    let panel = panel!();
    let refused = call(&panel.router, "GET", "/v1/traffic", None, None).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);

    let (_, token) = admin(&panel, Role::Superadmin).await;
    let series = call(
        &panel.router,
        "GET",
        "/v1/traffic?days=7",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(series.status, StatusCode::OK, "{}", series.body);
    assert!(series.json().is_array(), "{}", series.body);

    let (_, reseller) = admin(&panel, Role::Reseller).await;
    let own = call(
        &panel.router,
        "GET",
        "/v1/traffic?days=7",
        Some(&reseller),
        None,
    )
    .await;
    assert_eq!(own.status, StatusCode::OK, "{}", own.body);
    assert_eq!(own.json().as_array().map(Vec::len), Some(0), "{}", own.body);
}

#[tokio::test]
async fn accesses_are_listed_across_clients_but_only_ones_own() {
    let panel = panel!();
    let refused = call(&panel.router, "GET", "/v1/accesses", None, None).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);

    let (_, token) = admin(&panel, Role::Superadmin).await;
    let (client_id, access_id) = an_access(&panel, &token, "socks5").await;
    let listed = call(
        &panel.router,
        "GET",
        "/v1/accesses?limit=200",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    let items = listed.json();
    let items = items.as_array().unwrap();
    assert!(items.len() <= 200);
    // Newest first, so the one just issued leads.
    assert_eq!(items[0]["id"], access_id, "{}", listed.body);
    assert_eq!(items[0]["client_id"], client_id);
    assert!(
        items.iter().all(|item| !item["client_id"].is_null()),
        "a public link was listed"
    );

    // The reseller created none of these clients and sees none of the accesses.
    let (_, reseller) = admin(&panel, Role::Reseller).await;
    let own = call(&panel.router, "GET", "/v1/accesses", Some(&reseller), None).await;
    assert_eq!(own.status, StatusCode::OK, "{}", own.body);
    assert_eq!(own.json().as_array().map(Vec::len), Some(0), "{}", own.body);
}

#[tokio::test]
async fn an_account_without_a_second_factor_is_entered_with_a_password() {
    let panel = panel!();
    let login = unique("a");
    let none = ap_panel::create_admin(
        &panel.state,
        &login,
        "correct horse",
        Role::Superadmin,
        false,
    )
    .await
    .unwrap();
    assert!(
        none.is_none(),
        "a secret was drawn for an account without one"
    );

    // No field at all, which is what the interface sends when the box is
    // left empty.
    let signed_in = call(
        &panel.router,
        "POST",
        "/v1/session",
        None,
        Some(serde_json::json!({ "login": login, "password": "correct horse" })),
    )
    .await;
    assert_eq!(signed_in.status, StatusCode::CREATED, "{}", signed_in.body);

    // A code offered where none is kept changes nothing, and the password
    // still has to be right.
    let with_a_code = call(
        &panel.router,
        "POST",
        "/v1/session",
        None,
        Some(serde_json::json!({ "login": login, "password": "correct horse", "totp": "000000" })),
    )
    .await;
    assert_eq!(
        with_a_code.status,
        StatusCode::CREATED,
        "{}",
        with_a_code.body
    );

    let wrong = call(
        &panel.router,
        "POST",
        "/v1/session",
        None,
        Some(serde_json::json!({ "login": login, "password": "wrong horse" })),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_panel_that_has_an_owner_cannot_be_set_up_again() {
    let panel = panel!();
    // The helper leaves an administrator behind, so from here on the panel
    // is owned however it started.
    let (_, _token) = admin(&panel, Role::Superadmin).await;

    let asked = call(&panel.router, "GET", "/v1/setup", None, None).await;
    assert_eq!(asked.status, StatusCode::OK, "{}", asked.body);
    assert_eq!(asked.json()["needed"], false, "{}", asked.body);

    let again = call(
        &panel.router,
        "POST",
        "/v1/setup",
        None,
        Some(serde_json::json!({ "login": unique("a"), "password": "a long enough password" })),
    )
    .await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{}", again.body);
    assert_eq!(again.json()["error"]["code"], "already_set_up");

    // Refused every time, not merely the first. Whether a row was written on
    // the way to being refused is the store's own test.
    let once_more = call(
        &panel.router,
        "POST",
        "/v1/setup",
        None,
        Some(serde_json::json!({ "login": unique("a"), "password": "a long enough password" })),
    )
    .await;
    assert_eq!(once_more.status, StatusCode::CONFLICT, "{}", once_more.body);
}

#[tokio::test]
async fn a_short_password_is_not_taken_for_the_owner() {
    let panel = panel!();
    let refused = call(
        &panel.router,
        "POST",
        "/v1/setup",
        None,
        Some(serde_json::json!({ "login": unique("a"), "password": "short" })),
    )
    .await;
    assert_eq!(
        refused.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        refused.body
    );
    assert_eq!(refused.json()["error"]["code"], "password_too_short");
}
