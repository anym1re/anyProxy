//! The feed the public site reads (0091), against a real PostgreSQL.
//! Skipped when DATABASE_URL is absent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ap_core::Role;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[macro_use]
mod common;

use common::{Panel, admin, call, unique};

/// A node of the given transport, made active and given an address, as an
/// operator would after the agent enrolled.
async fn a_node(panel: &Panel, token: &str, kind: &str, address: Option<&str>) -> String {
    let node = call(
        &panel.router,
        "POST",
        "/v1/nodes",
        Some(token),
        Some(serde_json::json!({ "label": unique("n"), "kind": kind })),
    )
    .await;
    assert_eq!(node.status, StatusCode::CREATED, "{}", node.body);
    let id = node.json()["id"].as_str().unwrap().to_owned();
    ap_store::NodeRepo::set_state(
        ap_panel::channel::pool_of(&panel.state),
        id.parse().unwrap(),
        ap_core::NodeState::Active,
    )
    .await
    .unwrap();
    if let Some(address) = address {
        let set = call(
            &panel.router,
            "POST",
            &format!("/v1/nodes/{id}/address"),
            Some(token),
            Some(serde_json::json!({ "address": address })),
        )
        .await;
        assert_eq!(set.status, StatusCode::NO_CONTENT, "{}", set.body);
    }
    id
}

async fn a_public_link(panel: &Panel, token: &str, node_id: &str, name: &str) -> String {
    let access = call(
        &panel.router,
        "POST",
        "/v1/accesses",
        Some(token),
        Some(serde_json::json!({ "name": name, "node_id": node_id })),
    )
    .await;
    assert_eq!(access.status, StatusCode::CREATED, "{}", access.body);
    access.json()["id"].as_str().unwrap().to_owned()
}

async fn feed(panel: &Panel) -> serde_json::Value {
    let response = ap_panel::feed_router(panel.state.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/public-links")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn named<'a>(feed: &'a serde_json::Value, name: &str) -> Option<&'a serde_json::Value> {
    feed["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == name)
}

#[tokio::test]
async fn the_feed_carries_what_is_published_and_nothing_else() {
    let panel = panel!();
    let (_, token) = admin(&panel, Role::Superadmin).await;

    let addressed = a_node(&panel, &token, "mtproto", Some("203.0.113.7")).await;
    let unaddressed = a_node(&panel, &token, "mtproto", None).await;
    let socks = a_node(&panel, &token, "socks5", Some("203.0.113.8")).await;

    let shown = unique("shown");
    let disabled = unique("disabled");
    let homeless = unique("homeless");
    let account = unique("account");
    a_public_link(&panel, &token, &addressed, &shown).await;
    let disabled_id = a_public_link(&panel, &token, &addressed, &disabled).await;
    a_public_link(&panel, &token, &unaddressed, &homeless).await;
    a_public_link(&panel, &token, &socks, &account).await;

    let stopped = call(
        &panel.router,
        "POST",
        &format!("/v1/accesses/{disabled_id}/state"),
        Some(&token),
        Some(serde_json::json!({ "state": "disabled" })),
    )
    .await;
    assert_eq!(stopped.status, StatusCode::NO_CONTENT, "{}", stopped.body);

    // A client's link on the same node: never on the site.
    let client = call(
        &panel.router,
        "POST",
        "/v1/clients",
        Some(&token),
        Some(serde_json::json!({ "label": unique("c") })),
    )
    .await;
    let client_id = client.json()["id"].as_str().unwrap().to_owned();
    let owned = call(
        &panel.router,
        "POST",
        "/v1/accesses",
        Some(&token),
        Some(serde_json::json!({ "client_id": client_id, "node_id": addressed })),
    )
    .await;
    assert_eq!(owned.status, StatusCode::CREATED, "{}", owned.body);

    let feed = feed(&panel).await;

    let row = named(&feed, &shown).expect("the published link is in the feed");
    assert_eq!(row["method"], "mtproto");
    let link = row["link"].as_str().unwrap();
    assert!(
        link.starts_with("https://t.me/proxy?server=203.0.113.7&port=8443&secret=dd"),
        "{link}"
    );
    assert!(
        row.get("host").is_none(),
        "a link row carries account fields"
    );

    let row = named(&feed, &account).expect("the account link is in the feed");
    assert_eq!(row["method"], "socks5");
    assert_eq!(row["host"], "203.0.113.8");
    assert_eq!(row["port"], 1080);
    assert!(row["user"].as_str().is_some_and(|user| !user.is_empty()));
    assert!(
        row["password"]
            .as_str()
            .is_some_and(|pass| !pass.is_empty())
    );

    assert!(
        named(&feed, &disabled).is_none(),
        "a disabled link is shown"
    );
    assert!(
        named(&feed, &homeless).is_none(),
        "a link on a node without an address is shown"
    );
    for row in feed["links"].as_array().unwrap() {
        assert!(row.get("id").is_none() && row.get("node_id").is_none());
        assert!(row.get("label").is_none(), "a node's label leaked");
        assert!(row["name"].is_string(), "a row without a name: {row}");
    }
    assert!(
        !feed.to_string().contains(&client_id),
        "a client's identifier is in the feed"
    );
}

#[tokio::test]
async fn a_web_link_names_the_domain_and_needs_no_address() {
    let panel = panel!();
    let (_, token) = admin(&panel, Role::Superadmin).await;
    let domain = format!("{}.example", unique("w"));
    let node = call(
        &panel.router,
        "POST",
        "/v1/nodes",
        Some(&token),
        Some(serde_json::json!({ "label": unique("n"), "kind": "web", "domain": domain })),
    )
    .await;
    assert_eq!(node.status, StatusCode::CREATED, "{}", node.body);
    let id = node.json()["id"].as_str().unwrap().to_owned();
    ap_store::NodeRepo::set_state(
        ap_panel::channel::pool_of(&panel.state),
        id.parse().unwrap(),
        ap_core::NodeState::Active,
    )
    .await
    .unwrap();
    let name = unique("web");
    a_public_link(&panel, &token, &id, &name).await;

    let feed = feed(&panel).await;
    let row = named(&feed, &name).expect("the web link is in the feed");
    assert_eq!(row["method"], "web");
    assert!(
        row["link"]
            .as_str()
            .unwrap()
            .starts_with(&format!("https://t.me/webproxy?server={domain}&secret=")),
        "{}",
        row["link"]
    );
}

#[tokio::test]
async fn a_node_that_is_burned_or_expired_link_leaves_the_feed() {
    let panel = panel!();
    let (_, token) = admin(&panel, Role::Superadmin).await;
    let node = a_node(&panel, &token, "mtproto", Some("203.0.113.9")).await;
    let expired = unique("expired");
    let access = call(
        &panel.router,
        "POST",
        "/v1/accesses",
        Some(&token),
        Some(serde_json::json!({
            "name": expired, "node_id": node, "expires_at": "2020-01-01T00:00:00Z"
        })),
    )
    .await;
    assert_eq!(access.status, StatusCode::CREATED, "{}", access.body);
    let live = unique("live");
    a_public_link(&panel, &token, &node, &live).await;

    let before = feed(&panel).await;
    assert!(
        named(&before, &expired).is_none(),
        "an expired link is shown"
    );
    assert!(named(&before, &live).is_some());

    let burned = call(
        &panel.router,
        "POST",
        &format!("/v1/nodes/{node}/burn"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(burned.status, StatusCode::NO_CONTENT, "{}", burned.body);
    let after = feed(&panel).await;
    assert!(
        named(&after, &live).is_none(),
        "a burned node's link is shown"
    );
}

#[tokio::test]
async fn publishing_is_written_to_the_journal_by_name() {
    let panel = panel!();
    let (_, token) = admin(&panel, Role::Superadmin).await;
    let node = a_node(&panel, &token, "mtproto", Some("203.0.113.10")).await;
    let name = unique("named");
    let id = a_public_link(&panel, &token, &node, &name).await;

    let audit = call(
        &panel.router,
        "GET",
        "/v1/audit?limit=50&prefix=access.",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(audit.status, StatusCode::OK, "{}", audit.body);
    let entries = audit.json();
    let entry = entries["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["action"] == "access.created" && entry["target"] == id)
        .unwrap_or_else(|| panic!("the publication is not in the journal: {}", audit.body));
    assert_eq!(entry["details"]["holder"], "public");
    assert_eq!(entry["details"]["name"], name);

    // The address, too, by the node's label.
    let node_entry = entries["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["action"] == "node.address");
    assert!(!node_entry, "a node entry answered an access prefix");
    let nodes = call(
        &panel.router,
        "GET",
        "/v1/audit?limit=50&prefix=node.",
        Some(&token),
        None,
    )
    .await;
    assert!(
        nodes.json()["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["action"] == "node.address"
                && entry["details"]["address"] == "203.0.113.10"),
        "the address was not recorded: {}",
        nodes.body
    );
}

#[tokio::test]
async fn an_address_is_an_ip_and_only_a_node_manager_sets_it() {
    let panel = panel!();
    let (_, token) = admin(&panel, Role::Superadmin).await;
    let node = a_node(&panel, &token, "mtproto", None).await;

    let refused = call(
        &panel.router,
        "POST",
        &format!("/v1/nodes/{node}/address"),
        Some(&token),
        Some(serde_json::json!({ "address": "not an address" })),
    )
    .await;
    assert_eq!(
        refused.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        refused.body
    );
    assert_eq!(refused.json()["error"]["code"], "address_form");

    let (_, operator) = admin(&panel, Role::Operator).await;
    let not_theirs = call(
        &panel.router,
        "POST",
        &format!("/v1/nodes/{node}/address"),
        Some(&operator),
        Some(serde_json::json!({ "address": "203.0.113.1" })),
    )
    .await;
    assert_eq!(
        not_theirs.status,
        StatusCode::NOT_FOUND,
        "{}",
        not_theirs.body
    );

    let six = call(
        &panel.router,
        "POST",
        &format!("/v1/nodes/{node}/address"),
        Some(&token),
        Some(serde_json::json!({ "address": "2001:db8::7" })),
    )
    .await;
    assert_eq!(six.status, StatusCode::NO_CONTENT, "{}", six.body);
    let read = call(&panel.router, "GET", "/v1/nodes", Some(&token), None).await;
    let shown = read.json();
    let mine = shown
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == node)
        .unwrap();
    assert_eq!(mine["address"], "2001:db8::7");

    let cleared = call(
        &panel.router,
        "POST",
        &format!("/v1/nodes/{node}/address"),
        Some(&token),
        Some(serde_json::json!({ "address": null })),
    )
    .await;
    assert_eq!(cleared.status, StatusCode::NO_CONTENT, "{}", cleared.body);
}
