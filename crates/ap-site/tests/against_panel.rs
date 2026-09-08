//! The site against a real panel and a real PostgreSQL: a link made public
//! in the database reaches the page. Skipped when DATABASE_URL is absent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::net::IpAddr;
use std::path::PathBuf;

use ap_core::{
    Access, AccessCommon, AnyAccess, Client, Credential, Holder, KeyStore, Label, LinkName, Node,
    NodeKind, NodeState, Open, OpenMethod,
};
use ap_panel::{AppState, Config};
use time::OffsetDateTime;

use common::{config, get, start};

fn key_file() -> PathBuf {
    let dir = std::env::temp_dir().join("anyproxy-site-test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("panel.key");
    if !path.exists() {
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

fn unique(prefix: &str) -> String {
    let id = uuid::Uuid::now_v7().simple().to_string();
    format!("{prefix}-{}", &id[16..])
}

async fn a_node(state: &AppState, address: IpAddr) -> Node {
    let mut node = Node::new(
        Label::try_from(unique("n").as_str()).unwrap(),
        NodeKind::Mtproto,
        OffsetDateTime::now_utc(),
    );
    node.set_address(address);
    node.set_state(NodeState::Active);
    ap_store::NodeRepo::insert(ap_panel::channel::pool_of(state), &node)
        .await
        .unwrap();
    node
}

async fn an_access(state: &AppState, holder: Holder, node: &Node) -> AnyAccess {
    let common = AccessCommon::new(holder, node.id(), OffsetDateTime::now_utc());
    let access = AnyAccess::Open(Access::<Open>::new(common, OpenMethod::Mtproto));
    ap_store::AccessRepo::insert(
        ap_panel::channel::pool_of(state),
        &access,
        &Credential::generate_secret(),
        &KeyStore::from_bytes([11u8; 32]),
    )
    .await
    .unwrap();
    access
}

#[tokio::test]
async fn a_link_made_public_in_the_database_reaches_the_page() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let state = AppState::build(&Config::loopback(0, url, key_file()))
        .await
        .expect("state");

    let node = a_node(&state, "203.0.113.77".parse().unwrap()).await;
    let name = unique("site");
    an_access(
        &state,
        Holder::Public(LinkName::try_from(name.as_str()).unwrap()),
        &node,
    )
    .await;
    let client = Client::new(
        Label::try_from(unique("c").as_str()).unwrap(),
        OffsetDateTime::now_utc(),
    );
    ap_store::ClientRepo::insert(ap_panel::channel::pool_of(&state), &client, None)
        .await
        .unwrap();
    let owned = an_access(&state, Holder::Client(client.id()), &node).await;

    // The feed on a socket of its own, the way the panel serves it.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let feed = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, ap_panel::feed_router(state)).await;
    });

    let running = start(config(feed)).await;
    // Asked again, out loud: the first ask in `start` swallows a refusal, and
    // a page without the link should say why rather than only that.
    let shown = running.site.refresh().await.expect("the feed answered");
    assert!(shown >= 1, "the feed carried nothing");
    for path in ["/ru/", "/en/"] {
        let page = get(running.public, path).await.text();
        assert!(page.contains(&name), "{path}: the public link is not shown");
        assert!(
            page.contains("https://t.me/proxy?server=203.0.113.77&amp;port=8443&amp;secret=dd"),
            "{path}: the link is not the node's"
        );
        assert!(
            !page.contains(&owned.common().id().to_string()),
            "{path}: a client's access reached the page"
        );
    }
    let machine = get(running.public, "/links.json").await;
    let parsed: serde_json::Value = serde_json::from_slice(&machine.body).unwrap();
    let shown = parsed["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == name)
        .expect("the public link is in the machine copy");
    assert_eq!(shown["method"], "mtproto");
    let health = get(running.admin, "/health").await;
    assert_eq!(health.status, 200);
}
