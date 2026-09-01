//! Reaching somewhere by way of a SOCKS5 proxy.
//!
//! The proxy is this project's own listener, which is the one thing to hand
//! that speaks the protocol properly, refuses a wrong password and resolves
//! the name itself. No Tor is needed to find out whether the dial works.

// An integration test is a separate build target and does not inherit the
// relaxations in clippy.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ap_agent::through::{Through, dial};
use ap_inbound::registry::{Method, Registry};
use ap_proto::{WireAccess, WireCredential};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

/// Somewhere to be reached: answers one line and closes.
async fn a_destination() -> String {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.write_all(b"arrived").await;
            // Closed by shutting the sending half, not by dropping the socket.
            // A socket dropped straight after a write can be closed with a
            // reset, and a reset throws away what was still in flight — which
            // this test then read as a proxy that lost the answer.
            let _ = stream.shutdown().await;
        }
    });
    address
}

/// A proxy that wants a login, and the login it wants.
async fn a_proxy(user: &str, pass: &str) -> String {
    let access = WireAccess {
        id: Uuid::now_v7(),
        method: "socks5".to_owned(),
        credential: WireCredential::Login {
            user: user.to_owned(),
            pass: pass.to_owned(),
        },
        max_devices: None,
        state: "active".to_owned(),
    };
    let registry = std::sync::Arc::new(Registry::new(&[access], [9u8; 32]));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = ap_inbound::serve(listener, Method::Socks5, registry).await;
    });
    address
}

#[tokio::test]
async fn a_connection_arrives_by_way_of_the_proxy() {
    let destination = a_destination().await;
    let proxy = a_proxy("node", "opens the tunnel").await;

    let through = Through::parse(&format!("node:opens the tunnel@{proxy}")).unwrap();
    let mut stream = dial(&destination, Some(&through)).await.unwrap();

    let mut said = [0u8; 7];
    stream.read_exact(&mut said).await.unwrap();
    assert_eq!(&said, b"arrived");
}

#[tokio::test]
async fn a_wrong_login_does_not_get_through() {
    let destination = a_destination().await;
    let proxy = a_proxy("node", "opens the tunnel").await;

    let through = Through::parse(&format!("node:some other thing@{proxy}")).unwrap();
    assert!(
        dial(&destination, Some(&through)).await.is_err(),
        "the proxy let a wrong password through"
    );
}

#[tokio::test]
async fn a_proxy_wanting_a_login_that_was_not_given_is_refused_here() {
    let destination = a_destination().await;
    let proxy = a_proxy("node", "opens the tunnel").await;

    let through = Through::parse(&proxy).unwrap();
    assert!(dial(&destination, Some(&through)).await.is_err());
}

#[tokio::test]
async fn without_a_proxy_the_connection_is_made_directly() {
    let destination = a_destination().await;
    let mut stream = dial(&destination, None).await.unwrap();

    let mut said = [0u8; 7];
    stream.read_exact(&mut said).await.unwrap();
    assert_eq!(&said, b"arrived");
}

#[test]
fn a_setting_that_is_not_a_proxy_address_is_refused() {
    // A node meant to speak through a tunnel must not fall back to speaking
    // without one because the setting had a typo in it.
    for text in ["", "host", "user@host", ":9050", "127.0.0.1:"] {
        assert!(
            Through::parse(text).is_err(),
            "{text} was taken for a proxy address"
        );
    }

    let plain = Through::parse("127.0.0.1:9050").unwrap();
    assert_eq!(plain.credentials, None);
    let with_login = Through::parse("who:knows@127.0.0.1:9050").unwrap();
    assert_eq!(
        with_login.credentials,
        Some(("who".to_owned(), "knows".to_owned()))
    );
    assert_eq!(with_login.address, "127.0.0.1:9050");
}
