//! The panel side of the agent channel, against a real PostgreSQL.
//! Skipped when DATABASE_URL is absent.

// An integration test is a separate build target and does not inherit the
// relaxations in clippy.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use ap_core::{
    Access, AccessCommon, AccessState, AnyAccess, Client, Credential, Domain, KeyStore, Label,
    Node, NodeKind, OpenMethod, StealthMethod,
};
use ap_panel::{AppState, Config as PanelConfig};
use ap_proto::{DeviceCount, Health, Message, Telemetry, TrafficDelta};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

// The same key file as the api tests use. The panel identity in the database
// is sealed with it, and a panel holding a different key cannot open it, which
// is the point of sealing it. Two test binaries sharing one database must
// therefore share one key.
fn key_file() -> PathBuf {
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

async fn state() -> Option<AppState> {
    let url = std::env::var("DATABASE_URL").ok()?;
    Some(
        AppState::build(&PanelConfig::loopback(0, url, key_file()))
            .await
            .expect("state"),
    )
}

macro_rules! state {
    () => {
        match state().await {
            Some(state) => state,
            None => return,
        }
    };
}

fn unique(prefix: &str) -> String {
    // The first half of a version 7 identifier is a millisecond timestamp, so
    // two calls inside one millisecond share it. The second half is random.
    let id = uuid::Uuid::now_v7().simple().to_string();
    format!("{prefix}-{}", &id[16..])
}

fn key() -> KeyStore {
    KeyStore::from_bytes([11u8; 32])
}

async fn open_node(state: &AppState) -> Node {
    let node = Node::new(
        Label::try_from(unique("n").as_str()).unwrap(),
        NodeKind::Open,
        OffsetDateTime::now_utc(),
    );
    ap_store::NodeRepo::insert(ap_panel::channel::pool_of(state), &node)
        .await
        .unwrap();
    node
}

async fn a_client(state: &AppState) -> Client {
    let client = Client::new(
        Label::try_from(unique("c").as_str()).unwrap(),
        OffsetDateTime::now_utc(),
    );
    ap_store::ClientRepo::insert(ap_panel::channel::pool_of(state), &client, None)
        .await
        .unwrap();
    client
}

async fn an_access(state: &AppState, client: &Client, node: &Node) -> AnyAccess {
    let common = AccessCommon::new(client.id(), node.id(), OffsetDateTime::now_utc());
    let access = AnyAccess::Open(Access::<ap_core::Open>::new(common, OpenMethod::Mtproto));
    ap_store::AccessRepo::insert(
        ap_panel::channel::pool_of(state),
        &access,
        &Credential::generate_secret(),
        &key(),
    )
    .await
    .unwrap();
    access
}

fn csr() -> String {
    let pair = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "whatever the agent wants");
    params.serialize_request(&pair).unwrap().pem().unwrap()
}

#[tokio::test]
async fn a_code_works_once() {
    let state = state!();
    let node = open_node(&state).await;
    let issued = ap_panel::enrollment::issue(&state, node.id())
        .await
        .unwrap();

    let first =
        ap_panel::channel::enrol_directly(&state, state.authority(), &issued.code, &csr()).await;
    assert!(first.is_ok(), "the first enrolment failed");
    assert_eq!(first.unwrap().node_id, node.id());

    let second =
        ap_panel::channel::enrol_directly(&state, state.authority(), &issued.code, &csr()).await;
    assert!(second.is_err(), "the code was accepted twice");
}

#[tokio::test]
async fn a_wrong_code_and_an_unknown_one_answer_alike() {
    let state = state!();
    let node = open_node(&state).await;
    let issued = ap_panel::enrollment::issue(&state, node.id())
        .await
        .unwrap();
    ap_panel::channel::enrol_directly(&state, state.authority(), &issued.code, &csr())
        .await
        .unwrap();

    let used =
        ap_panel::channel::enrol_directly(&state, state.authority(), &issued.code, &csr()).await;
    let never =
        ap_panel::channel::enrol_directly(&state, state.authority(), &unique("x"), &csr()).await;

    assert_eq!(
        format!("{:?}", used.err()),
        format!("{:?}", never.err()),
        "a spent code and one that never existed answer differently"
    );
}

#[tokio::test]
async fn the_certificate_names_the_node_not_the_request() {
    let state = state!();
    let node = open_node(&state).await;
    let issued = ap_panel::enrollment::issue(&state, node.id())
        .await
        .unwrap();
    let enrolled =
        ap_panel::channel::enrol_directly(&state, state.authority(), &issued.code, &csr())
            .await
            .unwrap();

    assert!(
        enrolled.certificate.contains("BEGIN CERTIFICATE"),
        "no certificate came back"
    );
    assert!(!enrolled.certificate.contains("whatever the agent wants"));

    let der = CertificateDer::pem_slice_iter(enrolled.certificate.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let bound = ap_store::EnrollmentRepo::node_of_certificate(
        ap_panel::channel::pool_of(&state),
        &Sha256::digest(der.as_ref()),
    )
    .await
    .unwrap();
    assert_eq!(bound, Some(node.id()));
}

#[tokio::test]
async fn a_configuration_carries_only_this_node() {
    let state = state!();
    let mine = open_node(&state).await;
    let theirs = Node::new(
        Label::try_from(unique("n").as_str()).unwrap(),
        NodeKind::Stealth {
            domain: Domain::try_from(format!("{}.example.com", unique("d")).as_str()).unwrap(),
        },
        OffsetDateTime::now_utc(),
    );
    ap_store::NodeRepo::insert(ap_panel::channel::pool_of(&state), &theirs)
        .await
        .unwrap();

    let client = a_client(&state).await;
    an_access(&state, &client, &mine).await;

    let config = ap_panel::channel::configuration_for(&state, mine.id())
        .await
        .unwrap();
    let rendered = serde_json::to_string(&config).unwrap();

    assert!(!rendered.contains(theirs.label().as_str()));
    assert!(!rendered.contains(theirs.kind().domain().unwrap().as_str()));
    assert!(!rendered.contains(&theirs.id().to_string()));
    assert_eq!(config.accesses.len(), 1);
}

#[tokio::test]
async fn a_withdrawn_access_is_absent_rather_than_marked() {
    let state = state!();
    let node = open_node(&state).await;
    let client = a_client(&state).await;
    let access = an_access(&state, &client, &node).await;

    let before = ap_panel::channel::configuration_for(&state, node.id())
        .await
        .unwrap();
    assert_eq!(before.accesses.len(), 1);

    ap_store::AccessRepo::set_state(
        ap_panel::channel::pool_of(&state),
        access.common().id(),
        AccessState::Revoked,
    )
    .await
    .unwrap();

    let after = ap_panel::channel::configuration_for(&state, node.id())
        .await
        .unwrap();
    assert!(after.accesses.is_empty(), "a withdrawn access was sent");
    assert!(
        !serde_json::to_string(&after)
            .unwrap()
            .contains(&access.common().id().to_string())
    );
}

#[tokio::test]
async fn each_configuration_carries_a_later_revision() {
    let state = state!();
    let node = open_node(&state).await;
    let first = ap_panel::channel::configuration_for(&state, node.id())
        .await
        .unwrap();
    let second = ap_panel::channel::configuration_for(&state, node.id())
        .await
        .unwrap();
    assert!(
        second.revision > first.revision,
        "revisions did not move forward"
    );
    let stored =
        ap_store::EnrollmentRepo::last_revision(ap_panel::channel::pool_of(&state), node.id())
            .await
            .unwrap();
    assert_eq!(stored, Some(second.revision));
}

#[tokio::test]
async fn telemetry_for_a_foreign_access_moves_nothing() {
    let state = state!();
    let mine = open_node(&state).await;
    let theirs = open_node(&state).await;
    let client = a_client(&state).await;
    let foreign = an_access(&state, &client, &theirs).await;
    let ours = an_access(&state, &client, &mine).await;

    let telemetry = Telemetry {
        revision: Uuid::now_v7(),
        sent_at: ap_core::time::format_rfc3339(OffsetDateTime::now_utc()).unwrap(),
        deltas: vec![
            TrafficDelta {
                access_id: foreign.common().id(),
                day: "2026-08-26".to_owned(),
                bytes_in: 100,
                bytes_out: 200,
            },
            TrafficDelta {
                access_id: ours.common().id(),
                day: "2026-08-26".to_owned(),
                bytes_in: 1,
                bytes_out: 2,
            },
        ],
        devices: Vec::new(),
        health: Health {
            engine: "up".to_owned(),
            site: "up".to_owned(),
            cert_not_after: None,
        },
    };

    // The delivery is taken, because the panel cannot tell an access that was
    // moved off this node from one that was never on it, and a node whose
    // whole delivery was thrown away would keep sending the same one for ever
    // — its own accesses uncounted along with the foreign one.
    ap_panel::channel::ingest_telemetry(&state, mine.id(), &telemetry)
        .await
        .unwrap();

    let pool = ap_panel::channel::pool_of(&state);
    let stolen = ap_store::TrafficRepo::for_access(pool, foreign.common().id())
        .await
        .unwrap();
    assert_eq!(
        stolen.total(),
        0,
        "a node wrote into an access that is not on it"
    );
    let counted = ap_store::TrafficRepo::for_access(pool, ours.common().id())
        .await
        .unwrap();
    assert_eq!(
        counted.total(),
        3,
        "the node's own traffic was lost along with the foreign delta"
    );
}

#[tokio::test]
async fn a_repeated_delivery_moves_the_counter_once() {
    let state = state!();
    let node = open_node(&state).await;
    let client = a_client(&state).await;
    let access = an_access(&state, &client, &node).await;

    let telemetry = Telemetry {
        revision: Uuid::now_v7(),
        sent_at: ap_core::time::format_rfc3339(OffsetDateTime::now_utc()).unwrap(),
        deltas: vec![TrafficDelta {
            access_id: access.common().id(),
            day: "2026-08-26".to_owned(),
            bytes_in: 100,
            bytes_out: 200,
        }],
        devices: vec![DeviceCount {
            access_id: access.common().id(),
            period: "2026-08-26".to_owned(),
            unique: 2,
        }],
        health: Health {
            engine: "up".to_owned(),
            site: "up".to_owned(),
            cert_not_after: None,
        },
    };

    ap_panel::channel::ingest_telemetry(&state, node.id(), &telemetry)
        .await
        .unwrap();
    ap_panel::channel::ingest_telemetry(&state, node.id(), &telemetry)
        .await
        .unwrap();

    let totals =
        ap_store::TrafficRepo::for_access(ap_panel::channel::pool_of(&state), access.common().id())
            .await
            .unwrap();
    assert_eq!(totals.total(), 300);
}

// The node is decided by the certificate the connection presented. A frame
// naming a different node changes nothing, which is what this checks: the
// conversation is driven end to end over a pipe with node A's certificate
// while the hello names node B.
#[tokio::test]
async fn a_frame_naming_another_node_changes_nothing() {
    let state = state!();
    let mine = open_node(&state).await;
    let theirs = open_node(&state).await;

    let issued = ap_panel::enrollment::issue(&state, mine.id())
        .await
        .unwrap();
    let enrolled =
        ap_panel::channel::enrol_directly(&state, state.authority(), &issued.code, &csr())
            .await
            .unwrap();
    let der = CertificateDer::pem_slice_iter(enrolled.certificate.as_bytes())
        .next()
        .unwrap()
        .unwrap();

    let (mut ours, theirs_side) = tokio::io::duplex(64 * 1024);
    let authority = state.authority_handle();
    let served = tokio::spawn(ap_panel::channel::converse_over(
        state.clone(),
        Arc::clone(&authority),
        theirs_side,
        Some(der),
    ));

    let mut hello = ap_panel::channel::hello_of(theirs.id());
    hello.node_id = theirs.id();
    ours.write_all(&ap_proto::encode(&Message::Hello(hello)).unwrap())
        .await
        .unwrap();

    let mut buffer = vec![0u8; 128 * 1024];
    let read = ours.read(&mut buffer).await.unwrap();
    ours.shutdown().await.ok();
    let _ = served.await;

    let mut cursor = &buffer[..read];
    let mut config = None;
    while let Ok(Some((message, consumed))) = ap_proto::decode(cursor) {
        if let Message::Config(inner) = message {
            config = Some(inner);
        }
        cursor = &cursor[consumed..];
    }

    let config = config.expect("no configuration came back");
    assert_eq!(
        config.node.kind,
        mine.kind().tag().as_stored(),
        "the panel answered about the node named in the frame"
    );
    let stored =
        ap_store::EnrollmentRepo::last_revision(ap_panel::channel::pool_of(&state), mine.id())
            .await
            .unwrap();
    assert_eq!(stored, Some(config.revision));
}

#[tokio::test]
async fn a_connection_without_a_certificate_may_only_enrol() {
    let state = state!();
    let node = open_node(&state).await;

    let (mut ours, theirs) = tokio::io::duplex(64 * 1024);
    let authority = state.authority_handle();
    let served = tokio::spawn(ap_panel::channel::converse_over(
        state.clone(),
        authority,
        theirs,
        None,
    ));

    ours.write_all(
        &ap_proto::encode(&Message::Hello(ap_panel::channel::hello_of(node.id()))).unwrap(),
    )
    .await
    .unwrap();
    ours.shutdown().await.ok();

    let outcome = served.await.unwrap();
    assert!(outcome.is_err(), "a hello without a certificate was served");
}

#[tokio::test]
async fn a_cache_key_is_fresh_for_every_connection() {
    let state = state!();
    let node = open_node(&state).await;
    let issued = ap_panel::enrollment::issue(&state, node.id())
        .await
        .unwrap();
    let enrolled =
        ap_panel::channel::enrol_directly(&state, state.authority(), &issued.code, &csr())
            .await
            .unwrap();
    let der = CertificateDer::pem_slice_iter(enrolled.certificate.as_bytes())
        .next()
        .unwrap()
        .unwrap();

    let mut keys = Vec::new();
    for _ in 0..2 {
        let (mut ours, theirs) = tokio::io::duplex(64 * 1024);
        let authority = state.authority_handle();
        let served = tokio::spawn(ap_panel::channel::converse_over(
            state.clone(),
            authority,
            theirs,
            Some(der.clone()),
        ));
        ours.write_all(
            &ap_proto::encode(&Message::Hello(ap_panel::channel::hello_of(node.id()))).unwrap(),
        )
        .await
        .unwrap();

        let mut buffer = vec![0u8; 128 * 1024];
        let read = ours.read(&mut buffer).await.unwrap();
        ours.shutdown().await.ok();
        let _ = served.await;

        if let Ok(Some((Message::Welcome(welcome), _))) = ap_proto::decode(&buffer[..read]) {
            keys.push(welcome.cache_key);
        }
    }

    assert_eq!(keys.len(), 2, "two welcomes were expected");
    assert_ne!(keys[0], keys[1], "the same cache key was handed out twice");
    assert_eq!(keys[0].len(), 64);
}

#[tokio::test]
async fn burning_a_node_withdraws_its_accesses_and_refuses_its_certificate() {
    let state = state!();
    let node = open_node(&state).await;
    let client = a_client(&state).await;
    let access = an_access(&state, &client, &node).await;

    let issued = ap_panel::enrollment::issue(&state, node.id())
        .await
        .unwrap();
    let enrolled =
        ap_panel::channel::enrol_directly(&state, state.authority(), &issued.code, &csr())
            .await
            .unwrap();
    let der = CertificateDer::pem_slice_iter(enrolled.certificate.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let digest = Sha256::digest(der.as_ref()).to_vec();

    let pool = ap_panel::channel::pool_of(&state);
    assert_eq!(
        ap_store::EnrollmentRepo::node_of_certificate(pool, &digest)
            .await
            .unwrap(),
        Some(node.id())
    );

    ap_store::AccessRepo::revoke_by_node(pool, node.id())
        .await
        .unwrap();
    ap_store::NodeRepo::set_state(pool, node.id(), ap_core::NodeState::Burned)
        .await
        .unwrap();

    assert_eq!(
        ap_store::EnrollmentRepo::node_of_certificate(pool, &digest)
            .await
            .unwrap(),
        None,
        "a burned node still answered to its certificate"
    );

    let read = ap_store::AccessRepo::by_id(pool, access.common().id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.common().state(), AccessState::Revoked);
}

#[tokio::test]
async fn a_stealth_node_is_told_to_listen_on_443_alone() {
    let state = state!();
    let node = Node::new(
        Label::try_from(unique("n").as_str()).unwrap(),
        NodeKind::Stealth {
            domain: Domain::try_from(format!("{}.example.com", unique("d")).as_str()).unwrap(),
        },
        OffsetDateTime::now_utc(),
    );
    ap_store::NodeRepo::insert(ap_panel::channel::pool_of(&state), &node)
        .await
        .unwrap();

    let config = ap_panel::channel::configuration_for(&state, node.id())
        .await
        .unwrap();
    assert_eq!(config.listeners.len(), 1);
    assert_eq!(config.listeners[0].bind, "0.0.0.0:443");
    assert_eq!(config.listeners[0].method, "faketls");
    let _ = StealthMethod::FakeTls;
}

#[tokio::test]
async fn a_stealth_node_whose_clients_arrive_inside_a_site_serves_the_site() {
    // One socket on 443 carries one thing. A node holding an access that
    // arrives inside a real site serves that; the forged handshake and the
    // site cannot both have the port.
    let state = state!();
    let node = Node::new(
        Label::try_from(unique("n").as_str()).unwrap(),
        NodeKind::Stealth {
            domain: Domain::try_from(format!("{}.example.com", unique("d")).as_str()).unwrap(),
        },
        OffsetDateTime::now_utc(),
    );
    let pool = ap_panel::channel::pool_of(&state);
    ap_store::NodeRepo::insert(pool, &node).await.unwrap();

    let client = a_client(&state).await;
    let common = AccessCommon::new(client.id(), node.id(), OffsetDateTime::now_utc());
    let access = AnyAccess::Stealth(Access::<ap_core::Stealth>::new(common, StealthMethod::Web));
    ap_store::AccessRepo::insert(pool, &access, &Credential::generate_secret(), &key())
        .await
        .unwrap();

    let config = ap_panel::channel::configuration_for(&state, node.id())
        .await
        .unwrap();
    assert_eq!(config.listeners.len(), 1);
    assert_eq!(config.listeners[0].method, "web");
    assert_eq!(
        config.listeners[0].bind, "127.0.0.1:8444",
        "the engine was put on the port the front door needs"
    );
}

#[tokio::test]
async fn a_stealth_node_serving_both_carriers_puts_both_behind_the_door() {
    // The site is served over real TLS, which the front door ends. It sends on
    // by the name the client asked for, so the forged handshake can live on the
    // same node — behind the door rather than on the port.
    let state = state!();
    let node = Node::new(
        Label::try_from(unique("n").as_str()).unwrap(),
        NodeKind::Stealth {
            domain: Domain::try_from(format!("{}.example.com", unique("d")).as_str()).unwrap(),
        },
        OffsetDateTime::now_utc(),
    );
    let pool = ap_panel::channel::pool_of(&state);
    ap_store::NodeRepo::insert(pool, &node).await.unwrap();

    let client = a_client(&state).await;
    for method in [StealthMethod::Web, StealthMethod::FakeTls] {
        let common = AccessCommon::new(client.id(), node.id(), OffsetDateTime::now_utc());
        let access = AnyAccess::Stealth(Access::<ap_core::Stealth>::new(common, method));
        ap_store::AccessRepo::insert(pool, &access, &Credential::generate_secret(), &key())
            .await
            .unwrap();
    }

    let config = ap_panel::channel::configuration_for(&state, node.id())
        .await
        .unwrap();
    let mut bound: Vec<(&str, &str)> = config
        .listeners
        .iter()
        .map(|listener| (listener.method.as_str(), listener.bind.as_str()))
        .collect();
    bound.sort_unstable();
    assert_eq!(
        bound,
        vec![("faketls", "127.0.0.1:8445"), ("web", "127.0.0.1:8444")],
        "one of the two took the port the front door needs"
    );
}

#[tokio::test]
async fn a_node_opens_a_socket_for_what_it_serves_and_no_other() {
    let state = state!();
    let node = open_node(&state).await;
    let client = a_client(&state).await;

    // Nothing granted yet: nothing to listen on.
    let empty = ap_panel::channel::configuration_for(&state, node.id())
        .await
        .unwrap();
    assert!(
        empty.listeners.is_empty(),
        "a node with nothing to serve opened {:?}",
        empty.listeners
    );

    let common = AccessCommon::new(client.id(), node.id(), OffsetDateTime::now_utc());
    let access = AnyAccess::Open(Access::<ap_core::Open>::new(common, OpenMethod::Mtproto));
    ap_store::AccessRepo::insert(
        ap_panel::channel::pool_of(&state),
        &access,
        &Credential::generate_secret(),
        &key(),
    )
    .await
    .unwrap();

    let config = ap_panel::channel::configuration_for(&state, node.id())
        .await
        .unwrap();
    let methods: Vec<&str> = config
        .listeners
        .iter()
        .map(|listener| listener.method.as_str())
        .collect();
    assert_eq!(methods, vec!["mtproto"], "{:?}", config.listeners);
    for unwanted in ["socks5", "http"] {
        assert!(
            !methods.contains(&unwanted),
            "{unwanted} was opened with nothing behind it"
        );
    }
}

#[tokio::test]
async fn a_node_whose_agent_is_talking_is_no_longer_merely_registered() {
    let state = state!();
    let node = open_node(&state).await;
    assert_eq!(node.state(), ap_core::NodeState::Pending);

    let issued = ap_panel::enrollment::issue(&state, node.id())
        .await
        .unwrap();
    let enrolled =
        ap_panel::channel::enrol_directly(&state, state.authority(), &issued.code, &csr())
            .await
            .unwrap();
    let der = CertificateDer::pem_slice_iter(enrolled.certificate.as_bytes())
        .next()
        .unwrap()
        .unwrap();

    let (mut ours, theirs) = tokio::io::duplex(64 * 1024);
    let served = tokio::spawn(ap_panel::channel::converse_over(
        state.clone(),
        state.authority_handle(),
        theirs,
        Some(der),
    ));

    let hello = ap_panel::channel::hello_of(node.id());
    ours.write_all(&ap_proto::encode(&Message::Hello(hello)).unwrap())
        .await
        .unwrap();
    let mut buffer = vec![0u8; 128 * 1024];
    let _ = ours.read(&mut buffer).await.unwrap();
    ours.shutdown().await.ok();
    let _ = served.await;

    let seen = ap_store::NodeRepo::list(ap_panel::channel::pool_of(&state))
        .await
        .unwrap()
        .into_iter()
        .find(|found| found.id() == node.id())
        .expect("the node");

    // A node that is serving clients must not read the same as one nobody has
    // installed yet: an operator looking for one that stopped has to be able
    // to tell them apart.
    assert_eq!(seen.state(), ap_core::NodeState::Active);
    assert!(
        seen.last_seen_at().is_some(),
        "nothing recorded the contact"
    );
}
