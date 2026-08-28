//! The agent against a running panel, over TLS, with a real PostgreSQL behind
//! it. Skipped when DATABASE_URL is absent.

// An integration test is a separate build target and does not inherit the
// relaxations in clippy.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use ap_agent::identity::Paths;
use ap_agent::meter::Meter;
use ap_agent::posture::{Posture, Silent};
use ap_agent::{AgentError, cache, identity, link, session};
use ap_core::{Holder, KeyStore, Label, Node, NodeKind};
use ap_panel::{AppState, Config as PanelConfig};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

// The same key file as the other panel test binaries use. The panel identity
// in the database is sealed with it, and a panel holding a different key
// cannot open it.
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

fn unique(prefix: &str) -> String {
    // The first half of a version 7 identifier is a millisecond timestamp, so
    // two calls inside one millisecond share it. The second half is random.
    let id = Uuid::now_v7().simple().to_string();
    format!("{prefix}-{}", &id[16..])
}

fn agent_dir(name: &str) -> Paths {
    let dir = std::env::temp_dir()
        .join("anyproxy-agent-test")
        .join(format!("{name}-{}", Uuid::now_v7().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    Paths::new(dir)
}

/// A panel listening on a port the operating system chose.
struct Panel {
    state: AppState,
    address: String,
    fingerprint: String,
}

async fn panel() -> Option<Panel> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let state = AppState::build(&PanelConfig::loopback(0, url, key_file()))
        .await
        .expect("state");
    let authority = state.authority_handle();
    let fingerprint = authority.fingerprint().unwrap();

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap().to_string();

    let served = state.clone();
    tokio::spawn(async move {
        let _ = ap_panel::channel::serve(served, authority, listener).await;
    });

    Some(Panel {
        state,
        address,
        fingerprint,
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

async fn a_node(panel: &Panel) -> Uuid {
    let node = Node::new(
        Label::try_from(unique("n").as_str()).unwrap(),
        NodeKind::Mtproto,
        OffsetDateTime::now_utc(),
    );
    let id = node.id();
    ap_store::NodeRepo::insert(ap_panel::channel::pool_of(&panel.state), &node)
        .await
        .unwrap();
    id
}

async fn a_code(panel: &Panel, node_id: Uuid) -> String {
    ap_panel::enrollment::issue(&panel.state, node_id)
        .await
        .unwrap()
        .code
}

#[tokio::test]
async fn a_code_reaches_the_panel_and_comes_back_as_an_identity() {
    let panel = panel!();
    let node_id = a_node(&panel).await;
    let code = a_code(&panel, node_id).await;

    let mut channel = link::connect(&panel.address, &panel.fingerprint, None)
        .await
        .unwrap();
    let identity = session::enrol(&mut channel, &code).await.unwrap();

    assert_eq!(identity.node_id, node_id);
    assert!(identity.certificate_pem.contains("BEGIN CERTIFICATE"));
    assert!(identity.key_pem.contains("PRIVATE KEY"));
    assert_eq!(
        identity.fingerprint().unwrap(),
        panel.fingerprint,
        "the agent arrived at a different value for the same authority"
    );
}

#[tokio::test]
async fn a_panel_that_is_not_the_pinned_one_never_sees_the_code() {
    let panel = panel!();
    let node_id = a_node(&panel).await;
    let code = a_code(&panel, node_id).await;

    // A fingerprint of the right shape and the wrong value. Nothing else about
    // the panel changes.
    let wrong = hex::encode([0xabu8; 32]);
    let refused = link::connect(&panel.address, &wrong, None).await;
    assert!(
        matches!(refused, Err(AgentError::WrongPanel)),
        "a panel that did not match the pin was accepted"
    );

    // The code is still unspent, which is what says it never left the agent.
    let mut channel = link::connect(&panel.address, &panel.fingerprint, None)
        .await
        .unwrap();
    assert!(
        session::enrol(&mut channel, &code).await.is_ok(),
        "the code had already been used"
    );
}

#[tokio::test]
async fn a_code_works_once() {
    let panel = panel!();
    let node_id = a_node(&panel).await;
    let code = a_code(&panel, node_id).await;

    let mut first = link::connect(&panel.address, &panel.fingerprint, None)
        .await
        .unwrap();
    session::enrol(&mut first, &code).await.unwrap();

    let mut second = link::connect(&panel.address, &panel.fingerprint, None)
        .await
        .unwrap();
    assert!(
        session::enrol(&mut second, &code).await.is_err(),
        "the same code enrolled a second agent"
    );
}

#[tokio::test]
async fn an_enrolled_agent_receives_its_own_configuration() {
    let panel = panel!();
    let node_id = a_node(&panel).await;
    let code = a_code(&panel, node_id).await;
    let paths = agent_dir("configured");

    let mut channel = link::connect(&panel.address, &panel.fingerprint, None)
        .await
        .unwrap();
    let identity = session::enrol(&mut channel, &code).await.unwrap();
    identity::store(&paths, &identity).unwrap();
    drop(channel);

    let mut channel = link::connect(&panel.address, &panel.fingerprint, Some(&identity))
        .await
        .unwrap();
    let state = session::open(
        &mut channel,
        identity.node_id,
        &paths,
        None,
        OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();

    assert!(state.posture.is_serving());
    assert!(state.applied_revision.is_some());
    assert_eq!(state.ttl_secs, 72 * 3600);
}

#[tokio::test]
async fn a_restart_without_the_panel_leaves_the_proxy_paths_down() {
    let panel = panel!();
    let node_id = a_node(&panel).await;
    let code = a_code(&panel, node_id).await;
    let paths = agent_dir("restart");

    let mut channel = link::connect(&panel.address, &panel.fingerprint, None)
        .await
        .unwrap();
    let identity = session::enrol(&mut channel, &code).await.unwrap();
    identity::store(&paths, &identity).unwrap();
    drop(channel);

    let mut channel = link::connect(&panel.address, &panel.fingerprint, Some(&identity))
        .await
        .unwrap();
    let state = session::open(
        &mut channel,
        identity.node_id,
        &paths,
        None,
        OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();
    assert!(state.posture.is_serving());
    assert!(paths.cache().exists(), "nothing was cached");

    // What a restart amounts to: the process is gone, the file is not, and the
    // key that opens it existed only in the process.
    drop(state);
    drop(channel);

    let posture = session::posture_before_contact();
    assert_eq!(posture, Posture::SiteOnly(Silent::NoCacheKey));
    assert!(!posture.is_serving());
    assert!(posture.site_answers());

    // And no other key opens it either.
    let outcome = cache::read(
        &paths.cache(),
        &KeyStore::from_bytes([0u8; 32]),
        OffsetDateTime::now_utc(),
    );
    assert!(matches!(outcome, Err(AgentError::Cache)));
}

#[tokio::test]
async fn a_cache_past_its_life_stops_the_proxy_and_leaves_the_site() {
    let panel = panel!();
    let node_id = a_node(&panel).await;
    let code = a_code(&panel, node_id).await;
    let paths = agent_dir("expired");

    let mut channel = link::connect(&panel.address, &panel.fingerprint, None)
        .await
        .unwrap();
    let identity = session::enrol(&mut channel, &code).await.unwrap();
    drop(channel);

    let mut channel = link::connect(&panel.address, &panel.fingerprint, Some(&identity))
        .await
        .unwrap();
    let sealed_at = OffsetDateTime::now_utc();
    let mut state = session::open(&mut channel, identity.node_id, &paths, None, sealed_at)
        .await
        .unwrap();
    assert!(state.posture.is_serving());

    let long_after = sealed_at + Duration::seconds(i64::from(state.ttl_secs) + 1);
    state.reconsider(&paths, long_after).unwrap();

    assert_eq!(state.posture, Posture::SiteOnly(Silent::CacheExpired));
    assert!(!state.posture.is_serving());
    assert!(state.posture.site_answers());
}

#[tokio::test]
async fn a_node_that_lost_the_panel_keeps_serving_until_its_cache_runs_out() {
    let panel = panel!();
    let node_id = a_node(&panel).await;
    let code = a_code(&panel, node_id).await;
    let paths = agent_dir("unreachable");

    let mut channel = link::connect(&panel.address, &panel.fingerprint, None)
        .await
        .unwrap();
    let identity = session::enrol(&mut channel, &code).await.unwrap();
    drop(channel);

    let mut channel = link::connect(&panel.address, &panel.fingerprint, Some(&identity))
        .await
        .unwrap();
    let sealed_at = OffsetDateTime::now_utc();
    let mut state = session::open(&mut channel, identity.node_id, &paths, None, sealed_at)
        .await
        .unwrap();

    // The panel is gone. The agent is not, and neither is the key it holds.
    drop(channel);

    let a_day_later = sealed_at + Duration::hours(24);
    state.reconsider(&paths, a_day_later).unwrap();
    assert!(
        state.posture.is_serving(),
        "the node stopped serving while its cache was still good"
    );
    assert!(state.posture.site_answers());
}

#[tokio::test]
async fn a_revision_the_node_already_passed_is_refused() {
    let panel = panel!();
    let node_id = a_node(&panel).await;
    let code = a_code(&panel, node_id).await;
    let paths = agent_dir("stale");

    let mut channel = link::connect(&panel.address, &panel.fingerprint, None)
        .await
        .unwrap();
    let identity = session::enrol(&mut channel, &code).await.unwrap();
    drop(channel);

    let mut channel = link::connect(&panel.address, &panel.fingerprint, Some(&identity))
        .await
        .unwrap();
    let now = OffsetDateTime::now_utc();
    let mut state = session::open(&mut channel, identity.node_id, &paths, None, now)
        .await
        .unwrap();
    let running = state.applied_revision.unwrap();

    let mut older = ap_panel::channel::configuration_for(&panel.state, node_id)
        .await
        .unwrap();
    older.revision = Uuid::from_u128(running.as_u128() - 1);

    session::apply(&mut channel, &mut state, &paths, older, now)
        .await
        .unwrap();

    assert_eq!(
        state.applied_revision,
        Some(running),
        "an older revision replaced the running one"
    );
}

#[tokio::test]
async fn the_key_that_opens_the_cache_is_not_written_anywhere() {
    let panel = panel!();
    let node_id = a_node(&panel).await;
    let code = a_code(&panel, node_id).await;
    let paths = agent_dir("no-key-on-disk");

    let mut channel = link::connect(&panel.address, &panel.fingerprint, None)
        .await
        .unwrap();
    let identity = session::enrol(&mut channel, &code).await.unwrap();
    identity::store(&paths, &identity).unwrap();
    drop(channel);

    let mut channel = link::connect(&panel.address, &panel.fingerprint, Some(&identity))
        .await
        .unwrap();
    let state = session::open(
        &mut channel,
        identity.node_id,
        &paths,
        None,
        OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();

    let key = format!("{:?}", state.cache_key);
    assert!(
        key.contains("redacted"),
        "the key renders itself in full: {key}"
    );

    for entry in std::fs::read_dir(&paths.dir).unwrap() {
        let path = entry.unwrap().path();
        let bytes = std::fs::read(&path).unwrap();
        for candidate in 0u8..=255 {
            let filled = [candidate; 32];
            assert!(
                !bytes.windows(32).any(|window| window == filled),
                "{} holds a run of one repeated byte the length of a key",
                path.display()
            );
        }
        assert!(
            !String::from_utf8_lossy(&bytes).contains("cache_key"),
            "{} names the cache key",
            path.display()
        );
    }
}

#[tokio::test]
async fn a_certificate_others_can_read_is_refused_before_it_is_used() {
    let panel = panel!();
    let node_id = a_node(&panel).await;
    let code = a_code(&panel, node_id).await;
    let paths = agent_dir("exposed");

    let mut channel = link::connect(&panel.address, &panel.fingerprint, None)
        .await
        .unwrap();
    let identity = session::enrol(&mut channel, &code).await.unwrap();
    identity::store(&paths, &identity).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(paths.key(), std::fs::Permissions::from_mode(0o444)).unwrap();
        let outcome = identity::load(&paths);
        assert!(
            matches!(outcome, Err(AgentError::Exposed(_))),
            "a world-readable key was loaded: {outcome:?}"
        );
    }
}

/// An access on this node that the panel will accept telemetry for.
async fn an_access_on(panel: &Panel, node_id: Uuid) -> Uuid {
    use ap_core::{Access, AccessCommon, AnyAccess, Client, Credential, Label, Open, OpenMethod};

    let pool = ap_panel::channel::pool_of(&panel.state);
    let client = Client::new(
        Label::try_from(unique("c").as_str()).unwrap(),
        OffsetDateTime::now_utc(),
    );
    ap_store::ClientRepo::insert(pool, &client, None)
        .await
        .unwrap();

    let common = AccessCommon::new(
        Holder::Client(client.id()),
        node_id,
        OffsetDateTime::now_utc(),
    );
    let access = AnyAccess::Open(Access::<Open>::new(common, OpenMethod::Mtproto));
    let id = access.common().id();
    ap_store::AccessRepo::insert(
        pool,
        &access,
        &Credential::generate_secret(),
        &KeyStore::from_bytes([11u8; 32]),
    )
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn what_the_node_counted_is_what_the_panel_holds() {
    let panel = panel!();
    let node_id = a_node(&panel).await;
    let code = a_code(&panel, node_id).await;
    let paths = agent_dir("counted");
    let access = an_access_on(&panel, node_id).await;

    let mut channel = link::connect(&panel.address, &panel.fingerprint, None)
        .await
        .unwrap();
    let identity = session::enrol(&mut channel, &code).await.unwrap();
    drop(channel);

    let mut channel = link::connect(&panel.address, &panel.fingerprint, Some(&identity))
        .await
        .unwrap();
    let now = OffsetDateTime::now_utc();
    session::open(&mut channel, identity.node_id, &paths, None, now)
        .await
        .unwrap();

    // Two readings of the engine's counters, so the meter has a difference to
    // report rather than a first sighting.
    let mut meter = Meter::new();
    meter.observe(&a_reading(access, 0, 0), now).unwrap();
    meter.observe(&a_reading(access, 4096, 1024), now).unwrap();

    let delivery = meter
        .delivery(
            ap_proto::Health {
                engine: "up".to_owned(),
                site: "unknown".to_owned(),
                cert_not_after: None,
            },
            now,
        )
        .unwrap();
    let sent: i64 = delivery.deltas.iter().map(|delta| delta.bytes_in).sum();
    let sent_out: i64 = delivery.deltas.iter().map(|delta| delta.bytes_out).sum();

    assert!(
        session::deliver(&mut channel, &mut meter, delivery)
            .await
            .unwrap(),
        "the panel did not acknowledge the delivery"
    );
    assert!(
        !meter.waiting(),
        "the meter is still owed an acknowledgement"
    );

    let held = ap_store::TrafficRepo::for_access(ap_panel::channel::pool_of(&panel.state), access)
        .await
        .unwrap();
    assert_eq!(held.bytes_in, sent, "the panel holds a different total");
    assert_eq!(held.bytes_out, sent_out);
}

#[tokio::test]
async fn a_delivery_repeated_after_a_lost_acknowledgement_counts_once() {
    let panel = panel!();
    let node_id = a_node(&panel).await;
    let code = a_code(&panel, node_id).await;
    let paths = agent_dir("repeated");
    let access = an_access_on(&panel, node_id).await;

    let mut channel = link::connect(&panel.address, &panel.fingerprint, None)
        .await
        .unwrap();
    let identity = session::enrol(&mut channel, &code).await.unwrap();
    drop(channel);

    let mut channel = link::connect(&panel.address, &panel.fingerprint, Some(&identity))
        .await
        .unwrap();
    let now = OffsetDateTime::now_utc();
    session::open(&mut channel, identity.node_id, &paths, None, now)
        .await
        .unwrap();

    let mut meter = Meter::new();
    meter.observe(&a_reading(access, 0, 0), now).unwrap();
    meter.observe(&a_reading(access, 2048, 512), now).unwrap();

    let health = ap_proto::Health {
        engine: "up".to_owned(),
        site: "unknown".to_owned(),
        cert_not_after: None,
    };
    let delivery = meter.delivery(health.clone(), now).unwrap();

    // The panel receives it and answers, but the answer never reaches the
    // node: sent, acknowledged, and the meter never told. That is what a lost
    // acknowledgement is.
    channel
        .send(&ap_proto::Message::Telemetry(delivery.clone()))
        .await
        .unwrap();
    let acked = channel.receive().await.unwrap();
    assert!(
        matches!(acked, Some(ap_proto::Message::Ack(_))),
        "the panel did not answer the first delivery"
    );
    assert!(meter.waiting(), "the meter stopped waiting on its own");

    // So the node sends the same delivery again, under the identifier it
    // carried before.
    let again = meter.delivery(health, now).unwrap();
    assert_eq!(again.revision, delivery.revision);
    session::deliver(&mut channel, &mut meter, again)
        .await
        .unwrap();

    let held = ap_store::TrafficRepo::for_access(ap_panel::channel::pool_of(&panel.state), access)
        .await
        .unwrap();
    assert_eq!(held.bytes_in, 2048, "the repeat was counted twice");
    assert_eq!(held.bytes_out, 512);
}

/// A reading of the engine's counters for one access.
fn a_reading(access: Uuid, bytes_in: i64, bytes_out: i64) -> ap_engine::metrics::Reading {
    let mut by_access = std::collections::BTreeMap::new();
    by_access.insert(
        access,
        ap_engine::metrics::Counters {
            bytes_in,
            bytes_out,
            devices: 1,
            connections: 1,
        },
    );
    ap_engine::metrics::Reading {
        by_access,
        unread: 0,
    }
}

#[tokio::test]
async fn a_node_refused_by_the_panel_is_told_why() {
    // A refusal used to be a connection that simply dropped, which is exactly
    // what a panel that is not running looks like. An operator then spends the
    // evening on the network while the panel is up and objecting.
    let panel = panel!();
    let node_id = a_node(&panel).await;
    let access = an_access_on(&panel, node_id).await;
    let code = a_code(&panel, node_id).await;
    let paths = agent_dir("refused");

    let mut channel = link::connect(&panel.address, &panel.fingerprint, None)
        .await
        .unwrap();
    let identity = session::enrol(&mut channel, &code).await.unwrap();
    drop(channel);

    let mut channel = link::connect(&panel.address, &panel.fingerprint, Some(&identity))
        .await
        .unwrap();
    let now = OffsetDateTime::now_utc();
    session::open(&mut channel, identity.node_id, &paths, None, now)
        .await
        .unwrap();

    let telemetry = ap_proto::Telemetry {
        revision: Uuid::now_v7(),
        sent_at: ap_core::time::format_rfc3339(now).unwrap(),
        deltas: vec![ap_proto::TrafficDelta {
            access_id: access,
            // Not a day. Nothing sensible can be done with it, so it is a
            // refusal rather than something to skip and carry on from.
            day: "sometime last week".to_owned(),
            bytes_in: 100,
            bytes_out: 200,
        }],
        devices: Vec::new(),
        health: ap_proto::Health {
            engine: "up".to_owned(),
            site: "unknown".to_owned(),
            cert_not_after: None,
        },
    };

    let mut meter = Meter::new();
    let outcome = session::deliver(&mut channel, &mut meter, telemetry).await;
    let reason = match outcome {
        Err(ap_agent::AgentError::Panel(reason)) => reason,
        other => panic!("the panel did not say why it refused: {other:?}"),
    };
    assert!(
        reason.contains("malformed_day"),
        "the reason does not name what was wrong: {reason}"
    );
}

#[tokio::test]
async fn a_delivery_counts_every_access_it_carries() {
    // The revision names the delivery, not the delta. When only the revision
    // was remembered, the first delta claimed it and the rest of the same
    // delivery were taken for repeats: a node serving three accesses counted
    // one of them, quietly, and every quota it fed was wrong.
    let panel = panel!();
    let node_id = a_node(&panel).await;
    let code = a_code(&panel, node_id).await;
    let paths = agent_dir("every-delta");
    let first = an_access_on(&panel, node_id).await;
    let second = an_access_on(&panel, node_id).await;

    let mut channel = link::connect(&panel.address, &panel.fingerprint, None)
        .await
        .unwrap();
    let identity = session::enrol(&mut channel, &code).await.unwrap();
    drop(channel);

    let mut channel = link::connect(&panel.address, &panel.fingerprint, Some(&identity))
        .await
        .unwrap();
    let now = OffsetDateTime::now_utc();
    session::open(&mut channel, identity.node_id, &paths, None, now)
        .await
        .unwrap();

    let mut before = a_reading(first, 0, 0);
    before
        .by_access
        .insert(second, ap_engine::metrics::Counters::default());
    let mut after = a_reading(first, 4096, 1024);
    after.by_access.insert(
        second,
        ap_engine::metrics::Counters {
            bytes_in: 8192,
            bytes_out: 2048,
            ..Default::default()
        },
    );

    let mut meter = Meter::new();
    meter.observe(&before, now).unwrap();
    meter.observe(&after, now).unwrap();
    let delivery = meter
        .delivery(
            ap_proto::Health {
                engine: "up".to_owned(),
                site: "unknown".to_owned(),
                cert_not_after: None,
            },
            now,
        )
        .unwrap();
    assert_eq!(delivery.deltas.len(), 2, "the meter owes both accesses");

    assert!(
        session::deliver(&mut channel, &mut meter, delivery)
            .await
            .unwrap()
    );

    let pool = ap_panel::channel::pool_of(&panel.state);
    for (access, bytes_in, bytes_out) in [(first, 4096, 1024), (second, 8192, 2048)] {
        let held = ap_store::TrafficRepo::for_access(pool, access)
            .await
            .unwrap();
        assert_eq!(
            (held.bytes_in, held.bytes_out),
            (bytes_in, bytes_out),
            "the panel dropped a delta the delivery carried"
        );
    }
}
