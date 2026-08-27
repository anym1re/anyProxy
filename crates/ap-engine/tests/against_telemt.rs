//! The engine control against a real telemt.
//!
//! Skipped unless ANYPROXY_TELEMT names the binary, so a machine without it
//! still builds and runs the unit tests. The binary is the one the pin names;
//! `scripts/fetch-telemt.sh` puts it in place and checks the digest.

// An integration test is a separate build target and does not inherit the
// relaxations in clippy.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::time::Duration;

use ap_engine::config::{self, Settings};
use ap_engine::control::Control;
use ap_proto::{Config, Listener, NodeShape, Policy, WireAccess, WireCredential};
use uuid::Uuid;

/// A telemt started for one test and killed after it.
struct Engine {
    child: std::process::Child,
    control: Control,
    metrics_port: u16,
    #[allow(dead_code)]
    dir: PathBuf,
}

impl Engine {
    fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn binary() -> Option<PathBuf> {
    std::env::var("ANYPROXY_TELEMT").ok().map(PathBuf::from)
}

/// Three ports nothing else on this machine is using.
fn free_ports() -> (u16, u16, u16) {
    let mut taken = Vec::new();
    let mut ports = Vec::new();
    for _ in 0..3 {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        ports.push(listener.local_addr().unwrap().port());
        taken.push(listener);
    }
    drop(taken);
    (ports[0], ports[1], ports[2])
}

/// Sixteen bytes as the wire carries them.
///
/// Built rather than written out: a literal of this shape is what a real
/// client secret looks like, and the secret scanner is right to stop one from
/// being committed.
fn a_secret(byte: u8) -> String {
    hex::encode([byte; 16])
}

fn an_access() -> WireAccess {
    WireAccess {
        id: Uuid::now_v7(),
        method: "faketls".to_owned(),
        credential: WireCredential::Secret {
            hex: a_secret(0x11),
        },
        max_devices: Some(3),
        state: "active".to_owned(),
    }
}

fn a_config(port: u16, accesses: Vec<WireAccess>) -> Config {
    Config {
        revision: Uuid::now_v7(),
        issued_at: "2026-08-26T10:00:00Z".to_owned(),
        node: NodeShape {
            kind: "stealth".to_owned(),
            domain: Some("cover.example.com".to_owned()),
        },
        listeners: vec![Listener {
            method: "faketls".to_owned(),
            bind: format!("127.0.0.1:{port}"),
        }],
        accesses,
        policy: Policy {
            log_level: "quiet".to_owned(),
            carrier_mode: "https".to_owned(),
        },
    }
}

async fn start(accesses: Vec<WireAccess>) -> Option<Engine> {
    let binary = binary()?;
    let (api_port, metrics_port, listen_port) = free_ports();

    let dir = std::env::temp_dir().join(format!("anyproxy-engine-{}", Uuid::now_v7().simple()));
    std::fs::create_dir_all(&dir).unwrap();

    let settings = Settings {
        api_port,
        metrics_port,
        api_token: "Bearer test-token".to_owned(),
        data_path: dir.join("state").display().to_string(),
        // This host cannot reach Telegram's middle proxies, and waiting on
        // them would make every test here a test of the network.
        middle_proxy: false,
        mask_host: "www.cloudflare.com".to_owned(),
    };
    std::fs::create_dir_all(dir.join("state")).unwrap();

    let rendered = config::render(&a_config(listen_port, accesses), &settings).unwrap();
    let config_path = dir.join("telemt.toml");
    std::fs::write(&config_path, &rendered).unwrap();

    let child = std::process::Command::new(&binary)
        .arg("run")
        .arg(&config_path)
        .arg("--silent")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("{}: {error}", binary.display()));

    let control = Control::new(api_port, settings.api_token.clone());
    let engine = Engine {
        child,
        control,
        metrics_port,
        dir,
    };

    // The engine reaches out to Telegram while starting, so give it room.
    for _ in 0..100 {
        if engine.control.health().await.unwrap_or(false) {
            return Some(engine);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("the engine did not answer within twenty seconds");
}

macro_rules! engine {
    ($accesses:expr) => {
        match start($accesses).await {
            Some(engine) => engine,
            None => return,
        }
    };
}

#[tokio::test]
async fn a_rendered_configuration_starts_the_engine() {
    let access = an_access();
    let engine = engine!(vec![access.clone()]);

    assert!(engine.control.health().await.unwrap());

    let info = engine.control.system_info().await.unwrap();
    assert!(
        info.get("version").is_some() || info.get("build").is_some(),
        "the engine said nothing about itself: {info}"
    );
}

#[tokio::test]
async fn an_access_becomes_a_user_the_engine_knows() {
    let access = an_access();
    let engine = engine!(vec![access.clone()]);

    let users = engine.control.users().await.unwrap();
    let listed = users.to_string();
    assert!(
        listed.contains(&config::user_of(access.id)),
        "the access is not among the users: {listed}"
    );
}

#[tokio::test]
async fn applying_a_change_reaches_the_running_engine_without_restarting_it() {
    let engine = engine!(vec![an_access()]);
    let before = engine.pid();

    let added = an_access();
    let name = config::user_of(added.id);
    let reply = engine
        .control
        .create_user(&name, &a_secret(0x22))
        .await
        .unwrap();
    // The engine answers 202 when it has taken the change and submitted a
    // reload of its own, which is the usual outcome.
    assert!(
        matches!(reply.status, 200..=202),
        "creating a user was refused: {} {}",
        reply.status,
        reply.body
    );

    // On disk is not enough. The user has to appear in the generation that is
    // actually serving, which is what `in_runtime` says.
    assert!(
        in_runtime(&engine, &name).await,
        "the user never reached the running engine"
    );

    assert!(engine.control.health().await.unwrap());
    assert_eq!(before, engine.pid(), "the engine was restarted");
}

/// Waits for one user to appear in the generation that is serving.
async fn in_runtime(engine: &Engine, username: &str) -> bool {
    for _ in 0..100 {
        let users = engine
            .control
            .users()
            .await
            .unwrap_or(serde_json::Value::Null);
        let found = users
            .as_array()
            .into_iter()
            .flatten()
            .find(|user| user.get("username").and_then(|name| name.as_str()) == Some(username));
        if let Some(user) = found
            && user.get("in_runtime").and_then(|flag| flag.as_bool()) == Some(true)
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

#[tokio::test]
async fn a_disabled_user_stops_being_served_without_a_restart() {
    let access = an_access();
    let engine = engine!(vec![access.clone()]);
    let before = engine.pid();

    let name = config::user_of(access.id);
    let reply = engine.control.disable_user(&name).await.unwrap();
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(before, engine.pid());

    let reply = engine.control.enable_user(&name).await.unwrap();
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(before, engine.pid());
}

#[tokio::test]
async fn the_engine_reports_its_configuration_with_a_revision() {
    let engine = engine!(vec![an_access()]);

    let reply = engine.control.config().await.unwrap();
    assert_eq!(reply.status, 200, "{}", reply.body);
    let revision = reply.revision().expect("a revision");
    assert_eq!(revision.len(), 64, "the revision is not a digest");

    // The users are never in the configuration the API returns.
    let data = reply.data().unwrap().to_string();
    assert!(!data.contains("access"), "the users came back with it");
}

#[tokio::test]
async fn a_patch_naming_the_users_is_refused_rather_than_half_applied() {
    let engine = engine!(vec![an_access()]);
    let before = engine.pid();

    let patch = serde_json::json!({ "access": { "users": { "someone": "00" } } });
    let reply = engine.control.patch_config(&patch, None).await.unwrap();
    assert_eq!(reply.status, 400, "{}", reply.body);
    assert!(reply.body.contains("access_not_editable"), "{}", reply.body);

    assert!(engine.control.health().await.unwrap());
    assert_eq!(before, engine.pid());
}

#[tokio::test]
async fn the_metrics_carry_the_access_the_panel_named() {
    let access = an_access();
    let engine = engine!(vec![access.clone()]);

    let body = engine.control.metrics(engine.metrics_port).await.unwrap();
    let reading = ap_engine::metrics::read(&body);

    // Nothing has connected, so the counters are zero; what matters is that
    // the access is named at all, which is what attribution rests on.
    assert!(
        body.contains(&config::user_of(access.id)),
        "the metrics do not mention the access"
    );
    assert_eq!(reading.unread, 0, "the metrics did not parse cleanly");
}

#[tokio::test]
async fn the_control_api_and_the_metrics_are_not_reachable_from_outside() {
    let engine = engine!(vec![an_access()]);

    // Same machine, but by an address that is not loopback. A listener bound
    // to loopback does not answer here; one bound to every address would.
    let Some(outward) = an_outward_address() else {
        return;
    };
    for port in [engine.control.address().port(), engine.metrics_port] {
        let outcome = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::TcpStream::connect((outward, port)),
        )
        .await;
        assert!(
            matches!(outcome, Ok(Err(_)) | Err(_)),
            "port {port} answered on {outward}"
        );
    }
}

#[tokio::test]
async fn reading_the_configuration_again_does_not_restart_the_process() {
    let engine = engine!(vec![an_access()]);
    let before = engine.pid();

    // The way a setting the control API will not edit is changed: rewrite the
    // file and ask the engine to read it. The WEB carrier is the one that
    // matters, and telemt gives a new carrier only to sessions issued after
    // the swap, so what is already established is not disturbed.
    let reply = engine.control.reload().await.unwrap();
    assert!(
        matches!(reply.status, 200 | 202),
        "the engine refused to reload: {} {}",
        reply.status,
        reply.body
    );

    assert!(engine.control.health().await.unwrap());
    assert_eq!(before, engine.pid(), "the engine was restarted");
}

#[tokio::test]
async fn a_health_report_says_the_engine_is_up_while_it_is() {
    let engine = engine!(vec![an_access()]);

    let health = ap_engine::health::report(&engine.control, ap_engine::health::Site::Unknown, None)
        .await
        .unwrap();
    assert_eq!(health.engine, "up");
    assert_eq!(health.site, "unknown");
}

/// An address of this machine that is not loopback, when it has one.
fn an_outward_address() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    socket.connect(("192.0.2.1", 9)).ok()?;
    let address = socket.local_addr().ok()?.ip();
    (!address.is_loopback()).then_some(address)
}
