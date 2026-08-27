//! A client that really connects.
//!
//! Everything else about the engine is checked through its control API, which
//! says what it believes about itself. This says what it does: an obfuscated
//! MTProto client performs the handshake the protocol actually specifies, and
//! the engine's own counters move for the access it authenticated as.
//!
//! Skipped unless ANYPROXY_TELEMT names the binary.

// An integration test is a separate build target and does not inherit the
// relaxations in clippy.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use aes::cipher::{KeyIvInit, StreamCipher};
use ap_engine::config::{self, Settings};
use ap_engine::control::Control;
use ap_proto::{Config, Listener, NodeShape, Policy, WireAccess, WireCredential};
use sha2::{Digest, Sha256};
use uuid::Uuid;

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// The tag that selects the padded intermediate transport.
///
/// Chosen over the abridged one because every frame carries its own length,
/// which is what lets a test send something and know it was framed correctly
/// rather than hoping.
const PADDED_INTERMEDIATE: [u8; 4] = [0xdd, 0xdd, 0xdd, 0xdd];

fn binary() -> Option<PathBuf> {
    std::env::var("ANYPROXY_TELEMT").ok().map(PathBuf::from)
}

fn a_secret(byte: u8) -> String {
    hex::encode([byte; 16])
}

/// The sixty-four bytes an obfuscated client opens with.
///
/// The first fifty-six travel in the clear and carry the keys; the last eight
/// travel encrypted and carry the transport tag, which is what proves to the
/// server that the keys were derived the same way.
fn handshake(secret: &[u8; 16]) -> ([u8; 64], Aes256Ctr, Aes256Ctr) {
    use rand::RngCore as _;

    let mut init = [0u8; 64];
    loop {
        rand::rng().fill_bytes(&mut init);
        if init[0] == 0xef {
            continue;
        }
        let first = u32::from_le_bytes([init[0], init[1], init[2], init[3]]);
        // Four-byte openings the server reads as something other than this
        // protocol: HEAD, POST, GET and OPTIONS, and two reserved values.
        if matches!(
            first,
            0x4854_5450 | 0x5453_4f50 | 0x2054_4547 | 0x4954_504f | 0xdddd_dddd | 0xeeee_eeee
        ) {
            continue;
        }
        if init[4..8] == [0, 0, 0, 0] {
            continue;
        }
        break;
    }
    init[56..60].copy_from_slice(&PADDED_INTERMEDIATE);

    let mut reversed = init;
    reversed[8..56].reverse();

    let mut encrypt = derive(&init[8..40], &init[40..56], secret);
    let decrypt = derive(&reversed[8..40], &reversed[40..56], secret);

    // The whole opening is encrypted, and the same cipher goes on from where
    // that left it: the server decrypts those sixty-four bytes with its own
    // and reads the stream from the same point. A cipher started again at zero
    // here produces a handshake that looks right and a stream that does not.
    let mut whole = init;
    encrypt.apply_keystream(&mut whole);

    // The keys travel in the clear; only the tail, which carries the tag, is
    // sent as it was encrypted.
    let mut sent = init;
    sent[56..64].copy_from_slice(&whole[56..64]);

    (sent, encrypt, decrypt)
}

/// The key a side uses, folded together with the access secret.
fn derive(key: &[u8], iv: &[u8], secret: &[u8; 16]) -> Aes256Ctr {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(secret);
    let key = hasher.finalize();
    Aes256Ctr::new(&key, iv.into())
}

/// A node serving one access on a port the operating system chose.
struct Node {
    child: std::process::Child,
    control: Control,
    metrics_port: u16,
    proxy_port: u16,
    access: Uuid,
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_ports() -> (u16, u16, u16) {
    let held: Vec<_> = (0..3)
        .map(|_| std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap())
        .collect();
    let ports: Vec<u16> = held
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect();
    drop(held);
    (ports[0], ports[1], ports[2])
}

fn start() -> Option<Node> {
    let binary = binary()?;
    let (api_port, metrics_port, proxy_port) = free_ports();
    let access = Uuid::now_v7();

    let dir = std::env::temp_dir().join(format!("anyproxy-client-{}", Uuid::now_v7().simple()));
    std::fs::create_dir_all(dir.join("state")).unwrap();

    let settings = Settings {
        api_port,
        metrics_port,
        api_token: "Bearer client-test".to_owned(),
        data_path: dir.join("state").display().to_string(),
        // Direct to the data centres. What is being checked is that the node
        // authenticates a client and counts what it sent, not that this host
        // has a route to Telegram's middle proxies.
        middle_proxy: false,
        mask_host: "www.cloudflare.com".to_owned(),
    };

    let config = Config {
        revision: Uuid::now_v7(),
        issued_at: "2026-08-27T00:00:00Z".to_owned(),
        node: NodeShape {
            kind: "open".to_owned(),
            domain: None,
        },
        listeners: vec![Listener {
            method: "mtproto".to_owned(),
            bind: format!("127.0.0.1:{proxy_port}"),
        }],
        accesses: vec![WireAccess {
            id: access,
            method: "mtproto".to_owned(),
            credential: WireCredential::Secret {
                hex: a_secret(0x2a),
            },
            max_devices: None,
            state: "active".to_owned(),
        }],
        policy: Policy {
            log_level: "quiet".to_owned(),
            carrier_mode: "https".to_owned(),
        },
    };

    let rendered = config::render(&config, &settings).unwrap();
    let path = dir.join("telemt.toml");
    std::fs::write(&path, &rendered).unwrap();

    let child = std::process::Command::new(&binary)
        .arg("run")
        .arg(&path)
        .arg("--silent")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let node = Node {
        child,
        control: Control::new(api_port, settings.api_token.clone()),
        metrics_port,
        proxy_port,
        access,
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for _ in 0..150 {
        if runtime.block_on(node.control.health()).unwrap_or(false)
            && TcpStream::connect(("127.0.0.1", proxy_port)).is_ok()
        {
            return Some(node);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("the node did not come up within thirty seconds");
}

macro_rules! node {
    () => {
        match start() {
            Some(node) => node,
            None => return,
        }
    };
}

/// Reads the engine's counters for one access.
fn counters(node: &Node) -> ap_engine::metrics::Counters {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let body = runtime
        .block_on(node.control.metrics(node.metrics_port))
        .unwrap_or_default();
    ap_engine::metrics::read(&body)
        .by_access
        .get(&node.access)
        .copied()
        .unwrap_or_default()
}

#[test]
fn a_client_that_knows_the_secret_is_served_and_counted() {
    let node = node!();
    let before = counters(&node);

    let mut secret = [0u8; 16];
    secret.copy_from_slice(&hex::decode(a_secret(0x2a)).unwrap());
    let (opening, mut encrypt, _decrypt) = handshake(&secret);

    let mut stream = TcpStream::connect(("127.0.0.1", node.proxy_port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(&opening).unwrap();

    // One frame of the padded intermediate transport: a length, then that many
    // bytes. What is inside does not matter here; that the node accepted the
    // handshake and read the frame does.
    let payload = [0u8; 64];
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    encrypt.apply_keystream(&mut frame);
    stream.write_all(&frame).unwrap();
    stream.flush().unwrap();

    // Give the engine a moment to account for it.
    let mut after = before;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(200));
        after = counters(&node);
        if after.bytes_out > before.bytes_out {
            break;
        }
    }

    assert!(
        after.bytes_out > before.bytes_out,
        "the node counted nothing from a client it authenticated: {before:?} -> {after:?}"
    );
    assert!(
        after.connections >= 1 || after.bytes_out > 0,
        "the node did not see a connection: {after:?}"
    );

    // And it is counted against the access the panel issued, not against
    // anything else.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let body = runtime
        .block_on(node.control.metrics(node.metrics_port))
        .unwrap();
    assert!(
        body.contains(&config::user_of(node.access)),
        "the metrics do not name the access"
    );
}

#[test]
fn a_client_that_does_not_know_the_secret_is_not_served() {
    let node = node!();
    let before = counters(&node);

    // The same protocol, a secret nobody granted.
    let mut wrong = [0u8; 16];
    wrong.copy_from_slice(&hex::decode(a_secret(0x99)).unwrap());
    let (opening, mut encrypt, _) = handshake(&wrong);

    let mut stream = TcpStream::connect(("127.0.0.1", node.proxy_port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(&opening).unwrap();
    let mut frame = vec![64u8, 0, 0, 0];
    frame.extend_from_slice(&[0u8; 64]);
    encrypt.apply_keystream(&mut frame);
    let _ = stream.write_all(&frame);
    let _ = stream.flush();

    std::thread::sleep(Duration::from_secs(3));
    let after = counters(&node);
    assert_eq!(
        after.bytes_out, before.bytes_out,
        "traffic was counted for a secret nobody granted"
    );
    assert_eq!(
        after.connections, before.connections,
        "a connection nobody authenticated was counted as one"
    );

    // Whether the node answers at all is not the point, and silence would be
    // the wrong answer: an unauthenticated connection is relayed to the site
    // the node imitates, which is what makes a probe see an ordinary server.
    // What must not happen is that any of it lands on somebody's access.
    let mut answer = [0u8; 1];
    let _ = stream.read(&mut answer);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let body = runtime
        .block_on(node.control.metrics(node.metrics_port))
        .unwrap_or_default();
    let reading = ap_engine::metrics::read(&body);
    assert!(
        reading
            .by_access
            .get(&node.access)
            .map(|counted| counted.bytes_out == before.bytes_out)
            .unwrap_or(true),
        "a client with the wrong secret moved the access it was not granted"
    );
}
