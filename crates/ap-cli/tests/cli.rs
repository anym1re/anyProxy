//! Runs the built binary against a panel it starts for itself.
//!
//! Skipped when DATABASE_URL is absent, so a machine without a database still
//! builds and runs the unit tests. Nothing here reaches the database: the
//! command line speaks to the panel and the panel speaks to the database,
//! which is the point of the change these tests cover.

// An integration test is a separate build target and does not inherit the
// relaxations in clippy.toml. Failing loudly is what a test is for.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn binary(name: &str) -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

fn have_database() -> bool {
    std::env::var("DATABASE_URL").is_ok()
}

fn unique(prefix: &str) -> String {
    // The first half of a version 7 identifier is a millisecond timestamp, so
    // two calls inside one millisecond share it. The second half is random.
    let id = uuid::Uuid::now_v7().simple().to_string();
    format!("{prefix}-{}", &id[16..])
}

/// The key the panel seals with.
///
/// The same file every panel binary in these tests uses: the panel identity in
/// the database is sealed with it, and a panel holding a different key cannot
/// open it — which is the point of sealing it.
fn key_file() -> PathBuf {
    let dir = std::env::temp_dir().join("anyproxy-panel-test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("panel.key");
    if !path.exists() {
        // Assembled beside the target and moved onto it: a binary that saw it
        // before its mode was set would refuse to start.
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

/// Two ports nothing else on this machine is using.
fn free_ports() -> (u16, u16) {
    let held: Vec<_> = (0..2)
        .map(|_| std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap())
        .collect();
    let ports: Vec<u16> = held
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect();
    drop(held);
    (ports[0], ports[1])
}

/// A panel started for one test, and the session the commands use.
struct Panel {
    process: std::process::Child,
    address: String,
    token_file: PathBuf,
}

impl Drop for Panel {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

impl Panel {
    /// Runs one command against this panel, signed in.
    fn run(&self, args: &[&str]) -> Output {
        Command::new(binary("anyproxy"))
            .args(args)
            .env("ANYPROXY_PANEL", &self.address)
            .env("ANYPROXY_TOKEN_FILE", &self.token_file)
            .env_remove("ANYPROXY_TOKEN")
            .output()
            .unwrap()
    }

    /// Runs one command with no session at all.
    fn run_signed_out(&self, args: &[&str]) -> Output {
        Command::new(binary("anyproxy"))
            .args(args)
            .env("ANYPROXY_PANEL", &self.address)
            .env(
                "ANYPROXY_TOKEN_FILE",
                self.token_file.with_extension("absent"),
            )
            .env_remove("ANYPROXY_TOKEN")
            .output()
            .unwrap()
    }
}

fn start_panel() -> Option<Panel> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let (rest_port, channel_port) = free_ports();
    let address = format!("127.0.0.1:{rest_port}");

    let login = unique("a");
    let password = "correct horse battery staple";

    // An administrator to sign in as. The panel makes its own on first
    // sight (0062), but this database has been set up by whatever ran
    // before, so one is made through the library the panel itself uses.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let secret = runtime
        .block_on(async {
            let state =
                ap_panel::AppState::build(&ap_panel::Config::loopback(0, url.clone(), key_file()))
                    .await?;
            ap_panel::create_admin(&state, &login, password, ap_core::Role::Superadmin, true).await
        })
        .expect("the administrator was not created")
        .expect("a second factor was asked for");

    let process = Command::new(binary("anyproxy-panel"))
        .env("DATABASE_URL", &url)
        .env("ANYPROXY_KEY_FILE", key_file())
        .env("ANYPROXY_PANEL_BIND", &address)
        .env("ANYPROXY_CHANNEL_BIND", format!("127.0.0.1:{channel_port}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let token_file = std::env::temp_dir()
        .join("anyproxy-cli-test")
        .join(format!("token-{}", uuid::Uuid::now_v7().simple()));
    let panel = Panel {
        process,
        address,
        token_file,
    };

    for _ in 0..100 {
        if std::net::TcpStream::connect(&panel.address).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // The step that is new: everything below this line needs a session.
    let mut signing_in = Command::new(binary("anyproxy"))
        .arg("login")
        .env("ANYPROXY_PANEL", &panel.address)
        .env("ANYPROXY_TOKEN_FILE", &panel.token_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let typed = format!("{login}\n{password}\n{}\n", code_now(&secret));
    signing_in
        .stdin
        .as_mut()
        .unwrap()
        .write_all(typed.as_bytes())
        .unwrap();
    let signed_in = signing_in.wait_with_output().unwrap();
    assert!(
        signed_in.status.success(),
        "signing in failed: {}",
        String::from_utf8_lossy(&signed_in.stderr)
    );

    Some(panel)
}

macro_rules! panel {
    () => {
        match start_panel() {
            Some(panel) => panel,
            None => return,
        }
    };
}

fn code_now(secret: &str) -> String {
    let bytes = totp_rs::Secret::Encoded(secret.to_owned())
        .to_bytes()
        .unwrap();
    totp_rs::TOTP::new(totp_rs::Algorithm::SHA1, 6, 1, 30, bytes)
        .unwrap()
        .generate_current()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

#[test]
fn the_phase_criterion_reproduces() {
    if !have_database() {
        return;
    }
    let panel = panel!();
    let label = unique("alice");
    let tag = unique("friends");

    assert_eq!(code(&panel.run(&["tag", "add", &tag])), 0);
    let added = panel.run(&[
        "client",
        "add",
        &label,
        "--tag-unused",
        "--quota",
        "50G",
        "--until",
        "2026-12-31",
    ]);
    assert_eq!(code(&added), 2, "an unknown flag is an argument error");

    let added = panel.run(&[
        "client",
        "add",
        &label,
        "--quota",
        "50G",
        "--until",
        "2026-12-31",
    ]);
    assert_eq!(
        code(&added),
        0,
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );

    let shown = panel.run(&["client", "show", &label]);
    assert_eq!(code(&shown), 0);
    assert!(
        stdout(&shown).contains("2026-12-31T23:59:59Z"),
        "expiry missing from:\n{}",
        stdout(&shown)
    );

    let english = panel.run(&["--locale", "en", "client", "show", &label]);
    let russian = panel.run(&["--locale", "ru", "client", "show", &label]);
    assert!(stdout(&english).contains("2026-12-31T23:59:59Z"));
    assert!(stdout(&russian).contains("2026-12-31T23:59:59Z"));
    assert_ne!(
        stdout(&english),
        stdout(&russian),
        "both languages produced identical output"
    );
}

#[test]
fn a_missing_client_reports_not_found() {
    if !have_database() {
        return;
    }
    let panel = panel!();
    let output = panel.run(&["client", "show", &unique("absent")]);
    assert_eq!(code(&output), 3);
}

#[test]
fn json_output_carries_no_secret() {
    if !have_database() {
        return;
    }
    let panel = panel!();
    let label = unique("bob");
    assert_eq!(code(&panel.run(&["client", "add", &label])), 0);
    let node = unique("node");
    assert_eq!(
        code(&panel.run(&["node", "add", &node, "--kind", "mtproto"])),
        0
    );
    assert_eq!(
        code(&panel.run(&[
            "access", "add", &label, "--node", &node, "--method", "mtproto"
        ])),
        0
    );

    let shown = panel.run(&["--format", "json", "client", "show", &label]);
    assert_eq!(code(&shown), 0);
    let text = stdout(&shown);
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["label"], label.as_str());
    for forbidden in ["secret", "credential", "pass", "password"] {
        assert!(
            !text.to_lowercase().contains(forbidden),
            "{forbidden} appeared in json output"
        );
    }
}

#[test]
fn a_method_the_node_does_not_serve_is_refused() {
    if !have_database() {
        return;
    }
    let panel = panel!();
    let label = unique("carol");
    assert_eq!(code(&panel.run(&["client", "add", &label])), 0);
    let node = unique("cover");
    let domain = format!("{}.example.com", unique("d"));
    assert_eq!(
        code(&panel.run(&[
            "node", "add", &node, "--kind", "mtproto", "--masked", "--domain", &domain
        ])),
        0
    );

    let refused = panel.run(&[
        "access", "add", &label, "--node", &node, "--method", "socks5",
    ]);
    assert_eq!(
        code(&refused),
        2,
        "socks5 was accepted on a stealth node: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
}

#[test]
fn a_link_is_not_printed_without_acknowledgement() {
    if !have_database() {
        return;
    }
    let panel = panel!();
    let label = unique("dave");
    assert_eq!(code(&panel.run(&["client", "add", &label])), 0);
    let node = unique("node");
    assert_eq!(
        code(&panel.run(&["node", "add", &node, "--kind", "mtproto"])),
        0
    );
    assert_eq!(
        code(&panel.run(&[
            "access", "add", &label, "--node", &node, "--method", "mtproto"
        ])),
        0
    );

    let listed = panel.run(&["--format", "json", "access", "list", &label]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&listed)).unwrap();
    let id = parsed[0]["id"].as_str().unwrap().to_owned();

    let refused = panel.run(&["access", "link", &id, "--host", "203.0.113.7"]);
    assert_eq!(code(&refused), 2);
    assert!(stdout(&refused).is_empty());

    let printed = panel.run(&["access", "link", &id, "--host", "203.0.113.7", "--yes"]);
    assert_eq!(
        code(&printed),
        0,
        "{}",
        String::from_utf8_lossy(&printed.stderr)
    );
    assert!(stdout(&printed).starts_with("https://t.me/proxy?server=203.0.113.7"));
}

#[test]
fn a_bad_size_is_an_argument_error() {
    if !have_database() {
        return;
    }
    let panel = panel!();
    let output = panel.run(&["client", "add", &unique("eve"), "--quota", "50"]);
    assert_eq!(code(&output), 2);
}

#[test]
fn without_a_session_nothing_is_read() {
    if !have_database() {
        return;
    }
    let panel = panel!();
    let output = panel.run_signed_out(&["client", "list"]);

    assert_eq!(code(&output), 1, "an unauthenticated read was allowed");
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        !said.contains("unauthenticated"),
        "the panel's code was printed raw: {said}"
    );
}

#[test]
fn a_password_given_as_an_argument_is_not_a_way_in() {
    if !have_database() {
        return;
    }
    let panel = panel!();
    // There is no flag to carry it: an argument reaches the shell history and
    // the process list.
    let output = panel.run(&["login", "--password", "correct horse battery staple"]);
    assert_eq!(code(&output), 2, "a password flag was accepted");
}

#[test]
fn adding_a_node_shows_its_enrolment_code_once() {
    if !have_database() {
        return;
    }
    let panel = panel!();
    let node = unique("edge");

    let added = panel.run(&["node", "add", &node, "--kind", "mtproto"]);
    assert_eq!(
        code(&added),
        0,
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    let printed = stdout(&added);
    assert!(
        printed.contains("anyproxy-agent enroll"),
        "no command to run on the node:\n{printed}"
    );

    // The code the operator carries to the node. It is sixteen bytes as
    // hexadecimal, and it appears here and nowhere else.
    let code_line = printed
        .lines()
        .find(|line| line.contains("enrol"))
        .expect("a line carrying the code");
    let enrolment: String = code_line
        .split_whitespace()
        .find(|word| word.len() == 32 && word.chars().all(|c| c.is_ascii_hexdigit()))
        .expect("a code in the line")
        .to_owned();

    let listed = panel.run(&["--format", "json", "node", "list"]);
    assert!(
        !stdout(&listed).contains(&enrolment),
        "the code came back on a later reading"
    );
}

#[test]
fn a_node_is_given_the_address_clients_reach_it_at() {
    if !have_database() {
        return;
    }
    let panel = panel!();
    let node = unique("edge");
    assert_eq!(
        code(&panel.run(&["node", "add", &node, "--kind", "mtproto"])),
        0
    );

    let neither = panel.run(&["node", "address", &node]);
    assert_eq!(
        code(&neither),
        2,
        "an address command with nothing to do ran"
    );

    let refused = panel.run(&["node", "address", &node, "not-an-address"]);
    assert_ne!(code(&refused), 0, "a word was taken for an address");

    let set = panel.run(&["node", "address", &node, "203.0.113.42"]);
    assert_eq!(code(&set), 0, "{}", String::from_utf8_lossy(&set.stderr));
    let listed = stdout(&panel.run(&["--format", "json", "node", "list"]));
    assert!(
        listed.contains("\"address\":\"203.0.113.42\"")
            || listed.contains("\"address\": \"203.0.113.42\""),
        "the address is not on the node: {listed}"
    );

    let cleared = panel.run(&["node", "address", &node, "--clear"]);
    assert_eq!(code(&cleared), 0);
}

#[cfg(unix)]
#[test]
fn a_token_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    if !have_database() {
        return;
    }
    let panel = panel!();
    std::fs::set_permissions(&panel.token_file, std::fs::Permissions::from_mode(0o444)).unwrap();

    let output = panel.run(&["client", "list"]);
    assert_eq!(code(&output), 1, "a world-readable token was used");

    #[cfg(unix)]
    std::fs::set_permissions(&panel.token_file, std::fs::Permissions::from_mode(0o400)).unwrap();
}

#[cfg(unix)]
#[test]
fn the_token_is_kept_readable_by_its_owner_alone() {
    use std::os::unix::fs::PermissionsExt;

    if !have_database() {
        return;
    }
    let panel = panel!();
    let mode = std::fs::metadata(&panel.token_file)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o400);
}
