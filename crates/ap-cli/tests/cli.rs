//! Runs the built binary. Skipped when DATABASE_URL is absent, so a machine
//! without a database still builds and runs the unit tests.

// An integration test is a separate build target and does not inherit the
// relaxations in clippy.toml. Failing loudly is what a test is for.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn binary() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join(format!("anyproxy{}", std::env::consts::EXE_SUFFIX))
}

fn key_file() -> PathBuf {
    let dir = std::env::temp_dir().join("anyproxy-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("panel.key");
    if !path.exists() {
        std::fs::write(&path, [5u8; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
    }
    path
}

fn run(args: &[&str]) -> Output {
    let url = std::env::var("DATABASE_URL").unwrap();
    Command::new(binary())
        .args(args)
        .env("DATABASE_URL", url)
        .env("ANYPROXY_KEY_FILE", key_file())
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn have_database() -> bool {
    std::env::var("DATABASE_URL").is_ok()
}

fn unique(prefix: &str) -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{}", stamp % 1_000_000_000)
}

#[test]
fn the_phase_criterion_reproduces() {
    if !have_database() {
        return;
    }
    let label = unique("alice");
    let tag = unique("friends");

    assert_eq!(code(&run(&["tag", "add", &tag])), 0);
    let added = run(&[
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

    let added = run(&[
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

    let shown = run(&["client", "show", &label]);
    assert_eq!(code(&shown), 0);
    assert!(
        stdout(&shown).contains("2026-12-31T23:59:59Z"),
        "expiry missing from:\n{}",
        stdout(&shown)
    );

    let english = run(&["--locale", "en", "client", "show", &label]);
    let russian = run(&["--locale", "ru", "client", "show", &label]);
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
    let output = run(&["client", "show", &unique("absent")]);
    assert_eq!(code(&output), 3);
}

#[test]
fn json_output_carries_no_secret() {
    if !have_database() {
        return;
    }
    let label = unique("bob");
    assert_eq!(code(&run(&["client", "add", &label])), 0);
    let node = unique("node");
    assert_eq!(code(&run(&["node", "add", &node, "--kind", "open"])), 0);
    assert_eq!(
        code(&run(&[
            "access", "add", &label, "--node", &node, "--method", "mtproto"
        ])),
        0
    );

    let shown = run(&["--format", "json", "client", "show", &label]);
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
fn a_method_the_node_does_not_serve_is_refused_before_the_database() {
    if !have_database() {
        return;
    }
    let label = unique("carol");
    assert_eq!(code(&run(&["client", "add", &label])), 0);
    let node = unique("cover");
    let domain = format!("{}.example.com", unique("d"));
    assert_eq!(
        code(&run(&[
            "node", "add", &node, "--kind", "stealth", "--domain", &domain
        ])),
        0
    );

    let refused = run(&[
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
    let label = unique("dave");
    assert_eq!(code(&run(&["client", "add", &label])), 0);
    let node = unique("node");
    assert_eq!(code(&run(&["node", "add", &node, "--kind", "open"])), 0);
    assert_eq!(
        code(&run(&[
            "access", "add", &label, "--node", &node, "--method", "mtproto"
        ])),
        0
    );

    let listed = run(&["--format", "json", "access", "list", &label]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&listed)).unwrap();
    let id = parsed[0]["id"].as_str().unwrap().to_owned();

    let refused = run(&["access", "link", &id, "--host", "203.0.113.7"]);
    assert_eq!(code(&refused), 2);
    assert!(stdout(&refused).is_empty());

    let printed = run(&["access", "link", &id, "--host", "203.0.113.7", "--yes"]);
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
    let output = run(&["client", "add", &unique("eve"), "--quota", "50"]);
    assert_eq!(code(&output), 2);
}
