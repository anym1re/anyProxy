use std::fmt::Write as _;

use ap_proto::{Config, WireCredential};

use crate::EngineError;

/// What the node decides for itself, rather than the panel.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Port the control API answers on.
    ///
    /// A port and not an address: the address is always loopback, so a control
    /// API reachable from outside the node cannot be configured by mistake
    /// or by a panel that has been taken over.
    pub api_port: u16,
    /// Port the metrics answer on. Loopback for the same reason.
    pub metrics_port: u16,
    /// Value the control API expects in `Authorization`.
    pub api_token: String,
    /// Where telemt keeps its own state.
    pub data_path: String,
    /// Whether to route through Telegram's middle proxies.
    ///
    /// A sponsored channel needs them. A node that cannot reach them falls
    /// back to routing to the data centres directly, and a test host has no
    /// business waiting on them at all.
    pub middle_proxy: bool,
}

/// The address every listener the node talks to itself on is bound to.
const LOOPBACK: &str = "127.0.0.1";

/// Renders the configuration telemt reads.
///
/// Two things are never taken from the panel: the addresses of the control API
/// and of the metrics. They are written here, always on loopback.
pub fn render(config: &Config, settings: &Settings) -> Result<String, EngineError> {
    let mut out = String::new();

    // Both of these live under [general]. Written at the top level telemt
    // discards them with a warning and carries on with its own defaults.
    writeln!(out, "[general]").ok();
    writeln!(out, "data_path = \"{}\"", settings.data_path).ok();
    writeln!(out, "config_strict = true").ok();
    writeln!(out, "use_middle_proxy = {}", settings.middle_proxy).ok();
    writeln!(out, "ad_tag = \"{}\"", ad_tag(config)).ok();
    writeln!(out).ok();

    writeln!(out, "[general.telemetry]").ok();
    writeln!(out, "core_enabled = true").ok();
    writeln!(out, "user_enabled = true").ok();
    writeln!(out).ok();

    writeln!(out, "[server]").ok();
    writeln!(
        out,
        "metrics_listen = \"{LOOPBACK}:{}\"",
        settings.metrics_port
    )
    .ok();
    writeln!(out, "metrics_whitelist = [\"127.0.0.1/32\", \"::1/128\"]").ok();
    writeln!(out).ok();

    writeln!(out, "[server.api]").ok();
    writeln!(out, "enabled = true").ok();
    writeln!(out, "listen = \"{LOOPBACK}:{}\"", settings.api_port).ok();
    writeln!(out, "whitelist = [\"127.0.0.1/32\", \"::1/128\"]").ok();
    writeln!(out, "auth_header = \"{}\"", settings.api_token).ok();
    writeln!(out, "read_only = false").ok();
    writeln!(out).ok();

    for listener in &config.listeners {
        let (ip, port) = split_bind(&listener.bind)?;
        writeln!(out, "[[server.listeners]]").ok();
        writeln!(out, "ip = \"{ip}\"").ok();
        writeln!(out, "port = {port}").ok();
        writeln!(out, "transport = \"{}\"", transport(&listener.method)?).ok();
        writeln!(out).ok();
    }

    if config.listeners.iter().any(|listener| {
        transport(&listener.method)
            .map(|t| t == "web")
            .unwrap_or(false)
    }) {
        writeln!(out, "[web]").ok();
        writeln!(out, "enabled = true").ok();
        writeln!(
            out,
            "carrier = \"{}\"",
            carrier(&config.policy.carrier_mode)?
        )
        .ok();
        writeln!(out).ok();
    }

    render_access(&mut out, config)?;
    Ok(out)
}

/// The `[access]` tables: who may connect and under what limits.
fn render_access(out: &mut String, config: &Config) -> Result<(), EngineError> {
    writeln!(out, "[access.users]").ok();
    let mut any = false;
    for access in &config.accesses {
        let WireCredential::Secret { hex } = &access.credential else {
            // A login belongs to SOCKS5 or HTTP, which never share a machine
            // with this engine. Reaching here means the panel sent a node's
            // configuration to the wrong kind of node.
            return Err(EngineError::Refused(format!(
                "access {} carries a login, which this engine does not serve",
                access.id
            )));
        };
        if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(EngineError::Refused(format!(
                "access {} carries a secret that is not sixteen bytes",
                access.id
            )));
        }
        writeln!(out, "{} = \"{hex}\"", user_of(access.id)).ok();
        any = true;
    }
    if !any {
        // telemt refuses a configuration with no users at all. A node with
        // nothing to serve gets one that authenticates nobody.
        writeln!(out, "{} = \"{}\"", NOBODY, "0".repeat(32)).ok();
    }
    writeln!(out).ok();

    let disabled: Vec<_> = config
        .accesses
        .iter()
        .filter(|access| access.state != "active")
        .collect();
    if !disabled.is_empty() {
        writeln!(out, "[access.user_enabled]").ok();
        for access in disabled {
            writeln!(out, "{} = false", user_of(access.id)).ok();
        }
        writeln!(out).ok();
    }

    let limited: Vec<_> = config
        .accesses
        .iter()
        .filter_map(|access| access.max_devices.map(|devices| (access.id, devices)))
        .collect();
    if !limited.is_empty() {
        writeln!(out, "[access.user_max_unique_ips]").ok();
        for (id, devices) in limited {
            writeln!(out, "{} = {devices}", user_of(id)).ok();
        }
        writeln!(out).ok();
    }
    Ok(())
}

/// The user a node with nothing to serve is configured with.
const NOBODY: &str = "nobody";

/// The name one access answers to inside the engine.
///
/// The identifier itself, so a counter the engine reports is attributed
/// without a table in between.
pub fn user_of(access_id: uuid::Uuid) -> String {
    access_id.simple().to_string()
}

/// The access a name the engine reported belongs to.
pub fn access_of(user: &str) -> Option<uuid::Uuid> {
    uuid::Uuid::parse_str(user).ok()
}

/// The sponsored-channel tag, or none at all.
fn ad_tag(config: &Config) -> String {
    let _ = config;
    "0".repeat(32)
}

/// Which telemt transport serves one of our methods.
fn transport(method: &str) -> Result<&'static str, EngineError> {
    match method {
        "faketls" | "mtproto" => Ok("mtproxy"),
        "web" => Ok("web"),
        other => Err(EngineError::Refused(format!(
            "this engine does not serve {other}"
        ))),
    }
}

/// The carrier a WEB listener uses.
fn carrier(mode: &str) -> Result<&str, EngineError> {
    match mode {
        "https" | "https-lanes" | "websocket" | "websocket-lanes" => Ok(mode),
        other => Err(EngineError::Refused(format!("unknown carrier {other}"))),
    }
}

/// Splits `host:port`, refusing anything that is not one.
fn split_bind(bind: &str) -> Result<(&str, u16), EngineError> {
    let (host, port) = bind
        .rsplit_once(':')
        .ok_or_else(|| EngineError::Refused(format!("{bind} is not an address and a port")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| EngineError::Refused(format!("{bind} does not end in a port")))?;
    if host.is_empty() {
        return Err(EngineError::Refused(format!("{bind} has no address")));
    }
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap_proto::{Listener, NodeShape, Policy, WireAccess};
    use uuid::Uuid;

    fn settings() -> Settings {
        Settings {
            api_port: 9091,
            metrics_port: 9090,
            api_token: "Bearer opaque".to_owned(),
            data_path: "/var/lib/anyproxy/engine".to_owned(),
            middle_proxy: true,
        }
    }

    /// Sixteen bytes as the wire carries them.
    ///
    /// Built rather than written out: a literal of this shape is what a real
    /// client secret looks like, and the secret scanner is right to stop one
    /// from being committed. A test does not need to argue with it.
    fn a_secret(byte: u8) -> String {
        hex::encode([byte; 16])
    }

    fn an_access(method: &str) -> WireAccess {
        WireAccess {
            id: Uuid::now_v7(),
            method: method.to_owned(),
            credential: WireCredential::Secret {
                hex: a_secret(0x11),
            },
            max_devices: None,
            state: "active".to_owned(),
        }
    }

    fn a_config(listeners: Vec<Listener>, accesses: Vec<WireAccess>) -> Config {
        Config {
            revision: Uuid::now_v7(),
            issued_at: "2026-08-26T10:00:00Z".to_owned(),
            node: NodeShape {
                kind: "stealth".to_owned(),
                domain: Some("cover.example.com".to_owned()),
            },
            listeners,
            accesses,
            policy: Policy {
                log_level: "quiet".to_owned(),
                carrier_mode: "https".to_owned(),
            },
        }
    }

    fn a_listener(method: &str, bind: &str) -> Listener {
        Listener {
            method: method.to_owned(),
            bind: bind.to_owned(),
        }
    }

    #[test]
    fn the_control_api_and_the_metrics_answer_on_loopback_only() {
        let config = a_config(vec![a_listener("faketls", "0.0.0.0:443")], vec![]);
        let rendered = render(&config, &settings()).unwrap();

        assert!(rendered.contains("listen = \"127.0.0.1:9091\""));
        assert!(rendered.contains("metrics_listen = \"127.0.0.1:9090\""));
        for line in rendered.lines() {
            let is_own = line.starts_with("listen =") || line.starts_with("metrics_listen =");
            if is_own {
                assert!(
                    line.contains("127.0.0.1"),
                    "an address of ours faces outward: {line}"
                );
            }
        }
    }

    #[test]
    fn the_settings_that_belong_to_general_are_written_there() {
        let config = a_config(vec![a_listener("faketls", "0.0.0.0:443")], vec![]);
        let rendered = render(&config, &settings()).unwrap();

        // telemt discards these with a warning when they sit at the top level,
        // and then runs on its own defaults instead of ours.
        let general = rendered
            .split("[general.telemetry]")
            .next()
            .unwrap()
            .split("[general]")
            .nth(1)
            .expect("a general section");
        for key in ["data_path", "config_strict", "use_middle_proxy", "ad_tag"] {
            assert!(general.contains(key), "{key} is not under [general]");
        }
    }

    #[test]
    fn a_listener_the_panel_sent_keeps_its_address() {
        let config = a_config(vec![a_listener("faketls", "0.0.0.0:443")], vec![]);
        let rendered = render(&config, &settings()).unwrap();
        assert!(rendered.contains("ip = \"0.0.0.0\""));
        assert!(rendered.contains("port = 443"));
        assert!(rendered.contains("transport = \"mtproxy\""));
    }

    #[test]
    fn a_web_listener_brings_the_web_section_with_it() {
        let config = a_config(vec![a_listener("web", "0.0.0.0:443")], vec![]);
        let rendered = render(&config, &settings()).unwrap();
        assert!(rendered.contains("transport = \"web\""));
        assert!(rendered.contains("[web]"));
        assert!(rendered.contains("carrier = \"https\""));
    }

    #[test]
    fn a_node_without_a_web_listener_has_no_web_section() {
        let config = a_config(vec![a_listener("faketls", "0.0.0.0:443")], vec![]);
        let rendered = render(&config, &settings()).unwrap();
        assert!(!rendered.contains("[web]"));
    }

    #[test]
    fn an_access_becomes_a_user_named_by_its_identifier() {
        let access = an_access("faketls");
        let id = access.id;
        let config = a_config(vec![a_listener("faketls", "0.0.0.0:443")], vec![access]);
        let rendered = render(&config, &settings()).unwrap();

        assert!(rendered.contains(&format!("{} = \"{}\"", user_of(id), a_secret(0x11))));
        assert_eq!(access_of(&user_of(id)), Some(id));
    }

    #[test]
    fn a_disabled_access_is_present_and_turned_off() {
        let mut access = an_access("faketls");
        access.state = "disabled".to_owned();
        let id = access.id;
        let config = a_config(vec![a_listener("faketls", "0.0.0.0:443")], vec![access]);
        let rendered = render(&config, &settings()).unwrap();

        // Present, so a client that reaches it is refused rather than unknown,
        // and telemt closes the sessions it already had.
        assert!(rendered.contains(&user_of(id)));
        assert!(rendered.contains(&format!("{} = false", user_of(id))));
    }

    #[test]
    fn a_device_limit_travels_with_the_access() {
        let mut access = an_access("faketls");
        access.max_devices = Some(3);
        let id = access.id;
        let config = a_config(vec![a_listener("faketls", "0.0.0.0:443")], vec![access]);
        let rendered = render(&config, &settings()).unwrap();

        assert!(rendered.contains("[access.user_max_unique_ips]"));
        assert!(rendered.contains(&format!("{} = 3", user_of(id))));
    }

    #[test]
    fn a_node_with_nothing_to_serve_still_renders() {
        let config = a_config(vec![a_listener("faketls", "0.0.0.0:443")], vec![]);
        let rendered = render(&config, &settings()).unwrap();
        assert!(rendered.contains("[access.users]"));
        assert!(rendered.contains(NOBODY));
    }

    #[test]
    fn a_login_is_refused_rather_than_rendered() {
        let mut access = an_access("faketls");
        access.credential = WireCredential::Login {
            user: "someone".to_owned(),
            pass: "something".to_owned(),
        };
        let config = a_config(vec![a_listener("faketls", "0.0.0.0:443")], vec![access]);
        let outcome = render(&config, &settings());
        assert!(matches!(outcome, Err(EngineError::Refused(_))));
    }

    #[test]
    fn a_secret_of_the_wrong_length_is_refused() {
        let mut access = an_access("faketls");
        access.credential = WireCredential::Secret {
            hex: "0011".to_owned(),
        };
        let config = a_config(vec![a_listener("faketls", "0.0.0.0:443")], vec![access]);
        assert!(matches!(
            render(&config, &settings()),
            Err(EngineError::Refused(_))
        ));
    }

    #[test]
    fn a_method_this_engine_does_not_serve_is_refused() {
        for method in ["socks5", "http"] {
            let config = a_config(vec![a_listener(method, "0.0.0.0:1080")], vec![]);
            assert!(
                matches!(render(&config, &settings()), Err(EngineError::Refused(_))),
                "{method} was rendered"
            );
        }
    }

    #[test]
    fn a_carrier_that_is_not_one_of_the_four_is_refused() {
        let mut config = a_config(vec![a_listener("web", "0.0.0.0:443")], vec![]);
        config.policy.carrier_mode = "smoke signals".to_owned();
        assert!(matches!(
            render(&config, &settings()),
            Err(EngineError::Refused(_))
        ));

        for mode in ["https", "https-lanes", "websocket", "websocket-lanes"] {
            config.policy.carrier_mode = mode.to_owned();
            let rendered = render(&config, &settings()).unwrap();
            assert!(rendered.contains(&format!("carrier = \"{mode}\"")));
        }
    }

    #[test]
    fn an_address_without_a_port_is_refused() {
        for bind in ["0.0.0.0", "0.0.0.0:", ":443", "0.0.0.0:notaport"] {
            let config = a_config(vec![a_listener("faketls", bind)], vec![]);
            assert!(
                matches!(render(&config, &settings()), Err(EngineError::Refused(_))),
                "{bind} was accepted"
            );
        }
    }
}
