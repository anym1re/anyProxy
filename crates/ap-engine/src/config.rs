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
    /// Where a connection that fails to authenticate is sent instead.
    ///
    /// A probe that does not know a secret must see a real site with real TLS,
    /// or the node answers a plausible handshake with something that is not
    /// one — which is the single most telling thing it could do. Until the
    /// front door on 443 serves a site of our own, this points at a site that
    /// already exists.
    pub mask_host: String,
    /// Where the cover site answers, as an origin on this machine.
    ///
    /// The engine sends anything that is not a client of ours to this, so it
    /// has to be a site and not a redirect: a visitor who followed a link and
    /// found nothing there learns as much as one who found an error.
    ///
    /// Loopback or a private address, which is the engine's own rule. A cover
    /// site somewhere else would be a second party who could see who visits.
    pub cover_site: String,
    /// The address clients reach this node on, with the port they reach it on.
    ///
    /// A literal address rather than a name: the engine wants one, and a node
    /// whose name does not resolve to the machine it runs on cannot serve this
    /// method at all.
    pub public_addr: String,
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

    // Which of telemt's client modes are allowed, decided by what the node
    // actually serves. Both are off by default except the TLS one, so a node
    // serving plain MTProto without this refuses every client it was issued
    // links for — with the links looking perfectly correct.
    let serves_plain = config
        .listeners
        .iter()
        .any(|listener| listener.method == "mtproto");
    let serves_masked = config
        .listeners
        .iter()
        .any(|listener| listener.method == "faketls" || listener.method == "web");
    writeln!(out, "[general.modes]").ok();
    writeln!(out, "classic = false").ok();
    writeln!(out, "secure = {serves_plain}").ok();
    writeln!(out, "tls = {serves_masked}").ok();
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
        let transport = transport(&listener.method)?;
        writeln!(out, "transport = \"{transport}\"").ok();
        if transport == "web" {
            // Who is allowed to say where a request came from. The front door
            // that ends the TLS runs on this machine, so nobody else is.
            writeln!(out, "web_trusted_proxy_cidrs = [\"127.0.0.1/32\"]").ok();
        }
        writeln!(out).ok();
    }

    // What clients present as the name they are connecting to, and what the
    // engine imitates. These must be the same value: a link telling a client
    // to say one name while the node imitates another is a node that fails
    // the first thing anyone would check.
    //
    // The node's own name, unless it has been given an alibi to borrow. A node
    // that also serves a site needs both: the site answers to its own name and
    // holds a certificate for it, and the forged handshake goes on borrowing
    // somebody else's, which is what lets the front door tell them apart.
    if let Some(domain) = masquerade(config).filter(|_| serves_masked) {
        writeln!(out, "[censorship]").ok();
        writeln!(out, "tls_domain = \"{domain}\"").ok();
        writeln!(out, "mask = true").ok();
        writeln!(out, "mask_host = \"{}\"", settings.mask_host).ok();
        writeln!(out, "mask_port = 443").ok();
        writeln!(out).ok();
    }

    if config.listeners.iter().any(|listener| {
        transport(&listener.method)
            .map(|t| t == "web")
            .unwrap_or(false)
    }) {
        render_web(&mut out, config, settings)?;
    }

    render_access(&mut out, config)?;
    Ok(out)
}

/// The `[web]` tables: the name the node answers to, what a visitor sees, and
/// which accesses arrive this way.
///
/// The carrier hides inside ordinary requests to a site that is really there.
/// The site is ours and runs on this machine, so a visitor who followed a link
/// out of curiosity is served by us and seen by nobody else.
fn render_web(out: &mut String, config: &Config, settings: &Settings) -> Result<(), EngineError> {
    let Some(domain) = config.node.domain.as_deref().filter(|d| !d.is_empty()) else {
        return Err(EngineError::Refused(
            "a node serving web has no name for clients to ask for".to_owned(),
        ));
    };

    writeln!(out, "[web]").ok();
    writeln!(out, "enabled = true").ok();
    writeln!(
        out,
        "carrier = \"{}\"",
        carrier(&config.policy.carrier_mode)?
    )
    .ok();
    writeln!(out).ok();

    writeln!(out, "[[web.vhosts]]").ok();
    writeln!(out, "host = \"{domain}\"").ok();
    writeln!(out, "public_addr = \"{}\"", settings.public_addr).ok();
    writeln!(out).ok();

    writeln!(out, "[web.vhosts.decoy]").ok();
    writeln!(out, "mode = \"http_upstream\"").ok();
    writeln!(out, "upstream = \"{}\"", settings.cover_site).ok();
    writeln!(out).ok();

    let mut any = false;
    for access in &config.accesses {
        if access.method != "web" || access.state != "active" {
            continue;
        }
        any = true;
        writeln!(out, "[[web.vhosts.profiles]]").ok();
        writeln!(out, "user = \"{}\"", access.id.simple()).ok();
        writeln!(out, "secret_mode = \"plain\"").ok();
        writeln!(out).ok();
    }
    if !any {
        return Err(EngineError::Refused(
            "a node serving web has no access that arrives that way".to_owned(),
        ));
    }
    Ok(())
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

/// The name a stealth node answers to, when it is one.
///
/// An open node has none: it serves plain MTProto, SOCKS5 and HTTP, none of
/// which pretends to be a website.
fn masquerade(config: &Config) -> Option<&str> {
    (config.node.kind == "stealth")
        .then_some(
            config
                .node
                .alibi
                .as_deref()
                .filter(|alibi| !alibi.is_empty())
                .or(config.node.domain.as_deref()),
        )
        .flatten()
        .filter(|domain| !domain.is_empty() && !domain.contains(['/', ' ']))
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
            mask_host: "www.cloudflare.com".to_owned(),
            cover_site: "http://127.0.0.1:8081".to_owned(),
            public_addr: "203.0.113.7:443".to_owned(),
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
                alibi: None,
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
    fn a_node_allows_the_mode_the_links_it_issues_are_written_for() {
        // A plain MTProto link carries a `dd` secret, which telemt calls the
        // secure mode and leaves off unless told. Left off, every client the
        // panel issued a link for is refused while the link looks right.
        let plain = a_config(vec![a_listener("mtproto", "0.0.0.0:8443")], vec![]);
        let rendered = render(&plain, &settings()).unwrap();
        assert!(rendered.contains("secure = true"), "{rendered}");
        assert!(rendered.contains("tls = false"));

        // A masked link carries `ee`, which is the TLS mode.
        let masked = a_config(vec![a_listener("faketls", "0.0.0.0:443")], vec![]);
        let rendered = render(&masked, &settings()).unwrap();
        assert!(rendered.contains("tls = true"), "{rendered}");
        assert!(rendered.contains("secure = false"));

        // Classic MTProxy has no secret worth the name and is never allowed.
        for config in [plain, masked] {
            assert!(
                render(&config, &settings())
                    .unwrap()
                    .contains("classic = false")
            );
        }
    }

    #[test]
    fn a_stealth_node_imitates_the_name_its_clients_are_told_to_present() {
        let mut config = a_config(vec![a_listener("faketls", "0.0.0.0:443")], vec![]);
        config.node.kind = "stealth".to_owned();
        config.node.domain = Some("cover.example.com".to_owned());
        let rendered = render(&config, &settings()).unwrap();

        // The same name the link puts in the secret. A node imitating one site
        // while its clients announce another fails the first thing a probe
        // would compare.
        assert!(
            rendered.contains("tls_domain = \"cover.example.com\""),
            "{rendered}"
        );
        assert!(rendered.contains("mask = true"));
        assert!(rendered.contains("mask_host = \"www.cloudflare.com\""));
    }

    #[test]
    fn an_open_node_pretends_to_be_nothing() {
        let mut config = a_config(vec![a_listener("mtproto", "0.0.0.0:8443")], vec![]);
        config.node.kind = "open".to_owned();
        config.node.domain = None;
        let rendered = render(&config, &settings()).unwrap();
        assert!(!rendered.contains("[censorship]"), "{rendered}");
    }

    #[test]
    fn a_domain_that_is_not_one_is_not_written_out() {
        for bad in ["", "not a domain", "example.com/path"] {
            let mut config = a_config(vec![a_listener("faketls", "0.0.0.0:443")], vec![]);
            config.node.kind = "stealth".to_owned();
            config.node.domain = Some(bad.to_owned());
            let rendered = render(&config, &settings()).unwrap();
            assert!(
                !rendered.contains("tls_domain"),
                "{bad:?} reached the engine"
            );
        }
    }

    #[test]
    fn a_web_listener_brings_the_web_section_with_it() {
        let access = an_access("web");
        let config = a_config(vec![a_listener("web", "0.0.0.0:443")], vec![access.clone()]);
        let rendered = render(&config, &settings()).unwrap();

        assert!(rendered.contains("transport = \"web\""));
        assert!(rendered.contains("web_trusted_proxy_cidrs = [\"127.0.0.1/32\"]"));
        assert!(rendered.contains("[web]"));
        assert!(rendered.contains("carrier = \"https\""));
        assert!(rendered.contains("host = \"cover.example.com\""));
        assert!(rendered.contains("public_addr = \"203.0.113.7:443\""));
        assert!(rendered.contains("mode = \"http_upstream\""));
        assert!(
            rendered.contains("upstream = \"http://127.0.0.1:8081\""),
            "the cover site is not on this machine: {rendered}"
        );
        assert!(rendered.contains(&format!("user = \"{}\"", access.id.simple())));
        assert!(rendered.contains("secret_mode = \"plain\""));
    }

    #[test]
    fn a_node_serving_web_without_a_name_is_refused() {
        // The whole method rests on a client asking for a name and getting a
        // certificate for it. A node without one cannot serve this at all, and
        // rendering something that starts and then fails every client is worse
        // than saying so here.
        let mut config = a_config(
            vec![a_listener("web", "0.0.0.0:443")],
            vec![an_access("web")],
        );
        config.node.domain = None;
        assert!(render(&config, &settings()).is_err());
    }

    #[test]
    fn a_node_serving_web_with_no_access_that_arrives_that_way_is_refused() {
        let config = a_config(
            vec![a_listener("web", "0.0.0.0:443")],
            vec![an_access("faketls")],
        );
        assert!(render(&config, &settings()).is_err());
    }

    #[test]
    fn an_access_that_is_not_active_brings_no_profile() {
        let mut withdrawn = an_access("web");
        withdrawn.state = "disabled".to_owned();
        let serving = an_access("web");
        let config = a_config(
            vec![a_listener("web", "0.0.0.0:443")],
            vec![withdrawn.clone(), serving.clone()],
        );

        let rendered = render(&config, &settings()).unwrap();
        assert!(rendered.contains(&format!("user = \"{}\"", serving.id.simple())));
        assert!(
            !rendered.contains(&format!("user = \"{}\"", withdrawn.id.simple())),
            "a withdrawn access still arrives by this road: {rendered}"
        );
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
        let mut config = a_config(
            vec![a_listener("web", "0.0.0.0:443")],
            vec![an_access("web")],
        );
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

#[cfg(test)]
mod alibi_tests {
    use super::*;
    use ap_proto::{Listener, NodeShape, Policy};
    use uuid::Uuid;

    fn a_stealth_config(domain: &str, alibi: Option<&str>) -> Config {
        Config {
            revision: Uuid::now_v7(),
            issued_at: "2026-08-27T10:00:00Z".to_owned(),
            node: NodeShape {
                kind: "stealth".to_owned(),
                domain: Some(domain.to_owned()),
                alibi: alibi.map(str::to_owned),
            },
            listeners: vec![Listener {
                method: "faketls".to_owned(),
                bind: "0.0.0.0:443".to_owned(),
            }],
            accesses: Vec::new(),
            policy: Policy {
                log_level: "quiet".to_owned(),
                carrier_mode: "https".to_owned(),
            },
        }
    }

    fn plain_settings() -> Settings {
        Settings {
            api_port: 9091,
            metrics_port: 9090,
            api_token: "Bearer x".to_owned(),
            data_path: "/tmp/engine".to_owned(),
            middle_proxy: false,
            mask_host: "www.cloudflare.com".to_owned(),
            cover_site: "http://127.0.0.1:8081".to_owned(),
            public_addr: "203.0.113.7:443".to_owned(),
        }
    }

    #[test]
    fn a_node_without_an_alibi_claims_its_own_name() {
        let rendered = render(&a_stealth_config("ya.ru", None), &plain_settings()).unwrap();
        assert!(rendered.contains("tls_domain = \"ya.ru\""));
    }

    #[test]
    fn an_alibi_is_what_the_forged_handshake_claims_to_be() {
        // A node that also serves a site answers to its own name there, and
        // must claim a different one here, or the front door cannot tell a
        // client of the site from a client of the handshake.
        let rendered = render(
            &a_stealth_config("203-0-113-110.sslip.io", Some("ya.ru")),
            &plain_settings(),
        )
        .unwrap();
        assert!(rendered.contains("tls_domain = \"ya.ru\""));
        assert!(
            !rendered.contains("tls_domain = \"203-0-113-110.sslip.io\""),
            "the handshake claims the same name as the site: {rendered}"
        );
    }

    #[test]
    fn an_empty_alibi_is_no_alibi() {
        let rendered = render(&a_stealth_config("ya.ru", Some("")), &plain_settings()).unwrap();
        assert!(rendered.contains("tls_domain = \"ya.ru\""));
    }
}
