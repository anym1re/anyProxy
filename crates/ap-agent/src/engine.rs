use ap_engine::config::Settings;
use rand::RngCore;

use crate::AgentError;
use crate::identity::{self, Paths};

/// How often the node reads the engine's counters.
pub const READING_INTERVAL_SECS: u64 = 60;

/// Where a connection that fails to authenticate is sent, on a test host.
///
/// There is no value that is right everywhere, which is why this is only a
/// fallback. The imitated site works when it is dull and reachable *in the
/// country the clients are in*; Cloudflare is partly blocked in Russia, so a
/// node there pretending to be it either stands out or is caught by the same
/// block. The operator sets this per node. A node carrying clients inside a
/// site of its own does not use this at all: it answers as that site, which is
/// really there.
const DEFAULT_MASK_HOST: &str = "www.cloudflare.com";

/// Ports the engine answers on, on loopback and nowhere else.
const API_PORT: u16 = 9091;
const METRICS_PORT: u16 = 9090;

/// Where the cover site answers, on loopback and nowhere else.
///
/// A visitor reaches it through the front door on 443; nothing outside this
/// machine talks to it directly.
pub const COVER_PORT: u16 = 8081;

/// The port clients reach a node serving web on.
const WEB_PORT: u16 = 443;

/// Reads the node's engine settings, making them on first use.
///
/// The token is drawn once and kept, because the engine outlives a restart of
/// the agent and the two have to go on agreeing. It is written where the
/// identity is, readable by its owner alone.
pub fn settings(paths: &Paths) -> Result<Settings, AgentError> {
    let path = paths.dir.join("engine.token");
    let token = match std::fs::read_to_string(&path) {
        Ok(token) => token.trim().to_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let token = format!("Bearer {}", fresh_token());
            identity::write_owner_only(&path, token.as_bytes())?;
            token
        }
        Err(error) => return Err(AgentError::file(path.display(), error)),
    };

    Ok(Settings {
        api_port: API_PORT,
        metrics_port: METRICS_PORT,
        api_token: token,
        data_path: paths.dir.join("engine").display().to_string(),
        cover_site: format!("http://127.0.0.1:{COVER_PORT}"),
        // Filled in when a configuration arrives and the node has a name to
        // resolve. Until then there is nothing to reach it by.
        public_addr: String::new(),
        mask_host: std::env::var("ANYPROXY_MASK_HOST")
            .unwrap_or_else(|_| DEFAULT_MASK_HOST.to_owned()),
    })
}

/// Where the engine binary is, unless told otherwise.
fn engine_binary() -> std::path::PathBuf {
    std::env::var("ANYPROXY_TELEMT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/usr/local/bin/telemt"))
}

/// Where the configuration the engine reads is written.
pub fn config_path(paths: &Paths) -> std::path::PathBuf {
    paths.dir.join("telemt.toml")
}

/// Writes the configuration and starts the engine on it.
///
/// The file is written before the process exists, so there is no moment where
/// the engine is running on something older than what the panel just sent.
pub fn start(
    paths: &Paths,
    settings: &Settings,
    config: &ap_proto::Config,
) -> Result<std::process::Child, AgentError> {
    write_config(paths, settings, config)?;
    std::fs::create_dir_all(&settings.data_path)
        .map_err(|error| AgentError::file(&settings.data_path, error))?;

    let binary = engine_binary();
    std::process::Command::new(&binary)
        .arg("run")
        .arg(config_path(paths))
        .arg("--silent")
        .spawn()
        .map_err(|error| AgentError::file(binary.display(), error))
}

/// Writes what the engine reads, without touching the running one.
pub fn write_config(
    paths: &Paths,
    settings: &Settings,
    config: &ap_proto::Config,
) -> Result<(), AgentError> {
    let mut settings = settings.clone();
    if serves_web(config) {
        settings.public_addr = reachable_as(config)?;
    }
    let rendered = ap_engine::config::render(config, &settings)
        .map_err(|error| AgentError::Refused(error.to_string()))?;
    identity::write_owner_only(&config_path(paths), rendered.as_bytes())
}

/// Whether this configuration asks the engine to carry clients inside a site.
fn serves_web(config: &ap_proto::Config) -> bool {
    config
        .listeners
        .iter()
        .any(|listener| listener.method == "web")
}

/// The address clients reach this node on, taken from its own name.
///
/// Resolved here rather than sent by the panel: the name is what clients ask
/// for and what the certificate is issued to, so a name that does not lead to
/// this machine is a node that cannot serve this method whatever the panel
/// believes. Found out now rather than by every client in turn.
fn reachable_as(config: &ap_proto::Config) -> Result<String, AgentError> {
    use std::net::ToSocketAddrs as _;

    let Some(domain) = config.node.domain.as_deref().filter(|d| !d.is_empty()) else {
        return Err(AgentError::Refused(
            "this node serves web and has no name".to_owned(),
        ));
    };
    let found = (domain, WEB_PORT)
        .to_socket_addrs()
        .map_err(|error| AgentError::Refused(format!("{domain} leads nowhere: {error}")))?
        // Of the fourth version: the engine wants one address and the node may
        // have several. The one clients of both kinds can reach is this.
        .find(|address| address.is_ipv4())
        .ok_or_else(|| AgentError::Refused(format!("{domain} leads nowhere of the fourth kind")))?;
    Ok(found.to_string())
}

/// Thirty-two bytes of randomness, as hexadecimal.
fn fresh_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// When the engine is started again after it stopped on its own.
///
/// Noticed while the panel is still on the line, and not only between
/// connections: an engine that died under a long quiet channel stayed dead
/// until the channel broke, which on a good day is never.
///
/// The wait doubles like the panel's own does, and for the same reason: an
/// engine that dies on the spot every time is not helped by being started
/// faster, and the site behind it keeps answering meanwhile.
#[derive(Debug, Default)]
pub struct Relaunch {
    attempt: u32,
    not_before: Option<std::time::Instant>,
}

impl Relaunch {
    /// Ready to start at once.
    pub fn new() -> Self {
        Self::default()
    }

    /// The engine was found stopped. The next start waits its turn.
    pub fn stopped(&mut self, now: std::time::Instant) {
        self.not_before = Some(now + crate::backoff::base(self.attempt));
        self.attempt = self.attempt.saturating_add(1);
    }

    /// A start that did not take counts as a stop.
    pub fn failed(&mut self, now: std::time::Instant) {
        self.stopped(now);
    }

    /// Whether it is time to try.
    pub fn due(&self, now: std::time::Instant) -> bool {
        self.not_before.is_none_or(|then| now >= then)
    }

    /// The engine is up; the count starts over.
    pub fn started(&mut self) {
        self.attempt = 0;
        self.not_before = None;
    }
}

#[cfg(test)]
mod relaunch_tests {
    use std::time::{Duration, Instant};

    use super::Relaunch;

    #[test]
    fn a_fresh_relaunch_is_due_at_once() {
        assert!(Relaunch::new().due(Instant::now()));
    }

    #[test]
    fn a_stop_waits_a_second_and_then_is_due() {
        let now = Instant::now();
        let mut relaunch = Relaunch::new();
        relaunch.stopped(now);
        assert!(!relaunch.due(now));
        assert!(!relaunch.due(now + Duration::from_millis(999)));
        assert!(relaunch.due(now + Duration::from_secs(1)));
    }

    #[test]
    fn repeated_stops_wait_longer_and_stop_growing_at_a_minute() {
        let now = Instant::now();
        let mut relaunch = Relaunch::new();
        for _ in 0..3 {
            relaunch.stopped(now);
        }
        // 1, 2, 4: the third stop set a four-second wait.
        assert!(!relaunch.due(now + Duration::from_secs(3)));
        assert!(relaunch.due(now + Duration::from_secs(4)));
        for _ in 0..20 {
            relaunch.stopped(now);
        }
        assert!(!relaunch.due(now + Duration::from_secs(59)));
        assert!(relaunch.due(now + Duration::from_secs(60)));
    }

    #[test]
    fn a_start_that_took_resets_the_count() {
        let now = Instant::now();
        let mut relaunch = Relaunch::new();
        relaunch.stopped(now);
        relaunch.stopped(now);
        relaunch.started();
        assert!(relaunch.due(now));
        relaunch.stopped(now);
        assert!(relaunch.due(now + Duration::from_secs(1)));
    }

    #[test]
    fn a_failed_start_counts_like_a_stop() {
        let now = Instant::now();
        let mut relaunch = Relaunch::new();
        relaunch.failed(now);
        assert!(!relaunch.due(now));
        assert!(relaunch.due(now + Duration::from_secs(1)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_dir(name: &str) -> Paths {
        let dir = std::env::temp_dir()
            .join("anyproxy-agent-engine")
            .join(format!("{name}-{}", uuid::Uuid::now_v7().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        Paths::new(dir)
    }

    #[test]
    fn the_token_survives_a_restart_of_the_agent() {
        let paths = a_dir("stable");
        let first = settings(&paths).unwrap();
        let second = settings(&paths).unwrap();
        assert_eq!(first.api_token, second.api_token);
    }

    #[test]
    fn two_nodes_do_not_share_a_token() {
        let first = settings(&a_dir("one")).unwrap();
        let second = settings(&a_dir("two")).unwrap();
        assert_ne!(first.api_token, second.api_token);
        assert!(first.api_token.starts_with("Bearer "));
    }

    #[cfg(unix)]
    #[test]
    fn the_token_is_readable_by_its_owner_alone() {
        use std::os::unix::fs::PermissionsExt;

        let paths = a_dir("mode");
        settings(&paths).unwrap();
        let mode = std::fs::metadata(paths.dir.join("engine.token"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o400);
    }
}
