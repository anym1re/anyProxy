use std::path::PathBuf;
use std::time::Duration;

use ap_agent::identity::Paths;
use ap_agent::meter::Meter;
use ap_agent::posture::{Posture, Silent};
use ap_agent::through::Through;
use ap_agent::{AgentError, backoff, engine, host, identity, link, say, session};
use ap_engine::control::Control;
use ap_engine::health::{self, Reach, Site};
use ap_inbound::{Method, Registry};
use ap_proto::Message;
use clap::{Parser, Subcommand};
use time::OffsetDateTime;

/// Node-side daemon for anyProxy.
#[derive(Parser)]
#[command(name = "anyproxy-agent", version, about)]
struct Cli {
    /// Directory holding the identity and the sealed configuration.
    #[arg(
        long,
        global = true,
        env = "ANYPROXY_AGENT_DIR",
        default_value = "/var/lib/anyproxy"
    )]
    dir: PathBuf,

    /// SOCKS5 proxy the panel is reached through, if it is not reached
    /// directly. Either `host:port` or `user:pass@host:port`.
    #[arg(long, global = true, env = "ANYPROXY_THROUGH")]
    through: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Presents a one-time code and stores the identity the panel issues.
    Enroll {
        /// Address of the panel channel, host and port.
        #[arg(long, env = "ANYPROXY_PANEL")]
        panel: String,
        /// The one-time code the operator was given.
        #[arg(long, env = "ANYPROXY_ENROLLMENT_CODE")]
        code: String,
        /// Fingerprint of the panel authority, 64 hexadecimal characters.
        #[arg(long, env = "ANYPROXY_PANEL_FINGERPRINT")]
        fingerprint: String,
    },
    /// Keeps the channel to the panel and the node's configuration current.
    Run {
        /// Address of the panel channel, host and port.
        #[arg(long, env = "ANYPROXY_PANEL")]
        panel: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        std::process::exit(1);
    };

    if let Err(reason) = runtime.block_on(run(cli)) {
        eprintln!("{reason}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), AgentError> {
    let paths = Paths::new(cli.dir);
    // A setting that is not a proxy address stops the node here. Falling back
    // to a direct connection would be a node reaching its panel by a way
    // nobody chose, which on a machine that was meant to speak only through a
    // tunnel is the one thing that must not happen.
    let through = cli.through.as_deref().map(Through::parse).transpose()?;
    match cli.command {
        Command::Enroll {
            panel,
            code,
            fingerprint,
        } => enrol(&paths, &panel, &code, &fingerprint, through.as_ref()).await,
        Command::Run { panel } => serve(&paths, &panel, through.as_ref()).await,
    }
}

async fn enrol(
    paths: &Paths,
    panel: &str,
    code: &str,
    fingerprint: &str,
    through: Option<&Through>,
) -> Result<(), AgentError> {
    // The pin is checked while the connection is being established, so a panel
    // that is not the pinned one never sees the code.
    let mut channel = link::connect_through(panel, fingerprint, None, through).await?;
    let identity = session::enrol(&mut channel, code).await?;
    identity::store(paths, &identity)?;
    println!("enrolled as node {}", identity.node_id);
    Ok(())
}

async fn serve(paths: &Paths, panel: &str, through: Option<&Through>) -> Result<(), AgentError> {
    // Held for as long as this agent runs. A second one on the same directory
    // would overwrite this one's cache and report an empty set of counters
    // over the top of what this one is actually carrying.
    let _claim = ap_agent::only_one::claim(paths)?;
    let identity = identity::load(paths)?;
    let fingerprint = identity.fingerprint()?;

    // Nothing is served until the panel answers: the key that opens the cache
    // is not on this machine.
    report(&session::posture_before_contact());

    let settings = engine::settings(paths)?;
    let control = Control::new(settings.api_port, settings.api_token.clone());
    let metrics_port = settings.metrics_port;
    // The engine is started when the first configuration arrives: before that
    // there is nothing for it to serve, and a node with nothing to serve is a
    // node that should not be listening.
    let mut engine_process: Option<std::process::Child> = None;
    // The listeners an open node serves. The engine does MTProto and WEB; a
    // login is carried here, and the two never share a machine.
    let inbound = std::sync::Arc::new(Registry::new(&[], fresh_salt()));
    let mut inbound_open = false;
    // The site a node serving web shows anyone else. Put up once, kept for as
    // long as the agent runs.
    let mut cover_open = false;

    let mut applied_revision = None;
    let mut attempt = 0u32;
    let mut meter = Meter::new();
    let mut relaunch = engine::Relaunch::new();
    let mut rates = host::Rates::new();

    loop {
        if let Some(child) = engine_process.as_mut()
            && matches!(child.try_wait(), Ok(Some(_)))
        {
            // It stopped on its own. It is started again once the panel is
            // back, after the wait its stopping earned; until then the cover
            // site is what answers.
            eprintln!("the engine stopped");
            engine_process = None;
            relaunch.stopped(std::time::Instant::now());
        }

        match once(
            paths,
            panel,
            &fingerprint,
            &identity,
            applied_revision,
            &control,
            metrics_port,
            &mut meter,
            &settings,
            &mut engine_process,
            &mut relaunch,
            &mut rates,
            &inbound,
            &mut inbound_open,
            &mut cover_open,
            through,
        )
        .await
        {
            Ok(revision) => {
                applied_revision = revision;
                attempt = 0;
            }
            Err(reason) => {
                eprintln!("panel unreachable: {reason}");
                attempt = attempt.saturating_add(1);
            }
        }
        tokio::time::sleep(backoff::jittered(attempt)).await;
    }
}

/// One connection, from greeting to the moment it breaks.
#[allow(clippy::too_many_arguments)]
async fn once(
    paths: &Paths,
    panel: &str,
    fingerprint: &str,
    identity: &identity::Identity,
    applied_revision: Option<uuid::Uuid>,
    control: &Control,
    metrics_port: u16,
    meter: &mut Meter,
    settings: &ap_engine::config::Settings,
    engine_process: &mut Option<std::process::Child>,
    relaunch: &mut engine::Relaunch,
    rates: &mut host::Rates,
    inbound: &std::sync::Arc<Registry>,
    inbound_open: &mut bool,
    cover_open: &mut bool,
    through: Option<&Through>,
) -> Result<Option<uuid::Uuid>, AgentError> {
    let mut channel = link::connect_through(panel, fingerprint, Some(identity), through).await?;
    let mut state = session::open(
        &mut channel,
        identity.node_id,
        paths,
        applied_revision,
        OffsetDateTime::now_utc(),
    )
    .await?;
    report(&state.posture);

    if let ap_agent::posture::Posture::Serving(running) = &state.posture {
        inbound.replace(&running.accesses);
        if !*inbound_open {
            *inbound_open = open_inbounds(running, inbound).await;
        }
        if !*cover_open && shows_a_site(running) {
            *cover_open = open_cover(identity.node_id, engine::COVER_PORT).await;
        }
        match engine_process {
            Some(_) => settle(paths, settings, control, running).await,
            // An open node serves logins and never runs the engine. Starting
            // it to watch it refuse the configuration would be a failure
            // reported every minute for something nobody asked for.
            None if needs_engine(running) => {
                start_engine(paths, settings, running, engine_process, relaunch);
            }
            None => {}
        }
    }

    // What the machine was short of when last looked at, and what the probes
    // last found. Both are kept so that under pressure the node can say what
    // it knew rather than spend on finding out again.
    let mut last_pressure = host::Pressure::Calm;
    let mut last_probe: Option<(Site, Reach)> = None;

    // Whichever comes first: the panel says something, or it is time to read
    // the counters again.
    let heartbeat = Duration::from_secs(
        u64::from(state.heartbeat_secs.max(1)).min(engine::READING_INTERVAL_SECS),
    );
    // Set when the panel asks for a look now: the next turn of the loop is
    // taken at once instead of at the end of the wait (0070).
    let mut at_once = false;
    loop {
        let waiting = if at_once { Duration::ZERO } else { heartbeat };
        at_once = false;
        let received = tokio::time::timeout(waiting, channel.receive()).await;
        let now = OffsetDateTime::now_utc();

        match received {
            Ok(Ok(Some(Message::Config(config)))) => {
                let revision = config.revision;
                session::apply(&mut channel, &mut state, paths, config, now).await?;
                report(&state.posture);
                if state.applied_revision == Some(revision)
                    && let ap_agent::posture::Posture::Serving(running) = &state.posture
                {
                    inbound.replace(&running.accesses);
                    if !*inbound_open {
                        *inbound_open = open_inbounds(running, inbound).await;
                    }
                    if !*cover_open && shows_a_site(running) {
                        *cover_open = open_cover(identity.node_id, engine::COVER_PORT).await;
                    }
                    settle(paths, settings, control, running).await;
                }
            }
            // An operator asked this node to look at itself now (0070). What
            // it last found is forgotten, so the probes run again rather than
            // being repeated from memory, and the turn that runs them is taken
            // immediately rather than at the end of the wait.
            Ok(Ok(Some(Message::Command(asked)))) => {
                let done = if asked.action == "probe" {
                    last_probe = None;
                    at_once = true;
                    "ok"
                } else {
                    "unknown"
                };
                channel
                    .send(&Message::Result(ap_proto::CommandResult {
                        id: asked.id,
                        status: done.to_owned(),
                        detail: None,
                    }))
                    .await?;
            }
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) => return Ok(state.applied_revision),
            Ok(Err(reason)) => return Err(reason),
            // Nothing arrived within the heartbeat. The connection may be gone
            // without having said so, the cache may have run out, and the
            // counters are due to be read.
            Err(_) => {
                let before = state.posture.is_serving();
                state.reconsider(paths, now)?;
                if before != state.posture.is_serving() {
                    report(&state.posture);
                }

                // The engine may have died while the panel was still on the
                // line. It is looked at here, on every beat, and started
                // again after the wait its stopping earned.
                let instant = std::time::Instant::now();
                if let Some(child) = engine_process.as_mut()
                    && matches!(child.try_wait(), Ok(Some(_)))
                {
                    eprintln!("the engine stopped");
                    *engine_process = None;
                    relaunch.stopped(instant);
                }
                if engine_process.is_none()
                    && let Posture::Serving(running) = &state.posture
                    && needs_engine(running)
                    && relaunch.due(instant)
                {
                    start_engine(paths, settings, running, engine_process, relaunch);
                    rates.engine_restarted();
                }

                // The machine, read before anything is spent on probes: what
                // it is short of decides whether they run at all.
                let machine = host::observe(engine_process.as_ref().map(std::process::Child::id));
                let pressure = machine
                    .as_ref()
                    .map(host::Reading::pressure)
                    .unwrap_or(host::Pressure::Calm);
                if pressure != last_pressure {
                    eprintln!("the machine is {}", pressure.as_reported());
                    last_pressure = pressure;
                }
                // The node's own listeners turn the next client away while
                // the machine is critical: it would fail after being paid
                // for, and take the clients already served down with it.
                inbound.set_shedding(matches!(pressure, host::Pressure::Critical));

                measure(control, metrics_port, meter, inbound, now).await;
                let health =
                    state_of_health(control, &state.posture, pressure, &mut last_probe).await;
                // Speeds come from the difference between this reading and
                // the last, counted here rather than in the panel (0064).
                let speeds = machine
                    .as_ref()
                    .map(|reading| rates.advance(reading, reading.cpus))
                    .unwrap_or_default();
                let machine = machine
                    .as_ref()
                    .map(|reading| reading.report(speeds, rates));
                match meter.delivery(health.clone(), now) {
                    Some(mut delivery) => {
                        delivery.machine = machine;
                        // A node that reports nothing and one that reports
                        // zeroes look the same from the panel, and the
                        // difference is where a fault lives. Counting is per
                        // access, so it is said only at the level that allows
                        // that.
                        say::Voice::following(&state.posture).counted(&format!(
                            "reporting {} traffic and {} device counts",
                            delivery.deltas.len(),
                            delivery.devices.len()
                        ));
                        session::deliver(&mut channel, meter, delivery).await?;
                    }
                    // Nothing to report is still said. The panel answers what
                    // a node sends and never speaks first, so a silent node is
                    // one that cannot be told its accesses have changed.
                    None => {
                        if let Some(mut beat) = meter.heartbeat(health, now) {
                            beat.machine = machine;
                            session::deliver(&mut channel, meter, beat).await?;
                        }
                    }
                }
            }
        }
    }
}

/// Starts the engine and records how that went.
///
/// A start that does not take is counted like a stop, so a binary that is
/// missing or refuses to run is retried at the same lengthening intervals
/// as one that dies after starting, rather than on every beat.
fn start_engine(
    paths: &Paths,
    settings: &ap_engine::config::Settings,
    running: &ap_proto::Config,
    engine_process: &mut Option<std::process::Child>,
    relaunch: &mut engine::Relaunch,
) {
    match engine::start(paths, settings, running) {
        Ok(child) => {
            *engine_process = Some(child);
            relaunch.started();
        }
        Err(reason) => {
            eprintln!("the engine did not start: {reason}");
            relaunch.failed(std::time::Instant::now());
        }
    }
}

/// Reads the engine's counters into the meter.
///
/// A reading that does not arrive is not a reading of zero: the counters keep
/// what they had and the next reading carries the difference from before the
/// gap, so nothing is lost when the engine is briefly unreachable.
async fn measure(
    control: &Control,
    metrics_port: u16,
    meter: &mut Meter,
    inbound: &Registry,
    now: OffsetDateTime,
) {
    let mut reading = match control.metrics(metrics_port).await {
        Ok(body) => ap_engine::metrics::read(&body),
        Err(reason) => {
            // A node with no engine still has its own listeners to report.
            eprintln!("engine metrics: {reason}");
            ap_engine::metrics::Reading::default()
        }
    };
    if reading.unread > 0 {
        eprintln!("engine metrics: {} lines could not be read", reading.unread);
    }

    // The node's own listeners count the same way the engine does: totals that
    // only climb, so the meter takes the difference between two readings.
    for (access, (bytes_in, bytes_out, devices)) in inbound.taken() {
        reading.by_access.insert(
            access,
            ap_engine::metrics::Counters {
                bytes_in,
                bytes_out,
                devices,
                connections: 0,
            },
        );
    }

    if let Err(reason) = meter.observe(&reading, now) {
        eprintln!("metrics: {reason}");
    }
}

/// Opens the listeners an open node serves, if it serves any.
///
/// Returns whether they are up: a node whose configuration names no login has
/// nothing to open, and one whose ports are taken says so once rather than
/// on every revision.
async fn open_inbounds(config: &ap_proto::Config, registry: &std::sync::Arc<Registry>) -> bool {
    let mut opened = false;
    for listener in &config.listeners {
        let method = match listener.method.as_str() {
            "socks5" => Method::Socks5,
            "http" => Method::Http,
            _ => continue,
        };
        match tokio::net::TcpListener::bind(&listener.bind).await {
            Ok(bound) => {
                let registry = std::sync::Arc::clone(registry);
                tokio::spawn(async move {
                    let _ = ap_inbound::serve(bound, method, registry).await;
                });
                println!("serving {} on {}", method.as_stored(), listener.bind);
                opened = true;
            }
            Err(reason) => eprintln!("{}: {reason}", listener.bind),
        }
    }
    opened
}

/// Puts up the site a node shows anyone who is not a client of it.
///
/// Built from the node's own identifier, so this node looks the same every
/// time it is asked and no two nodes look alike. It answers on loopback: what
/// reaches it came through the front door on 443, which is on this machine.
async fn open_cover(node_id: uuid::Uuid, port: u16) -> bool {
    use sha2::{Digest, Sha256};

    let seed: [u8; 32] = Sha256::digest(node_id.as_bytes()).into();
    let site = std::sync::Arc::new(ap_cover::site(seed));
    match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
        Ok(bound) => {
            tokio::spawn(async move { ap_cover::serve(bound, site).await });
            println!("showing a site on 127.0.0.1:{port}");
            true
        }
        Err(reason) => {
            eprintln!("127.0.0.1:{port}: {reason}");
            false
        }
    }
}

/// Whether anything in this configuration is the engine's to serve.
/// Whether this node carries its clients inside a site of its own.
fn shows_a_site(config: &ap_proto::Config) -> bool {
    config
        .listeners
        .iter()
        .any(|listener| listener.method == "web")
}

fn needs_engine(config: &ap_proto::Config) -> bool {
    config
        .listeners
        .iter()
        .any(|listener| matches!(listener.method.as_str(), "faketls" | "web" | "mtproto"))
}

/// The salt the node counts devices by.
///
/// Drawn once per process and never written down: a digest taken with it means
/// nothing to another node or to this one after a restart, so the counts
/// cannot be joined up into a history of who was where.
fn fresh_salt() -> [u8; 32] {
    use rand::RngCore as _;

    let mut salt = [0u8; 32];
    rand::rng().fill_bytes(&mut salt);
    salt
}

/// What the node says about itself.
///
/// The probes open connections and hold file descriptors, which are exactly
/// what a machine under pressure is short of. So they run only while the
/// machine is calm; otherwise the node repeats what it last found, and a node
/// that has never found anything says it was not asked.
async fn state_of_health(
    control: &Control,
    posture: &Posture,
    pressure: host::Pressure,
    last_probe: &mut Option<(Site, Reach)>,
) -> ap_proto::Health {
    let (site, reach) = if pressure.eases_off() {
        last_probe.unwrap_or((Site::Unknown, Reach::Unknown))
    } else {
        // The site is asked of the front door, the way a visitor asks, and
        // only on a node that shows one. A node with no site to show has none
        // to be down, and saying "unknown" there is the truth rather than a
        // shrug.
        let site = match site_of(posture) {
            Some(domain) => ap_agent::probe::site(&domain).await,
            None => Site::Unknown,
        };

        // Asked of every node, whatever it serves. A node carrying SOCKS5 or
        // HTTP is carrying Telegram through them, so the path out matters
        // there too.
        let reach = if ap_agent::probe::reaches_telegram().await {
            Reach::Open
        } else {
            Reach::Blocked
        };
        *last_probe = Some((site, reach));
        (site, reach)
    };

    health::report(control, site, reach, None)
        .await
        .unwrap_or(ap_proto::Health {
            engine: "down".to_owned(),
            site: site.as_reported().to_owned(),
            reach: reach.as_reported().to_owned(),
            cert_not_after: None,
        })
}

/// The name this node serves a site on, when it serves one.
fn site_of(posture: &Posture) -> Option<String> {
    let Posture::Serving(running) = posture else {
        return None;
    };
    if running.node.kind != "web" {
        return None;
    }
    running
        .node
        .domain
        .as_deref()
        .filter(|domain| !domain.is_empty())
        .map(str::to_owned)
}

/// Brings the engine to what the panel just sent.
///
/// The configuration file is rewritten and the users are reconciled through
/// the control API, which the engine applies without restarting. Withdrawals
/// go first, so a revoked access stops working before anything is added.
async fn settle(
    paths: &Paths,
    settings: &ap_engine::config::Settings,
    control: &Control,
    config: &ap_proto::Config,
) {
    if let Err(reason) = engine::write_config(paths, settings, config) {
        eprintln!("engine configuration: {reason}");
        return;
    }

    let present = match control.present().await {
        Ok(present) => present,
        Err(reason) => {
            eprintln!("engine users: {reason}");
            return;
        }
    };
    let steps = match ap_engine::reconcile::plan(&config.accesses, &present) {
        Ok(steps) => steps,
        Err(reason) => {
            eprintln!("engine plan: {reason}");
            return;
        }
    };
    for step in &steps {
        if let Err(reason) = control.take(step).await {
            eprintln!("engine step: {reason}");
        }
    }
}

fn report(posture: &Posture) {
    match posture {
        Posture::Serving(config) => {
            println!("serving revision {}", config.revision);
        }
        Posture::SiteOnly(Silent::CacheExpired) => {
            eprintln!(
                "the configuration is past the life the panel gave it: \
                 proxy paths are down, the site keeps answering"
            );
        }
        Posture::SiteOnly(Silent::NoCacheKey) => {
            eprintln!("no key for the cache yet: proxy paths are down, the site keeps answering");
        }
        Posture::SiteOnly(Silent::NoConfig) => {
            eprintln!("no configuration yet: proxy paths are down, the site keeps answering");
        }
    }
}
