use std::path::PathBuf;
use std::time::Duration;

use ap_agent::identity::Paths;
use ap_agent::meter::Meter;
use ap_agent::posture::{Posture, Silent};
use ap_agent::{AgentError, backoff, engine, identity, link, session};
use ap_engine::control::Control;
use ap_engine::health::{self, Site};
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
    match cli.command {
        Command::Enroll {
            panel,
            code,
            fingerprint,
        } => enrol(&paths, &panel, &code, &fingerprint).await,
        Command::Run { panel } => serve(&paths, &panel).await,
    }
}

async fn enrol(
    paths: &Paths,
    panel: &str,
    code: &str,
    fingerprint: &str,
) -> Result<(), AgentError> {
    // The pin is checked while the connection is being established, so a panel
    // that is not the pinned one never sees the code.
    let mut channel = link::connect(panel, fingerprint, None).await?;
    let identity = session::enrol(&mut channel, code).await?;
    identity::store(paths, &identity)?;
    println!("enrolled as node {}", identity.node_id);
    Ok(())
}

async fn serve(paths: &Paths, panel: &str) -> Result<(), AgentError> {
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

    let mut applied_revision = None;
    let mut attempt = 0u32;
    let mut meter = Meter::new();

    loop {
        if let Some(child) = engine_process.as_mut()
            && matches!(child.try_wait(), Ok(Some(_)))
        {
            // It stopped on its own. The next configuration starts it again;
            // until then the cover site is what answers.
            eprintln!("the engine stopped");
            engine_process = None;
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
            &inbound,
            &mut inbound_open,
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
    inbound: &std::sync::Arc<Registry>,
    inbound_open: &mut bool,
) -> Result<Option<uuid::Uuid>, AgentError> {
    let mut channel = link::connect(panel, fingerprint, Some(identity)).await?;
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
        match engine_process {
            Some(_) => settle(paths, settings, control, running).await,
            // An open node serves logins and never runs the engine. Starting
            // it to watch it refuse the configuration would be a failure
            // reported every minute for something nobody asked for.
            None if needs_engine(running) => match engine::start(paths, settings, running) {
                Ok(child) => *engine_process = Some(child),
                Err(reason) => eprintln!("the engine did not start: {reason}"),
            },
            None => {}
        }
    }

    // Whichever comes first: the panel says something, or it is time to read
    // the counters again.
    let heartbeat = Duration::from_secs(
        u64::from(state.heartbeat_secs.max(1)).min(engine::READING_INTERVAL_SECS),
    );
    loop {
        let received = tokio::time::timeout(heartbeat, channel.receive()).await;
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
                    settle(paths, settings, control, running).await;
                }
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
                measure(control, metrics_port, meter, inbound, now).await;
                if let Some(delivery) =
                    meter.delivery(state_of_health(control, &state.posture).await, now)
                {
                    session::deliver(&mut channel, meter, delivery).await?;
                }
            }
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

/// Whether anything in this configuration is the engine's to serve.
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
async fn state_of_health(control: &Control, posture: &Posture) -> ap_proto::Health {
    // The cover site is served by the front door, which does not exist yet, so
    // there is nothing to ask about it. Saying so is not saying it is down.
    let site = Site::Unknown;
    let _ = posture;
    health::report(control, site, None)
        .await
        .unwrap_or(ap_proto::Health {
            engine: "down".to_owned(),
            site: "unknown".to_owned(),
            cert_not_after: None,
        })
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
