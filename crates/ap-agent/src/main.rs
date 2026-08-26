use std::path::PathBuf;
use std::time::Duration;

use ap_agent::identity::Paths;
use ap_agent::posture::{Posture, Silent};
use ap_agent::{AgentError, backoff, identity, link, session};
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

    let mut applied_revision = None;
    let mut attempt = 0u32;

    loop {
        match once(paths, panel, &fingerprint, &identity, applied_revision).await {
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
async fn once(
    paths: &Paths,
    panel: &str,
    fingerprint: &str,
    identity: &identity::Identity,
    applied_revision: Option<uuid::Uuid>,
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

    let heartbeat = Duration::from_secs(u64::from(state.heartbeat_secs.max(1)));
    loop {
        let received = tokio::time::timeout(heartbeat, channel.receive()).await;
        let now = OffsetDateTime::now_utc();

        match received {
            Ok(Ok(Some(Message::Config(config)))) => {
                session::apply(&mut channel, &mut state, paths, config, now).await?;
                report(&state.posture);
            }
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) => return Ok(state.applied_revision),
            Ok(Err(reason)) => return Err(reason),
            // Nothing arrived within the heartbeat. The connection may be gone
            // without having said so, and the cache may have run out.
            Err(_) => {
                let before = state.posture.is_serving();
                state.reconsider(paths, now)?;
                if before != state.posture.is_serving() {
                    report(&state.posture);
                }
            }
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
