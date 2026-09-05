use std::io::Read as _;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// The panel: operator interface and agent channel.
#[derive(Parser)]
#[command(name = "anyproxy-panel", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Serves the operator interface and the agent channel. The default.
    Serve,
    /// Creates an administrator and prints the second-factor secret once.
    ///
    /// The password is read from standard input, never from an argument: an
    /// argument reaches the shell history and the process list, where anyone
    /// on the machine can read it.
    AddAdmin {
        /// Name the administrator signs in with.
        login: String,
        /// What they may do: superadmin, operator or reseller.
        #[arg(long, default_value = "superadmin")]
        role: String,
        /// Create the account without a second factor: a password is then
        /// the whole of what stands between anyone and every secret this
        /// panel holds.
        #[arg(long)]
        no_second_factor: bool,
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

    let config = ap_panel::Config {
        bind: std::env::var("ANYPROXY_PANEL_BIND")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| ([127, 0, 0, 1], 8080).into()),
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        key_file: std::env::var("ANYPROXY_KEY_FILE")
            .map(PathBuf::from)
            .unwrap_or_default(),
    };

    let channel_bind = std::env::var("ANYPROXY_CHANNEL_BIND")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| ([0, 0, 0, 0], 8443).into());

    let outcome = match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => runtime.block_on(run(config, channel_bind)),
        Command::AddAdmin {
            login,
            role,
            no_second_factor,
        } => runtime.block_on(add_admin(config, &login, &role, !no_second_factor)),
    };

    if let Err(reason) = outcome {
        eprintln!("{reason}");
        std::process::exit(1);
    }
}

/// Creates the administrator the panel is first reached with.
async fn add_admin(
    config: ap_panel::Config,
    login: &str,
    role: &str,
    second_factor: bool,
) -> Result<(), String> {
    let role = match role {
        "superadmin" => ap_core::Role::Superadmin,
        "operator" => ap_core::Role::Operator,
        "reseller" => ap_core::Role::Reseller,
        other => return Err(format!("unknown role: {other}")),
    };

    let mut password = String::new();
    std::io::stdin()
        .read_to_string(&mut password)
        .map_err(|error| format!("password: {error}"))?;
    let password = password.trim_end();
    if password.is_empty() {
        return Err("the password was empty".to_owned());
    }

    let state = ap_panel::AppState::build(&config).await?;
    let secret = ap_panel::create_admin(&state, login, password, role, second_factor).await?;

    // Shown once. It is not stored in a form anyone can read back, so an
    // operator who loses it needs a new administrator rather than a reminder.
    // An account created without a second factor has nothing to show.
    if let Some(secret) = secret {
        println!("{secret}");
    }
    Ok(())
}

/// Serves the operator interface and the agent channel side by side.
///
/// They are separate listeners on purpose: the first binds to loopback and
/// holds every secret, the second faces the nodes and must be reachable.
async fn run(config: ap_panel::Config, channel_bind: std::net::SocketAddr) -> Result<(), String> {
    let state = ap_panel::AppState::build(&config).await?;
    let authority = state.authority_handle();

    let rest = {
        let state = state.clone();
        let bind = config.bind;
        async move {
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .map_err(|error| format!("bind {bind}: {error}"))?;
            axum::serve(listener, ap_panel::router(state))
                .await
                .map_err(|error| format!("serve: {error}"))
        }
    };

    let channel = async move {
        let listener = tokio::net::TcpListener::bind(channel_bind)
            .await
            .map_err(|error| format!("bind {channel_bind}: {error}"))?;
        ap_panel::channel::serve(state, authority, listener).await
    };

    tokio::select! {
        outcome = rest => outcome,
        outcome = channel => outcome,
    }
}
