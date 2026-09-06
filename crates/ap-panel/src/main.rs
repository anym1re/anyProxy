use std::path::PathBuf;

use clap::Parser;

/// The panel: operator interface and agent channel.
///
/// It takes no commands. The administrator it is first opened by is created
/// on its own screen, once, and there is no other way in (0062).
#[derive(Parser)]
#[command(name = "anyproxy-panel", version, about)]
struct Cli;

fn main() {
    Cli::parse();
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
        channel_address: String::new(),
    };

    let channel_bind: std::net::SocketAddr = std::env::var("ANYPROXY_CHANNEL_BIND")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| ([0, 0, 0, 0], 8443).into());

    // What an operator should type to reach the channel. Told outright where
    // the listening address is not one a node could dial (0065).
    let config = ap_panel::Config {
        channel_address: std::env::var("ANYPROXY_CHANNEL_ADDRESS").unwrap_or_else(|_| {
            if channel_bind.ip().is_unspecified() {
                format!(":{}", channel_bind.port())
            } else {
                channel_bind.to_string()
            }
        }),
        ..config
    };

    if let Err(reason) = runtime.block_on(run(config, channel_bind)) {
        eprintln!("{reason}");
        std::process::exit(1);
    }
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
            axum::serve(
                listener,
                ap_panel::router(state)
                    .into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
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
