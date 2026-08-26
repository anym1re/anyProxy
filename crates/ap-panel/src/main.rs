use std::path::PathBuf;

fn main() {
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
            axum::serve(listener, ap_panel::router(state))
                .await
                .map_err(|error| format!("serve: {error}"))
        }
    };

    let channel = ap_panel::channel::serve(state, authority, channel_bind);

    tokio::select! {
        outcome = rest => outcome,
        outcome = channel => outcome,
    }
}
