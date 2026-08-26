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

    if let Err(reason) = runtime.block_on(ap_panel::serve(config)) {
        eprintln!("{reason}");
        std::process::exit(1);
    }
}
