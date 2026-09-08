use std::net::SocketAddr;
use std::sync::Arc;

use ap_core::Locale;
use clap::Parser;

/// The public site: the links an operator made public, for anyone.
///
/// Everything is read from the environment; there are no commands.
#[derive(Parser)]
#[command(name = "anyproxy-site", version, about)]
struct Cli {
    /// Public address of the site: https://name, nothing after the host.
    #[arg(long, env = "ANYPROXY_SITE_URL")]
    url: String,

    /// Address of the panel's feed: http://host:port, reached over a tunnel.
    #[arg(long, env = "ANYPROXY_SITE_FEED")]
    feed: String,

    /// The public listener, behind the front on 443.
    #[arg(long, env = "ANYPROXY_SITE_BIND", default_value = "127.0.0.1:8081")]
    bind: SocketAddr,

    /// The listener for health and metrics, on loopback.
    #[arg(
        long,
        env = "ANYPROXY_SITE_ADMIN_BIND",
        default_value = "127.0.0.1:8091"
    )]
    admin_bind: SocketAddr,

    /// How often the feed is asked, in seconds.
    #[arg(long, env = "ANYPROXY_SITE_REFRESH", default_value_t = 60)]
    refresh: u64,

    /// Where / leads when the visitor states no preference: ru or en.
    #[arg(long, env = "ANYPROXY_SITE_DEFAULT_LANG", default_value = "ru")]
    default_lang: String,
}

fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let default_locale = match cli.default_lang.to_ascii_lowercase().as_str() {
        "ru" => Locale::Ru,
        "en" => Locale::En,
        _ => {
            tracing::error!("the default language must be ru or en");
            std::process::exit(2);
        }
    };
    let config = match ap_site::Config::build(
        &cli.url,
        &cli.feed,
        cli.bind,
        cli.admin_bind,
        cli.refresh,
        default_locale,
    ) {
        Ok(config) => config,
        Err(reason) => {
            tracing::error!(reason = %reason, "configuration refused");
            std::process::exit(2);
        }
    };

    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        std::process::exit(1);
    };
    if let Err(reason) = runtime.block_on(run(config)) {
        tracing::error!(reason = %reason, "stopped");
        std::process::exit(1);
    }
}

async fn run(config: ap_site::Config) -> Result<(), String> {
    let bind = config.bind;
    let admin_bind = config.admin_bind;
    let site = Arc::new(ap_site::Site::new(config).map_err(|error| error.to_string())?);

    let public = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|error| format!("bind {bind}: {error}"))?;
    let admin = tokio::net::TcpListener::bind(admin_bind)
        .await
        .map_err(|error| format!("bind {admin_bind}: {error}"))?;
    tracing::info!(public = %bind, admin = %admin_bind, "listening");

    let feed = tokio::spawn(ap_site::keep_fresh(Arc::clone(&site)));
    let serving = tokio::spawn(ap_site::serve::serve(public, Arc::clone(&site)));
    let watching = tokio::spawn(ap_site::admin::serve(admin, site));

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("stopping");
        }
        _ = feed => {}
        _ = serving => {}
        _ = watching => {}
    }
    Ok(())
}
