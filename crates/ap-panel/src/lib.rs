//! REST for the panel.
//!
//! The listener binds to loopback unless told otherwise: this service holds
//! every secret in the system, and a port on the open internet is reachable by
//! scanners, opportunists and a targeted attacker at once.

mod auth;
pub mod bot;
pub mod ca;
pub mod channel;
pub mod enrollment;
mod error;
pub mod feed;
mod guard;
pub mod handout;
mod own;
mod routes;
pub mod settings;

pub use error::ApiError;
pub use guard::{Actor, DEFAULT_PAGE, Guarded, MAX_PAGE};

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use ap_core::KeyStore;
use sqlx::PgPool;

/// Where the panel listens and what it opens.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address for the REST listener.
    pub bind: SocketAddr,
    /// Connection string for the database.
    pub database_url: String,
    /// File holding the key that seals secrets.
    pub key_file: std::path::PathBuf,
    /// The address agents dial, as an operator should type it (0065).
    ///
    /// Empty, or a bare `:port`, when the channel listens on no particular
    /// address: the interface then reads the host from the panel it is
    /// already looking at.
    pub channel_address: String,
    /// Where the bot talks to Telegram (0081). [`BOT_API`] outside tests; a
    /// test points it at a double on the loopback.
    pub bot_api: String,
}

/// The Bot API, where it really is.
pub const BOT_API: &str = "https://api.telegram.org";

impl Config {
    /// Loopback and nothing else, which is the only safe default.
    pub fn loopback(port: u16, database_url: String, key_file: std::path::PathBuf) -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], port)),
            database_url,
            key_file,
            channel_address: String::new(),
            bot_api: BOT_API.to_owned(),
        }
    }
}

/// Everything a handler is allowed to reach.
///
/// The pool is private on purpose: a handler cannot take it out and query
/// directly, so every read and write passes the permission checks in
/// [`Guarded`].
#[derive(Clone)]
pub struct AppState {
    pool: PgPool,
    key: Arc<KeyStore>,
    authority: Arc<ca::Authority>,
    attempts: Arc<auth::Attempts>,
    channel_address: Arc<str>,
    bot_api: Arc<str>,
    bot: Arc<bot::Status>,
    /// When this process started answering, for the figure the foot of the
    /// dashboard was drawn with.
    started: std::time::Instant,
}

impl AppState {
    /// Opens the database and reads the key.
    ///
    /// Refuses to build if the key cannot be read: running with unreadable
    /// secrets means handing out links that do not work, silently.
    pub async fn build(config: &Config) -> Result<Self, String> {
        let key = KeyStore::from_file(Path::new(&config.key_file))
            .map_err(|error| format!("key file: {error}"))?;
        let pool = ap_store::connect(&config.database_url, 16)
            .await
            .map_err(|error| format!("database: {error}"))?;
        ap_store::migrate(&pool)
            .await
            .map_err(|error| format!("migrations: {error}"))?;
        let authority = ca::Authority::load_or_create(&pool, &key).await?;
        Ok(Self {
            pool,
            key: Arc::new(key),
            authority: Arc::new(authority),
            attempts: Arc::new(auth::Attempts::default()),
            channel_address: Arc::from(config.channel_address.as_str()),
            bot_api: Arc::from(config.bot_api.as_str()),
            bot: Arc::new(bot::Status::default()),
            started: std::time::Instant::now(),
        })
    }

    /// The only door to the database.
    pub fn guarded<'a>(&'a self, actor: &'a Actor) -> Guarded<'a> {
        Guarded::new(&self.pool, &self.key, actor)
    }

    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub(crate) fn key(&self) -> &KeyStore {
        &self.key
    }

    /// The authority that signs agent certificates.
    pub fn authority(&self) -> &ca::Authority {
        &self.authority
    }

    /// The authority, shared, for the agent channel.
    pub fn authority_handle(&self) -> Arc<ca::Authority> {
        Arc::clone(&self.authority)
    }

    /// The address agents dial, as the operator should type it (0065).
    pub(crate) fn channel_address(&self) -> &str {
        &self.channel_address
    }

    /// How long this process has been answering, in seconds.
    pub(crate) fn uptime_seconds(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// Where the bot talks to Telegram.
    pub(crate) fn bot_api(&self) -> &str {
        &self.bot_api
    }

    /// What the bot is doing right now (0085).
    pub fn bot_status(&self) -> &bot::Status {
        &self.bot
    }

    pub(crate) fn attempts(&self) -> &auth::Attempts {
        &self.attempts
    }
}

/// Builds the router.
pub fn router(state: AppState) -> axum::Router {
    routes::router(state)
}

/// Builds the router of the feed the public site reads (0091).
///
/// Served on a listener of its own, never on the one [`router`] is served on.
pub fn feed_router(state: AppState) -> axum::Router {
    feed::router(state)
}

/// Serves until the process is stopped.
pub async fn serve(config: Config) -> Result<(), String> {
    let state = AppState::build(&config).await?;
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|error| format!("bind {}: {error}", config.bind))?;
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|error| format!("serve: {error}"))
}

/// What became of an attempt to set the panel up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirstAdmin {
    /// The account was created; the second-factor secret, if it has one, is
    /// here and nowhere else.
    Created(Option<String>),
    /// Somebody already owns this panel.
    AlreadySetUp,
}

/// Assembles an administrator and the secret to be shown once.
fn build_admin(
    state: &AppState,
    login: &str,
    password: &str,
    role: ap_core::Role,
    second_factor: bool,
) -> Result<(ap_core::AdminUser, Option<String>), String> {
    use ap_core::{AdminLogin, AdminUser, Encrypted};

    let login = AdminLogin::try_from(login).map_err(|error| error.to_string())?;
    let hash = auth::hash_password(password).map_err(|_| "password".to_owned())?;
    let secret = second_factor.then(auth::new_totp_secret);
    let sealed = match &secret {
        Some(secret) => {
            Some(Encrypted::seal(secret, state.key()).map_err(|error| error.to_string())?)
        }
        None => None,
    };
    let admin = AdminUser::new(login, hash, sealed, role, time::OffsetDateTime::now_utc())
        .map_err(|error| error.to_string())?;
    Ok((admin, secret))
}

/// Registers an administrator, with or without a second factor (0060).
///
/// The secret is generated here rather than accepted from the caller, and
/// returned once: it is sealed on the way to the database and cannot be read
/// back. An account created without one is entered with a password alone.
pub async fn create_admin(
    state: &AppState,
    login: &str,
    password: &str,
    role: ap_core::Role,
    second_factor: bool,
) -> Result<Option<String>, String> {
    let (admin, secret) = build_admin(state, login, password, role, second_factor)?;
    ap_store::AdminRepo::insert(state.pool(), &admin)
        .await
        .map_err(|error| error.to_string())?;
    Ok(secret)
}

/// Registers the administrator the panel is first opened by (0062).
///
/// Succeeds only while the panel has none. There is no command and no other
/// door: whoever reaches the panel before anyone else has been set up becomes
/// its owner, and everyone after that is told it is taken.
pub async fn set_up(
    state: &AppState,
    login: &str,
    password: &str,
    second_factor: bool,
) -> Result<FirstAdmin, String> {
    let (admin, secret) = build_admin(
        state,
        login,
        password,
        ap_core::Role::Superadmin,
        second_factor,
    )?;
    let created = ap_store::AdminRepo::insert_first(state.pool(), &admin)
        .await
        .map_err(|error| error.to_string())?;
    Ok(if created {
        FirstAdmin::Created(secret)
    } else {
        FirstAdmin::AlreadySetUp
    })
}
