//! REST for the panel.
//!
//! The listener binds to loopback unless told otherwise: this service holds
//! every secret in the system, and a port on the open internet is reachable by
//! scanners, opportunists and a targeted attacker at once.

mod auth;
pub mod ca;
pub mod channel;
pub mod enrollment;
mod error;
mod guard;
mod routes;

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
}

impl Config {
    /// Loopback and nothing else, which is the only safe default.
    pub fn loopback(port: u16, database_url: String, key_file: std::path::PathBuf) -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], port)),
            database_url,
            key_file,
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

    pub(crate) fn attempts(&self) -> &auth::Attempts {
        &self.attempts
    }
}

/// Builds the router.
pub fn router(state: AppState) -> axum::Router {
    routes::router(state)
}

/// Serves until the process is stopped.
pub async fn serve(config: Config) -> Result<(), String> {
    let state = AppState::build(&config).await?;
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|error| format!("bind {}: {error}", config.bind))?;
    axum::serve(listener, router(state))
        .await
        .map_err(|error| format!("serve: {error}"))
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
    ap_store::AdminRepo::insert(state.pool(), &admin)
        .await
        .map_err(|error| error.to_string())?;
    Ok(secret)
}
