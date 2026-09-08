//! The bot for the panel's users (0080).
//!
//! A task beside the REST listener and the agent channel. It opens no port:
//! it asks Telegram for updates with a long poll and answers what it is
//! asked, using the same code the panel's own endpoints use. Whether it runs
//! at all, and as whom, is a setting (0085).

pub mod api;
mod talk;

use std::sync::Mutex;
use std::time::Duration;

use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::{ApiError, AppState};
pub use api::{BotApi, Fault};
pub use talk::{Incoming, answer};

/// How long a poll waits for an update before returning empty-handed.
const POLL_WAIT: u64 = 25;

/// How long to wait before looking at the settings again while off.
const IDLE: Duration = Duration::from_secs(10);

/// What the bot is doing, in one word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Standing {
    /// Not running: switched off, or no token.
    #[default]
    Off,
    /// Asking Telegram for updates and answering them.
    Polling,
    /// Telegram does not know the token it was given.
    Refused,
    /// Telegram is not answering.
    Unreachable,
}

impl Standing {
    /// The word, as the screen and the journal get it.
    pub fn as_stored(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Polling => "polling",
            Self::Refused => "refused",
            Self::Unreachable => "unreachable",
        }
    }
}

#[derive(Debug, Default)]
struct Inner {
    standing: Standing,
    username: Option<String>,
    token_digest: Option<Vec<u8>>,
}

/// What the bot is doing right now, for the screen (0085).
///
/// Process memory, like the count of sign-in attempts: after a restart it
/// is found out again by the first call to Telegram.
#[derive(Debug, Default)]
pub struct Status {
    inner: Mutex<Inner>,
}

impl Status {
    /// The standing and the name the bot answers under, if known.
    pub fn snapshot(&self) -> (Standing, Option<String>) {
        match self.inner.lock() {
            Ok(inner) => (inner.standing, inner.username.clone()),
            Err(_) => (Standing::Off, None),
        }
    }

    /// Records a standing. Whether it differs from the one before.
    fn set(&self, standing: Standing, username: Option<String>) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        let changed = inner.standing != standing || inner.username != username;
        inner.standing = standing;
        inner.username = username;
        changed
    }

    /// Whether Telegram should be asked who the bot is before polling: the
    /// token is new, or the bot was not polling a moment ago.
    fn needs_hello(&self, token_digest: &[u8]) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return true;
        };
        let fresh = inner.token_digest.as_deref() != Some(token_digest);
        inner.token_digest = Some(token_digest.to_vec());
        fresh || inner.standing != Standing::Polling
    }
}

/// Why a turn stopped.
#[derive(Debug)]
pub enum Trouble {
    /// On the way to Telegram or back.
    Telegram(Fault),
    /// In the panel itself.
    Panel(ApiError),
}

impl From<Fault> for Trouble {
    fn from(fault: Fault) -> Self {
        Self::Telegram(fault)
    }
}

impl From<ApiError> for Trouble {
    fn from(error: ApiError) -> Self {
        Self::Panel(error)
    }
}

/// Runs the bot until the process stops.
///
/// Never returns and never gives up: a token that is refused today may be
/// replaced on the settings screen in a minute, and the loop reads the
/// settings again before every turn.
pub async fn serve(state: AppState) {
    loop {
        let pause = turn(&state).await;
        tokio::time::sleep(pause).await;
    }
}

/// One turn: read the settings, and either poll once or say why not.
/// Returns how long to wait before the next.
async fn turn(state: &AppState) -> Duration {
    let settings = match crate::settings::Settings::read(state.pool()).await {
        Ok(settings) => settings,
        Err(_) => return IDLE,
    };
    let token = if settings.on("bot_enabled") {
        ap_store::SealedSettingRepo::open(state.pool(), "bot_token", state.key())
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    let Some(token) = token.filter(|token| !token.is_empty()) else {
        note(state, Standing::Off, None).await;
        return IDLE;
    };
    let api = match BotApi::new(state.bot_api(), &token) {
        Ok(api) => api,
        Err(_) => {
            note(state, Standing::Unreachable, None).await;
            return IDLE;
        }
    };

    if state
        .bot_status()
        .needs_hello(&Sha256::digest(token.as_bytes()))
    {
        match api.get_me().await {
            Ok(username) => note(state, Standing::Polling, Some(username)).await,
            Err(Fault::Unauthorized) => {
                note(state, Standing::Refused, None).await;
                return Duration::from_secs(60);
            }
            Err(_) => {
                note(state, Standing::Unreachable, None).await;
                return IDLE;
            }
        }
    }

    match step(state, &api).await {
        Ok(_) => Duration::ZERO,
        Err(Trouble::Telegram(Fault::Unauthorized)) => {
            note(state, Standing::Refused, None).await;
            Duration::from_secs(60)
        }
        Err(Trouble::Telegram(_)) => {
            note(state, Standing::Unreachable, None).await;
            IDLE
        }
        Err(Trouble::Panel(_)) => IDLE,
    }
}

/// Records what the bot is doing, and writes the change to the journal —
/// one line per change, not one per turn (0085).
async fn note(state: &AppState, standing: Standing, username: Option<String>) {
    if !state.bot_status().set(standing, username.clone()) {
        return;
    }
    let _ = ap_store::AuditRepo::record(
        state.pool(),
        None,
        "bot.state",
        Some(standing.as_stored()),
        OffsetDateTime::now_utc(),
        serde_json::json!({ "by": "panel", "bot": username }),
    )
    .await;
}

/// One poll: takes the updates after the cursor, answers each, and moves
/// the cursor past them (0087). How many were answered.
pub async fn step(state: &AppState, api: &BotApi) -> Result<usize, Trouble> {
    let cursor = ap_store::BotRepo::cursor(state.pool())
        .await
        .map_err(ApiError::from)?;
    let updates = api.get_updates(cursor, POLL_WAIT).await?;
    let mut next = cursor;
    let mut answered = 0;
    for update in updates {
        next = next.max(update.update_id + 1);
        let Some(incoming) = Incoming::from_update(update) else {
            continue;
        };
        let replies = answer(state, &incoming).await?;
        for text in replies {
            api.send_message(incoming.chat_id, &text).await?;
        }
        answered += 1;
    }
    if next != cursor {
        ap_store::BotRepo::move_cursor(state.pool(), next, OffsetDateTime::now_utc())
            .await
            .map_err(ApiError::from)?;
    }
    Ok(answered)
}
