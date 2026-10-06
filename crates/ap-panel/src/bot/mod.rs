//! The bot for the panel's users (0080).
//!
//! A task beside the REST listener and the agent channel. It opens no port:
//! it asks Telegram for updates with a long poll and answers what it is
//! asked, using the same code the panel's own endpoints use. Whether it runs
//! at all, and as whom, is a setting (0085).

pub mod api;
pub mod outbox;
mod signup;
mod talk;

use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::{ApiError, AppState};
pub use api::{BotApi, Fault, Markup, Reply};
pub use signup::Pace;
pub use talk::{Incoming, answer};

/// How long a poll waits for an update before returning empty-handed.
const POLL_WAIT: u64 = 25;

/// How long to wait before looking at the settings again while off.
const IDLE: Duration = Duration::from_secs(10);

/// How often quotas and terms are looked at for warnings (0102).
const SCAN_EVERY: Duration = Duration::from_secs(600);

/// Least time between turns while there is more to send, so a long queue goes
/// out at a pace Telegram accepts rather than as fast as the loop can spin.
const PACE: Duration = Duration::from_secs(1);

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
    scanned_at: Option<Instant>,
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

    /// Whether it is time to look at quotas and terms again, and if so,
    /// marks it done now.
    fn scan_due(&self) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        let due = inner.scanned_at.is_none_or(|at| at.elapsed() >= SCAN_EVERY);
        if due {
            inner.scanned_at = Some(Instant::now());
        }
        due
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
            Ok(username) => {
                note(state, Standing::Polling, Some(username)).await;
                announce(&api).await;
            }
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

    if state.bot_status().scan_due() {
        let _ = outbox::scan(state).await;
    }

    // What is waiting goes first, and while more is waiting the poll does not
    // sit for its full wait: a long queue would otherwise drain at one batch
    // per quiet poll.
    let delivered = match outbox::deliver(state, &api).await {
        Ok(delivery) => delivery,
        Err(trouble) => return after(state, trouble).await,
    };
    if let Some(hold) = delivered.hold {
        return hold;
    }
    let wait = if delivered.more { 0 } else { POLL_WAIT };
    match step(state, &api, wait).await {
        Ok(_) if delivered.more => PACE,
        Ok(_) => Duration::ZERO,
        Err(trouble) => after(state, trouble).await,
    }
}

/// Tells Telegram which commands the bot answers, in each language it
/// speaks and once more for everybody else (0106). A list that did not get
/// through costs a person the hint beside the box they type in and nothing
/// more, so a failure here stops nothing.
async fn announce(api: &BotApi) {
    for locale in ap_core::Locale::all() {
        let _ = api
            .set_commands(&talk::commands(locale), Some(locale.code()))
            .await;
    }
    let _ = api
        .set_commands(&talk::commands(ap_core::Locale::default()), None)
        .await;
}

/// What a turn that stopped on trouble waits before the next.
async fn after(state: &AppState, trouble: Trouble) -> Duration {
    match trouble {
        Trouble::Telegram(Fault::Unauthorized) => {
            note(state, Standing::Refused, None).await;
            Duration::from_secs(60)
        }
        // Asked to slow down: not a fault of the bot's, nothing to report.
        Trouble::Telegram(Fault::Slow(seconds)) => Duration::from_secs(seconds),
        Trouble::Telegram(_) => {
            note(state, Standing::Unreachable, None).await;
            IDLE
        }
        Trouble::Panel(_) => IDLE,
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
/// the cursor past them (0087). How many were answered. The poll waits up to
/// `wait_secs` for an update to arrive.
pub async fn step(state: &AppState, api: &BotApi, wait_secs: u64) -> Result<usize, Trouble> {
    let cursor = ap_store::BotRepo::cursor(state.pool())
        .await
        .map_err(ApiError::from)?;
    let updates = api.get_updates(cursor, wait_secs).await?;
    let mut next = cursor;
    let mut answered = 0;
    for update in updates {
        next = next.max(update.update_id + 1);
        let Some(incoming) = Incoming::from_update(update) else {
            continue;
        };
        let replies = answer(state, &incoming).await?;
        for reply in &replies {
            api.send(incoming.chat_id, reply).await?;
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
