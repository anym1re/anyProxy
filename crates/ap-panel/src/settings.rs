//! What the panel is set to (0069).
//!
//! Six figures that used to be constants in the code. Each is read from the
//! database when it is needed; there are a handful of readers and each does
//! one small query, which is cheaper than a cache that can go stale while an
//! operator watches the screen they just changed.

use crate::ApiError;
use sqlx::PgPool;

/// A setting the panel knows, with the value it has when nobody has set it.
pub struct Known {
    /// The name it is stored and asked for under.
    pub name: &'static str,
    /// What it is when nobody has said otherwise.
    pub fallback: &'static str,
    /// What may be chosen. Empty when the value is free text.
    pub choices: &'static [&'static str],
}

/// Every setting the panel has, in the order the screen draws them.
pub const KNOWN: &[Known] = &[
    Known {
        name: "channel_address",
        fallback: "",
        choices: &[],
    },
    Known {
        name: "loopback_only",
        fallback: "on",
        choices: &["on", "off"],
    },
    Known {
        name: "session_hours",
        fallback: "12",
        choices: &["4", "12", "24"],
    },
    Known {
        name: "heartbeat_secs",
        fallback: "30",
        choices: &["10", "30", "60"],
    },
    Known {
        name: "silence_minutes",
        fallback: "5",
        choices: &["2", "5", "15"],
    },
    Known {
        name: "default_ad_tag",
        fallback: "",
        choices: &[],
    },
];

/// The panel's settings as they stand, with anything unset left at its
/// fallback.
#[derive(Debug, Clone)]
pub struct Settings {
    values: std::collections::HashMap<String, String>,
}

impl Settings {
    /// Reads them all.
    pub async fn read(pool: &PgPool) -> Result<Self, ApiError> {
        let stored = ap_store::SettingRepo::all(pool).await?;
        Ok(Self {
            values: stored
                .into_iter()
                .map(|one| (one.name, one.value))
                .collect(),
        })
    }

    /// What a setting says, as text.
    pub fn text(&self, name: &str) -> &str {
        self.values
            .get(name)
            .map(String::as_str)
            .or_else(|| {
                KNOWN
                    .iter()
                    .find(|known| known.name == name)
                    .map(|known| known.fallback)
            })
            .unwrap_or_default()
    }

    /// What a setting says, as a number. Falls back when it says nonsense,
    /// which a value written before a version change may.
    pub fn number(&self, name: &str) -> i64 {
        let said = self.text(name).parse().ok();
        said.unwrap_or_else(|| {
            KNOWN
                .iter()
                .find(|known| known.name == name)
                .and_then(|known| known.fallback.parse().ok())
                .unwrap_or(0)
        })
    }

    /// Whether a setting is on.
    pub fn on(&self, name: &str) -> bool {
        self.text(name) == "on"
    }
}

/// Whether a value may be stored under a name.
///
/// A setting with choices takes one of them and nothing else; free text is
/// bounded so a stray paste cannot become a row of a hundred kilobytes.
pub fn acceptable(name: &str, value: &str) -> bool {
    let Some(known) = KNOWN.iter().find(|known| known.name == name) else {
        return false;
    };
    if known.choices.is_empty() {
        return value.len() <= 200 && !value.contains(['\n', '\r']);
    }
    known.choices.contains(&value)
}
