//! What the panel is set to (0069).
//!
//! Figures that used to be constants in the code, and the switches of the
//! bot (0085). Each is read from the database when it is needed; there are a
//! handful of readers and each does one small query, which is cheaper than a
//! cache that can go stale while an operator watches the screen they just
//! changed.
//!
//! A setting that is a secret is kept sealed in a table of its own (0084).
//! It is never read into [`Settings`]: the one reader that needs it opens it
//! at the moment of use and nowhere else.

use crate::ApiError;
use sqlx::PgPool;

/// The two positions of a switch.
const SWITCH: &[&str] = &["on", "off"];

/// A setting the panel knows, with the value it has when nobody has set it.
pub struct Known {
    /// The name it is stored and asked for under.
    pub name: &'static str,
    /// What it is when nobody has said otherwise.
    pub fallback: &'static str,
    /// What may be chosen. Empty when the value is free text.
    pub choices: &'static [&'static str],
    /// Longest free text taken, in bytes. Ignored where there are choices.
    pub max: usize,
    /// Whether the value is kept sealed and never shown again (0084).
    pub secret: bool,
}

/// Every setting the panel has, in the order the screen draws them.
pub const KNOWN: &[Known] = &[
    Known {
        name: "channel_address",
        fallback: "",
        choices: &[],
        max: 200,
        secret: false,
    },
    Known {
        name: "loopback_only",
        fallback: "on",
        choices: SWITCH,
        max: 0,
        secret: false,
    },
    Known {
        name: "session_hours",
        fallback: "12",
        choices: &["4", "12", "24"],
        max: 0,
        secret: false,
    },
    Known {
        name: "heartbeat_secs",
        fallback: "30",
        choices: &["10", "30", "60"],
        max: 0,
        secret: false,
    },
    Known {
        name: "silence_minutes",
        fallback: "5",
        choices: &["2", "5", "15"],
        max: 0,
        secret: false,
    },
    Known {
        name: "default_ad_tag",
        fallback: "",
        choices: &[],
        max: 200,
        secret: false,
    },
    Known {
        name: "bot_enabled",
        fallback: "off",
        choices: SWITCH,
        max: 0,
        secret: false,
    },
    Known {
        name: "bot_token",
        fallback: "",
        choices: &[],
        max: 200,
        secret: true,
    },
    Known {
        name: "bot_greeting",
        fallback: "",
        choices: &[],
        max: 500,
        secret: false,
    },
    Known {
        name: "bot_show_usage",
        fallback: "on",
        choices: SWITCH,
        max: 0,
        secret: false,
    },
    Known {
        name: "bot_show_node",
        fallback: "on",
        choices: SWITCH,
        max: 0,
        secret: false,
    },
    // Whether an account that writes to the bot is given a client of its
    // own, and what that client starts with (0105). Nought is no limit.
    Known {
        name: "bot_signup",
        fallback: "on",
        choices: SWITCH,
        max: 0,
        secret: false,
    },
    Known {
        name: "bot_signup_quota_gb",
        fallback: "0",
        choices: &["0", "10", "50", "100", "500"],
        max: 0,
        secret: false,
    },
    Known {
        name: "bot_signup_days",
        fallback: "0",
        choices: &["0", "7", "30", "90", "365"],
        max: 0,
        secret: false,
    },
    Known {
        name: "bot_signup_devices",
        fallback: "0",
        choices: &["0", "1", "2", "3", "5"],
        max: 0,
        secret: false,
    },
    // At what share of a quota the bot warns the person, once (0102).
    Known {
        name: "bot_warn_quota_percent",
        fallback: "90",
        choices: &["80", "90", "95"],
        max: 0,
        secret: false,
    },
    // How many days before the end of a term the bot warns, once (0102).
    Known {
        name: "bot_warn_days",
        fallback: "3",
        choices: &["1", "3", "7"],
        max: 0,
        secret: false,
    },
];

/// The description of a setting, by name.
pub fn known(name: &str) -> Option<&'static Known> {
    KNOWN.iter().find(|known| known.name == name)
}

/// Whether a setting is one that is kept sealed.
pub fn is_secret(name: &str) -> bool {
    known(name).is_some_and(|known| known.secret)
}

/// The panel's settings as they stand, with anything unset left at its
/// fallback. Sealed settings are not among them.
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
                .filter(|one| !is_secret(&one.name))
                .map(|one| (one.name, one.value))
                .collect(),
        })
    }

    /// What a setting says, as text.
    pub fn text(&self, name: &str) -> &str {
        self.values
            .get(name)
            .map(String::as_str)
            .or_else(|| known(name).map(|known| known.fallback))
            .unwrap_or_default()
    }

    /// What a setting says, as a number. Falls back when it says nonsense,
    /// which a value written before a version change may.
    pub fn number(&self, name: &str) -> i64 {
        let said = self.text(name).parse().ok();
        said.unwrap_or_else(|| {
            known(name)
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
/// bounded so a stray paste cannot become a row of a hundred kilobytes. A
/// sealed setting takes an empty value too: that is how it is cleared.
pub fn acceptable(name: &str, value: &str) -> bool {
    let Some(known) = known(name) else {
        return false;
    };
    if known.choices.is_empty() {
        return value.len() <= known.max && !value.contains(['\n', '\r']);
    }
    known.choices.contains(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_text_is_bounded_by_its_own_setting() {
        assert!(acceptable("channel_address", &"a".repeat(200)));
        assert!(!acceptable("channel_address", &"a".repeat(201)));
        assert!(acceptable("bot_greeting", &"a".repeat(500)));
        assert!(!acceptable("bot_greeting", &"a".repeat(501)));
        assert!(!acceptable("bot_greeting", "two\nlines"));
    }

    #[test]
    fn a_switch_takes_its_two_positions_and_nothing_else() {
        for name in [
            "loopback_only",
            "bot_enabled",
            "bot_show_usage",
            "bot_show_node",
            "bot_signup",
        ] {
            assert!(acceptable(name, "on"), "{name}");
            assert!(acceptable(name, "off"), "{name}");
            assert!(!acceptable(name, "yes"), "{name}");
        }
    }

    #[test]
    fn the_token_is_the_one_sealed_setting_and_may_be_cleared() {
        assert!(is_secret("bot_token"));
        assert!(KNOWN.iter().filter(|known| known.secret).count() == 1);
        assert!(acceptable("bot_token", ""));
        assert!(acceptable("bot_token", "123456:abc"));
        assert!(!acceptable("bot_token", "with\nline"));
    }

    #[test]
    fn a_warning_threshold_is_one_of_its_steps() {
        assert!(acceptable("bot_warn_quota_percent", "90"));
        assert!(!acceptable("bot_warn_quota_percent", "85"));
        assert!(!acceptable("bot_warn_quota_percent", "90%"));
        assert!(acceptable("bot_warn_days", "7"));
        assert!(!acceptable("bot_warn_days", "0"));
    }

    #[test]
    fn a_name_nobody_knows_is_refused() {
        assert!(!acceptable("bot_colour", "blue"));
    }
}
