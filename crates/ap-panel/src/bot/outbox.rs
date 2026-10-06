//! What the bot writes first (0102): what goes on the queue, and sending it.
//!
//! Nothing here sends from inside a request. The panel's handlers put the
//! intent on the queue and return; the bot's own loop sends when it can, at a
//! pace Telegram accepts, and keeps what it could not send for later.

use std::time::Duration;

use ap_core::i18n::Argument;
use ap_core::{AccessState, Client, ClientState, Locale};
use ap_store::{AccessRepo, BotRepo, ClientRepo, NodeRepo, Outgoing, TrafficRepo};
use time::OffsetDateTime;
use uuid::Uuid;

use super::Trouble;
use super::api::{BotApi, Fault, Reply};
use super::talk::{bytes_words, date_words, links, method_of, method_words, record, say, say_with};
use crate::settings::Settings;
use crate::{ApiError, AppState};

/// Most messages sent in one turn. Telegram takes about thirty a second from
/// one bot; a turn is at least a second when there is more to send.
const BATCH: i64 = 20;

/// Failures before a message is given up on.
const ATTEMPTS: i32 = 5;

/// Longest text sent in one message, in UTF-16 units, which is how Telegram
/// counts; its own ceiling is 4096.
const MESSAGE_CEILING: usize = 4000;

/// Longest message an operator may write.
pub const OPERATOR_CEILING: usize = MESSAGE_CEILING;

// ── what goes on the queue ───────────────────────────────────────────────

/// Queues «your links changed» for every client the bot can reach that holds
/// an access on a node which is not revoked. How many were queued.
///
/// Called after a node's name or address changes. For a node being burned,
/// the clients are found before it is, with [`reachable_on_node`], because
/// burning revokes the accesses that tell who they were.
pub async fn links_changed_on_node(state: &AppState, node_id: Uuid) -> Result<usize, ApiError> {
    let clients = BotRepo::reachable_on_node(state.pool(), node_id).await?;
    links_changed_for(state, &clients).await
}

/// The clients [`links_changed_on_node`] would reach, read now.
pub async fn reachable_on_node(state: &AppState, node_id: Uuid) -> Result<Vec<Uuid>, ApiError> {
    Ok(BotRepo::reachable_on_node(state.pool(), node_id).await?)
}

/// Queues «your links changed» for these clients. Several changes in a row
/// come to one message: one is not queued while another is waiting.
pub async fn links_changed_for(state: &AppState, clients: &[Uuid]) -> Result<usize, ApiError> {
    let now = OffsetDateTime::now_utc();
    for client in clients {
        BotRepo::queue_links(state.pool(), *client, now).await?;
    }
    Ok(clients.len())
}

/// Queues «your links changed» for one client, when the bot can reach it.
pub async fn links_changed_for_client(state: &AppState, client_id: Uuid) -> Result<bool, ApiError> {
    let reachable = ClientRepo::by_id(state.pool(), client_id)
        .await?
        .is_some_and(|client| client.telegram_account().is_some());
    if reachable {
        links_changed_for(state, &[client_id]).await?;
    }
    Ok(reachable)
}

/// Queues an operator's message for each of these clients.
pub async fn operator_message(
    state: &AppState,
    clients: &[Uuid],
    text: &str,
) -> Result<usize, ApiError> {
    let now = OffsetDateTime::now_utc();
    let body = serde_json::json!({ "text": text });
    for client in clients {
        BotRepo::queue(state.pool(), *client, "operator", &body, now).await?;
    }
    Ok(clients.len())
}

// ── warnings ─────────────────────────────────────────────────────────────

/// One condition worth a warning, and what it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Warning {
    kind: &'static str,
    /// The value it is about: the quota in bytes, or the end of the term as
    /// a Unix time. A new value makes the warning possible again.
    about: String,
}

/// Which warning a quota and a term call for now, at most one of each.
fn due_warnings(
    quota: Option<i64>,
    used: i64,
    expires_at: Option<OffsetDateTime>,
    now: OffsetDateTime,
    percent: i64,
    days: i64,
) -> Vec<Warning> {
    let mut found = Vec::new();
    if let Some(quota) = quota.filter(|quota| *quota > 0) {
        if used >= quota {
            found.push(Warning {
                kind: "quota-spent",
                about: quota.to_string(),
            });
        } else if used.saturating_mul(100) >= quota.saturating_mul(percent) {
            found.push(Warning {
                kind: "quota-near",
                about: quota.to_string(),
            });
        }
    }
    if let Some(at) = expires_at {
        if now >= at {
            found.push(Warning {
                kind: "term-over",
                about: at.unix_timestamp().to_string(),
            });
        } else if at - now <= time::Duration::days(days) {
            found.push(Warning {
                kind: "term-near",
                about: at.unix_timestamp().to_string(),
            });
        }
    }
    found
}

/// Looks at every client the bot can reach, and queues each warning that has
/// come due and was not given before. How many were queued.
pub async fn scan(state: &AppState) -> Result<usize, ApiError> {
    let settings = Settings::read(state.pool()).await?;
    let percent = settings.number("bot_warn_quota_percent").clamp(1, 100);
    let days = settings.number("bot_warn_days").clamp(0, 365);
    let now = OffsetDateTime::now_utc();
    let mut queued = 0;
    for client in BotRepo::reachable(state.pool(), None).await? {
        if client.state() != ClientState::Active {
            continue;
        }
        let used = TrafficRepo::for_client(state.pool(), client.id())
            .await?
            .total();
        for warning in due_warnings(
            client.quota_bytes(),
            used,
            client.expires_at(),
            now,
            percent,
            days,
        ) {
            if BotRepo::warn_once(state.pool(), client.id(), warning.kind, &warning.about, now)
                .await?
            {
                let body = serde_json::json!({ "kind": warning.kind, "scope": "client" });
                BotRepo::queue(state.pool(), client.id(), "warning", &body, now).await?;
                queued += 1;
            }
        }
        for access in AccessRepo::by_client(state.pool(), client.id()).await? {
            let common = access.common();
            if common.state() != AccessState::Active {
                continue;
            }
            let used = TrafficRepo::for_access(state.pool(), common.id())
                .await?
                .total();
            for warning in due_warnings(
                common.quota_bytes(),
                used,
                common.expires_at(),
                now,
                percent,
                days,
            ) {
                if BotRepo::warn_once(state.pool(), common.id(), warning.kind, &warning.about, now)
                    .await?
                {
                    let body = serde_json::json!({
                        "kind": warning.kind,
                        "scope": "access",
                        "access": common.id(),
                    });
                    BotRepo::queue(state.pool(), client.id(), "warning", &body, now).await?;
                    queued += 1;
                }
            }
        }
    }
    Ok(queued)
}

/// The words for a warning, from what is true now. `None` when it no longer
/// applies — the access was taken away, or the node is gone.
async fn warning_words(
    state: &AppState,
    locale: Locale,
    client: &Client,
    body: &serde_json::Value,
) -> Result<Option<String>, ApiError> {
    let kind = body["kind"].as_str().unwrap_or_default();
    let (quota, used, expires_at, prefix) = if body["scope"] == "access" {
        let Some(id) = body["access"]
            .as_str()
            .and_then(|id| id.parse::<Uuid>().ok())
        else {
            return Ok(None);
        };
        let Some(access) = AccessRepo::by_id(state.pool(), id).await? else {
            return Ok(None);
        };
        let common = access.common();
        if common.state() == AccessState::Revoked {
            return Ok(None);
        }
        let Some(node) = NodeRepo::by_id(state.pool(), common.node_id()).await? else {
            return Ok(None);
        };
        let used = TrafficRepo::for_access(state.pool(), common.id())
            .await?
            .total();
        let method = method_words(locale, method_of(&access))?;
        (
            common.quota_bytes(),
            used,
            common.expires_at(),
            Some(format!("{} · {method}", node.label())),
        )
    } else {
        let used = TrafficRepo::for_client(state.pool(), client.id())
            .await?
            .total();
        (client.quota_bytes(), used, client.expires_at(), None)
    };

    let words = match kind {
        "quota-near" | "quota-spent" => {
            let Some(quota) = quota else {
                return Ok(None);
            };
            say_with(
                locale,
                &format!("bot-warn-{kind}"),
                &[
                    ("used", Argument::Text(&bytes_words(locale, used)?)),
                    ("quota", Argument::Text(&bytes_words(locale, quota)?)),
                ],
            )?
        }
        "term-near" | "term-over" => {
            let Some(at) = expires_at else {
                return Ok(None);
            };
            say_with(
                locale,
                &format!("bot-warn-{kind}"),
                &[("date", Argument::Text(&date_words(at)?))],
            )?
        }
        _ => return Ok(None),
    };
    Ok(Some(match prefix {
        Some(prefix) => say_with(
            locale,
            "bot-warn-access",
            &[
                ("access", Argument::Text(&prefix)),
                ("words", Argument::Text(&words)),
            ],
        )?,
        None => words,
    }))
}

// ── sending ──────────────────────────────────────────────────────────────

/// How long a text is to Telegram: a character beyond the basic plane, which
/// most emoji are, counts twice.
fn units(text: &str) -> usize {
    text.encode_utf16().count()
}

/// Pieces no longer than a message may be, split between parts. A part too
/// long for one message goes in several rather than being cut short: an
/// operator's 4000 characters of emoji are 8000 units.
fn messages(parts: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in parts {
        match out.last_mut() {
            Some(last) if units(last) + 2 + units(&part) <= MESSAGE_CEILING => {
                last.push_str("\n\n");
                last.push_str(&part);
            }
            _ => out.extend(pieces(&part)),
        }
    }
    out
}

/// One text in as few messages as it fits in.
fn pieces(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut piece = String::new();
    let mut size = 0;
    for ch in text.chars() {
        if size + ch.len_utf16() > MESSAGE_CEILING {
            out.push(std::mem::take(&mut piece));
            size = 0;
        }
        piece.push(ch);
        size += ch.len_utf16();
    }
    if !piece.is_empty() {
        out.push(piece);
    }
    out
}

/// What to write for one queued message, from what is true now. Empty when
/// there is nothing to say any more.
async fn words_for(
    state: &AppState,
    locale: Locale,
    client: &Client,
    outgoing: &Outgoing,
) -> Result<Vec<Reply>, ApiError> {
    Ok(match outgoing.kind.as_str() {
        // A client that is not served has no links to be told about.
        "links" if client.state() == ClientState::Active => {
            // Each link keeps its own message, because the button that
            // opens it hangs on the message (0106); what the message is
            // about goes on top of the first.
            let mut replies = links(state, locale, client).await?;
            let header = say(locale, "bot-links-changed")?;
            match replies.first_mut() {
                Some(first) => first.text = format!("{header}\n\n{}", first.text),
                None => replies.push(Reply::plain(header)),
            }
            replies
        }
        "warning" if client.state() == ClientState::Active => {
            warning_words(state, locale, client, &outgoing.body)
                .await?
                .into_iter()
                .map(Reply::plain)
                .collect()
        }
        "operator" => outgoing.body["text"]
            .as_str()
            .map(|text| {
                messages(vec![text.to_owned()])
                    .into_iter()
                    .map(Reply::plain)
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    })
}

/// How long to wait before trying a message again after it failed.
fn backoff(attempts: i32) -> time::Duration {
    let seconds = 30i64.saturating_mul(1i64 << attempts.clamp(0, 7));
    time::Duration::seconds(seconds.min(3600))
}

/// Writes a failure the bot is responsible for, by the client's name.
async fn failed(state: &AppState, client: &Client, kind: &str, why: &str) -> Result<(), ApiError> {
    record(
        state,
        "bot.message.failed",
        client.label().as_str(),
        serde_json::json!({ "kind": kind, "why": why }),
    )
    .await
}

/// What a round of sending came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivery {
    /// Messages sent.
    pub sent: usize,
    /// Whether more are due now, so the next turn should not wait.
    pub more: bool,
    /// How long Telegram asked the bot to wait, when it did.
    pub hold: Option<Duration>,
}

/// Sends what is due, a batch at most.
pub async fn deliver(state: &AppState, api: &BotApi) -> Result<Delivery, Trouble> {
    let now = OffsetDateTime::now_utc();
    let due = BotRepo::due(state.pool(), now, BATCH)
        .await
        .map_err(ApiError::from)?;
    let mut sent = 0;
    for outgoing in due {
        let client = ClientRepo::by_id(state.pool(), outgoing.client_id)
            .await
            .map_err(ApiError::from)?;
        // Untied, blocked or removed since it was queued: nothing to send to.
        let Some((client, sealed)) = client.and_then(|client| {
            let sealed = client.telegram_account().cloned()?;
            Some((client, sealed))
        }) else {
            BotRepo::done(state.pool(), outgoing.id, outgoing.revision)
                .await
                .map_err(ApiError::from)?;
            continue;
        };
        let Ok(account) = sealed.open(state.key()) else {
            BotRepo::done(state.pool(), outgoing.id, outgoing.revision)
                .await
                .map_err(ApiError::from)?;
            failed(state, &client, &outgoing.kind, "sealed").await?;
            continue;
        };
        let locale = Locale::from_code(account.language());
        let texts = words_for(state, locale, &client, &outgoing).await?;

        let mut outcome = Ok(());
        for text in &texts {
            outcome = api.send(account.chat(), text).await;
            if outcome.is_err() {
                break;
            }
        }
        match outcome {
            Ok(()) => {
                BotRepo::done(state.pool(), outgoing.id, outgoing.revision)
                    .await
                    .map_err(ApiError::from)?;
                // Nothing left to say is taken off, and is not a message sent.
                if !texts.is_empty() {
                    sent += 1;
                }
            }
            Err(Fault::Forbidden) => {
                // The person blocked the bot. Nothing more can go to them
                // until they write again, and then they are remembered anew.
                BotRepo::forget_account(state.pool(), client.id())
                    .await
                    .map_err(ApiError::from)?;
                BotRepo::done(state.pool(), outgoing.id, outgoing.revision)
                    .await
                    .map_err(ApiError::from)?;
                failed(state, &client, &outgoing.kind, "blocked").await?;
            }
            Err(Fault::Slow(seconds)) => {
                let hold = Duration::from_secs(seconds);
                BotRepo::hold(state.pool(), now + time::Duration::seconds(seconds as i64))
                    .await
                    .map_err(ApiError::from)?;
                return Ok(Delivery {
                    sent,
                    more: true,
                    hold: Some(hold),
                });
            }
            Err(Fault::Refused(why)) => {
                if outgoing.attempts + 1 >= ATTEMPTS {
                    BotRepo::done(state.pool(), outgoing.id, outgoing.revision)
                        .await
                        .map_err(ApiError::from)?;
                    failed(state, &client, &outgoing.kind, &why).await?;
                } else {
                    BotRepo::retry(state.pool(), outgoing.id, now + backoff(outgoing.attempts))
                        .await
                        .map_err(ApiError::from)?;
                }
            }
            Err(fault) => {
                // Telegram is out of reach or refuses the token: this message
                // waits, and so does everything after it.
                BotRepo::retry(state.pool(), outgoing.id, now + backoff(outgoing.attempts))
                    .await
                    .map_err(ApiError::from)?;
                return Err(Trouble::Telegram(fault));
            }
        }
    }
    let more = !BotRepo::due(state.pool(), OffsetDateTime::now_utc(), 1)
        .await
        .map_err(ApiError::from)?
        .is_empty();
    Ok(Delivery {
        sent,
        more,
        hold: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).unwrap()
    }

    #[test]
    fn a_quota_warns_near_its_end_and_again_when_spent() {
        let kinds = |used| {
            due_warnings(Some(1000), used, None, at(0), 90, 3)
                .into_iter()
                .map(|warning| warning.kind)
                .collect::<Vec<_>>()
        };
        assert!(kinds(899).is_empty());
        assert_eq!(kinds(900), ["quota-near"]);
        assert_eq!(kinds(1000), ["quota-spent"]);
        assert_eq!(kinds(5000), ["quota-spent"]);
    }

    #[test]
    fn a_term_warns_days_before_and_once_it_is_over() {
        let day = 86_400;
        let kinds = |now| {
            due_warnings(None, 0, Some(at(10 * day)), at(now), 90, 3)
                .into_iter()
                .map(|warning| warning.kind)
                .collect::<Vec<_>>()
        };
        assert!(kinds(6 * day).is_empty());
        assert_eq!(kinds(7 * day), ["term-near"]);
        assert_eq!(kinds(10 * day), ["term-over"]);
    }

    #[test]
    fn a_warning_is_about_the_value_it_was_given_for() {
        let before = due_warnings(Some(1000), 950, None, at(0), 90, 3);
        let raised = due_warnings(Some(2000), 1850, None, at(0), 90, 3);
        assert_ne!(
            before[0].about, raised[0].about,
            "a raised quota re-arms the warning"
        );
    }

    #[test]
    fn no_limit_warns_nothing() {
        assert!(due_warnings(None, i64::MAX, None, at(0), 90, 3).is_empty());
        assert!(due_warnings(Some(0), 10, None, at(0), 90, 3).is_empty());
    }

    #[test]
    fn long_answers_are_split_between_parts_not_inside_them() {
        let part = "x".repeat(1500);
        let split = messages(vec![part.clone(), part.clone(), part.clone()]);
        assert_eq!(split.len(), 2);
        assert!(split.iter().all(|one| units(one) <= MESSAGE_CEILING));
        assert_eq!(split[0], format!("{part}\n\n{part}"));
    }

    #[test]
    fn a_text_too_long_for_one_message_goes_whole_in_several() {
        // Four thousand emoji are within what an operator may write and twice
        // what one message holds.
        let text = "\u{1F642}".repeat(4000);
        let split = messages(vec![text.clone()]);
        assert_eq!(split.len(), 2);
        assert!(split.iter().all(|one| units(one) <= MESSAGE_CEILING));
        assert_eq!(split.concat(), text, "nothing is lost");

        let plain = messages(vec!["я".repeat(4000)]);
        assert_eq!(plain.len(), 1, "Cyrillic is one unit a letter");
    }

    #[test]
    fn waiting_grows_and_stops_at_an_hour() {
        assert_eq!(backoff(0), time::Duration::seconds(30));
        assert_eq!(backoff(1), time::Duration::seconds(60));
        assert_eq!(backoff(20), time::Duration::seconds(3600));
    }
}
