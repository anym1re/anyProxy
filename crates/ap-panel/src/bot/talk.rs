//! What the bot says (0083).
//!
//! Every reply is built from the catalogue under `bot-*` keys, in the
//! language the account is set to. An account the panel does not know gets
//! the greeting and a request for a code, and nothing that would say whether
//! any client exists.

use ap_core::i18n::{Argument, message, message_with};
use ap_core::time::format_date;
use ap_core::{AccessState, AnyAccess, Client, ClientState, Locale, Node, NodeState};
use ap_store::{AccessRepo, AuditRepo, BotRepo, ClientRepo, NodeRepo, TrafficRepo};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use super::api::Update;
use crate::handout::{Handout, handout, host_of};
use crate::settings::Settings;
use crate::{ApiError, AppState};

/// A message the bot was sent, reduced to what it answers by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    /// The account that wrote. Never stored as such.
    pub user_id: i64,
    /// Where the answer goes.
    pub chat_id: i64,
    /// The language to answer in.
    pub locale: Locale,
    /// What was written.
    pub text: String,
}

impl Incoming {
    /// Reads an update, when it is a text message from somebody.
    pub fn from_update(update: Update) -> Option<Self> {
        let message = update.message?;
        let from = message.from?;
        let text = message.text?;
        Some(Self {
            user_id: from.id,
            chat_id: message.chat.id,
            locale: Locale::from_code(from.language_code.as_deref().unwrap_or_default()),
            text,
        })
    }
}

/// What was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Ask {
    /// `/start`, with the code from the operator when there is one.
    Start(Option<String>),
    /// The connection links.
    Links,
    /// Allowance, term and the nodes.
    Status,
    /// Take the account off the client.
    Unlink,
    /// Anything else.
    Help,
}

/// Whether a piece of text has the shape of a code: thirty-two hex digits.
fn looks_like_code(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse(text: &str) -> Ask {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix('/') {
        let mut words = rest.split_whitespace();
        // A command in a group carries the bot's name after an at-sign.
        let command = words
            .next()
            .unwrap_or_default()
            .split('@')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        return match command.as_str() {
            "start" => Ask::Start(words.next().map(str::to_owned)),
            "links" | "link" => Ask::Links,
            "status" => Ask::Status,
            "unlink" => Ask::Unlink,
            _ => Ask::Help,
        };
    }
    if looks_like_code(text) {
        Ask::Start(Some(text.to_owned()))
    } else {
        Ask::Help
    }
}

fn say(locale: Locale, key: &str) -> Result<String, ApiError> {
    message(locale, key).map_err(|_| ApiError::Internal("catalogue"))
}

fn say_with(locale: Locale, key: &str, args: &[(&str, Argument<'_>)]) -> Result<String, ApiError> {
    message_with(locale, key, args).map_err(|_| ApiError::Internal("catalogue"))
}

/// Bytes in the largest unit that keeps a digit before the point.
fn bytes_words(locale: Locale, bytes: i64) -> Result<String, ApiError> {
    const STEP: f64 = 1024.0;
    let mut value = bytes.max(0) as f64;
    let mut unit = "b";
    for next in ["kb", "mb", "gb", "tb"] {
        if value < STEP {
            break;
        }
        value /= STEP;
        unit = next;
    }
    let figure = if unit == "b" {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
    };
    // Russian writes a comma before the fraction.
    let figure = match locale {
        Locale::Ru => figure.replace('.', ","),
        Locale::En => figure,
    };
    say_with(
        locale,
        &format!("bot-bytes-{unit}"),
        &[("count", Argument::Text(&figure))],
    )
}

fn date_words(at: OffsetDateTime) -> Result<String, ApiError> {
    format_date(at.date()).map_err(ApiError::from)
}

/// How a node stands, in the user's terms.
fn node_words(locale: Locale, node: &Node) -> Result<String, ApiError> {
    let key = match node.state() {
        NodeState::Pending => "bot-node-pending",
        NodeState::Disabled => "bot-node-disabled",
        NodeState::Burned => "bot-node-gone",
        NodeState::Active => match node.health() {
            None => "bot-node-no-report",
            Some(_) if node.wants_attention() => "bot-node-trouble",
            Some(_) => "bot-node-ok",
        },
    };
    say(locale, key)
}

fn client_state_words(locale: Locale, state: ClientState) -> Result<String, ApiError> {
    say(locale, &format!("bot-client-{}", state.as_stored()))
}

fn access_state_words(locale: Locale, state: AccessState) -> Result<String, ApiError> {
    say(locale, &format!("bot-access-{}", state.as_stored()))
}

fn method_words(locale: Locale, method: &str) -> Result<String, ApiError> {
    say(locale, &format!("bot-method-{method}"))
}

/// The keyed digest an account is known by (0082).
fn digest_of(state: &AppState, user_id: i64) -> Vec<u8> {
    state
        .key()
        .digest(format!("telegram:{user_id}").as_bytes())
        .to_vec()
}

/// Writes a line the bot is responsible for. No operator behind it: the
/// journal says `by: bot` in the details (0075).
async fn record(
    state: &AppState,
    action: &str,
    target: &str,
    mut details: serde_json::Value,
) -> Result<(), ApiError> {
    if let Some(map) = details.as_object_mut() {
        map.insert("by".to_owned(), serde_json::json!("bot"));
    }
    AuditRepo::record(
        state.pool(),
        None,
        action,
        Some(target),
        OffsetDateTime::now_utc(),
        details,
    )
    .await?;
    Ok(())
}

/// Answers one message. The replies, in order, to send back.
pub async fn answer(state: &AppState, incoming: &Incoming) -> Result<Vec<String>, ApiError> {
    let locale = incoming.locale;
    let digest = digest_of(state, incoming.user_id);
    let known = BotRepo::client_of(state.pool(), &digest).await?;
    let settings = Settings::read(state.pool()).await?;

    match parse(&incoming.text) {
        Ask::Start(Some(code)) => Ok(vec![claim(state, incoming, &digest, &code).await?]),
        Ask::Start(None) => {
            let greeting = match settings.text("bot_greeting").trim() {
                "" => say(locale, "bot-hello")?,
                said => said.to_owned(),
            };
            let then = match &known {
                Some(client) => say_with(
                    locale,
                    "bot-linked-as",
                    &[("label", Argument::Text(client.label().as_str()))],
                )?,
                None => say(locale, "bot-ask-code")?,
            };
            Ok(vec![format!("{greeting}\n\n{then}")])
        }
        Ask::Links => match &known {
            Some(client) => links(state, locale, client).await,
            None => Ok(vec![say(locale, "bot-not-linked")?]),
        },
        Ask::Status => match &known {
            Some(client) => Ok(vec![status(state, locale, client, &settings).await?]),
            None => Ok(vec![say(locale, "bot-not-linked")?]),
        },
        Ask::Unlink => match &known {
            Some(client) => {
                BotRepo::unlink(state.pool(), client.id()).await?;
                record(
                    state,
                    "bot.unlinked",
                    client.label().as_str(),
                    serde_json::json!({}),
                )
                .await?;
                Ok(vec![say(locale, "bot-unlinked")?])
            }
            None => Ok(vec![say(locale, "bot-not-linked")?]),
        },
        Ask::Help => Ok(vec![say(locale, "bot-help")?]),
    }
}

/// Ties the account to the client a code was issued for.
///
/// A wrong, spent and expired code get one answer. Guesses are counted the
/// way sign-in attempts are, and held back the same way (Б13).
async fn claim(
    state: &AppState,
    incoming: &Incoming,
    digest: &[u8],
    code: &str,
) -> Result<String, ApiError> {
    let locale = incoming.locale;
    let subject = format!("telegram:{}", incoming.user_id);
    if let Some(wait) = state.attempts().record(&subject) {
        return say_with(
            locale,
            "bot-wait",
            &[("seconds", Argument::Number(wait as i64))],
        );
    }
    let now = OffsetDateTime::now_utc();
    let hash = Sha256::digest(code.trim().as_bytes());
    let Some(client_id) = BotRepo::claim_code(state.pool(), &hash, now).await? else {
        return say(locale, "bot-code-refused");
    };
    let linked = BotRepo::link(state.pool(), client_id, digest, now).await?;
    state.attempts().forget(&subject);
    let label = ClientRepo::by_id(state.pool(), client_id)
        .await?
        .map(|client| client.label().as_str().to_owned())
        .unwrap_or_else(|| client_id.to_string());
    if let Some(before) = &linked.moved_from {
        record(
            state,
            "bot.unlinked",
            before,
            serde_json::json!({ "moved_to": label }),
        )
        .await?;
    }
    record(state, "bot.linked", &label, serde_json::json!({})).await?;
    say_with(locale, "bot-linked", &[("label", Argument::Text(&label))])
}

/// One message per access the client may connect with.
///
/// Each is written to the journal before it is built, the way the panel's
/// own endpoint does it: no line, no link.
async fn links(state: &AppState, locale: Locale, client: &Client) -> Result<Vec<String>, ApiError> {
    if client.state() != ClientState::Active {
        return Ok(vec![client_state_words(locale, client.state())?]);
    }
    let accesses = AccessRepo::by_client(state.pool(), client.id()).await?;
    let mut said = Vec::new();
    for access in accesses
        .iter()
        .filter(|access| access.common().state() == AccessState::Active)
    {
        let common = access.common();
        let Some(node) = NodeRepo::by_id(state.pool(), common.node_id()).await? else {
            continue;
        };
        if node.state() == NodeState::Burned {
            continue;
        }
        let method = method_words(locale, method_of(access))?;
        let Some(host) = host_of(&node) else {
            said.push(say_with(
                locale,
                "bot-link-not-ready",
                &[
                    ("node", Argument::Text(node.label().as_str())),
                    ("method", Argument::Text(&method)),
                ],
            )?);
            continue;
        };
        let Some(credential) =
            AccessRepo::credential(state.pool(), common.id(), state.key()).await?
        else {
            continue;
        };
        record(
            state,
            "bot.link.rendered",
            &format!("{} · {}", client.label(), node.label()),
            serde_json::json!({ "access": common.id(), "host": host }),
        )
        .await?;
        said.push(match handout(access, &credential, node.kind(), &host)? {
            Handout::Link { link, .. } => say_with(
                locale,
                "bot-link-line",
                &[
                    ("node", Argument::Text(node.label().as_str())),
                    ("method", Argument::Text(&method)),
                    ("link", Argument::Text(&link)),
                ],
            )?,
            Handout::Account {
                host,
                port,
                user,
                password,
                ..
            } => say_with(
                locale,
                "bot-account-line",
                &[
                    ("node", Argument::Text(node.label().as_str())),
                    ("method", Argument::Text(&method)),
                    ("host", Argument::Text(&host)),
                    ("port", Argument::Number(i64::from(port))),
                    ("user", Argument::Text(&user)),
                    ("password", Argument::Text(&password)),
                ],
            )?,
        });
    }
    if said.is_empty() {
        said.push(say(locale, "bot-links-none")?);
    }
    Ok(said)
}

fn method_of(access: &AnyAccess) -> &'static str {
    match access {
        AnyAccess::Stealth(access) => access.method().as_stored(),
        AnyAccess::Open(access) => access.method().as_stored(),
    }
}

/// The client's standing, allowance and term, and each node's word — what
/// the settings allow to be said (0083).
async fn status(
    state: &AppState,
    locale: Locale,
    client: &Client,
    settings: &Settings,
) -> Result<String, ApiError> {
    let show_usage = settings.on("bot_show_usage");
    let show_node = settings.on("bot_show_node");
    let mut lines = vec![say_with(
        locale,
        "bot-status-client",
        &[
            ("label", Argument::Text(client.label().as_str())),
            (
                "state",
                Argument::Text(&client_state_words(locale, client.state())?),
            ),
        ],
    )?];
    if show_usage {
        let used = TrafficRepo::for_client(state.pool(), client.id()).await?;
        let used_words = bytes_words(locale, used.total())?;
        lines.push(match client.quota_bytes() {
            Some(quota) => say_with(
                locale,
                "bot-status-usage",
                &[
                    ("used", Argument::Text(&used_words)),
                    ("quota", Argument::Text(&bytes_words(locale, quota)?)),
                ],
            )?,
            None => say_with(
                locale,
                "bot-status-usage-unlimited",
                &[("used", Argument::Text(&used_words))],
            )?,
        });
        lines.push(match client.expires_at() {
            Some(at) => say_with(
                locale,
                "bot-status-until",
                &[("date", Argument::Text(&date_words(at)?))],
            )?,
            None => say(locale, "bot-status-no-expiry")?,
        });
    }
    let accesses = AccessRepo::by_client(state.pool(), client.id()).await?;
    for access in accesses
        .iter()
        .filter(|access| access.common().state() != AccessState::Revoked)
    {
        let common = access.common();
        let Some(node) = NodeRepo::by_id(state.pool(), common.node_id()).await? else {
            continue;
        };
        let method = method_words(locale, method_of(access))?;
        let mut parts = vec![access_state_words(locale, common.state())?];
        if show_node {
            parts.push(node_words(locale, &node)?);
        }
        if show_usage {
            if let Some(quota) = common.quota_bytes() {
                let used = TrafficRepo::for_access(state.pool(), common.id()).await?;
                parts.push(say_with(
                    locale,
                    "bot-status-usage",
                    &[
                        ("used", Argument::Text(&bytes_words(locale, used.total())?)),
                        ("quota", Argument::Text(&bytes_words(locale, quota)?)),
                    ],
                )?);
            }
            if let Some(at) = common.expires_at() {
                parts.push(say_with(
                    locale,
                    "bot-status-until",
                    &[("date", Argument::Text(&date_words(at)?))],
                )?);
            }
        }
        lines.push(say_with(
            locale,
            "bot-status-access",
            &[
                ("node", Argument::Text(node.label().as_str())),
                ("method", Argument::Text(&method)),
                ("words", Argument::Text(&parts.join(" · "))),
            ],
        )?);
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_are_read_with_or_without_the_bot_name() {
        assert_eq!(parse("/start"), Ask::Start(None));
        assert_eq!(
            parse("/start@some_bot abcdef"),
            Ask::Start(Some("abcdef".to_owned()))
        );
        assert_eq!(parse(" /LINKS "), Ask::Links);
        assert_eq!(parse("/link"), Ask::Links);
        assert_eq!(parse("/status"), Ask::Status);
        assert_eq!(parse("/unlink"), Ask::Unlink);
        assert_eq!(parse("/help"), Ask::Help);
        assert_eq!(parse("hello"), Ask::Help);
    }

    #[test]
    fn a_bare_code_is_taken_as_a_start() {
        let code = "0123456789abcdef0123456789abcdef";
        assert_eq!(parse(code), Ask::Start(Some(code.to_owned())));
        assert_eq!(parse("0123456789abcdef0123456789abcdeg"), Ask::Help);
    }

    #[test]
    fn bytes_are_said_in_the_largest_unit_that_fits() {
        assert_eq!(bytes_words(Locale::En, 512).unwrap(), "512 B");
        assert_eq!(bytes_words(Locale::En, 1536).unwrap(), "1.5 KB");
        assert_eq!(
            bytes_words(Locale::Ru, 3 * 1024 * 1024 * 1024).unwrap(),
            "3,0 ГБ"
        );
    }

    #[test]
    fn every_word_the_bot_uses_is_in_both_catalogues() {
        for locale in Locale::all() {
            for key in [
                "bot-hello",
                "bot-ask-code",
                "bot-not-linked",
                "bot-code-refused",
                "bot-unlinked",
                "bot-help",
                "bot-links-none",
                "bot-status-no-expiry",
                "bot-node-pending",
                "bot-node-disabled",
                "bot-node-gone",
                "bot-node-no-report",
                "bot-node-trouble",
                "bot-node-ok",
                "bot-client-active",
                "bot-client-suspended",
                "bot-client-archived",
                "bot-access-active",
                "bot-access-disabled",
                "bot-access-revoked",
                "bot-method-faketls",
                "bot-method-web",
                "bot-method-mtproto",
                "bot-method-socks5",
                "bot-method-http",
            ] {
                assert!(say(locale, key).is_ok(), "{key} in {locale:?}");
            }
        }
    }
}
