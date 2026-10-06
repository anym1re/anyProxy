//! What the panel says, and whether it is believed.
//!
//! The feed is trusted to be the panel, because it is reached through a
//! tunnel and nowhere else; it is not trusted to be well-formed. Every row is
//! held to the same rules the panel itself applies, and a list with one bad
//! row is refused whole (0094).

use std::time::Duration;

use ap_core::{LinkName, NodeKindTag};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};

/// Most rows a feed may carry.
pub const MOST_ROWS: usize = 1000;

/// Longest body read from the feed.
const BODY_CEILING: usize = 1024 * 1024;

/// How long one fetch may take, connect to last byte.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the feed answers: a host, a port and the one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedAddress {
    host: String,
    port: u16,
}

impl FeedAddress {
    /// Reads `http://host:port`, and nothing else.
    ///
    /// Plain HTTP on purpose: the feed is reached over a tunnel, which is what
    /// carries the connection (0091). A path is refused rather than kept,
    /// because there is only one.
    pub fn parse(text: &str) -> Option<Self> {
        let rest = text.trim().strip_prefix("http://")?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        let (host, port) = rest.rsplit_once(':')?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let port: u16 = port.parse().ok()?;
        if host.is_empty() || port == 0 || host.contains('/') {
            return None;
        }
        Some(Self {
            host: host.to_owned(),
            port,
        })
    }

    /// The socket to open.
    pub fn socket(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Why a feed was not taken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeedError {
    /// The feed could not be reached.
    #[error("connect: {0}")]
    Connect(String),
    /// The whole fetch took longer than allowed.
    #[error("timeout")]
    Timeout,
    /// The feed answered with something other than 200.
    #[error("status {0}")]
    Status(u16),
    /// The body was larger than the ceiling.
    #[error("body too large")]
    TooLarge,
    /// The body was not the shape a feed has.
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// More rows than the ceiling.
    #[error("too many rows")]
    TooMany,
    /// The pages could not be built from a list that parsed.
    #[error("render")]
    Render,
}

/// One row of the feed as it arrives, before anything is believed about it.
#[derive(Debug, Clone, serde::Deserialize)]
struct Row {
    name: String,
    method: String,
    #[serde(default)]
    link: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

/// What the panel says about the site itself, before it is believed.
#[derive(Debug, Default, serde::Deserialize)]
struct SiteRow {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    indexed: Option<bool>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    intro: Option<String>,
    #[serde(default)]
    bot: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct Body {
    links: Vec<Row>,
    /// Absent from a panel older than 0108, which is read as before: a site
    /// that answers and may be indexed.
    #[serde(default)]
    site: Option<SiteRow>,
}

/// What the panel says the site is to be (0108).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// Whether the site answers at all.
    pub enabled: bool,
    /// Whether an indexer may take it.
    pub indexed: bool,
    /// The heading, when the operator wrote one.
    pub title: Option<String>,
    /// The words under it, when the operator wrote any.
    pub intro: Option<String>,
    /// The bot to point at, when there is one that takes people in.
    pub bot: Option<String>,
}

impl Default for Setting {
    fn default() -> Self {
        Self {
            enabled: true,
            indexed: true,
            title: None,
            intro: None,
            bot: None,
        }
    }
}

/// A feed, whole: what the site is to be and what it shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feed {
    /// What the site is to be.
    pub site: Setting,
    /// The links it shows.
    pub links: Vec<PublicLink>,
}

/// One link the site shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicLink {
    /// A method with a `t.me` link.
    Link {
        /// The name the operator gave it.
        name: LinkName,
        /// The method served.
        method: NodeKindTag,
        /// The link, beginning `https://t.me/`.
        link: String,
    },
    /// A method Telegram takes as host, port and an account.
    Account {
        /// The name the operator gave it.
        name: LinkName,
        /// The method served.
        method: NodeKindTag,
        /// The node's address.
        host: String,
        /// The port.
        port: u16,
        /// Account name.
        user: String,
        /// Account password.
        password: String,
    },
}

impl PublicLink {
    /// The name the operator gave it.
    pub fn name(&self) -> &LinkName {
        match self {
            Self::Link { name, .. } | Self::Account { name, .. } => name,
        }
    }

    /// The method served.
    pub fn method(&self) -> NodeKindTag {
        match self {
            Self::Link { method, .. } | Self::Account { method, .. } => *method,
        }
    }
}

/// Reads a feed body into links, or refuses it whole.
pub fn parse(body: &[u8]) -> Result<Vec<PublicLink>, FeedError> {
    parse_feed(body).map(|feed| feed.links)
}

/// Reads a feed body whole — what the site is to be and its links — or
/// refuses it whole.
pub fn parse_feed(body: &[u8]) -> Result<Feed, FeedError> {
    let body: Body = serde_json::from_slice(body).map_err(|_| FeedError::Malformed("json"))?;
    if body.links.len() > MOST_ROWS {
        return Err(FeedError::TooMany);
    }
    let site = match body.site {
        Some(row) => setting(row)?,
        None => Setting::default(),
    };
    let links = body
        .links
        .into_iter()
        .map(believe)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Feed { site, links })
}

/// Longest heading and longest text under it, in bytes: what the panel takes.
const TITLE_CEILING: usize = 160;
const INTRO_CEILING: usize = 600;

/// Holds what the panel says about the site to the rules, or refuses it.
///
/// The words go onto a public page. They are escaped there like a link's name;
/// here they are bounded and kept to one line of printable text. The bot's
/// name becomes part of an address, so it is only what Telegram makes a name
/// of.
fn setting(row: SiteRow) -> Result<Setting, FeedError> {
    let words = |value: Option<String>, ceiling: usize, what: &'static str| match value
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
    {
        None => Ok(None),
        Some(text) if text.len() <= ceiling && !text.chars().any(char::is_control) => {
            Ok(Some(text))
        }
        Some(_) => Err(FeedError::Malformed(what)),
    };
    let bot = match row.bot.filter(|name| !name.is_empty()) {
        None => None,
        Some(name)
            if (5..=32).contains(&name.len())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') =>
        {
            Some(name)
        }
        Some(_) => return Err(FeedError::Malformed("bot")),
    };
    Ok(Setting {
        enabled: row.enabled.unwrap_or(true),
        indexed: row.indexed.unwrap_or(true),
        title: words(row.title, TITLE_CEILING, "title")?,
        intro: words(row.intro, INTRO_CEILING, "intro")?,
        bot,
    })
}

/// The only prefix a link may have. Anything else is not a Telegram link,
/// whatever the feed says.
const LINK_PREFIX: &str = "https://t.me/";

/// Holds one row to the rules, or refuses it.
fn believe(row: Row) -> Result<PublicLink, FeedError> {
    let name = LinkName::try_from(row.name.as_str()).map_err(|_| FeedError::Malformed("name"))?;
    let method =
        NodeKindTag::from_stored(&row.method).map_err(|_| FeedError::Malformed("method"))?;
    match method {
        NodeKindTag::FakeTls | NodeKindTag::Web | NodeKindTag::Mtproto => {
            let link = row.link.ok_or(FeedError::Malformed("link"))?;
            let sound = link.starts_with(LINK_PREFIX)
                && link.len() <= 512
                && link.bytes().all(|byte| byte.is_ascii_graphic());
            if !sound {
                return Err(FeedError::Malformed("link"));
            }
            Ok(PublicLink::Link { name, method, link })
        }
        NodeKindTag::Socks5 | NodeKindTag::Http => {
            let host = plain(row.host, 253, "host")?;
            let port = row
                .port
                .filter(|port| *port != 0)
                .ok_or(FeedError::Malformed("port"))?;
            let user = plain(row.user, 128, "user")?;
            let password = plain(row.password, 128, "password")?;
            Ok(PublicLink::Account {
                name,
                method,
                host,
                port,
                user,
                password,
            })
        }
    }
}

/// A field that must be there, short, and free of anything that is not
/// printable.
fn plain(value: Option<String>, ceiling: usize, what: &'static str) -> Result<String, FeedError> {
    let value = value.ok_or(FeedError::Malformed(what))?;
    let sound = !value.is_empty()
        && value.chars().count() <= ceiling
        && !value.chars().any(|c| c.is_control() || c.is_whitespace());
    if sound {
        Ok(value)
    } else {
        Err(FeedError::Malformed(what))
    }
}

/// Asks the feed once and returns its body, within the ceiling and the time.
pub async fn fetch(feed: &FeedAddress) -> Result<Vec<u8>, FeedError> {
    tokio::time::timeout(FETCH_TIMEOUT, fetch_inner(feed))
        .await
        .map_err(|_| FeedError::Timeout)?
}

async fn fetch_inner(feed: &FeedAddress) -> Result<Vec<u8>, FeedError> {
    let socket = feed.socket();
    let stream = tokio::net::TcpStream::connect(&socket)
        .await
        .map_err(|error| FeedError::Connect(error.to_string()))?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|error| FeedError::Connect(error.to_string()))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = Request::builder()
        .method("GET")
        .uri("/v1/public-links")
        .header("host", socket)
        .body(Empty::<Bytes>::new())
        .map_err(|error| FeedError::Connect(error.to_string()))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| FeedError::Connect(error.to_string()))?;
    if response.status() != StatusCode::OK {
        return Err(FeedError::Status(response.status().as_u16()));
    }

    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| FeedError::Connect(error.to_string()))?;
        if let Some(chunk) = frame.data_ref() {
            if bytes.len() + chunk.len() > BODY_CEILING {
                return Err(FeedError::TooLarge);
            }
            bytes.extend_from_slice(chunk);
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(json: serde_json::Value) -> Result<Vec<PublicLink>, FeedError> {
        parse(
            serde_json::json!({ "links": [json] })
                .to_string()
                .as_bytes(),
        )
    }

    #[test]
    fn a_feed_address_is_host_and_port_and_nothing_else() {
        assert_eq!(
            FeedAddress::parse("http://10.0.0.1:8090"),
            Some(FeedAddress {
                host: "10.0.0.1".to_owned(),
                port: 8090
            })
        );
        assert_eq!(
            FeedAddress::parse("http://[fd00::1]:8090/").map(|feed| feed.socket()),
            Some("[fd00::1]:8090".to_owned())
        );
        for bad in [
            "https://10.0.0.1:8090",
            "http://10.0.0.1",
            "http://10.0.0.1:0",
            "http://10.0.0.1:8090/v1/public-links",
            "",
        ] {
            assert_eq!(FeedAddress::parse(bad), None, "{bad:?} was taken");
        }
    }

    #[test]
    fn a_link_row_is_taken_when_it_points_at_telegram() {
        let links = row(serde_json::json!({
            "name": "для всех", "method": "faketls",
            "link": "https://t.me/proxy?server=203.0.113.7&port=443&secret=ee00"
        }))
        .unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].method(), NodeKindTag::FakeTls);
        assert_eq!(links[0].name().as_str(), "для всех");
    }

    #[test]
    fn a_link_that_points_elsewhere_is_refused() {
        for link in [
            "https://example.com/proxy",
            "http://t.me/proxy",
            "https://t.me/proxy?server=a b",
            "javascript:alert(1)",
        ] {
            let refused = row(serde_json::json!({
                "name": "x", "method": "mtproto", "link": link
            }));
            assert_eq!(refused, Err(FeedError::Malformed("link")), "{link:?}");
        }
    }

    #[test]
    fn an_account_row_needs_every_field_and_no_control_characters() {
        let taken = row(serde_json::json!({
            "name": "socks", "method": "socks5", "host": "203.0.113.8",
            "port": 1080, "user": "u", "password": "p"
        }))
        .unwrap();
        assert!(matches!(taken[0], PublicLink::Account { port: 1080, .. }));

        let no_port = row(serde_json::json!({
            "name": "socks", "method": "socks5", "host": "203.0.113.8",
            "user": "u", "password": "p"
        }));
        assert_eq!(no_port, Err(FeedError::Malformed("port")));

        let bad_user = row(serde_json::json!({
            "name": "socks", "method": "http", "host": "203.0.113.8",
            "port": 3128, "user": "u\nv", "password": "p"
        }));
        assert_eq!(bad_user, Err(FeedError::Malformed("user")));
    }

    #[test]
    fn an_unknown_method_and_a_bad_name_refuse_the_row() {
        assert_eq!(
            row(serde_json::json!({ "name": "x", "method": "vless", "link": "https://t.me/x" })),
            Err(FeedError::Malformed("method"))
        );
        assert_eq!(
            row(serde_json::json!({ "name": "a\nb", "method": "web", "link": "https://t.me/x" })),
            Err(FeedError::Malformed("name"))
        );
    }

    #[test]
    fn one_bad_row_refuses_the_whole_feed() {
        let body = serde_json::json!({ "links": [
            { "name": "good", "method": "mtproto", "link": "https://t.me/proxy?x" },
            { "name": "bad", "method": "mtproto", "link": "https://elsewhere/" },
        ] });
        assert_eq!(
            parse(body.to_string().as_bytes()),
            Err(FeedError::Malformed("link"))
        );
    }

    #[test]
    fn more_rows_than_the_ceiling_are_refused() {
        let rows: Vec<_> = (0..=MOST_ROWS)
            .map(|i| serde_json::json!({ "name": format!("n{i}"), "method": "mtproto", "link": "https://t.me/x" }))
            .collect();
        let body = serde_json::json!({ "links": rows });
        assert_eq!(parse(body.to_string().as_bytes()), Err(FeedError::TooMany));
    }

    fn feed(site: serde_json::Value) -> Result<Feed, FeedError> {
        parse_feed(
            serde_json::json!({ "site": site, "links": [] })
                .to_string()
                .as_bytes(),
        )
    }

    #[test]
    fn a_feed_without_a_word_about_the_site_is_a_site_as_before() {
        let read = parse_feed(br#"{"links":[]}"#).unwrap();
        assert_eq!(read.site, Setting::default());
        assert!(read.site.enabled && read.site.indexed);
        assert_eq!(
            feed(serde_json::json!({})).unwrap().site,
            Setting::default()
        );
    }

    #[test]
    fn what_the_panel_says_about_the_site_is_taken() {
        let read = feed(serde_json::json!({
            "enabled": false, "indexed": false,
            "title": "  Прокси  ", "intro": "Откройте ссылку.", "bot": "any_proxy_bot",
        }))
        .unwrap()
        .site;
        assert!(!read.enabled && !read.indexed);
        assert_eq!(read.title.as_deref(), Some("Прокси"));
        assert_eq!(read.intro.as_deref(), Some("Откройте ссылку."));
        assert_eq!(read.bot.as_deref(), Some("any_proxy_bot"));
        // Words that are only spaces are no words.
        let blank = feed(serde_json::json!({ "title": "   ", "intro": "", "bot": "" }))
            .unwrap()
            .site;
        assert_eq!((blank.title, blank.intro, blank.bot), (None, None, None));
    }

    #[test]
    fn words_too_long_or_not_printable_refuse_the_feed() {
        for bad in [
            serde_json::json!({ "title": "x".repeat(161) }),
            serde_json::json!({ "intro": "x".repeat(601) }),
            serde_json::json!({ "title": "two\nlines" }),
            serde_json::json!({ "intro": "a\u{0007}b" }),
        ] {
            assert!(
                matches!(feed(bad.clone()), Err(FeedError::Malformed(_))),
                "{bad} was taken"
            );
        }
    }

    #[test]
    fn a_bot_name_is_only_what_telegram_makes_a_name_of() {
        for bad in [
            "a/b_c_d",
            "x y z w v",
            "https://t.me/x",
            "abcd",
            &"a".repeat(33),
        ] {
            assert_eq!(
                feed(serde_json::json!({ "bot": bad })),
                Err(FeedError::Malformed("bot")),
                "{bad:?} was taken"
            );
        }
    }

    #[test]
    fn something_that_is_not_a_feed_is_refused() {
        assert_eq!(parse(b"<html>"), Err(FeedError::Malformed("json")));
        assert_eq!(parse(b"{}"), Err(FeedError::Malformed("json")));
    }
}
