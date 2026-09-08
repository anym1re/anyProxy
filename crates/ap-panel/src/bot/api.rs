//! The three Bot API methods the bot uses, over the HTTP client the workspace
//! already has (0081).
//!
//! Nothing here knows what the bot says: this dials, sends and reads. The
//! token travels in the path, as Bot API wants it, and appears in no error.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::TcpStream;

/// How long a plain call may take, and how much is added on top of a long
/// poll's own wait.
const PATIENCE: Duration = Duration::from_secs(15);

/// What went wrong on the way to Telegram or back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// Telegram does not know this token.
    Unauthorized,
    /// Telegram could not be reached, or did not answer in time.
    Unreachable,
    /// Telegram answered, and said no. Its own words.
    Refused(String),
    /// The address of the Bot API is not one that can be dialled.
    Address,
}

/// One update from `getUpdates`. Only what the bot reads is named.
#[derive(Debug, Clone, Deserialize)]
pub struct Update {
    /// Monotonic; the next poll asks from the one after the last seen.
    pub update_id: i64,
    /// The message, when the update carries one.
    #[serde(default)]
    pub message: Option<Message>,
}

/// A message somebody sent the bot.
#[derive(Debug, Clone, Deserialize)]
pub struct Message {
    /// The text, when the message is text.
    #[serde(default)]
    pub text: Option<String>,
    /// Who sent it. Absent for messages from channels.
    #[serde(default)]
    pub from: Option<User>,
    /// Where to answer.
    pub chat: Chat,
}

/// The account behind a message.
#[derive(Debug, Clone, Deserialize)]
pub struct User {
    /// The account identifier. Kept in the panel only as a keyed digest.
    pub id: i64,
    /// The language the account is set to, when Telegram says.
    #[serde(default)]
    pub language_code: Option<String>,
}

/// The chat a message arrived in.
#[derive(Debug, Clone, Deserialize)]
pub struct Chat {
    /// The chat identifier, which answers go to.
    pub id: i64,
}

/// One bot, at one Bot API.
#[derive(Clone)]
pub struct BotApi {
    tls: Option<Arc<rustls::ClientConfig>>,
    host: String,
    port: u16,
    token: String,
}

impl BotApi {
    /// Points at a Bot API. `https://api.telegram.org` for the real one; a
    /// plain `http://` address for the double a test stands up.
    pub fn new(base: &str, token: &str) -> Result<Self, Fault> {
        let base = base.trim().trim_end_matches('/');
        let (secure, rest) = if let Some(rest) = base.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = base.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(Fault::Address);
        };
        if rest.is_empty() || rest.contains('/') {
            return Err(Fault::Address);
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().map_err(|_| Fault::Address)?),
            None => (rest, if secure { 443 } else { 80 }),
        };
        if host.is_empty() {
            return Err(Fault::Address);
        }
        let tls = secure.then(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            )
        });
        Ok(Self {
            tls,
            host: host.to_owned(),
            port,
            token: token.to_owned(),
        })
    }

    /// The name the bot answers under, without the `@`.
    pub async fn get_me(&self) -> Result<String, Fault> {
        let me = self.call("getMe", serde_json::json!({}), PATIENCE).await?;
        me["username"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Fault::Refused("no username".to_owned()))
    }

    /// Updates from `offset` on, waiting up to `wait_secs` for one to arrive.
    pub async fn get_updates(&self, offset: i64, wait_secs: u64) -> Result<Vec<Update>, Fault> {
        let result = self
            .call(
                "getUpdates",
                serde_json::json!({
                    "offset": offset,
                    "timeout": wait_secs,
                    "allowed_updates": ["message"],
                }),
                PATIENCE + Duration::from_secs(wait_secs),
            )
            .await?;
        serde_json::from_value(result).map_err(|_| Fault::Refused("updates".to_owned()))
    }

    /// Sends text to a chat. Previews are off: a connection link would draw a
    /// card for t.me under itself.
    pub async fn send_message(&self, chat_id: i64, text: &str) -> Result<(), Fault> {
        self.call(
            "sendMessage",
            serde_json::json!({
                "chat_id": chat_id,
                "text": text,
                "link_preview_options": { "is_disabled": true },
            }),
            PATIENCE,
        )
        .await?;
        Ok(())
    }

    /// One call: connect, send, read, and read the answer's own verdict.
    async fn call(
        &self,
        method: &str,
        body: serde_json::Value,
        patience: Duration,
    ) -> Result<serde_json::Value, Fault> {
        let stream = tokio::time::timeout(
            PATIENCE,
            TcpStream::connect((self.host.as_str(), self.port)),
        )
        .await
        .map_err(|_| Fault::Unreachable)?
        .map_err(|_| Fault::Unreachable)?;

        let authority = match (self.tls.is_some(), self.port) {
            (true, 443) | (false, 80) => self.host.clone(),
            _ => format!("{}:{}", self.host, self.port),
        };
        let request = Request::builder()
            .method("POST")
            .uri(format!("/bot{}/{method}", self.token))
            .header("host", authority)
            .header("content-type", "application/json")
            .header("connection", "close")
            .body(Full::new(Bytes::from(body.to_string())))
            .map_err(|_| Fault::Unreachable)?;

        let (status, bytes) = match &self.tls {
            Some(config) => {
                let name = rustls::pki_types::ServerName::try_from(self.host.clone())
                    .map_err(|_| Fault::Address)?;
                let connector = tokio_rustls::TlsConnector::from(Arc::clone(config));
                let tls = tokio::time::timeout(PATIENCE, connector.connect(name, stream))
                    .await
                    .map_err(|_| Fault::Unreachable)?
                    .map_err(|_| Fault::Unreachable)?;
                exchange(TokioIo::new(tls), request, patience).await?
            }
            None => exchange(TokioIo::new(stream), request, patience).await?,
        };

        if status == 401 {
            return Err(Fault::Unauthorized);
        }
        let answer: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| Fault::Unreachable)?;
        if answer["ok"].as_bool() == Some(true) {
            return Ok(answer["result"].clone());
        }
        match answer["error_code"].as_i64() {
            Some(401) => Err(Fault::Unauthorized),
            _ => Err(Fault::Refused(
                answer["description"]
                    .as_str()
                    .unwrap_or("refused")
                    .to_owned(),
            )),
        }
    }
}

impl std::fmt::Debug for BotApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BotApi({}:{}, token [redacted])", self.host, self.port)
    }
}

/// Sends one request on one connection and reads the whole answer.
async fn exchange<I>(
    io: I,
    request: Request<Full<Bytes>>,
    patience: Duration,
) -> Result<(u16, Bytes), Fault>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|_| Fault::Unreachable)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = tokio::time::timeout(patience, sender.send_request(request))
        .await
        .map_err(|_| Fault::Unreachable)?
        .map_err(|_| Fault::Unreachable)?;
    let status = response.status().as_u16();
    let bytes = tokio::time::timeout(patience, response.into_body().collect())
        .await
        .map_err(|_| Fault::Unreachable)?
        .map_err(|_| Fault::Unreachable)?
        .to_bytes();
    Ok((status, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_real_address_is_dialled_with_tls_on_its_port() {
        let api = BotApi::new("https://api.telegram.org", "1:a").unwrap();
        assert!(api.tls.is_some());
        assert_eq!(api.port, 443);
        assert_eq!(api.host, "api.telegram.org");
    }

    #[test]
    fn a_plain_address_with_a_port_is_taken_as_written() {
        let api = BotApi::new("http://127.0.0.1:4321/", "1:a").unwrap();
        assert!(api.tls.is_none());
        assert_eq!(api.port, 4321);
    }

    #[test]
    fn an_address_that_is_not_one_is_refused() {
        for bad in [
            "api.telegram.org",
            "https://",
            "https://host/path",
            "http://:80",
        ] {
            assert_eq!(BotApi::new(bad, "1:a").err(), Some(Fault::Address), "{bad}");
        }
    }

    #[test]
    fn the_token_is_not_in_the_debug_form() {
        let api = BotApi::new("https://api.telegram.org", "123456:secret-token").unwrap();
        assert!(!format!("{api:?}").contains("secret-token"));
    }
}
