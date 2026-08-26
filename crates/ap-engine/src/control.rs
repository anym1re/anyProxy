use std::net::SocketAddr;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use serde::Deserialize;

use crate::EngineError;

/// A reply the control API sent back.
#[derive(Debug, Clone)]
pub struct Reply {
    /// HTTP status.
    pub status: u16,
    /// Body, as it arrived.
    pub body: String,
}

impl Reply {
    /// The `data` of a success envelope.
    pub fn data(&self) -> Result<serde_json::Value, EngineError> {
        let envelope: Envelope = serde_json::from_str(&self.body)
            .map_err(|_| EngineError::Control(format!("unreadable reply: {}", self.body)))?;
        if !envelope.ok {
            let code = envelope
                .error
                .map(|error| error.code)
                .unwrap_or_else(|| "unknown".to_owned());
            return Err(EngineError::Control(format!("refused: {code}")));
        }
        Ok(envelope.data.unwrap_or(serde_json::Value::Null))
    }

    /// The revision the engine says its configuration is at.
    pub fn revision(&self) -> Option<String> {
        serde_json::from_str::<Envelope>(&self.body)
            .ok()
            .and_then(|envelope| envelope.revision)
    }
}

#[derive(Deserialize)]
struct Envelope {
    ok: bool,
    #[serde(default)]
    data: Option<serde_json::Value>,
    #[serde(default)]
    revision: Option<String>,
    #[serde(default)]
    error: Option<Failure>,
}

#[derive(Deserialize)]
struct Failure {
    code: String,
    #[serde(default)]
    #[allow(dead_code)]
    message: String,
}

/// Speaks to one engine's control API.
///
/// The address carries a port and nothing else: the engine's control API is
/// bound to loopback by the configuration this crate renders, and an agent
/// that could point this at another host would be an agent that could be told
/// to drive somebody else's engine.
#[derive(Debug, Clone)]
pub struct Control {
    port: u16,
    token: String,
}

impl Control {
    /// Talks to the engine on this node.
    pub fn new(port: u16, token: impl Into<String>) -> Self {
        Self {
            port,
            token: token.into(),
        }
    }

    /// Where the requests go.
    pub fn address(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    /// Whether the engine is answering.
    pub async fn health(&self) -> Result<bool, EngineError> {
        let reply = self.send(Method::GET, "/v1/health", None, None).await?;
        Ok(reply.status == 200 && reply.data().is_ok())
    }

    /// What the engine says it is and how long it has been running.
    pub async fn system_info(&self) -> Result<serde_json::Value, EngineError> {
        self.send(Method::GET, "/v1/system/info", None, None)
            .await?
            .data()
    }

    /// The editable configuration, as the engine holds it.
    pub async fn config(&self) -> Result<Reply, EngineError> {
        self.send(Method::GET, "/v1/config", None, None).await
    }

    /// Applies a sparse patch to the editable sections.
    ///
    /// The revision, when given, makes the write conditional: an engine whose
    /// configuration changed underneath refuses rather than overwriting.
    pub async fn patch_config(
        &self,
        patch: &serde_json::Value,
        revision: Option<&str>,
    ) -> Result<Reply, EngineError> {
        self.send(
            Method::PATCH,
            "/v1/config",
            Some(patch.to_string()),
            revision,
        )
        .await
    }

    /// Asks the engine to read its configuration file again.
    ///
    /// The way to change what the control API will not edit — the WEB carrier
    /// above all. telemt prepares a new generation and swaps to it, so the
    /// process is the same process afterwards and sessions already established
    /// keep the carrier they were issued with.
    pub async fn reload(&self) -> Result<Reply, EngineError> {
        self.send(Method::POST, "/v1/system/reload", None, None)
            .await
    }

    /// The users the engine currently authenticates.
    pub async fn users(&self) -> Result<serde_json::Value, EngineError> {
        self.send(Method::GET, "/v1/users", None, None)
            .await?
            .data()
    }

    /// Adds a user.
    pub async fn create_user(
        &self,
        username: &str,
        secret_hex: &str,
    ) -> Result<Reply, EngineError> {
        let body = serde_json::json!({ "username": username, "secret": secret_hex });
        self.send(Method::POST, "/v1/users", Some(body.to_string()), None)
            .await
    }

    /// Changes selected fields of one user.
    pub async fn patch_user(
        &self,
        username: &str,
        fields: &serde_json::Value,
    ) -> Result<Reply, EngineError> {
        self.send(
            Method::PATCH,
            &format!("/v1/users/{username}"),
            Some(fields.to_string()),
            None,
        )
        .await
    }

    /// Removes a user.
    pub async fn delete_user(&self, username: &str) -> Result<Reply, EngineError> {
        self.send(Method::DELETE, &format!("/v1/users/{username}"), None, None)
            .await
    }

    /// Stops a user and closes the sessions it already had.
    pub async fn disable_user(&self, username: &str) -> Result<Reply, EngineError> {
        self.send(
            Method::POST,
            &format!("/v1/users/{username}/disable"),
            None,
            None,
        )
        .await
    }

    /// Lets a user connect again.
    pub async fn enable_user(&self, username: &str) -> Result<Reply, EngineError> {
        self.send(
            Method::POST,
            &format!("/v1/users/{username}/enable"),
            None,
            None,
        )
        .await
    }

    /// Reads the metrics the engine exposes.
    pub async fn metrics(&self, port: u16) -> Result<String, EngineError> {
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let reply = request(address, Method::GET, "/metrics", None, None, None).await?;
        Ok(reply.body)
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<String>,
        revision: Option<&str>,
    ) -> Result<Reply, EngineError> {
        request(
            self.address(),
            method,
            path,
            body,
            Some(&self.token),
            revision,
        )
        .await
    }
}

/// One request and its reply, over plain HTTP on loopback.
async fn request(
    address: SocketAddr,
    method: Method,
    path: &str,
    body: Option<String>,
    token: Option<&str>,
    revision: Option<&str>,
) -> Result<Reply, EngineError> {
    let stream = tokio::net::TcpStream::connect(address)
        .await
        .map_err(|error| EngineError::Control(format!("{address}: {error}")))?;
    let io = hyper_util::rt::TokioIo::new(stream);

    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|error| EngineError::Control(error.to_string()))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", address.to_string());
    if let Some(token) = token {
        builder = builder.header("authorization", token);
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    // Makes the write conditional: an engine whose configuration moved on
    // refuses rather than overwriting what moved it.
    if let Some(revision) = revision {
        builder = builder.header("if-match", revision);
    }
    let request = builder
        .body(Full::new(Bytes::from(body.unwrap_or_default())))
        .map_err(|error| EngineError::Control(error.to_string()))?;

    let response = sender
        .send_request(request)
        .await
        .map_err(|error| EngineError::Control(error.to_string()))?;
    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|error| EngineError::Control(error.to_string()))?
        .to_bytes();

    Ok(Reply {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_control_speaks_to_loopback_and_nowhere_else() {
        let control = Control::new(9091, "Bearer opaque");
        assert_eq!(control.address().to_string(), "127.0.0.1:9091");
        assert!(control.address().ip().is_loopback());
    }

    #[test]
    fn a_success_envelope_gives_up_its_data() {
        let reply = Reply {
            status: 200,
            body: r#"{"ok":true,"data":{"read_only":false},"revision":"abc"}"#.to_owned(),
        };
        assert_eq!(reply.data().unwrap()["read_only"], false);
        assert_eq!(reply.revision().as_deref(), Some("abc"));
    }

    #[test]
    fn an_error_envelope_carries_its_code_out() {
        let reply = Reply {
            status: 400,
            body: r#"{"ok":false,"error":{"code":"access_not_editable","message":"no"}}"#
                .to_owned(),
        };
        let outcome = reply.data();
        match outcome {
            Err(EngineError::Control(reason)) => {
                assert!(reason.contains("access_not_editable"), "{reason}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_body_that_is_not_an_envelope_is_a_control_failure() {
        let reply = Reply {
            status: 502,
            body: "<html>gateway</html>".to_owned(),
        };
        assert!(matches!(reply.data(), Err(EngineError::Control(_))));
    }
}
