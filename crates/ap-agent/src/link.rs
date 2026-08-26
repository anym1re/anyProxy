use std::sync::Arc;

use ap_proto::Message;
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::AgentError;
use crate::identity::Identity;
use crate::pin::{PANEL_NAME, PinnedAuthority};

/// Largest buffer held for one connection before it is dropped.
const READ_CEILING: usize = ap_proto::MAX_PAYLOAD + ap_proto::HEADER_LEN;

/// A framed conversation with the panel.
///
/// Generic over the stream so the exchange can be exercised without a socket.
pub struct Link<S> {
    stream: S,
    buffer: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Link<S> {
    /// Wraps a stream that is already connected.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    /// Writes one message.
    pub async fn send(&mut self, message: &Message) -> Result<(), AgentError> {
        let frame =
            ap_proto::encode(message).map_err(|error| AgentError::Refused(error.to_string()))?;
        self.stream
            .write_all(&frame)
            .await
            .map_err(|error| AgentError::Panel(error.to_string()))?;
        self.stream
            .flush()
            .await
            .map_err(|error| AgentError::Panel(error.to_string()))
    }

    /// Reads one message, or nothing if the panel closed the connection.
    pub async fn receive(&mut self) -> Result<Option<Message>, AgentError> {
        loop {
            if let Some((message, consumed)) = ap_proto::decode(&self.buffer)
                .map_err(|error| AgentError::Refused(error.to_string()))?
            {
                self.buffer.drain(..consumed);
                return Ok(Some(message));
            }

            let mut chunk = [0u8; 8192];
            let read = self
                .stream
                .read(&mut chunk)
                .await
                .map_err(|error| AgentError::Panel(error.to_string()))?;
            if read == 0 {
                return Ok(None);
            }
            self.buffer.extend_from_slice(&chunk[..read]);
            if self.buffer.len() > READ_CEILING {
                return Err(AgentError::Refused(
                    "the panel sent an oversized frame".to_owned(),
                ));
            }
        }
    }
}

/// Opens a connection to the panel, verifying the pinned authority first.
///
/// The certificate is checked as part of the handshake, which finishes before
/// this returns. Nothing the caller passes afterwards — an enrolment code
/// above all — can reach a panel that failed the pin.
pub async fn connect(
    address: &str,
    fingerprint: &str,
    identity: Option<&Identity>,
) -> Result<Link<TlsStream<TcpStream>>, AgentError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedAuthority::from_hex(
        fingerprint,
        Arc::clone(&provider),
    )?);

    // The panel is its own authority and is recognised by the pin the operator
    // carried, so the usual public roots have nothing to say here.
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| AgentError::Refused(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);

    let config = match identity {
        Some(identity) => {
            let chain: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(identity.certificate_pem.as_bytes())
                    .collect::<Result<_, _>>()
                    .map_err(|error| AgentError::Refused(error.to_string()))?;
            let key = PrivateKeyDer::from_pem_slice(identity.key_pem.as_bytes())
                .map_err(|error| AgentError::Refused(error.to_string()))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|error| AgentError::Refused(error.to_string()))?
        }
        None => builder.with_no_client_auth(),
    };

    let stream = TcpStream::connect(address)
        .await
        .map_err(|error| AgentError::Panel(format!("{address}: {error}")))?;
    let name =
        ServerName::try_from(PANEL_NAME).map_err(|error| AgentError::Refused(error.to_string()))?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await
        .map_err(
            |error| match error.get_ref().map(|inner| inner.is::<rustls::Error>()) {
                // The handshake itself objected, which for this client means the
                // certificate did not answer to the pin.
                Some(true) => AgentError::WrongPanel,
                _ => AgentError::Panel(error.to_string()),
            },
        )?;

    Ok(Link::new(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap_proto::Hello;

    #[tokio::test]
    async fn a_message_survives_the_trip() {
        let (here, there) = tokio::io::duplex(4096);
        let mut sender = Link::new(here);
        let mut receiver = Link::new(there);

        let hello = Message::Hello(Hello {
            proto: ap_proto::PROTOCOL_VERSION,
            node_id: uuid::Uuid::now_v7(),
            agent_version: "test".to_owned(),
            applied_revision: None,
        });
        sender.send(&hello).await.unwrap();
        assert_eq!(receiver.receive().await.unwrap(), Some(hello));
    }

    #[tokio::test]
    async fn two_messages_in_one_write_are_read_apart() {
        let (here, there) = tokio::io::duplex(8192);
        let mut sender = Link::new(here);
        let mut receiver = Link::new(there);

        let first = Message::Ack(ap_proto::Ack {
            revision: uuid::Uuid::now_v7(),
        });
        let second = Message::Ack(ap_proto::Ack {
            revision: uuid::Uuid::now_v7(),
        });
        sender.send(&first).await.unwrap();
        sender.send(&second).await.unwrap();

        assert_eq!(receiver.receive().await.unwrap(), Some(first));
        assert_eq!(receiver.receive().await.unwrap(), Some(second));
    }

    #[tokio::test]
    async fn a_closed_connection_reads_as_nothing() {
        let (here, there) = tokio::io::duplex(64);
        drop(here);
        let mut receiver = Link::new(there);
        assert_eq!(receiver.receive().await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_fingerprint_that_is_not_a_digest_never_opens_a_socket() {
        // The address is one nothing listens on. Reaching it would be a
        // connection attempt; refusing the fingerprint happens first.
        let outcome = connect("127.0.0.1:1", "not a digest", None).await;
        assert!(matches!(outcome, Err(AgentError::WrongPanel)));
    }
}
