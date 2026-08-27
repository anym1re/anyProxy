//! Reaching the panel by way of something else.
//!
//! A panel that listens only on loopback is reached over a tunnel, and the one
//! the node is given may not resolve anywhere this machine can look: an onion
//! address has no meaning outside the proxy that knows it. So the name travels
//! to the proxy and is resolved there, never here.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::AgentError;

/// The only version this speaks.
const VERSION: u8 = 5;

/// No authentication, RFC 1928.
const AUTH_NONE: u8 = 0;

/// Username and password, RFC 1929.
const AUTH_LOGIN: u8 = 2;

/// A SOCKS5 proxy the node reaches the panel through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Through {
    /// Where the proxy listens.
    pub address: String,
    /// What it wants to be told, if it wants anything.
    pub credentials: Option<(String, String)>,
}

impl Through {
    /// Reads the setting an operator wrote.
    ///
    /// Either `host:port` or `user:pass@host:port`. Nothing is a proxy that
    /// makes this machine reachable by more than it was, so an unparseable
    /// setting is refused rather than quietly ignored: a node that was meant
    /// to speak through a tunnel must not fall back to speaking without one.
    pub fn parse(text: &str) -> Result<Self, AgentError> {
        let (credentials, address) = match text.rsplit_once('@') {
            Some((login, address)) => {
                let (user, pass) = login
                    .split_once(':')
                    .ok_or_else(|| AgentError::Refused(refusal(text)))?;
                (Some((user.to_owned(), pass.to_owned())), address)
            }
            None => (None, text),
        };
        if !address.contains(':') || address.starts_with(':') || address.ends_with(':') {
            return Err(AgentError::Refused(refusal(text)));
        }
        Ok(Self {
            address: address.to_owned(),
            credentials,
        })
    }
}

fn refusal(text: &str) -> String {
    format!("{text} is not a proxy address of the form user:pass@host:port")
}

/// Opens a connection to `panel`, through a proxy when there is one.
pub async fn dial(panel: &str, through: Option<&Through>) -> Result<TcpStream, AgentError> {
    let Some(through) = through else {
        return TcpStream::connect(panel)
            .await
            .map_err(|error| AgentError::Panel(format!("{panel}: {error}")));
    };

    let (host, port) = panel
        .rsplit_once(':')
        .ok_or_else(|| AgentError::Refused(format!("{panel} names no port")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| AgentError::Refused(format!("{panel} names no port")))?;

    let mut stream = TcpStream::connect(&through.address)
        .await
        .map_err(|error| AgentError::Panel(format!("{}: {error}", through.address)))?;

    greet(&mut stream, through).await?;
    ask_for(&mut stream, host, port).await?;
    Ok(stream)
}

/// Settles on a way of being recognised, and is recognised that way.
async fn greet(stream: &mut TcpStream, through: &Through) -> Result<(), AgentError> {
    // Both are offered. Tor asks for neither; a proxy an operator runs may ask
    // for a login, and a node that could only do one of the two would be a
    // node that works in one deployment and not the other.
    stream
        .write_all(&[VERSION, 2, AUTH_NONE, AUTH_LOGIN])
        .await
        .map_err(proxy_said)?;

    let mut answer = [0u8; 2];
    stream.read_exact(&mut answer).await.map_err(proxy_said)?;
    if answer[0] != VERSION {
        return Err(AgentError::Panel(
            "the proxy does not speak SOCKS5".to_owned(),
        ));
    }

    match answer[1] {
        AUTH_NONE => Ok(()),
        AUTH_LOGIN => {
            let Some((user, pass)) = &through.credentials else {
                return Err(AgentError::Refused(
                    "the proxy wants a login and none was given".to_owned(),
                ));
            };
            let mut request = vec![1];
            push_short(&mut request, user.as_bytes())?;
            push_short(&mut request, pass.as_bytes())?;
            stream.write_all(&request).await.map_err(proxy_said)?;

            let mut answer = [0u8; 2];
            stream.read_exact(&mut answer).await.map_err(proxy_said)?;
            if answer[1] != 0 {
                return Err(AgentError::Refused(
                    "the proxy did not accept the login".to_owned(),
                ));
            }
            Ok(())
        }
        _ => Err(AgentError::Panel(
            "the proxy would accept nothing this node can offer".to_owned(),
        )),
    }
}

/// Asks the proxy to reach the panel, by name.
async fn ask_for(stream: &mut TcpStream, host: &str, port: u16) -> Result<(), AgentError> {
    let mut request = vec![VERSION, 1, 0, 3];
    push_short(&mut request, host.as_bytes())?;
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.map_err(proxy_said)?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(proxy_said)?;
    if head[1] != 0 {
        return Err(AgentError::Panel(format!(
            "the proxy would not reach the panel: {}",
            head[1]
        )));
    }

    // The address it bound is of no use here, but it has to be read off the
    // wire before the conversation the panel expects can start.
    let rest = match head[3] {
        1 => 4,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await.map_err(proxy_said)?;
            usize::from(length[0])
        }
        4 => 16,
        _ => {
            return Err(AgentError::Panel(
                "the proxy answered with an address of no known kind".to_owned(),
            ));
        }
    };
    let mut discarded = vec![0u8; rest + 2];
    stream
        .read_exact(&mut discarded)
        .await
        .map_err(proxy_said)?;
    Ok(())
}

/// One length-prefixed field, as both SOCKS5 and its login exchange write them.
fn push_short(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), AgentError> {
    let length = u8::try_from(bytes.len()).map_err(|_| {
        AgentError::Refused("a proxy field is longer than SOCKS5 allows".to_owned())
    })?;
    out.push(length);
    out.extend_from_slice(bytes);
    Ok(())
}

fn proxy_said(error: std::io::Error) -> AgentError {
    AgentError::Panel(error.to_string())
}
