use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

use crate::registry::{Method, Registry};
use crate::{InboundError, http, socks5};

/// How long a client has to say what it wants before it is dropped.
///
/// A connection that opens and says nothing costs a slot; enough of them cost
/// every slot, and that is a cheap way to take a node off the air.
const GREETING_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a node waits to reach where a client asked to go.
const REACH_TIMEOUT: Duration = Duration::from_secs(20);

/// Serves one method until the process stops.
pub async fn serve(
    listener: TcpListener,
    method: Method,
    registry: Arc<Registry>,
) -> Result<(), InboundError> {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            continue;
        };
        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            // No deadline on the whole conversation: a proxy connection lasts
            // as long as the person using it needs it, and cutting it after a
            // minute would make the node useless for anything but a single
            // page. The opening has its own deadlines, which is where an
            // idling client actually costs something.
            //
            // Whatever went wrong is not written down. A log line saying which
            // address failed to authenticate, or where it wanted to go, is the
            // record this design exists to not keep.
            let _ = converse(stream, peer, method, registry).await;
        });
    }
}

/// One client, from its greeting to the end of what it does.
async fn converse(
    mut stream: TcpStream,
    peer: SocketAddr,
    method: Method,
    registry: Arc<Registry>,
) -> Result<(), InboundError> {
    let opening = match method {
        Method::Socks5 => open_socks5(&mut stream, peer, &registry).await?,
        Method::Http => open_http(&mut stream, peer, &registry).await?,
    };

    // A client that asked for its requests to be passed on keeps the
    // connection and sends more of them down it, so that conversation is
    // carried rather than relayed.
    if let Some(passed) = opening.passed {
        return crate::forward::carry(&mut stream, passed, opening.access, &registry).await;
    }

    let upstream = tokio::time::timeout(
        REACH_TIMEOUT,
        TcpStream::connect((opening.host.as_str(), opening.port)),
    )
    .await
    .map_err(|_| InboundError::Protocol("upstream"))?;

    let mut upstream = match upstream {
        Ok(upstream) => {
            match method {
                Method::Socks5 => socks5::answer_request(&mut stream, 0).await?,
                Method::Http => http::answer_established(&mut stream).await?,
            }
            upstream
        }
        Err(_) => {
            match method {
                // Five is "connection refused" in the protocol's own words.
                Method::Socks5 => socks5::answer_request(&mut stream, 5).await?,
                Method::Http => http::answer_unreachable(&mut stream).await?,
            }
            return Err(InboundError::Protocol("upstream"));
        }
    };

    relay(&mut stream, &mut upstream, opening.access, &registry).await
}

/// Where a client wants to go, once it has been let in.
struct Opening {
    /// Which access it came in on.
    access: Uuid,
    /// Where it wants to go.
    host: String,
    /// The port it wants.
    port: u16,
    /// The first request to pass on, when the client asked for that rather
    /// than for a tunnel.
    passed: Option<http::Forward>,
}

/// The SOCKS5 opening, up to knowing where the client wants to go.
async fn open_socks5<S>(
    stream: &mut S,
    peer: SocketAddr,
    registry: &Registry,
) -> Result<Opening, InboundError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(GREETING_TIMEOUT, socks5::negotiate(stream))
        .await
        .map_err(|_| InboundError::Protocol("socks5"))??;

    let (user, pass) = tokio::time::timeout(GREETING_TIMEOUT, socks5::credentials(stream))
        .await
        .map_err(|_| InboundError::Protocol("socks5"))??;

    let admitted = registry.admit(Method::Socks5, &user, &pass, peer.ip());
    socks5::answer_credentials(stream, admitted.is_ok()).await?;
    let access = admitted?;

    let request = tokio::time::timeout(GREETING_TIMEOUT, socks5::request(stream))
        .await
        .map_err(|_| InboundError::Protocol("socks5"))??;
    Ok(Opening {
        access,
        host: request.host,
        port: request.port,
        passed: None,
    })
}

/// The HTTP opening, up to knowing where the client wants to go.
async fn open_http<S>(
    stream: &mut S,
    peer: SocketAddr,
    registry: &Registry,
) -> Result<Opening, InboundError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let asked = tokio::time::timeout(GREETING_TIMEOUT, http::read_request(stream))
        .await
        .map_err(|_| InboundError::Protocol("http"))??;

    let (host, port, credentials, passed) = match asked {
        http::Asked::Tunnel(connect) => (connect.host, connect.port, connect.credentials, None),
        http::Asked::Forward(forward) => (
            forward.host.clone(),
            forward.port,
            forward.credentials.clone(),
            Some(forward),
        ),
    };

    let Some((user, pass)) = credentials else {
        http::answer_unauthorised(stream).await?;
        return Err(InboundError::Refused);
    };

    match registry.admit(Method::Http, &user, &pass, peer.ip()) {
        Ok(access) => Ok(Opening {
            access,
            host,
            port,
            passed,
        }),
        Err(refusal) => {
            http::answer_unauthorised(stream).await?;
            Err(refusal)
        }
    }
}

/// Moves bytes both ways and counts them as they go.
///
/// Counted while the connection runs rather than when it ends. A connection
/// that lasts an afternoon would otherwise be worth nothing until the
/// afternoon was over, and one cut by a network fault — or by the node being
/// restarted — would be worth nothing at all. The quota that is supposed to
/// stop at fifty gigabytes has to be able to see them arriving.
///
/// The two directions are named the way the panel counts them: what the client
/// received and what it sent.
async fn relay<C, U>(
    client: &mut C,
    upstream: &mut U,
    access: Uuid,
    registry: &Registry,
) -> Result<(), InboundError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (mut from_client, mut to_client) = tokio::io::split(client);
    let (mut from_upstream, mut to_upstream) = tokio::io::split(upstream);

    let upward = pump(&mut from_client, &mut to_upstream, |moved| {
        registry.used(access, 0, moved)
    });
    let downward = pump(&mut from_upstream, &mut to_client, |moved| {
        registry.used(access, moved, 0)
    });

    // Either side ending ends the other: a half-open connection to a proxy is
    // a slot nobody is using.
    tokio::select! {
        outcome = upward => outcome,
        outcome = downward => outcome,
    }
}

/// Copies one direction, telling the caller about each piece as it passes.
async fn pump<R, W, F>(reader: &mut R, writer: &mut W, mut moved: F) -> Result<(), InboundError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut(i64),
{
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        writer.write_all(&buffer[..read]).await?;
        // Counted after the write, so what is counted is what was carried
        // rather than what was merely received.
        moved(read as i64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap_proto::{WireAccess, WireCredential};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn an_access(method: &str, user: &str, pass: &str) -> WireAccess {
        WireAccess {
            id: Uuid::now_v7(),
            method: method.to_owned(),
            credential: WireCredential::Login {
                user: user.to_owned(),
                pass: pass.to_owned(),
            },
            max_devices: None,
            state: "active".to_owned(),
        }
    }

    /// A listener serving one method, and something upstream to reach.
    async fn a_node(method: Method, access: WireAccess) -> (SocketAddr, SocketAddr, Arc<Registry>) {
        let registry = Arc::new(Registry::new(std::slice::from_ref(&access), [3u8; 32]));

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let inbound = listener.local_addr().unwrap();
        let serving = Arc::clone(&registry);
        tokio::spawn(async move {
            let _ = serve(listener, method, serving).await;
        });

        // Something to be proxied to: it says one word and listens.
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let target = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = upstream.accept().await {
                tokio::spawn(async move {
                    let mut heard = [0u8; 16];
                    let read = stream.read(&mut heard).await.unwrap_or(0);
                    let _ = stream.write_all(&heard[..read]).await;
                });
            }
        });

        (inbound, target, registry)
    }

    #[tokio::test]
    async fn a_socks_client_with_the_right_password_is_carried_and_counted() {
        let access = an_access("socks5", "alice", "opens the door");
        let (inbound, target, registry) = a_node(Method::Socks5, access.clone()).await;

        let mut client = TcpStream::connect(inbound).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut answer = [0u8; 2];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [5, 2]);

        client.write_all(&[1, 5]).await.unwrap();
        client.write_all(b"alice").await.unwrap();
        client.write_all(&[14]).await.unwrap();
        client.write_all(b"opens the door").await.unwrap();
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [1, 0], "the password was refused");

        let mut request = vec![5u8, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&target.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0, "the connection was not opened");

        client.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
        drop(client);

        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Some((bytes_in, bytes_out, devices)) = registry.taken().get(&access.id).copied()
                && bytes_in > 0
                && bytes_out > 0
            {
                assert_eq!(devices, 1);
                return;
            }
        }
        panic!("nothing was counted for the access that carried it");
    }

    #[tokio::test]
    async fn a_socks_client_with_the_wrong_password_is_told_so() {
        let access = an_access("socks5", "alice", "opens the door");
        let (inbound, _target, registry) = a_node(Method::Socks5, access.clone()).await;

        let mut client = TcpStream::connect(inbound).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut answer = [0u8; 2];
        client.read_exact(&mut answer).await.unwrap();

        client.write_all(&[1, 5]).await.unwrap();
        client.write_all(b"alice").await.unwrap();
        client.write_all(&[5]).await.unwrap();
        client.write_all(b"wrong").await.unwrap();
        client.read_exact(&mut answer).await.unwrap();

        assert_eq!(
            answer,
            [1, 1],
            "a wrong password was not refused in the protocol"
        );
        assert!(registry.taken().is_empty(), "a refusal was counted as use");
    }

    #[tokio::test]
    async fn an_http_client_is_carried_and_counted() {
        let access = an_access("http", "carol", "opens the other");
        let (inbound, target, registry) = a_node(Method::Http, access.clone()).await;

        let mut client = TcpStream::connect(inbound).await.unwrap();
        // "carol:opens the other"
        let request = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\n\
             Proxy-Authorization: Basic Y2Fyb2w6b3BlbnMgdGhlIG90aGVy\r\n\r\n",
            target.port()
        );
        client.write_all(request.as_bytes()).await.unwrap();

        let mut head = [0u8; 39];
        client.read_exact(&mut head).await.unwrap();
        assert!(
            String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&head)
        );

        client.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
        drop(client);

        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Some((bytes_in, _, _)) = registry.taken().get(&access.id).copied()
                && bytes_in > 0
            {
                return;
            }
        }
        panic!("nothing was counted for the access that carried it");
    }

    #[tokio::test]
    async fn an_http_client_with_no_credentials_is_asked_for_them() {
        let access = an_access("http", "carol", "opens the other");
        let (inbound, target, _registry) = a_node(Method::Http, access).await;

        let mut client = TcpStream::connect(inbound).await.unwrap();
        let request = format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", target.port());
        client.write_all(request.as_bytes()).await.unwrap();

        let mut said = String::new();
        client.read_to_string(&mut said).await.unwrap();
        assert!(said.starts_with("HTTP/1.1 407"), "{said}");
    }

    #[tokio::test]
    async fn an_access_of_the_other_method_does_not_pass_here() {
        // The account exists on this node, for the other listener.
        let access = an_access("http", "carol", "opens the other");
        let (inbound, _target, _registry) = a_node(Method::Socks5, access).await;

        let mut client = TcpStream::connect(inbound).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut answer = [0u8; 2];
        client.read_exact(&mut answer).await.unwrap();

        client.write_all(&[1, 5]).await.unwrap();
        client.write_all(b"carol").await.unwrap();
        client.write_all(&[15]).await.unwrap();
        client.write_all(b"opens the other").await.unwrap();
        client.read_exact(&mut answer).await.unwrap();

        assert_eq!(answer, [1, 1], "an access crossed between listeners");
    }

    #[tokio::test]
    async fn what_is_carried_is_counted_before_the_connection_ends() {
        let access = an_access("socks5", "alice", "opens the door");
        let (inbound, target, registry) = a_node(Method::Socks5, access.clone()).await;

        let mut client = TcpStream::connect(inbound).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut answer = [0u8; 2];
        client.read_exact(&mut answer).await.unwrap();
        client.write_all(&[1, 5]).await.unwrap();
        client.write_all(b"alice").await.unwrap();
        client.write_all(&[14]).await.unwrap();
        client.write_all(b"opens the door").await.unwrap();
        client.read_exact(&mut answer).await.unwrap();

        let mut request = vec![5u8, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&target.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();

        client.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        client.read_exact(&mut echoed).await.unwrap();

        // The connection is still open. A count that only arrived at the end
        // would be worth nothing to a quota, which has to stop something while
        // it is happening.
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if let Some((bytes_in, bytes_out, _)) = registry.taken().get(&access.id).copied()
                && bytes_in > 0
                && bytes_out > 0
            {
                drop(client);
                return;
            }
        }
        panic!("nothing was counted while the connection was still open");
    }
}
