//! Passing requests on, one after another, over the connection that brought
//! them.
//!
//! Telegram over an HTTP proxy does not open a connection per request: it
//! posts to a data centre, waits for the answer on the same connection, and
//! posts again. Closing after the first answer left the client reconnecting in
//! a rhythm, which is what it looked like from the other end.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::InboundError;
use crate::buffered::Buffered;
use crate::http::{self, Asked, Body, Forward};
use crate::pool::Pool;
use crate::registry::Registry;

/// Longest answer head this listener will hold from a server.
const ANSWER_CEILING: usize = 64 * 1024;

/// How long a server has to answer before the connection is given up on.
const ANSWER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Largest body held in hand so a request can be sent a second time.
///
/// A connection taken from the pool may have been closed by the far end while
/// it waited. That is only recoverable if the request can be sent again, which
/// means holding it. Requests to a data centre are small; anything larger goes
/// on a connection opened for it, where the question does not arise.
const REPLAY_LIMIT: u64 = 64 * 1024;

/// Carries requests from one client until it stops sending them.
pub async fn carry<C>(
    client: &mut Buffered<C>,
    first: Forward,
    access: Uuid,
    registry: &Registry,
    pool: &Pool,
) -> Result<(), InboundError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut addressed = (first.host.clone(), first.port);
    let mut held: Option<Buffered<TcpStream>> = None;
    let mut request = Some(first);

    loop {
        let asking = match request.take() {
            Some(asking) => asking,
            None => match http::read_request(client).await {
                Ok(Asked::Forward(asking)) => asking,
                // The client has nothing more to send, or asks for a tunnel,
                // which is a different conversation it can have on its own
                // connection. Either way what is still open to the destination
                // outlives this client and is worth keeping warm.
                Ok(Asked::Tunnel(_)) | Err(_) => {
                    if let Some(spare) = held.take() {
                        pool.keep(&addressed.0, addressed.1, spare);
                    }
                    return Ok(());
                }
            },
        };

        if (asking.host.clone(), asking.port) != addressed {
            if let Some(spare) = held.take() {
                pool.keep(&addressed.0, addressed.1, spare);
            }
            addressed = (asking.host.clone(), asking.port);
        }

        // A body small enough to keep lets a stale connection be retried. A
        // larger one is streamed, and then only a connection opened for it
        // will do.
        let replayable = match asking.body {
            Body::Counted(length) if length <= REPLAY_LIMIT => {
                let mut body = Vec::with_capacity(length as usize);
                (&mut *client).take(length).read_to_end(&mut body).await?;
                Some(body)
            }
            _ => None,
        };

        let mut upstream = match held.take() {
            Some(upstream) => upstream,
            None => match replayable.is_some() {
                true => match pool.take(&addressed.0, addressed.1) {
                    Some(warm) => warm,
                    None => Pool::open(&addressed.0, addressed.1).await?,
                },
                false => Pool::open(&addressed.0, addressed.1).await?,
            },
        };

        let mut answer = None;
        let mut sent = 0i64;
        for attempt in 0..2 {
            upstream.write_all(&asking.head).await?;
            sent = asking.head.len() as i64
                + match &replayable {
                    Some(body) => {
                        upstream.write_all(body).await?;
                        body.len() as i64
                    }
                    None => pass(client, &mut upstream, asking.body).await?,
                };

            match tokio::time::timeout(ANSWER_TIMEOUT, upstream.head(ANSWER_CEILING)).await {
                Ok(Ok(head)) => {
                    answer = Some(head);
                    break;
                }
                // A connection that was waiting in the pool may have been
                // closed at the other end. Nothing has reached the client yet,
                // so the request can go again on a connection of its own.
                Ok(Err(_)) | Err(_) if attempt == 0 && replayable.is_some() => {
                    upstream = Pool::open(&addressed.0, addressed.1).await?;
                }
                Ok(Err(reason)) => return Err(reason),
                Err(_) => return Err(InboundError::Protocol("upstream")),
            }
        }
        let Some(answer) = answer else {
            return Err(InboundError::Protocol("upstream"));
        };

        // Counted once the exchange stood, so a request sent twice on a stale
        // connection is not charged twice.
        registry.used(access, 0, sent);
        client.write_all(&answer).await?;
        registry.used(access, answer.len() as i64, 0);

        let text = String::from_utf8_lossy(&answer).into_owned();
        let framing = Body::of_answer(&text);
        let back = pass(&mut upstream, client, framing).await?;
        registry.used(access, back, 0);

        // Whoever says the connection ends, ends it. What is left over is
        // worth keeping only when the exchange finished on its own terms.
        if framing == Body::UntilClosed || says_close(&text) {
            return Ok(());
        }
        held = Some(upstream);
    }
}

/// Whether a head asks for the connection to end after this message.
fn says_close(head: &str) -> bool {
    head.split("\r\n").skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("connection")
                && value.to_ascii_lowercase().contains("close")
        })
    })
}

/// Moves a body from one side to the other, however its length is stated.
async fn pass<R, W>(from: &mut R, to: &mut W, body: Body) -> Result<i64, InboundError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match body {
        Body::Counted(0) => Ok(0),
        Body::Counted(length) => counted(from, to, length).await,
        Body::Chunked => chunked(from, to).await,
        Body::UntilClosed => {
            let mut buffer = vec![0u8; 16 * 1024];
            let mut moved = 0i64;
            loop {
                let read = from.read(&mut buffer).await?;
                if read == 0 {
                    return Ok(moved);
                }
                to.write_all(&buffer[..read]).await?;
                moved += read as i64;
            }
        }
    }
}

/// Moves exactly as many bytes as were promised.
async fn counted<R, W>(from: &mut R, to: &mut W, length: u64) -> Result<i64, InboundError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut left = length;
    let mut buffer = vec![0u8; 16 * 1024];
    let mut moved = 0i64;
    while left > 0 {
        let want = usize::try_from(left.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = from.read(&mut buffer[..want]).await?;
        if read == 0 {
            // Fewer bytes than promised. Whatever arrived has been passed on;
            // the connection is over either way.
            return Ok(moved);
        }
        to.write_all(&buffer[..read]).await?;
        moved += read as i64;
        left -= read as u64;
    }
    Ok(moved)
}

/// Moves a body whose pieces each state their own length.
async fn chunked<R, W>(from: &mut R, to: &mut W) -> Result<i64, InboundError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut moved = 0i64;
    loop {
        let line = a_line(from).await?;
        to.write_all(&line).await?;
        moved += line.len() as i64;

        let text = String::from_utf8_lossy(&line);
        let size = text.trim().split(';').next().unwrap_or("");
        let size = u64::from_str_radix(size.trim(), 16).unwrap_or(0);

        if size == 0 {
            // The trailer, up to the blank line that ends it.
            loop {
                let line = a_line(from).await?;
                to.write_all(&line).await?;
                moved += line.len() as i64;
                if line == b"\r\n" || line.is_empty() {
                    return Ok(moved);
                }
            }
        }

        moved += counted(from, to, size).await?;
        let ending = a_line(from).await?;
        to.write_all(&ending).await?;
        moved += ending.len() as i64;
    }
}

/// One line, ending included.
async fn a_line<R>(from: &mut R) -> Result<Vec<u8>, InboundError>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while !line.ends_with(b"\n") {
        // A chunk header is short. Anything longer is not one.
        if line.len() >= 1024 {
            return Err(InboundError::Protocol("http"));
        }
        let read = from.read(&mut byte).await?;
        if read == 0 {
            return Ok(line);
        }
        line.push(byte[0]);
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_head_that_asks_to_close_is_recognised() {
        assert!(says_close("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"));
        assert!(says_close("HTTP/1.1 200 OK\r\nconnection: Close\r\n\r\n"));
        assert!(!says_close(
            "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n"
        ));
        assert!(!says_close("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
    }

    #[tokio::test]
    async fn a_counted_body_is_moved_whole() {
        let (mut source, mut writing) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = writing.write_all(b"0123456789rest of it").await;
        });
        let mut landed = Vec::new();
        let moved = counted(&mut source, &mut landed, 10).await.unwrap();
        assert_eq!(moved, 10);
        assert_eq!(landed, b"0123456789");
    }

    #[tokio::test]
    async fn a_chunked_body_is_moved_piece_by_piece() {
        let (mut source, mut writing) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let _ = writing
                .write_all(b"4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n")
                .await;
        });
        let mut landed = Vec::new();
        chunked(&mut source, &mut landed).await.unwrap();
        assert_eq!(
            String::from_utf8_lossy(&landed),
            "4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n"
        );
    }

    #[test]
    fn framing_is_read_out_of_a_head() {
        assert_eq!(
            Body::of("POST /api HTTP/1.1\r\nContent-Length: 42\r\n\r\n"),
            Body::Counted(42)
        );
        assert_eq!(
            Body::of("POST /api HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Body::Chunked
        );
        assert_eq!(
            Body::of("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            Body::Counted(0)
        );
        assert_eq!(
            Body::of_answer("HTTP/1.1 200 OK\r\nServer: x\r\n\r\n"),
            Body::UntilClosed
        );
        assert_eq!(
            Body::of_answer("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
            Body::Counted(0)
        );
    }
}
