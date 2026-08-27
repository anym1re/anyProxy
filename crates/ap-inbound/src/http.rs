use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::InboundError;

/// Longest request head this listener will read before giving up.
const HEAD_CEILING: usize = 8 * 1024;

/// What the client asked for, and who it says it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    /// Where it wants to go.
    pub host: String,
    /// The port it wants.
    pub port: u16,
    /// The name and password it offered, if it offered any.
    pub credentials: Option<(String, String)>,
}

/// Reads a CONNECT request.
///
/// Only CONNECT. Anything else would make this an ordinary forward proxy,
/// which means reading and rewriting what people send in the clear — a thing
/// this node has no business being able to do.
pub async fn read_connect<S>(stream: &mut S) -> Result<Connect, InboundError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= HEAD_CEILING {
            return Err(InboundError::Protocol("http"));
        }
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return Err(InboundError::Protocol("http"));
        }
        head.push(byte[0]);
    }

    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let request = lines.next().unwrap_or_default();
    let mut parts = request.split_whitespace();
    if !parts
        .next()
        .is_some_and(|verb| verb.eq_ignore_ascii_case("CONNECT"))
    {
        // Answered rather than dropped. A silent close is what a broken
        // network looks like, and someone who points a browser at this port to
        // see whether it is alive learns nothing from it — which is how an
        // afternoon goes into a listener that was working the whole time.
        answer_only_connect(stream).await?;
        return Err(InboundError::Protocol("http"));
    }
    let target = parts.next().ok_or(InboundError::Protocol("http"))?;
    let (host, port) = target
        .rsplit_once(':')
        .ok_or(InboundError::Protocol("http"))?;
    let port: u16 = port.parse().map_err(|_| InboundError::Protocol("http"))?;
    if host.is_empty() {
        return Err(InboundError::Protocol("http"));
    }

    let mut credentials = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
            continue;
        }
        let value = value.trim();
        let Some(encoded) = value
            .strip_prefix("Basic ")
            .or(value.strip_prefix("basic "))
        else {
            continue;
        };
        let Some(decoded) = from_base64(encoded.trim()) else {
            continue;
        };
        let decoded = String::from_utf8_lossy(&decoded).into_owned();
        if let Some((user, pass)) = decoded.split_once(':') {
            credentials = Some((user.to_owned(), pass.to_owned()));
        }
    }

    Ok(Connect {
        host: host.to_owned(),
        port,
        credentials,
    })
}

/// Tells the client the tunnel is open.
pub async fn answer_established<S>(stream: &mut S) -> Result<(), InboundError>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    Ok(())
}

/// Asks the client to authenticate, or tells it that it failed.
///
/// The same answer either way. A client that offered nothing and one that
/// offered the wrong thing must not be able to tell which happened, or the
/// difference becomes a way to find out which names exist.
pub async fn answer_unauthorised<S>(stream: &mut S) -> Result<(), InboundError>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=\"\"\r\n\
              Content-Length: 0\r\n\
              Connection: close\r\n\r\n",
        )
        .await?;
    Ok(())
}

/// Tells a client that asked for something else that this is not that.
///
/// No banner and no explanation: enough for a browser to show a status rather
/// than an empty page, and nothing that describes what is listening here.
pub async fn answer_only_connect<S>(stream: &mut S) -> Result<(), InboundError>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(
            b"HTTP/1.1 405 Method Not Allowed\r\n\
              Allow: CONNECT\r\n\
              Content-Length: 0\r\n\
              Connection: close\r\n\r\n",
        )
        .await?;
    Ok(())
}

/// Tells the client the node could not reach where it asked to go.
pub async fn answer_unreachable<S>(stream: &mut S) -> Result<(), InboundError>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(
            b"HTTP/1.1 502 Bad Gateway\r\n\
              Content-Length: 0\r\n\
              Connection: close\r\n\r\n",
        )
        .await?;
    Ok(())
}

/// Decodes the one encoding HTTP basic authentication uses.
///
/// Written out rather than taken as a dependency: it is twenty lines, and this
/// is the only place in the project that needs it.
fn from_base64(text: &str) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u32> {
        Some(match byte {
            b'A'..=b'Z' => u32::from(byte - b'A'),
            b'a'..=b'z' => u32::from(byte - b'a') + 26,
            b'0'..=b'9' => u32::from(byte - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }

    let bytes: Vec<u8> = text.bytes().filter(|byte| *byte != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut packed = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            packed |= value(*byte)? << (18 - 6 * index);
        }
        let taken = match chunk.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            _ => return None,
        };
        for index in 0..taken {
            out.push(((packed >> (16 - 8 * index)) & 0xFF) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read_from(request: &str) -> Result<Connect, InboundError> {
        let (mut client, mut server) = tokio::io::duplex(16 * 1024);
        let bytes = request.to_owned();
        tokio::spawn(async move {
            let _ = client.write_all(bytes.as_bytes()).await;
        });
        read_connect(&mut server).await
    }

    #[tokio::test]
    async fn a_connect_names_where_it_wants_to_go() {
        let parsed = read_from("CONNECT ya.ru:443 HTTP/1.1\r\nHost: ya.ru:443\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(parsed.host, "ya.ru");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.credentials, None);
    }

    #[tokio::test]
    async fn credentials_come_out_of_the_header() {
        // "alice:opens the door"
        let parsed = read_from(
            "CONNECT ya.ru:443 HTTP/1.1\r\n\
             Proxy-Authorization: Basic YWxpY2U6b3BlbnMgdGhlIGRvb3I=\r\n\r\n",
        )
        .await
        .unwrap();
        assert_eq!(
            parsed.credentials,
            Some(("alice".to_owned(), "opens the door".to_owned()))
        );
    }

    #[tokio::test]
    async fn a_verb_other_than_connect_is_refused() {
        for request in [
            "GET http://ya.ru/ HTTP/1.1\r\n\r\n",
            "POST http://ya.ru/ HTTP/1.1\r\n\r\n",
        ] {
            assert!(read_from(request).await.is_err(), "{request} was accepted");
        }
    }

    #[tokio::test]
    async fn a_verb_other_than_connect_is_answered_rather_than_dropped() {
        // A silent close is what a broken network looks like. Someone checking
        // whether the listener is alive by pointing a browser at it learns
        // nothing from silence, and spends the afternoon on a listener that
        // was working the whole time.
        let (mut client, mut server) = tokio::io::duplex(16 * 1024);
        let asked = tokio::spawn(async move {
            let _ = client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
            let mut said = Vec::new();
            let _ = client.read_to_end(&mut said).await;
            said
        });

        assert!(read_connect(&mut server).await.is_err());
        drop(server);

        let said = String::from_utf8_lossy(&asked.await.unwrap()).into_owned();
        assert!(
            said.starts_with("HTTP/1.1 405 "),
            "the client heard: {said}"
        );
        assert!(
            !said.to_ascii_lowercase().contains("proxy"),
            "the answer describes what is listening here: {said}"
        );
    }

    #[tokio::test]
    async fn a_target_without_a_port_is_refused() {
        assert!(read_from("CONNECT ya.ru HTTP/1.1\r\n\r\n").await.is_err());
        assert!(read_from("CONNECT :443 HTTP/1.1\r\n\r\n").await.is_err());
    }

    #[tokio::test]
    async fn a_head_that_never_ends_is_given_up_on() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = client.write_all(b"CONNECT ya.ru:443 HTTP/1.1\r\n").await;
            for _ in 0..600 {
                let _ = client
                    .write_all(b"X-Filler: aaaaaaaaaaaaaaaaaaaa\r\n")
                    .await;
            }
        });
        assert!(read_connect(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn the_challenge_says_nothing_about_what_exists() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        answer_unauthorised(&mut server).await.unwrap();
        drop(server);

        let mut said = String::new();
        client.read_to_string(&mut said).await.unwrap();
        assert!(said.starts_with("HTTP/1.1 407"));
        // An empty realm: a realm naming the operator or the node would say
        // more about who runs this than a refusal needs to.
        assert!(said.contains("realm=\"\""), "{said}");
    }

    #[test]
    fn the_encoding_round_trips_what_a_client_would_send() {
        for (encoded, expected) in [
            ("YWxpY2U6b3BlbnMgdGhlIGRvb3I=", "alice:opens the door"),
            ("Ym9iOng=", "bob:x"),
            ("YTpi", "a:b"),
        ] {
            assert_eq!(
                String::from_utf8(from_base64(encoded).unwrap()).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn something_that_is_not_the_encoding_is_refused() {
        for text in ["not base64!", "@@@@", "YWxpY2U6b3Blb!"] {
            assert!(from_base64(text).is_none(), "{text} was decoded");
        }
    }
}
