use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::InboundError;
use crate::buffered::Buffered;

/// Longest request head this listener will hold.
///
/// Generous, because real clients send heads that are mostly cookies and a
/// head of several kilobytes is ordinary. A ceiling that a working client
/// crosses is a ceiling that refuses working clients.
const HEAD_CEILING: usize = 64 * 1024;

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

/// One request addressed to somewhere else, to be passed on unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    /// Where it is addressed.
    pub host: String,
    /// The port it is addressed to.
    pub port: u16,
    /// The name and password it offered, if it offered any.
    pub credentials: Option<(String, String)>,
    /// The request as the server it is addressed to should receive it.
    pub head: Vec<u8>,
    /// How much body follows the head.
    pub body: Body,
}

/// How much of a message follows its head, and how to know when it has ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    /// A stated number of bytes.
    Counted(u64),
    /// Lengths given ahead of each piece, ending with a piece of none.
    Chunked,
    /// Until whoever is sending it closes.
    UntilClosed,
}

impl Body {
    /// Reads the framing out of a head, request or response alike.
    pub fn of(head: &str) -> Self {
        for line in head.split("\r\n").skip(1) {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                return Self::Chunked;
            }
            if name.eq_ignore_ascii_case("content-length")
                && let Ok(length) = value.trim().parse()
            {
                return Self::Counted(length);
            }
        }
        // A request without either carries nothing; a response without either
        // runs to the close. The caller knows which it is holding.
        Self::Counted(0)
    }

    /// The same, for a response, where silence means "until closed".
    pub fn of_answer(head: &str) -> Self {
        match Self::of(head) {
            Self::Counted(0) if !head.contains("Content-Length") => Self::UntilClosed,
            other => other,
        }
    }
}

/// What the client asked this listener to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asked {
    /// Open a tunnel and stay out of it.
    Tunnel(Connect),
    /// Pass one request on to where it is addressed.
    Forward(Forward),
}

/// Reads what the client is asking for.
///
/// Two shapes, because clients use both. `CONNECT` opens a tunnel and the node
/// never sees inside it. A request naming a whole `http://` address asks the
/// node to pass it on, which is what Telegram does over an HTTP proxy: it
/// posts to a data centre rather than tunnelling to one. A listener that knew
/// only `CONNECT` refused every Telegram client that ever tried it.
///
/// Passing on is passing on. The request line loses the part naming this
/// proxy, the headers that concern this hop are dropped, and nothing else is
/// touched. `https://` is not accepted: passing that on would mean standing in
/// for the other end, which is not a thing this node should be able to do.
pub async fn read_request<S>(stream: &mut Buffered<S>) -> Result<Asked, InboundError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let head = match stream.head(HEAD_CEILING).await {
        Ok(head) => head,
        Err(InboundError::TooLarge) => {
            answer_head_too_large(stream).await?;
            return Err(InboundError::TooLarge);
        }
        Err(reason) => return Err(reason),
    };
    let text = String::from_utf8_lossy(&head);
    let request = text.split("\r\n").next().unwrap_or_default();
    let credentials = credentials_in(text.split("\r\n").skip(1));

    let mut parts = request.split_whitespace();
    let verb = parts.next().unwrap_or_default();
    let target = parts.next().ok_or(InboundError::Protocol("http"))?;
    let version = parts.next().unwrap_or("HTTP/1.1");

    if verb.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_authority(target, None)?;
        return Ok(Asked::Tunnel(Connect {
            host,
            port,
            credentials,
        }));
    }

    let Some(rest) = strip_scheme(target) else {
        // Answered rather than dropped. A silent close is what a broken
        // network looks like, and someone who points a browser at this port to
        // see whether it is alive learns nothing from it — which is how an
        // afternoon goes into a listener that was working the whole time.
        answer_only_connect(stream).await?;
        return Err(InboundError::Protocol("http"));
    };
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let (host, port) = split_authority(authority, Some(80))?;

    let mut passed = Vec::with_capacity(head.len());
    passed.extend_from_slice(format!("{verb} {path} {version}\r\n").as_bytes());
    let mut said_host = false;
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, _)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        // What concerns this hop stops at this hop.
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("keep-alive")
        {
            continue;
        }
        said_host |= name.eq_ignore_ascii_case("host");
        passed.extend_from_slice(line.as_bytes());
        passed.extend_from_slice(b"\r\n");
    }
    if !said_host {
        passed.extend_from_slice(format!("Host: {authority}\r\n").as_bytes());
    }
    passed.extend_from_slice(b"\r\n");

    Ok(Asked::Forward(Forward {
        host,
        port,
        credentials,
        head: passed,
        body: Body::of(&text),
    }))
}

/// What follows `http://`, and nothing else.
fn strip_scheme(target: &str) -> Option<&str> {
    target
        .to_ascii_lowercase()
        .starts_with("http://")
        .then(|| &target[7..])
}

/// Host and port, with a default when the port is left out.
fn split_authority(authority: &str, default: Option<u16>) -> Result<(String, u16), InboundError> {
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse().map_err(|_| InboundError::Protocol("http"))?,
        ),
        None => (authority, default.ok_or(InboundError::Protocol("http"))?),
    };
    if host.is_empty() {
        return Err(InboundError::Protocol("http"));
    }
    Ok((host.to_owned(), port))
}

/// The name and password a request offered, if it offered any.
fn credentials_in<'a>(lines: impl Iterator<Item = &'a str>) -> Option<(String, String)> {
    let mut found = None;
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
            found = Some((user.to_owned(), pass.to_owned()));
        }
    }
    found
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

/// Tells the client its head is longer than this listener holds.
pub async fn answer_head_too_large<S>(stream: &mut S) -> Result<(), InboundError>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(
            b"HTTP/1.1 431 Request Header Fields Too Large\r\n\
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
    use tokio::io::AsyncReadExt;

    async fn asked_for(request: &str) -> Result<Asked, InboundError> {
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let bytes = request.to_owned();
        tokio::spawn(async move {
            let _ = client.write_all(bytes.as_bytes()).await;
        });
        read_request(&mut Buffered::new(server)).await
    }

    async fn read_from(request: &str) -> Result<Connect, InboundError> {
        match asked_for(request).await? {
            Asked::Tunnel(connect) => Ok(connect),
            Asked::Forward(_) => Err(InboundError::Protocol("http")),
        }
    }

    async fn passed_on(request: &str) -> Forward {
        match asked_for(request).await {
            Ok(Asked::Forward(forward)) => forward,
            other => panic!("not passed on: {other:?}"),
        }
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
    async fn a_request_naming_no_full_address_is_refused() {
        // A request in origin form is addressed to whoever it reached, which
        // for a proxy is nobody. Only a whole address says where to pass it.
        for request in [
            "GET / HTTP/1.1\r\nHost: ya.ru\r\n\r\n",
            "POST /api HTTP/1.1\r\nHost: ya.ru\r\n\r\n",
        ] {
            assert!(asked_for(request).await.is_err(), "{request} was accepted");
        }
    }

    #[tokio::test]
    async fn a_request_naming_a_whole_address_is_passed_on() {
        // What Telegram sends over an HTTP proxy, verbatim in shape: a post to
        // a data centre rather than a tunnel to one.
        let forward = passed_on(
            "POST http://149.154.167.41:80/api HTTP/1.1\r\n\
             Host: 149.154.167.41\r\n\
             Content-Length: 4\r\n\
             Proxy-Authorization: Basic YWxpY2U6b3BlbnMgdGhlIGRvb3I=\r\n\
             Proxy-Connection: keep-alive\r\n\r\n",
        )
        .await;

        assert_eq!(forward.host, "149.154.167.41");
        assert_eq!(forward.port, 80);
        assert_eq!(
            forward.credentials,
            Some(("alice".to_owned(), "opens the door".to_owned()))
        );

        let head = String::from_utf8(forward.head).unwrap();
        assert!(
            head.starts_with("POST /api HTTP/1.1\r\n"),
            "the request still names this proxy: {head}"
        );
        assert!(
            !head.to_ascii_lowercase().contains("proxy-authorization"),
            "the password for this hop was passed on: {head}"
        );
        assert!(
            !head.to_ascii_lowercase().contains("proxy-connection"),
            "a header for this hop was passed on: {head}"
        );
        assert!(head.contains("Content-Length: 4\r\n"), "{head}");
        assert!(head.contains("Host: 149.154.167.41\r\n"), "{head}");
        assert!(head.ends_with("\r\n\r\n"), "the head does not end: {head}");
    }

    #[tokio::test]
    async fn a_whole_address_without_a_port_is_passed_on_to_eighty() {
        let forward = passed_on("GET http://ya.ru/ HTTP/1.1\r\nHost: ya.ru\r\n\r\n").await;
        assert_eq!((forward.host.as_str(), forward.port), ("ya.ru", 80));
    }

    #[tokio::test]
    async fn a_request_for_somewhere_over_tls_is_refused() {
        // Passing this on would mean standing in for the other end.
        assert!(
            asked_for("GET https://ya.ru/ HTTP/1.1\r\nHost: ya.ru\r\n\r\n")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_verb_other_than_connect_is_answered_rather_than_dropped() {
        // A silent close is what a broken network looks like. Someone checking
        // whether the listener is alive by pointing a browser at it learns
        // nothing from silence, and spends the afternoon on a listener that
        // was working the whole time.
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let asked = tokio::spawn(async move {
            let _ = client.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
            let mut said = Vec::new();
            let _ = client.read_to_end(&mut said).await;
            said
        });

        let mut held = Buffered::new(server);
        assert!(read_request(&mut held).await.is_err());
        drop(held);

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
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let _ = client.write_all(b"CONNECT ya.ru:443 HTTP/1.1\r\n").await;
            for _ in 0..600 {
                let _ = client
                    .write_all(b"X-Filler: aaaaaaaaaaaaaaaaaaaa\r\n")
                    .await;
            }
        });
        assert!(read_request(&mut Buffered::new(server)).await.is_err());
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
