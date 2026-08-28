//! The listeners under the shapes a real client puts them in.
//!
//! Every defect these listeners have had was found on a live node rather than
//! here: a body counted only at the end, a head one kilobyte too large, an
//! answer with no length waited on until the connection closed, a connection
//! whose body stopped short handed to the next client. What they have in
//! common is that no test asked for the shape that broke.
//!
//! So this file asks for the shapes: many conversations at once, requests one
//! after another down one connection, answers in pieces, answers that carry
//! nothing, answers that stop short, heads far larger than anyone expects, and
//! what the meter says about all of it.

// An integration test is a separate build target and does not inherit the
// relaxations in clippy.toml.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use ap_inbound::{Method, Registry};
use ap_proto::{WireAccess, WireCredential};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

/// What the made-up server on the other side should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// A body of this many bytes, with a length that says so.
    Counted(usize),
    /// The same, with the header name in lower case, which is just as legal.
    CountedQuietly(usize),
    /// The same body, in pieces that each state their own size.
    Chunked(usize),
    /// A length that promises more than arrives.
    StopsShort { promised: usize, sent: usize },
    /// No content at all, and no length either.
    Nothing,
    /// Nothing changed, and no length either.
    Unchanged,
}

/// A server that answers however it was told to, once per request.
struct Somewhere {
    address: String,
}

impl Somewhere {
    /// Starts one, answering every request the same way.
    async fn answering(answer: Answer) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = converse(stream, answer).await;
                });
            }
        });
        Self { address }
    }
}

/// One conversation with the made-up server: as many requests as it is sent.
async fn converse(mut stream: TcpStream, answer: Answer) -> std::io::Result<()> {
    loop {
        let head = match read_head(&mut stream).await {
            Ok(head) => head,
            Err(_) => return Ok(()),
        };
        let text = String::from_utf8_lossy(&head).into_owned();
        // Whatever body came with it is read and thrown away.
        if let Some(length) = length_of(&text) {
            let mut body = vec![0u8; length];
            stream.read_exact(&mut body).await?;
        }

        match answer {
            Answer::Counted(size) => {
                stream
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n").as_bytes(),
                    )
                    .await?;
                stream.write_all(&vec![b'x'; size]).await?;
            }
            Answer::CountedQuietly(size) => {
                stream
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\ncontent-length: {size}\r\n\r\n").as_bytes(),
                    )
                    .await?;
                stream.write_all(&vec![b'w'; size]).await?;
            }
            Answer::Chunked(size) => {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                    .await?;
                let mut left = size;
                while left > 0 {
                    let piece = left.min(64);
                    stream
                        .write_all(format!("{piece:x}\r\n").as_bytes())
                        .await?;
                    stream.write_all(&vec![b'y'; piece]).await?;
                    stream.write_all(b"\r\n").await?;
                    left -= piece;
                }
                stream.write_all(b"0\r\n\r\n").await?;
            }
            Answer::StopsShort { promised, sent } => {
                stream
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {promised}\r\n\r\n").as_bytes(),
                    )
                    .await?;
                stream.write_all(&vec![b'z'; sent]).await?;
                return Ok(());
            }
            Answer::Nothing => {
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nServer: x\r\n\r\n")
                    .await?;
            }
            Answer::Unchanged => {
                stream
                    .write_all(b"HTTP/1.1 304 Not Modified\r\nETag: \"a\"\r\n\r\n")
                    .await?;
            }
        }
    }
}

/// Reads to the blank line that ends a head.
async fn read_head(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 128 * 1024 {
            return Err(std::io::Error::other("head too large"));
        }
        if stream.read(&mut byte).await? == 0 {
            return Err(std::io::Error::other("closed"));
        }
        head.push(byte[0]);
    }
    Ok(head)
}

/// The length a head states, if it states one.
fn length_of(head: &str) -> Option<usize> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

/// Two accesses, one per method, and the listeners serving them.
///
/// A login belongs to one access on one method, as the panel issues them. Two
/// methods sharing a name is not a shape a node is ever given.
struct Node {
    socks5: String,
    http: String,
    registry: Arc<Registry>,
    socks5_access: Uuid,
    socks5_user: String,
    http_access: Uuid,
    http_user: String,
    pass: String,
}

impl Node {
    /// Puts both listeners up on ports nobody chose.
    async fn open() -> Self {
        let socks5_access = Uuid::now_v7();
        let http_access = Uuid::now_v7();
        let pass = "opens the door".to_owned();
        let socks5_user = socks5_access.simple().to_string();
        let http_user = http_access.simple().to_string();

        let accesses = vec![
            WireAccess {
                id: socks5_access,
                method: "socks5".to_owned(),
                credential: WireCredential::Login {
                    user: socks5_user.clone(),
                    pass: pass.clone(),
                },
                max_devices: None,
                state: "active".to_owned(),
            },
            WireAccess {
                id: http_access,
                method: "http".to_owned(),
                credential: WireCredential::Login {
                    user: http_user.clone(),
                    pass: pass.clone(),
                },
                max_devices: None,
                state: "active".to_owned(),
            },
        ];

        let registry = Arc::new(Registry::new(&accesses, [7u8; 32]));
        let mut bound = Vec::new();
        for method in [Method::Socks5, Method::Http] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            bound.push(listener.local_addr().unwrap().to_string());
            let registry = Arc::clone(&registry);
            tokio::spawn(async move {
                let _ = ap_inbound::serve(listener, method, registry).await;
            });
        }

        Self {
            socks5: bound[0].clone(),
            http: bound[1].clone(),
            registry,
            socks5_access,
            socks5_user,
            http_access,
            http_user,
            pass,
        }
    }

    /// What the meter says has passed for one of the two accesses.
    fn counted(&self, access: Uuid) -> (i64, i64) {
        self.registry
            .taken()
            .get(&access)
            .map(|used| (used.0, used.1))
            .unwrap_or((0, 0))
    }
}

/// Opens a tunnel through the SOCKS5 listener and hands it back.
async fn through_socks5(node: &Node, to: &str, user: &str, pass: &str) -> Option<TcpStream> {
    let mut stream = TcpStream::connect(&node.socks5).await.ok()?;
    stream.write_all(&[5, 1, 2]).await.ok()?;
    let mut answer = [0u8; 2];
    stream.read_exact(&mut answer).await.ok()?;
    if answer != [5, 2] {
        return None;
    }

    let mut greeting = vec![1u8, user.len() as u8];
    greeting.extend_from_slice(user.as_bytes());
    greeting.push(pass.len() as u8);
    greeting.extend_from_slice(pass.as_bytes());
    stream.write_all(&greeting).await.ok()?;
    stream.read_exact(&mut answer).await.ok()?;
    if answer != [1, 0] {
        return None;
    }

    let (host, port) = to.rsplit_once(':')?;
    let mut request = vec![5u8, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.parse::<u16>().ok()?.to_be_bytes());
    stream.write_all(&request).await.ok()?;

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.ok()?;
    (reply[1] == 0).then_some(stream)
}

/// Opens a connection to the HTTP listener, ready for a request to be passed on.
async fn to_http(node: &Node) -> TcpStream {
    TcpStream::connect(&node.http).await.unwrap()
}

/// What a request through the HTTP listener looks like.
fn passed_on(to: &str, path: &str, user: &str, pass: &str, extra: &str) -> String {
    let credential = encode64(format!("{user}:{pass}").as_bytes());
    format!(
        "GET http://{to}{path} HTTP/1.1\r\n\
         Host: {to}\r\n\
         Proxy-Authorization: Basic {credential}\r\n\
         {extra}\r\n"
    )
}

/// The encoding basic authentication uses, written out for the test.
fn encode64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut packed = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            packed |= u32::from(*byte) << (16 - 8 * index);
        }
        let taken = chunk.len() + 1;
        for index in 0..taken {
            out.push(ALPHABET[((packed >> (18 - 6 * index)) & 0x3F) as usize] as char);
        }
        for _ in taken..4 {
            out.push('=');
        }
    }
    out
}

/// Reads a whole answer: head, then body as the head framed it.
async fn read_answer(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let head = read_head(stream).await.ok()?;
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut body = Vec::new();

    if text.contains("chunked") {
        loop {
            let mut line = Vec::new();
            let mut byte = [0u8; 1];
            while !line.ends_with(b"\n") {
                if stream.read(&mut byte).await.ok()? == 0 {
                    return Some((text, body));
                }
                line.push(byte[0]);
            }
            let size = usize::from_str_radix(String::from_utf8_lossy(&line).trim(), 16).ok()?;
            if size == 0 {
                let mut ending = [0u8; 2];
                let _ = stream.read_exact(&mut ending).await;
                break;
            }
            let mut piece = vec![0u8; size + 2];
            stream.read_exact(&mut piece).await.ok()?;
            body.extend_from_slice(&piece[..size]);
        }
    } else if let Some(length) = length_of(&text) {
        body.resize(length, 0);
        // Short reads are the point of one of these tests, so what arrives is
        // what is reported rather than a failure.
        let mut filled = 0;
        while filled < length {
            match stream.read(&mut body[filled..]).await {
                Ok(0) | Err(_) => break,
                Ok(read) => filled += read,
            }
        }
        body.truncate(filled);
    }
    Some((text, body))
}

#[tokio::test]
async fn a_hundred_conversations_at_once_are_all_served() {
    let node = Node::open().await;
    let somewhere = Somewhere::answering(Answer::Counted(4096)).await;

    let mut running = Vec::new();
    for _ in 0..100 {
        let to = somewhere.address.clone();
        let socks5 = node.socks5.clone();
        let user = node.socks5_user.clone();
        let pass = node.pass.clone();
        running.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(&socks5).await.ok()?;
            stream.write_all(&[5, 1, 2]).await.ok()?;
            let mut answer = [0u8; 2];
            stream.read_exact(&mut answer).await.ok()?;
            let mut greeting = vec![1u8, user.len() as u8];
            greeting.extend_from_slice(user.as_bytes());
            greeting.push(pass.len() as u8);
            greeting.extend_from_slice(pass.as_bytes());
            stream.write_all(&greeting).await.ok()?;
            stream.read_exact(&mut answer).await.ok()?;

            let (host, port) = to.rsplit_once(':')?;
            let mut request = vec![5u8, 1, 0, 3, host.len() as u8];
            request.extend_from_slice(host.as_bytes());
            request.extend_from_slice(&port.parse::<u16>().ok()?.to_be_bytes());
            stream.write_all(&request).await.ok()?;
            let mut reply = [0u8; 10];
            stream.read_exact(&mut reply).await.ok()?;

            stream
                .write_all(b"GET /x HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .ok()?;
            let (_, body) = read_answer(&mut stream).await?;
            Some(body.len())
        }));
    }

    let mut served = 0;
    for one in running {
        if one.await.unwrap() == Some(4096) {
            served += 1;
        }
    }
    assert_eq!(
        served, 100,
        "only {served} of a hundred conversations landed"
    );
}

#[tokio::test]
async fn many_requests_on_one_connection_are_all_answered() {
    // The listener that closed after the first answer made clients reconnect
    // in a rhythm, which is what it looked like from the other end.
    let node = Node::open().await;
    let somewhere = Somewhere::answering(Answer::Counted(64)).await;
    let mut stream = to_http(&node).await;

    for _ in 0..25 {
        let request = passed_on(&somewhere.address, "/x", &node.http_user, &node.pass, "");
        stream.write_all(request.as_bytes()).await.unwrap();
        let (head, body) = read_answer(&mut stream).await.expect("no answer came back");
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(body.len(), 64);
    }
}

#[tokio::test]
async fn an_answer_in_pieces_arrives_whole() {
    let node = Node::open().await;
    let somewhere = Somewhere::answering(Answer::Chunked(1000)).await;
    let mut stream = to_http(&node).await;

    let request = passed_on(&somewhere.address, "/x", &node.http_user, &node.pass, "");
    stream.write_all(request.as_bytes()).await.unwrap();
    let (head, body) = read_answer(&mut stream).await.expect("no answer came back");

    assert!(head.contains("chunked"), "{head}");
    assert_eq!(body.len(), 1000, "the pieces did not add up");
    assert!(body.iter().all(|byte| *byte == b'y'));
}

#[tokio::test]
async fn an_answer_that_carries_nothing_does_not_hang() {
    // Waiting for a body on one of these means waiting for the server to
    // close, which it has no reason to do.
    //
    // The head arrives either way, so that is not what is asked here. What is
    // asked is whether the conversation goes on afterwards: a listener still
    // waiting for a body it will never get answers nothing more.
    let node = Node::open().await;
    for answer in [Answer::Nothing, Answer::Unchanged] {
        let somewhere = Somewhere::answering(answer).await;
        let mut stream = to_http(&node).await;

        let request = passed_on(&somewhere.address, "/x", &node.http_user, &node.pass, "");
        stream.write_all(request.as_bytes()).await.unwrap();
        let (head, body) =
            tokio::time::timeout(std::time::Duration::from_secs(3), read_answer(&mut stream))
                .await
                .unwrap_or_else(|_| panic!("{answer:?}: the first answer never came"))
                .expect("no answer came back");
        assert!(
            head.starts_with("HTTP/1.1 2") || head.starts_with("HTTP/1.1 3"),
            "{head}"
        );
        assert!(body.is_empty());

        stream.write_all(request.as_bytes()).await.unwrap();
        let again =
            tokio::time::timeout(std::time::Duration::from_secs(3), read_answer(&mut stream))
                .await
                .unwrap_or_else(|_| {
                    panic!("{answer:?}: the listener was still waiting for a body that never comes")
                });
        let (head, _) = again.expect("the conversation ended after an empty answer");
        assert!(
            head.starts_with("HTTP/1.1 2") || head.starts_with("HTTP/1.1 3"),
            "{head}"
        );
    }
}

#[tokio::test]
async fn a_length_in_lower_case_is_still_a_length() {
    // Header names are not case sensitive. A server that writes it quietly is
    // not saying that the body runs until the connection closes.
    let node = Node::open().await;
    let somewhere = Somewhere::answering(Answer::CountedQuietly(700)).await;
    let mut stream = to_http(&node).await;

    let request = passed_on(&somewhere.address, "/x", &node.http_user, &node.pass, "");
    stream.write_all(request.as_bytes()).await.unwrap();
    let (_, body) =
        tokio::time::timeout(std::time::Duration::from_secs(3), read_answer(&mut stream))
            .await
            .expect("a quietly stated length was waited on until the deadline")
            .expect("no answer came back");
    assert_eq!(body.len(), 700);

    // And the conversation goes on, which it would not if the listener were
    // still waiting for a body it already had.
    stream.write_all(request.as_bytes()).await.unwrap();
    let again = tokio::time::timeout(std::time::Duration::from_secs(3), read_answer(&mut stream))
        .await
        .expect("the listener was still waiting after a quietly stated length");
    assert_eq!(again.expect("the conversation ended").1.len(), 700);
}

#[tokio::test]
async fn a_body_that_stops_short_reaches_the_client_as_far_as_it_got() {
    let node = Node::open().await;
    let somewhere = Somewhere::answering(Answer::StopsShort {
        promised: 5000,
        sent: 1200,
    })
    .await;
    let mut stream = to_http(&node).await;

    let request = passed_on(&somewhere.address, "/x", &node.http_user, &node.pass, "");
    stream.write_all(request.as_bytes()).await.unwrap();
    let came = tokio::time::timeout(std::time::Duration::from_secs(5), read_answer(&mut stream))
        .await
        .expect("a body that stopped short was waited on until the deadline");
    let (_, body) = came.expect("no answer came back");

    assert_eq!(body.len(), 1200, "what arrived was not passed on");
}

#[tokio::test]
async fn a_head_of_thirty_kilobytes_is_carried() {
    // A real client sends a head that is mostly cookies. At eight kilobytes
    // the connection used to be reset with no answer at all.
    let node = Node::open().await;
    let somewhere = Somewhere::answering(Answer::Counted(16)).await;
    let mut stream = to_http(&node).await;

    let mut padding = String::new();
    while padding.len() < 30 * 1024 {
        padding.push_str(&format!(
            "Cookie: filler{}={}\r\n",
            padding.len(),
            "q".repeat(200)
        ));
    }
    let request = passed_on(
        &somewhere.address,
        "/x",
        &node.http_user,
        &node.pass,
        &padding,
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let (head, body) = read_answer(&mut stream).await.expect("no answer came back");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body.len(), 16);
}

#[tokio::test]
async fn a_wrong_password_is_refused_while_the_right_one_is_served() {
    let node = Node::open().await;
    let somewhere = Somewhere::answering(Answer::Counted(32)).await;

    assert!(
        through_socks5(
            &node,
            &somewhere.address,
            &node.socks5_user,
            "not the password"
        )
        .await
        .is_none(),
        "a wrong password opened a tunnel"
    );
    assert!(
        through_socks5(&node, &somewhere.address, "nobody", &node.pass)
            .await
            .is_none(),
        "a name nobody holds opened a tunnel"
    );
    assert!(
        through_socks5(&node, &somewhere.address, &node.socks5_user, &node.pass)
            .await
            .is_some(),
        "the right password was refused after the wrong ones"
    );
}

#[tokio::test]
async fn what_passed_through_is_what_was_counted() {
    // The meter feeds a quota. A count that drifts from what actually moved is
    // a quota that stops at the wrong place.
    let node = Node::open().await;
    let somewhere = Somewhere::answering(Answer::Counted(10_000)).await;

    let before = node.counted(node.http_access);
    let mut carried = 0i64;
    for _ in 0..10 {
        let mut stream = to_http(&node).await;
        let request = passed_on(&somewhere.address, "/x", &node.http_user, &node.pass, "");
        stream.write_all(request.as_bytes()).await.unwrap();
        let (head, body) = read_answer(&mut stream).await.expect("no answer came back");
        carried += (head.len() + body.len()) as i64;
    }

    let after = node.counted(node.http_access);
    let counted_in = after.0 - before.0;
    assert!(
        counted_in >= carried,
        "the meter counted {counted_in} where {carried} reached the client"
    );
    // Everything counted towards the client is either the answer or its body,
    // so it cannot be much more than what the client saw.
    assert!(
        counted_in <= carried + 2048,
        "the meter counted {counted_in} where only {carried} moved"
    );
    assert!(after.1 > 0, "nothing was counted on the way out");
}

#[tokio::test]
async fn a_tunnel_carries_what_is_put_through_it_both_ways() {
    let node = Node::open().await;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                // Says back whatever it is told, until the other side stops.
                let mut chunk = [0u8; 4096];
                loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if stream.write_all(&chunk[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });

    let mut tunnel = through_socks5(&node, &address, &node.socks5_user, &node.pass)
        .await
        .expect("the tunnel did not open");

    let said = vec![b'k'; 64 * 1024];
    tunnel.write_all(&said).await.unwrap();
    let mut heard = vec![0u8; said.len()];
    tunnel.read_exact(&mut heard).await.unwrap();
    assert_eq!(heard, said, "what came back is not what went in");

    let (into, out) = node.counted(node.socks5_access);
    assert!(
        into >= said.len() as i64 && out >= said.len() as i64,
        "a tunnel carried {} bytes each way and the meter has {into} in and {out} out",
        said.len()
    );
}
