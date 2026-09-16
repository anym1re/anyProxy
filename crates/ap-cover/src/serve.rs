//! Answering for the cover site, on loopback and nowhere else.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::Site;

/// Longest request head this will read.
const HEAD_CEILING: usize = 16 * 1024;

/// How long a visitor has to say what they want.
const GREETING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Answers for the site until the process stops.
///
/// Everything that reaches here came through the front door on 443, which is
/// on this machine, so there is nothing to authenticate and nobody to refuse.
pub async fn serve(listener: TcpListener, site: Arc<Site>) {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                // Out of descriptors the refusal repeats the instant it is
                // retried, and retrying at once spends a whole core (0101).
                if let Some(pause) = ap_core::net::pause_after_accept(&error) {
                    tokio::time::sleep(pause).await;
                }
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let site = Arc::clone(&site);
        tokio::spawn(async move {
            // Nothing is written down about who asked for what. A cover site
            // that kept a log would hold the one record this design exists to
            // not keep.
            let _ = answer(&mut stream, &site).await;
        });
    }
}

/// One visitor, from their request to their answer.
async fn answer(stream: &mut tokio::net::TcpStream, site: &Site) -> std::io::Result<()> {
    let head = match tokio::time::timeout(GREETING_TIMEOUT, read_head(stream)).await {
        Ok(Ok(head)) => head,
        _ => return Ok(()),
    };

    let text = String::from_utf8_lossy(&head);
    let request = text.split("\r\n").next().unwrap_or_default();
    let mut parts = request.split_whitespace();
    let verb = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or("/");

    // A site of this kind reads and nothing else.
    if !verb.eq_ignore_ascii_case("GET") && !verb.eq_ignore_ascii_case("HEAD") {
        return say(stream, 405, "text/plain; charset=utf-8", b"", 0, true).await;
    }

    let (status, page) = match site.page(path) {
        Some(page) => (200, page),
        None => (404, site.missing()),
    };
    // A head asked for on its own still reports the length the whole thing
    // would have had.
    let body: &[u8] = if verb.eq_ignore_ascii_case("HEAD") {
        &[]
    } else {
        &page.bytes
    };
    say(
        stream,
        status,
        page.content_type,
        body,
        page.bytes.len(),
        false,
    )
    .await
}

/// Writes one answer.
async fn say(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    length: usize,
    close: bool,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Method Not Allowed",
    };
    // No name and no version. A header naming what serves this would be the
    // one thing on the page that did not belong to the business it describes.
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: public, max-age=600\r\n\
         Connection: {}\r\n\r\n",
        length,
        if close { "close" } else { "keep-alive" },
    );
    stream.write_all(head.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    Ok(())
}

/// Reads up to the blank line that ends a request head.
async fn read_head(stream: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 2048];
    while !head.windows(4).any(|four| four == b"\r\n\r\n") {
        if head.len() >= HEAD_CEILING {
            return Err(std::io::Error::other("head too large"));
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::other("closed before asking"));
        }
        head.extend_from_slice(&chunk[..read]);
    }
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn a_site_on_loopback() -> (String, Arc<Site>) {
        let site = Arc::new(crate::site([9u8; 32]));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let serving = Arc::clone(&site);
        tokio::spawn(async move { serve(listener, serving).await });
        (address, site)
    }

    async fn ask(address: &str, request: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut said = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_millis(400),
                stream.read(&mut chunk),
            )
            .await
            {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(read)) => said.extend_from_slice(&chunk[..read]),
                Ok(Err(_)) => break,
            }
        }
        String::from_utf8_lossy(&said).into_owned()
    }

    #[tokio::test]
    async fn the_front_page_is_served() {
        let (address, _) = a_site_on_loopback().await;
        let said = ask(&address, "GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(said.starts_with("HTTP/1.1 200 OK"), "{said}");
        assert!(said.contains("text/html"));
        assert!(said.contains("<!doctype html>"));
    }

    #[tokio::test]
    async fn a_path_that_is_not_here_is_answered_with_a_page() {
        let (address, _) = a_site_on_loopback().await;
        let said = ask(&address, "GET /nothing HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(said.starts_with("HTTP/1.1 404 Not Found"), "{said}");
        assert!(
            said.contains("<!doctype html>"),
            "a visitor got an empty answer: {said}"
        );
    }

    #[tokio::test]
    async fn nothing_says_what_is_serving_it() {
        // A header naming the software would be the one thing on the page that
        // does not belong to the business it describes.
        let (address, _) = a_site_on_loopback().await;
        let said = ask(&address, "GET / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let lowered = said.to_ascii_lowercase();
        for sign in ["server:", "x-powered-by", "anyproxy", "telemt"] {
            assert!(!lowered.contains(sign), "the answer names {sign}: {said}");
        }
    }

    #[tokio::test]
    async fn a_verb_that_is_not_a_reading_is_refused() {
        let (address, _) = a_site_on_loopback().await;
        let said = ask(&address, "POST / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(said.starts_with("HTTP/1.1 405"), "{said}");
    }

    #[tokio::test]
    async fn asking_for_the_head_alone_returns_no_body_but_the_right_length() {
        // Saying nothing follows and saying nothing exists are different
        // answers, and a crawler given the second would take the page for
        // empty.
        let (address, site) = a_site_on_loopback().await;
        let said = ask(&address, "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(said.starts_with("HTTP/1.1 200 OK"), "{said}");
        assert!(!said.contains("<!doctype html>"), "{said}");

        let length = site.page("/").unwrap().bytes.len();
        assert!(
            said.contains(&format!("Content-Length: {length}")),
            "the length was not the one a whole request would give: {said}"
        );
    }

    #[tokio::test]
    async fn a_second_page_is_served_on_the_same_connection() {
        let (address, site) = a_site_on_loopback().await;
        let inside = site
            .paths()
            .find(|path| path.len() > 1 && !path.ends_with(".css"))
            .unwrap()
            .to_owned();
        let said = ask(
            &address,
            &format!("GET {inside} HTTP/1.1\r\nHost: x\r\n\r\n"),
        )
        .await;
        assert!(said.starts_with("HTTP/1.1 200 OK"), "{said}");
    }
}
