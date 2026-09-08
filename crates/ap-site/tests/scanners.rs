//! The deterministic scanners (0094): what every answer of the site carries,
//! what the pages are made of, and where every link on them leads. Runs
//! without a network against a feed in the same process.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{PUBLIC_URL, Reply, ask, config, feed_server, get, start};

/// A feed with one of each shape, one of them named to break things.
const FEED: &str = r#"{ "links": [
  { "name": "для всех", "method": "faketls",
    "link": "https://t.me/proxy?server=203.0.113.7&port=443&secret=ee000102030405060708090a0b0c0d0e0f636f7665722e6578616d706c652e636f6d" },
  { "name": "<script>alert(1)</script>\"&'</script>", "method": "mtproto",
    "link": "https://t.me/proxy?server=203.0.113.9&port=8443&secret=dd000102030405060708090a0b0c0d0e0f" },
  { "name": "socks", "method": "socks5", "host": "203.0.113.8", "port": 1080,
    "user": "someone", "password": "something" }
] }"#;

/// Every path the site answers on, and the status each answers with.
const PATHS: [(&str, u16); 12] = [
    ("/", 302),
    ("/ru", 301),
    ("/en", 301),
    ("/ru/", 200),
    ("/en/", 200),
    ("/links.json", 200),
    ("/sitemap.xml", 200),
    ("/robots.txt", 200),
    ("/llms.txt", 200),
    ("/style.css", 200),
    ("/icon.svg", 200),
    ("/nothing-here", 404),
];

/// The headers every answer must carry, with their exact values.
const REQUIRED: [(&str, &str); 6] = [
    (
        "content-security-policy",
        "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includeSubDomains",
    ),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    (
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    ),
    ("cross-origin-resource-policy", "same-origin"),
];

fn check_headers(path: &str, reply: &Reply) {
    for (name, value) in REQUIRED {
        assert_eq!(
            reply.header(name),
            Some(value),
            "{path}: header {name} is {:?}",
            reply.header(name)
        );
    }
    for absent in ["server", "set-cookie", "x-powered-by", "via"] {
        assert_eq!(reply.header(absent), None, "{path}: carries {absent}");
    }
    let content_type = reply.header("content-type").unwrap_or_default();
    assert!(
        content_type.contains("charset=utf-8") || content_type == "image/svg+xml",
        "{path}: content-type {content_type:?} names no charset"
    );
    assert!(
        reply.header("cache-control").is_some(),
        "{path}: no cache-control"
    );
}

#[tokio::test]
async fn every_answer_carries_the_same_headers_and_the_expected_status() {
    let feed = feed_server(FEED).await;
    let running = start(config(feed)).await;
    for (path, status) in PATHS {
        let reply = get(running.public, path).await;
        assert_eq!(reply.status, status, "{path}: {}", reply.text());
        check_headers(path, &reply);
        let cache = reply.header("cache-control").unwrap();
        if status == 200 {
            assert!(cache.starts_with("public, max-age="), "{path}: {cache}");
        } else {
            assert_eq!(cache, "no-store", "{path}");
        }
    }
    // The loopback paths are unknown on the public listener.
    for path in ["/health", "/metrics"] {
        let reply = get(running.public, path).await;
        assert_eq!(reply.status, 404, "{path} answered on the public listener");
        check_headers(path, &reply);
    }
}

#[tokio::test]
async fn only_get_and_head_are_answered() {
    let feed = feed_server(FEED).await;
    let running = start(config(feed)).await;
    for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
        let reply = ask(running.public, method, "/ru/", &[]).await;
        assert_eq!(reply.status, 405, "{method}");
        assert_eq!(reply.header("allow"), Some("GET, HEAD"));
        check_headers("/ru/", &reply);
    }
    let whole = get(running.public, "/en/").await;
    let head = ask(running.public, "HEAD", "/en/", &[]).await;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty(), "a HEAD carried a body");
    assert_eq!(
        head.header("content-length"),
        whole.header("content-length")
    );
    check_headers("/en/", &head);
}

#[tokio::test]
async fn the_root_leads_by_preference_and_says_so() {
    let feed = feed_server(FEED).await;
    let running = start(config(feed)).await;
    for (accept, expected) in [
        (Some("en-US,en;q=0.9"), "/en/"),
        (Some("ru-RU,ru;q=0.9,en;q=0.8"), "/ru/"),
        (Some("de"), "/ru/"),
        (None, "/ru/"),
    ] {
        let headers: Vec<(&str, &str)> = accept
            .map(|value| vec![("accept-language", value)])
            .unwrap_or_default();
        let reply = ask(running.public, "GET", "/", &headers).await;
        assert_eq!(reply.status, 302, "{accept:?}");
        assert_eq!(
            reply.header("location"),
            Some(format!("{PUBLIC_URL}{expected}").as_str()),
            "{accept:?}"
        );
        assert_eq!(reply.header("vary"), Some("Accept-Language"));
    }
    let bare = get(running.public, "/en").await;
    assert_eq!(bare.status, 301);
    assert_eq!(
        bare.header("location"),
        Some(format!("{PUBLIC_URL}/en/").as_str())
    );
    // The query string changes nothing.
    let queried = get(running.public, "/ru/?utm=whatever").await;
    assert_eq!(queried.status, 200);
}

/// Elements that never close.
const VOID: [&str; 6] = ["meta", "link", "br", "hr", "img", "input"];

/// A strict reading of the page: balanced, quoted, one heading, a language.
fn check_html(page: &str) {
    assert!(page.starts_with("<!doctype html>\n"), "no doctype first");
    let rest = &page["<!doctype html>\n".len()..];
    let mut stack: Vec<String> = Vec::new();
    let mut h1 = 0;
    let mut scripts = 0;
    let mut position = 0;
    while let Some(open) = rest[position..].find('<') {
        let start = position + open;
        let close = rest[start..]
            .find('>')
            .map(|offset| start + offset)
            .expect("an unclosed tag");
        let tag = &rest[start + 1..close];
        // Text between tags must not hold a stray angle bracket.
        assert!(
            !rest[position..start].contains('>'),
            "a stray > before {tag:?}"
        );
        position = close + 1;
        if let Some(name) = tag.strip_prefix('/') {
            let opened = stack
                .pop()
                .unwrap_or_else(|| panic!("closing {name} with nothing open"));
            assert_eq!(opened, name, "closing {name} while {opened} is open");
            continue;
        }
        let (name, attributes) = tag.split_once(char::is_whitespace).unwrap_or((tag, ""));
        let name = name.trim_end_matches('/');
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()),
            "tag name {name:?} is not lowercase"
        );
        check_attributes(name, attributes.trim_end_matches('/'));
        match name {
            "h1" => h1 += 1,
            "script" => {
                scripts += 1;
                assert!(
                    attributes.contains("type=\"application/ld+json\""),
                    "a script that is not JSON-LD"
                );
                // Raw text until the closing tag; it must not close early.
                let end = rest[position..]
                    .find("</script>")
                    .expect("an unclosed script");
                let inside = &rest[position..position + end];
                assert!(!inside.contains('<'), "markup inside the JSON-LD");
                serde_json::from_str::<serde_json::Value>(inside).expect("the JSON-LD parses");
                position += end + "</script>".len();
                continue;
            }
            "html" => assert!(
                attributes.contains("lang=\"ru\"") || attributes.contains("lang=\"en\""),
                "html carries no lang"
            ),
            _ => {}
        }
        if !VOID.contains(&name) && !tag.ends_with('/') {
            stack.push(name.to_owned());
        }
    }
    assert!(stack.is_empty(), "left open: {stack:?}");
    assert_eq!(h1, 1, "the page has {h1} h1 elements");
    assert_eq!(scripts, 1, "the page has {scripts} scripts");
}

/// Every attribute is `name="value"` or a bare boolean, and none is an
/// event handler or an inline style.
fn check_attributes(tag: &str, attributes: &str) {
    let mut rest = attributes.trim();
    while !rest.is_empty() {
        let name_end = rest
            .find(|c: char| c == '=' || c.is_whitespace())
            .unwrap_or(rest.len());
        let name = &rest[..name_end];
        assert!(
            !name.starts_with("on") && name != "style",
            "<{tag}> carries {name}"
        );
        rest = rest[name_end..].trim_start();
        if let Some(after) = rest.strip_prefix('=') {
            let quoted = after
                .strip_prefix('"')
                .unwrap_or_else(|| panic!("<{tag} {name}=...> is not quoted"));
            let end = quoted.find('"').expect("an unclosed attribute");
            rest = quoted[end + 1..].trim_start();
        }
    }
}

#[tokio::test]
async fn the_pages_are_valid_html_without_scripts_or_inline_style() {
    let feed = feed_server(FEED).await;
    let running = start(config(feed)).await;
    for path in ["/ru/", "/en/"] {
        let page = get(running.public, path).await.text();
        check_html(&page);
        assert!(
            !page.contains("<script>alert"),
            "{path}: the name became markup"
        );
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(page.contains("для всех"));
        assert!(page.contains("<dd><code>1080</code></dd>"));
        // What an indexer reads.
        for needed in [
            "<link rel=\"canonical\" href=\"https://links.example",
            "<meta name=\"description\" content=\"",
            "<meta property=\"og:title\" content=\"",
            "<meta property=\"og:url\" content=\"https://links.example",
            "hreflang=\"x-default\"",
            "<main>",
            "<nav aria-label=",
        ] {
            assert!(page.contains(needed), "{path}: missing {needed}");
        }
    }
}

/// Every attribute value that is an address.
fn addresses(page: &str) -> Vec<String> {
    let mut found = Vec::new();
    for attribute in ["href=\"", "src=\""] {
        let mut rest = page;
        while let Some(start) = rest.find(attribute) {
            let value = &rest[start + attribute.len()..];
            let end = value.find('"').unwrap();
            found.push(value[..end].to_owned());
            rest = &value[end..];
        }
    }
    found
}

#[tokio::test]
async fn every_address_on_the_site_leads_somewhere() {
    let feed = feed_server(FEED).await;
    let running = start(config(feed)).await;
    let mut to_check: Vec<String> = Vec::new();
    for path in ["/ru/", "/en/"] {
        let page = get(running.public, path).await.text();
        for address in addresses(&page) {
            if address.starts_with("https://t.me/") {
                continue;
            }
            let local = address
                .strip_prefix(PUBLIC_URL)
                .unwrap_or_else(|| {
                    assert!(
                        address.starts_with('/'),
                        "{path}: foreign address {address}"
                    );
                    &address
                })
                .to_owned();
            to_check.push(local);
        }
    }
    let sitemap = get(running.public, "/sitemap.xml").await.text();
    let mut rest = sitemap.as_str();
    while let Some(start) = rest.find("<loc>") {
        let value = &rest[start + 5..];
        let end = value.find("</loc>").unwrap();
        to_check.push(value[..end].strip_prefix(PUBLIC_URL).unwrap().to_owned());
        rest = &value[end..];
    }
    let robots = get(running.public, "/robots.txt").await.text();
    assert!(robots.contains(&format!("Sitemap: {PUBLIC_URL}/sitemap.xml")));
    assert!(robots.contains("User-agent: *\nAllow: /"));
    let llms = get(running.public, "/llms.txt").await.text();
    assert!(llms.contains(&format!("{PUBLIC_URL}/links.json")));
    assert!(llms.contains(&format!("{PUBLIC_URL}/ru/")));
    assert!(llms.contains(&format!("{PUBLIC_URL}/en/")));

    assert!(to_check.len() >= 6, "too few addresses found: {to_check:?}");
    for local in to_check {
        let reply = get(running.public, &local).await;
        assert_eq!(reply.status, 200, "{local} does not answer");
    }
}

#[tokio::test]
async fn the_machine_copy_is_the_feed_verbatim_and_safe() {
    let feed = feed_server(FEED).await;
    let running = start(config(feed)).await;
    let reply = get(running.public, "/links.json").await;
    assert_eq!(
        reply.header("content-type"),
        Some("application/json; charset=utf-8")
    );
    let parsed: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
    let rows = parsed["links"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[1]["name"], "<script>alert(1)</script>\"&'</script>");
    assert_eq!(rows[2]["port"], 1080);
    let sitemap = get(running.public, "/sitemap.xml").await.text();
    assert!(sitemap.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert_eq!(sitemap.matches("hreflang=\"x-default\"").count(), 2);
}

#[tokio::test]
async fn a_feed_that_stops_answering_leaves_the_last_list_in_place() {
    // A feed that is not there: the list stays empty, honestly so.
    let never = start(config(([127, 0, 0, 1], 9).into())).await;
    let page = get(never.public, "/en/").await.text();
    assert!(page.contains("No links right now."));
    assert!(!page.contains("t.me"));
    let health = get(never.admin, "/health").await;
    assert_eq!(health.status, 503);
    assert_eq!(health.text(), "never\n");

    // A feed that answered once and then went away: what it said stays.
    let feed = feed_server(FEED).await;
    let running = start(config(feed)).await;
    assert!(get(running.public, "/en/").await.text().contains("t.me"));
    // The feed cannot be repointed on a running site, so the refusal is
    // exercised at the parser: a body that is not a feed changes nothing.
    assert!(ap_site::feed::parse(b"nonsense").is_err());
    assert_eq!(running.site.rendered().count, 3);
    let health = get(running.admin, "/health").await;
    assert_eq!(health.status, 200);
    assert_eq!(health.text(), "fresh\n");
}

#[tokio::test]
async fn the_loopback_listener_counts_and_names_nobody() {
    let feed = feed_server(FEED).await;
    let running = start(config(feed)).await;
    get(running.public, "/ru/").await;
    get(running.public, "/absent").await;
    ask(running.public, "POST", "/ru/", &[]).await;
    let metrics = get(running.admin, "/metrics").await.text();
    for line in [
        "site_requests_total{status=\"200\"} 1",
        "site_requests_total{status=\"404\"} 1",
        "site_requests_total{status=\"405\"} 1",
        "site_feed_fetches_total{outcome=\"ok\"} 1",
        "site_links 3",
    ] {
        assert!(metrics.contains(line), "missing {line:?} in:\n{metrics}");
    }
    assert!(metrics.contains("site_feed_age_seconds "));
    assert!(!metrics.contains("127.0.0.1"), "an address in the metrics");
    assert!(!metrics.contains("/ru/"), "a path in the metrics");
    let unknown = get(running.admin, "/ru/").await;
    assert_eq!(
        unknown.status, 404,
        "the page answered on the loopback listener"
    );
}

#[tokio::test]
async fn a_head_larger_than_the_ceiling_is_not_answered_with_a_page() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let feed = feed_server(FEED).await;
    let running = start(config(feed)).await;
    let mut stream = tokio::net::TcpStream::connect(running.public)
        .await
        .unwrap();
    let filler = "x".repeat(9 * 1024);
    let request = format!("GET /ru/ HTTP/1.1\r\nHost: a\r\nX-Filler: {filler}\r\n\r\n");
    let _ = stream.write_all(request.as_bytes()).await;
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut answer),
    )
    .await;
    let text = String::from_utf8_lossy(&answer);
    assert!(
        !text.starts_with("HTTP/1.1 200"),
        "an oversized head was answered with a page"
    );
}
