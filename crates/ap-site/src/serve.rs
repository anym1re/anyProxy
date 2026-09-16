//! The public listener: a fixed set of answers to a fixed set of paths.
//!
//! The path is the only input. Nothing from the request is echoed, nothing is
//! stored, no body is read. What can be asked and what is answered are both
//! enumerable, and the tests enumerate them (0094).

use std::sync::Arc;
use std::time::Duration;

use ap_core::Locale;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::Site;

/// Longest request head that is read.
pub const HEAD_CEILING: usize = 8 * 1024;

/// How long a visitor has to finish asking.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one connection may live, keep-alive included.
pub const CONNECTION_LIFETIME: Duration = Duration::from_secs(60);

/// How many connections are answered at once. Beyond it, accept waits.
pub const CONNECTIONS: usize = 1024;

/// What every answer carries.
///
/// Fixed, and the same on a `404` as on a page: a visitor learns nothing from
/// the shape of a refusal, and no path is an exception to the policy.
const FIXED_HEADERS: [(&str, &str); 6] = [
    (
        "content-security-policy",
        "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; \
         form-action 'none'; frame-ancestors 'none'",
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

/// How long a page may be kept by whoever asked for it.
const PAGE_CACHE: &str = "public, max-age=60";

/// How long the pieces that change with a build may be kept.
const STATIC_CACHE: &str = "public, max-age=86400";

/// Serves the public listener until the process stops.
pub async fn serve(listener: TcpListener, site: Arc<Site>) {
    let permits = Arc::new(Semaphore::new(CONNECTIONS));
    loop {
        // Waiting here rather than dropping the connection: a visitor over
        // the ceiling waits a moment for a slot, and a flood waits forever
        // without costing a thread.
        let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
            return;
        };
        let (stream, _) = match listener.accept().await {
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
            let io = TokioIo::new(stream);
            let connection = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEAD_TIMEOUT)
                .max_buf_size(HEAD_CEILING)
                .keep_alive(true)
                .serve_connection(
                    io,
                    service_fn(move |request: Request<Incoming>| {
                        let site = Arc::clone(&site);
                        async move {
                            let response = answer(&site, &request);
                            site.counters().answered(response.status().as_u16());
                            Ok::<_, std::convert::Infallible>(response)
                        }
                    }),
                );
            let _ = tokio::time::timeout(CONNECTION_LIFETIME, connection).await;
            drop(permit);
        });
    }
}

/// One answer, from the method, the path and — for `/` only — the language
/// the visitor prefers.
pub fn answer(site: &Site, request: &Request<Incoming>) -> Response<Full<Bytes>> {
    let method = request.method();
    if method != Method::GET && method != Method::HEAD {
        let mut response = plain(StatusCode::METHOD_NOT_ALLOWED, "no-store", "");
        if let Ok(value) = "GET, HEAD".parse() {
            response.headers_mut().insert("allow", value);
        }
        return response;
    }

    let path = request.uri().path();
    let preferred = request
        .headers()
        .get("accept-language")
        .and_then(|value| value.to_str().ok());
    route(site, path, preferred)
}

/// The answer to a path.
pub fn route(site: &Site, path: &str, accept_language: Option<&str>) -> Response<Full<Bytes>> {
    let rendered = site.rendered();
    let statics = site.statics();
    let config = site.config();
    match path {
        "/" => {
            let locale = choose(accept_language).unwrap_or(config.default_locale);
            let mut response = plain(StatusCode::FOUND, "no-store", "");
            if let Ok(value) = format!("{}/{}/", config.public_url, locale.code()).parse() {
                response.headers_mut().insert("location", value);
            }
            if let Ok(value) = "Accept-Language".parse() {
                response.headers_mut().insert("vary", value);
            }
            response
        }
        "/ru" | "/en" => {
            let mut response = plain(StatusCode::MOVED_PERMANENTLY, "no-store", "");
            if let Ok(value) = format!("{}{}/", config.public_url, path).parse() {
                response.headers_mut().insert("location", value);
            }
            response
        }
        "/ru/" => bytes(
            StatusCode::OK,
            "text/html; charset=utf-8",
            PAGE_CACHE,
            Arc::clone(&rendered.ru),
        ),
        "/en/" => bytes(
            StatusCode::OK,
            "text/html; charset=utf-8",
            PAGE_CACHE,
            Arc::clone(&rendered.en),
        ),
        "/links.json" => bytes(
            StatusCode::OK,
            "application/json; charset=utf-8",
            PAGE_CACHE,
            Arc::clone(&rendered.json),
        ),
        "/sitemap.xml" => text(
            StatusCode::OK,
            "application/xml; charset=utf-8",
            STATIC_CACHE,
            &statics.sitemap,
        ),
        "/robots.txt" => text(
            StatusCode::OK,
            "text/plain; charset=utf-8",
            STATIC_CACHE,
            &statics.robots,
        ),
        "/llms.txt" => text(
            StatusCode::OK,
            "text/plain; charset=utf-8",
            STATIC_CACHE,
            &statics.llms,
        ),
        "/style.css" => text(
            StatusCode::OK,
            "text/css; charset=utf-8",
            STATIC_CACHE,
            statics.style,
        ),
        "/icon.svg" => text(StatusCode::OK, "image/svg+xml", STATIC_CACHE, statics.icon),
        _ => plain(StatusCode::NOT_FOUND, "no-store", ""),
    }
}

/// The language a visitor asked for, if it is one of ours.
///
/// Reads `Accept-Language` as a list of tags with weights, highest first,
/// and takes the first whose language is Russian or English. Anything else
/// is nobody's preference.
pub fn choose(accept_language: Option<&str>) -> Option<Locale> {
    let header = accept_language?;
    let mut wanted: Vec<(u32, usize, Locale)> = Vec::new();
    for (position, part) in header.split(',').enumerate().take(32) {
        let mut pieces = part.split(';');
        let tag = pieces.next().unwrap_or_default().trim();
        let primary = tag.split(['-', '_']).next().unwrap_or_default();
        let locale = match primary.to_ascii_lowercase().as_str() {
            "ru" => Locale::Ru,
            "en" => Locale::En,
            _ => continue,
        };
        // The weight in thousandths, so it sorts as an integer; absent is 1.
        let weight = pieces
            .find_map(|piece| piece.trim().strip_prefix("q="))
            .and_then(|q| q.trim().parse::<f32>().ok())
            .map_or(1000, |q| (q.clamp(0.0, 1.0) * 1000.0) as u32);
        if weight > 0 {
            wanted.push((weight, position, locale));
        }
    }
    wanted.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    wanted.first().map(|(_, _, locale)| *locale)
}

fn plain(status: StatusCode, cache: &'static str, body: &'static str) -> Response<Full<Bytes>> {
    text(status, "text/plain; charset=utf-8", cache, body)
}

fn text(
    status: StatusCode,
    content_type: &'static str,
    cache: &'static str,
    body: &str,
) -> Response<Full<Bytes>> {
    build(
        status,
        content_type,
        cache,
        Bytes::copy_from_slice(body.as_bytes()),
    )
}

fn bytes(
    status: StatusCode,
    content_type: &'static str,
    cache: &'static str,
    body: Arc<[u8]>,
) -> Response<Full<Bytes>> {
    build(status, content_type, cache, Bytes::copy_from_slice(&body))
}

fn build(
    status: StatusCode,
    content_type: &'static str,
    cache: &'static str,
    body: Bytes,
) -> Response<Full<Bytes>> {
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("cache-control", cache);
    for (name, value) in FIXED_HEADERS {
        builder = builder.header(name, value);
    }
    match builder.body(Full::new(body)) {
        Ok(response) => response,
        // Every header above is a literal, so this cannot fail; if it ever
        // does, an empty refusal is still one that carries no data.
        Err(_) => Response::new(Full::new(Bytes::new())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_preferred_language_is_read_by_weight_then_order() {
        assert_eq!(choose(None), None);
        assert_eq!(choose(Some("")), None);
        assert_eq!(choose(Some("fr, de")), None);
        assert_eq!(choose(Some("en-US,en;q=0.9,ru;q=0.8")), Some(Locale::En));
        assert_eq!(choose(Some("fr;q=1, ru;q=0.5, en;q=0.9")), Some(Locale::En));
        assert_eq!(choose(Some("RU-ru")), Some(Locale::Ru));
        assert_eq!(choose(Some("en;q=0, ru")), Some(Locale::Ru));
        assert_eq!(choose(Some("en;q=0")), None);
        assert_eq!(choose(Some(" ru , en ")), Some(Locale::Ru));
    }
}
