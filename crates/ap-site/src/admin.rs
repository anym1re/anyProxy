//! The listener on loopback: whether the list is current, and the counters.
//!
//! Not on the public listener, where these paths are as unknown as any other
//! (0095). Same rule as a node's control and metrics ports: on the loop and
//! nowhere else.

use std::sync::Arc;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;

use crate::{Freshness, Site};

/// Serves `health` and `metrics` until the process stops.
pub async fn serve(listener: TcpListener, site: Arc<Site>) {
    loop {
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
        let site = Arc::clone(&site);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let connection = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(crate::serve::HEAD_TIMEOUT)
                .serve_connection(
                    io,
                    service_fn(move |request: Request<Incoming>| {
                        let site = Arc::clone(&site);
                        async move { Ok::<_, std::convert::Infallible>(answer(&site, &request)) }
                    }),
                );
            let _ = tokio::time::timeout(crate::serve::CONNECTION_LIFETIME, connection).await;
        });
    }
}

/// One answer on the loopback listener.
pub fn answer(site: &Site, request: &Request<Incoming>) -> Response<Full<Bytes>> {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        return reply(StatusCode::METHOD_NOT_ALLOWED, "");
    }
    match request.uri().path() {
        "/health" => {
            let freshness = site.freshness();
            let status = match freshness {
                Freshness::Fresh => StatusCode::OK,
                Freshness::Never | Freshness::Stale => StatusCode::SERVICE_UNAVAILABLE,
            };
            reply(status, &format!("{}\n", freshness.word()))
        }
        "/metrics" => reply(
            StatusCode::OK,
            &site
                .counters()
                .render(site.rendered().count, site.age_seconds()),
        ),
        _ => reply(StatusCode::NOT_FOUND, ""),
    }
}

fn reply(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    match Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
    {
        Ok(response) => response,
        Err(_) => Response::new(Full::new(Bytes::new())),
    }
}
