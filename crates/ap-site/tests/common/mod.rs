//! What the site's integration targets share: a feed that answers with a
//! fixed body, a site started against it, and a client that asks it.

// Compiled separately into each target, and each uses a subset of it.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use ap_core::Locale;
use ap_site::{Config, Site};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

/// A feed that always answers with the same body.
pub(crate) async fn feed_server(body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |_: Request<Incoming>| async move {
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from_static(body.as_bytes())))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            });
        }
    });
    address
}

/// Where the site says it is published, in tests.
pub(crate) const PUBLIC_URL: &str = "https://links.example";

pub(crate) fn config(feed: SocketAddr) -> Config {
    Config::build(
        PUBLIC_URL,
        &format!("http://{feed}"),
        ([127, 0, 0, 1], 0).into(),
        ([127, 0, 0, 1], 0).into(),
        5,
        Locale::Ru,
    )
    .unwrap()
}

/// A running site: its public and its loopback address.
pub(crate) struct Running {
    pub(crate) site: Arc<Site>,
    pub(crate) public: SocketAddr,
    pub(crate) admin: SocketAddr,
}

/// Starts the site against a feed, asks the feed once, and listens.
pub(crate) async fn start(config: Config) -> Running {
    let site = Arc::new(Site::new(config).unwrap());
    let _ = site.refresh().await;
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let running = Running {
        site: Arc::clone(&site),
        public: public.local_addr().unwrap(),
        admin: admin.local_addr().unwrap(),
    };
    tokio::spawn(ap_site::serve::serve(public, Arc::clone(&site)));
    tokio::spawn(ap_site::admin::serve(admin, site));
    running
}

/// What the site answered.
#[derive(Debug, Clone)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Reply {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// One request over a fresh connection.
pub(crate) async fn ask(
    address: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Reply {
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "whatever.example");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = sender
        .send_request(request.body(Empty::<Bytes>::new()).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    Reply {
        status,
        headers,
        body,
    }
}

pub(crate) async fn get(address: SocketAddr, path: &str) -> Reply {
    ask(address, "GET", path, &[]).await
}
