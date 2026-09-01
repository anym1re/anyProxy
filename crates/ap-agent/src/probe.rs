//! What the node can find out about itself by trying.
//!
//! The engine's own control API says whether the engine believes it is
//! running. That is the cheapest question and the least useful one: a node
//! whose site stopped answering, or whose path to Telegram is gone, answers it
//! exactly the same as a healthy one. Both of those happened on a live node
//! and neither showed up anywhere.
//!
//! So these probes go the way a client goes, and report what they find.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ap_engine::health::Site;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

/// How long any one probe is given.
///
/// Short: this runs on a heartbeat, and a probe that hangs delays the report
/// it belongs to. A site that needs longer than this to answer is a site a
/// visitor would have given up on.
const PATIENCE: Duration = Duration::from_secs(5);

/// Where the front door answers, on this machine.
const DOOR: u16 = 443;

/// Telegram data centres, by address.
///
/// Written out rather than resolved: a node whose DNS is interfered with would
/// otherwise report a reachability failure that is really a name failure, and
/// the two are answered differently. These addresses have been Telegram's for
/// years and belong to networks it owns; a probe that answers on any of them
/// is enough to say the path out is open.
const TELEGRAM: &[&str] = &[
    "149.154.175.50:443",
    "149.154.167.51:443",
    "91.108.56.130:443",
];

/// Whether this node can still reach Telegram.
///
/// A node that cannot is serving nobody, however healthy its engine reports
/// itself: the engine is up, the port is open, the link looks right, and every
/// client fails. Found exactly that way on a live node, by hand, because
/// nothing asked.
///
/// Any one answer is enough. Requiring all of them would report a fault when
/// one data centre is having a bad day.
pub async fn reaches_telegram() -> bool {
    for address in TELEGRAM {
        let Ok(address) = address.parse::<SocketAddr>() else {
            continue;
        };
        if let Ok(Ok(stream)) = tokio::time::timeout(PATIENCE, TcpStream::connect(address)).await {
            drop(stream);
            return true;
        }
    }
    false
}

/// What a visitor to this node's site would get.
///
/// Asked of the front door on 443 rather than of the site behind it, because
/// the ways this breaks are between them. A node whose engine lost its vhost
/// serves the site process perfectly well and answers every visitor 404; a
/// node whose front door failed to take the port serves nothing at all while
/// every part of it is running. Both were seen, and a probe of the site
/// process alone would have called both of them healthy.
///
/// Reached through the loopback: what is being asked is whether this machine
/// serves the site, and going out to its own public address to come back adds
/// a way to fail that has nothing to do with the answer.
pub async fn site(domain: &str) -> Site {
    match ask(domain).await {
        Ok(status) if (200..400).contains(&status) => Site::Up,
        // A status is an answer, and any other answer is the wrong one. The
        // site that returns 404 to a visitor is the failure this exists for.
        Ok(_) | Err(_) => Site::Down,
    }
}

/// Makes one request to the front door and returns the status it answered.
async fn ask(domain: &str) -> Result<u16, ()> {
    let name = rustls::pki_types::ServerName::try_from(domain.to_owned()).map_err(|_| ())?;

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let stream = tokio::time::timeout(PATIENCE, TcpStream::connect(("127.0.0.1", DOOR)))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    // The name is presented and verified against the public roots, so a
    // certificate that has expired or was issued for something else reads as a
    // site that is down — which, to every client, it is.
    let mut tls = tokio::time::timeout(PATIENCE, connector.connect(name, stream))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

    let request =
        format!("GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\nAccept: */*\r\n\r\n");
    tokio::time::timeout(PATIENCE, tls.write_all(request.as_bytes()))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

    // The status line and no further: what is wanted is the code, and reading
    // the body of a site to find out whether it is serving is work for nothing.
    let mut head = [0u8; 64];
    let read = tokio::time::timeout(PATIENCE, tls.read(&mut head))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;

    let line = String::from_utf8_lossy(&head[..read]);
    line.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_door_that_is_not_there_reads_as_a_site_that_is_down() {
        // Nothing is listening on this machine's 443 during a test run, so the
        // connection fails rather than answers. A probe that could not ask is
        // not a probe that found nothing wrong.
        assert_eq!(site("nothing.example.com").await, Site::Down);
    }

    #[tokio::test]
    async fn a_name_that_is_not_one_is_refused_before_anything_is_dialled() {
        assert!(ask("not a hostname").await.is_err());
    }
}
