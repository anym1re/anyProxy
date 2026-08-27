//! Connections to destinations, kept warm between client connections.
//!
//! Opening one costs a round trip to the destination, and a client that opens
//! many connections pays it every time: measured at 59 ms for the first
//! request on a connection against 30 ms for the ones after it, against a
//! Telegram data centre 30 ms away.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use crate::InboundError;
use crate::buffered::Buffered;

/// How long a connection nobody is using is kept.
///
/// Short on purpose. A server closes an idle connection on its own schedule,
/// and a connection handed out after the far end has closed it costs a failed
/// request. Ten seconds is long enough to cover a client opening connections
/// in a burst and short enough that the far end has not given up on it.
const IDLE_LIMIT: Duration = Duration::from_secs(10);

/// How many are held for one destination.
const PER_DESTINATION: usize = 8;

/// Warm connections, by where they lead.
#[derive(Default)]
pub struct Pool {
    held: Mutex<BTreeMap<(String, u16), Vec<Warm>>>,
}

/// One connection and when it was last used.
struct Warm {
    stream: Buffered<TcpStream>,
    since: Instant,
}

impl Pool {
    /// An empty pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes a warm connection to this destination, if there is one.
    pub fn take(&self, host: &str, port: u16) -> Option<Buffered<TcpStream>> {
        let mut held = self.held.lock().ok()?;
        let waiting = held.get_mut(&(host.to_owned(), port))?;
        while let Some(warm) = waiting.pop() {
            if warm.since.elapsed() < IDLE_LIMIT {
                return Some(warm.stream);
            }
        }
        None
    }

    /// Keeps a connection for whoever needs this destination next.
    ///
    /// Only a connection that finished an exchange cleanly is worth keeping:
    /// one with a body still unread on it would hand the next request somebody
    /// else's answer.
    pub fn keep(&self, host: &str, port: u16, stream: Buffered<TcpStream>) {
        let Ok(mut held) = self.held.lock() else {
            return;
        };
        let waiting = held.entry((host.to_owned(), port)).or_default();
        waiting.retain(|warm| warm.since.elapsed() < IDLE_LIMIT);
        if waiting.len() < PER_DESTINATION {
            waiting.push(Warm {
                stream,
                since: Instant::now(),
            });
        }
    }

    /// Opens a connection that does not wait to be acknowledged before sending.
    pub async fn open(host: &str, port: u16) -> Result<Buffered<TcpStream>, InboundError> {
        let stream = TcpStream::connect((host, port)).await?;
        let _ = stream.set_nodelay(true);
        Ok(Buffered::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn somewhere() -> (String, u16) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut kept = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                kept.push(stream);
            }
        });
        ("127.0.0.1".to_owned(), port)
    }

    #[tokio::test]
    async fn a_connection_kept_is_a_connection_handed_back() {
        let (host, port) = somewhere().await;
        let pool = Pool::new();
        assert!(pool.take(&host, port).is_none(), "an empty pool held one");

        let opened = Pool::open(&host, port).await.unwrap();
        pool.keep(&host, port, opened);
        assert!(pool.take(&host, port).is_some(), "what was kept was lost");
        assert!(pool.take(&host, port).is_none(), "one was handed out twice");
    }

    #[tokio::test]
    async fn a_connection_to_somewhere_else_is_not_handed_out() {
        let (host, port) = somewhere().await;
        let pool = Pool::new();
        pool.keep(&host, port, Pool::open(&host, port).await.unwrap());
        assert!(pool.take(&host, port + 1).is_none());
        assert!(pool.take("127.0.0.2", port).is_none());
    }

    #[tokio::test]
    async fn no_more_than_the_limit_is_held_for_one_destination() {
        let (host, port) = somewhere().await;
        let pool = Pool::new();
        for _ in 0..(PER_DESTINATION + 4) {
            pool.keep(&host, port, Pool::open(&host, port).await.unwrap());
        }
        let mut handed = 0;
        while pool.take(&host, port).is_some() {
            handed += 1;
        }
        assert_eq!(handed, PER_DESTINATION);
    }
}
