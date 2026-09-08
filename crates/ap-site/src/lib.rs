//! The public site: the links an operator made public, for anyone.
//!
//! It holds nothing. The list arrives from the panel's feed over a tunnel,
//! already rendered, and is kept in memory; there is no database, no key, no
//! cookie and no input beyond the path of a request (0091). Every page is
//! built on the server whole, so an indexer and an agent see what a person
//! sees (0093).
//!
//! Not the cover site of a node (`ap-cover`): that one pretends to be
//! something else, this one says what it is.

pub mod admin;
pub mod feed;
pub mod metrics;
pub mod page;
pub mod serve;

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use ap_core::Locale;

/// What the site is told once, at start.
#[derive(Debug, Clone)]
pub struct Config {
    /// Where the site is published: `https://name`, no trailing slash.
    pub public_url: String,
    /// Where the panel's feed answers.
    pub feed: feed::FeedAddress,
    /// The public listener, behind the front.
    pub bind: SocketAddr,
    /// The listener for `health` and `metrics`, on loopback.
    pub admin_bind: SocketAddr,
    /// How often the feed is asked.
    pub refresh: Duration,
    /// Where `/` leads when the visitor states no preference.
    pub default_locale: Locale,
}

/// Why the site would not start.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// The public address is not `https://host`.
    #[error("the public url must be https://host with nothing after the host")]
    PublicUrl,
    /// The refresh period is outside 5..=3600 seconds.
    #[error("the refresh period must be between 5 and 3600 seconds")]
    Refresh,
    /// The feed address is not `http://host:port`.
    #[error("the feed address must be http://host:port")]
    Feed,
}

/// Shortest and longest refresh periods, in seconds.
const REFRESH_RANGE: std::ops::RangeInclusive<u64> = 5..=3600;

impl Config {
    /// Checks the pieces that cannot be typed wrongly at run time.
    ///
    /// The public address in particular: it goes into every `canonical` and
    /// the sitemap, and a wrong one there tells every indexer to look
    /// elsewhere.
    pub fn build(
        public_url: &str,
        feed: &str,
        bind: SocketAddr,
        admin_bind: SocketAddr,
        refresh_seconds: u64,
        default_locale: Locale,
    ) -> Result<Self, ConfigError> {
        let public_url = public_url.trim().trim_end_matches('/');
        let host = public_url
            .strip_prefix("https://")
            .ok_or(ConfigError::PublicUrl)?;
        let plain = !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b':'))
            && !host.starts_with('.')
            && !host.ends_with('.');
        if !plain {
            return Err(ConfigError::PublicUrl);
        }
        if !REFRESH_RANGE.contains(&refresh_seconds) {
            return Err(ConfigError::Refresh);
        }
        Ok(Self {
            public_url: public_url.to_owned(),
            feed: feed::FeedAddress::parse(feed).ok_or(ConfigError::Feed)?,
            bind,
            admin_bind,
            refresh: Duration::from_secs(refresh_seconds),
            default_locale,
        })
    }
}

/// What is currently shown, rendered once per feed and served as is.
#[derive(Debug, Clone)]
pub struct Rendered {
    /// The Russian page.
    pub ru: Arc<[u8]>,
    /// The English page.
    pub en: Arc<[u8]>,
    /// The same links as JSON.
    pub json: Arc<[u8]>,
    /// How many links are on it.
    pub count: usize,
    /// When the feed this was built from arrived; absent before the first.
    pub taken: Option<Instant>,
}

/// Everything the listeners read.
///
/// The pages are rebuilt when the feed answers and read by every request in
/// between; the lock is held for a pointer swap and never across an await.
pub struct Site {
    config: Config,
    statics: page::Statics,
    rendered: RwLock<Arc<Rendered>>,
    counters: metrics::Counters,
}

impl Site {
    /// Builds the site with the pages that do not depend on the feed, and an
    /// empty list until the feed has been heard.
    pub fn new(config: Config) -> Result<Self, ap_core::Error> {
        let statics = page::Statics::build(&config)?;
        let rendered = Arc::new(Rendered {
            ru: page::html(Locale::Ru, &config, &[])?.into_bytes().into(),
            en: page::html(Locale::En, &config, &[])?.into_bytes().into(),
            json: page::json(&[]).into_bytes().into(),
            count: 0,
            taken: None,
        });
        Ok(Self {
            config,
            statics,
            rendered: RwLock::new(rendered),
            counters: metrics::Counters::default(),
        })
    }

    /// The configuration this site runs with.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The pages that were built once.
    pub fn statics(&self) -> &page::Statics {
        &self.statics
    }

    /// What is shown right now.
    pub fn rendered(&self) -> Arc<Rendered> {
        match self.rendered.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Request and feed counters.
    pub fn counters(&self) -> &metrics::Counters {
        &self.counters
    }

    /// Replaces what is shown with a list that just arrived.
    pub fn replace(&self, links: &[feed::PublicLink]) -> Result<(), ap_core::Error> {
        let fresh = Arc::new(Rendered {
            ru: page::html(Locale::Ru, &self.config, links)?
                .into_bytes()
                .into(),
            en: page::html(Locale::En, &self.config, links)?
                .into_bytes()
                .into(),
            json: page::json(links).into_bytes().into(),
            count: links.len(),
            taken: Some(Instant::now()),
        });
        match self.rendered.write() {
            Ok(mut guard) => *guard = fresh,
            Err(poisoned) => *poisoned.into_inner() = fresh,
        }
        Ok(())
    }

    /// Asks the feed once and shows what it said.
    ///
    /// A feed that fails leaves the pages as they were: half a list is worse
    /// than the whole old one, and a list from a feed that could not be
    /// reached is no list at all.
    pub async fn refresh(&self) -> Result<usize, feed::FeedError> {
        let started = Instant::now();
        let outcome = async {
            let body = feed::fetch(&self.config.feed).await?;
            let links = feed::parse(&body)?;
            self.replace(&links).map_err(|_| FeedError::Render)?;
            Ok(links.len())
        }
        .await;
        match &outcome {
            Ok(count) => {
                self.counters.feed_ok();
                tracing::info!(
                    links = count,
                    took_ms = started.elapsed().as_millis() as u64,
                    "feed received"
                );
            }
            Err(reason) => {
                self.counters.feed_error();
                tracing::warn!(reason = %reason, "feed not received");
            }
        }
        outcome
    }

    /// Whether the list is younger than three refresh periods.
    pub fn freshness(&self) -> Freshness {
        match self.rendered().taken {
            None => Freshness::Never,
            Some(taken) if taken.elapsed() <= self.config.refresh * 3 => Freshness::Fresh,
            Some(_) => Freshness::Stale,
        }
    }

    /// Age of the list in seconds, or none before the first feed.
    pub fn age_seconds(&self) -> Option<u64> {
        self.rendered().taken.map(|taken| taken.elapsed().as_secs())
    }
}

use feed::FeedError;

/// How current the shown list is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// The feed has not answered yet.
    Never,
    /// Younger than three periods.
    Fresh,
    /// Older than three periods.
    Stale,
}

impl Freshness {
    /// The word `health` answers with.
    pub fn word(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Fresh => "fresh",
            Self::Stale => "stale",
        }
    }
}

/// Asks the feed every period until the process stops.
pub async fn keep_fresh(site: Arc<Site>) {
    loop {
        let _ = site.refresh().await;
        tokio::time::sleep(site.config().refresh).await;
    }
}
