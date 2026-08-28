use ap_proto::Config;

use crate::cache::Stored;

/// Why the node is not serving proxy paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Silent {
    /// The panel has not been reached since the agent started, so the key that
    /// opens the cache does not exist on this machine.
    NoCacheKey,
    /// The cache opened and is older than the panel allowed.
    CacheExpired,
    /// The panel has been reached but has not sent a configuration yet.
    NoConfig,
}

/// What the node should be doing right now.
///
/// The cover site answers in every case. A proxy path that stops while the
/// site keeps serving is a node that lost its panel; a site that stops while
/// the proxy keeps serving is what a probe is looking for.
#[derive(Debug, Clone, PartialEq)]
pub enum Posture {
    /// Proxy paths run against this configuration.
    Serving(Box<Config>),
    /// Proxy paths are down.
    SiteOnly(Silent),
}

impl Posture {
    /// What to do with what was found on disk.
    pub fn from_cache(stored: Stored) -> Self {
        match stored {
            Stored::Fresh(config) => Self::Serving(config),
            Stored::Expired { .. } => Self::SiteOnly(Silent::CacheExpired),
            Stored::Absent => Self::SiteOnly(Silent::NoConfig),
        }
    }

    /// Whether clients are being served.
    pub fn is_serving(&self) -> bool {
        matches!(self, Self::Serving(_))
    }

    /// Whether the cover site answers. It always does.
    pub fn site_answers(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap_proto::{NodeShape, Policy};

    fn a_config() -> Config {
        Config {
            revision: uuid::Uuid::now_v7(),
            issued_at: "2026-08-26T10:00:00Z".to_owned(),
            node: NodeShape {
                kind: "faketls".to_owned(),
                domain: Some("cover.example.com".to_owned()),
            },
            listeners: Vec::new(),
            accesses: Vec::new(),
            policy: Policy {
                log_level: "quiet".to_owned(),
                carrier_mode: "https".to_owned(),
            },
        }
    }

    #[test]
    fn a_fresh_cache_serves() {
        let posture = Posture::from_cache(Stored::Fresh(Box::new(a_config())));
        assert!(posture.is_serving());
        assert!(posture.site_answers());
    }

    #[test]
    fn a_cache_past_its_life_stops_the_proxy_and_leaves_the_site() {
        let posture = Posture::from_cache(Stored::Expired { over_by_secs: 1 });
        assert_eq!(posture, Posture::SiteOnly(Silent::CacheExpired));
        assert!(!posture.is_serving());
        assert!(posture.site_answers());
    }

    #[test]
    fn nothing_cached_stops_the_proxy_and_leaves_the_site() {
        let posture = Posture::from_cache(Stored::Absent);
        assert_eq!(posture, Posture::SiteOnly(Silent::NoConfig));
        assert!(!posture.is_serving());
        assert!(posture.site_answers());
    }

    #[test]
    fn without_the_key_from_the_panel_the_proxy_stays_down() {
        let posture = Posture::SiteOnly(Silent::NoCacheKey);
        assert!(!posture.is_serving());
        assert!(posture.site_answers());
    }
}
