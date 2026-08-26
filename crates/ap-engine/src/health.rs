use ap_proto::Health;

use crate::EngineError;
use crate::control::Control;

/// What a probe of the cover site found.
///
/// The site is served by the front door on 443, which is a later piece of
/// work. Until it exists the agent has nothing to probe, and saying so is not
/// the same as saying the site is down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Site {
    /// It answered.
    Up,
    /// It did not answer.
    Down,
    /// There is nothing to ask yet.
    Unknown,
}

impl Site {
    fn as_reported(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Unknown => "unknown",
        }
    }
}

/// Builds the report the panel receives.
///
/// The engine's state is asked of the engine; the site's is passed in, because
/// what serves the site is not what serves the proxy and the two fail apart.
/// A dead engine beside a live site is a node that lost its engine; a dead
/// site beside a live engine is what a probe is looking for.
pub async fn report(
    control: &Control,
    site: Site,
    cert_not_after: Option<String>,
) -> Result<Health, EngineError> {
    let engine = match control.health().await {
        Ok(true) => "up",
        // A refusal and a silence both mean the proxy paths are not serving.
        // The reason belongs in the log, not in a field the panel branches on.
        Ok(false) | Err(_) => "down",
    };

    Ok(Health {
        engine: engine.to_owned(),
        site: site.as_reported().to_owned(),
        cert_not_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_engine_that_does_not_answer_is_reported_down() {
        // Nothing listens here, so the control call fails rather than replies.
        let control = Control::new(1, "Bearer nothing");
        let health = report(&control, Site::Up, None).await.unwrap();

        assert_eq!(health.engine, "down");
        // And the site is reported on its own terms, not dragged down with it.
        assert_eq!(health.site, "up");
    }

    #[tokio::test]
    async fn a_site_nobody_has_asked_about_is_not_reported_as_down() {
        let control = Control::new(1, "Bearer nothing");
        let health = report(&control, Site::Unknown, None).await.unwrap();
        assert_eq!(health.site, "unknown");
        assert_ne!(health.site, "down");
    }

    #[tokio::test]
    async fn the_certificate_expiry_is_carried_through_as_it_was_given() {
        let control = Control::new(1, "Bearer nothing");
        let health = report(&control, Site::Up, Some("2026-12-31T23:59:59Z".to_owned()))
            .await
            .unwrap();
        assert_eq!(
            health.cert_not_after.as_deref(),
            Some("2026-12-31T23:59:59Z")
        );
    }

    #[test]
    fn every_state_of_the_site_has_a_word_of_its_own() {
        let words: std::collections::BTreeSet<_> = [Site::Up, Site::Down, Site::Unknown]
            .into_iter()
            .map(Site::as_reported)
            .collect();
        assert_eq!(words.len(), 3);
    }
}
