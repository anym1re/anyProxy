/// What the node writes down about itself.
///
/// The default is the quiet one, and it is what a node runs at unless the
/// panel's policy says otherwise. This is not a matter of taste: a node exists
/// to carry other people's traffic without keeping a record of who carried
/// what, and a log line is a record like any other. The quiet level carries
/// what an operator needs to know the node is alive and why it stopped; the
/// other one adds the counting, which is per access.
use ap_proto::Policy;

/// How much a node says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Level {
    /// State changes and failures. Nothing per access.
    #[default]
    Minimal,
    /// The above, and what the node counted for whom.
    Normal,
}

impl Level {
    /// Reads the level out of a policy.
    ///
    /// Anything unrecognised is the quiet one. A policy from a newer panel
    /// naming a level this build has never heard of must not turn logging up.
    pub fn from_policy(policy: &Policy) -> Self {
        match policy.log_level.as_str() {
            "normal" => Self::Normal,
            _ => Self::Minimal,
        }
    }

    /// Whether a line that names an access may be written.
    pub fn says_per_access(self) -> bool {
        matches!(self, Self::Normal)
    }
}

/// The node's voice, set by the policy it is running under.
#[derive(Debug, Clone, Copy, Default)]
pub struct Voice {
    level: Level,
}

impl Voice {
    /// A voice at the quiet level, which is where a node starts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes the level from a policy the panel sent.
    pub fn follow(&mut self, policy: &Policy) {
        self.level = Level::from_policy(policy);
    }

    /// Takes the level from the configuration the node is running.
    ///
    /// A node that is not serving has no policy to follow and is quiet: the
    /// level a withdrawn configuration asked for does not outlive it.
    pub fn following(posture: &crate::posture::Posture) -> Self {
        match posture {
            crate::posture::Posture::Serving(config) => Self {
                level: Level::from_policy(&config.policy),
            },
            crate::posture::Posture::SiteOnly(_) => Self::default(),
        }
    }

    /// The level in force.
    pub fn level(&self) -> Level {
        self.level
    }

    /// Says something that is true of the node rather than of anyone using it.
    pub fn note(&self, line: &str) {
        println!("{line}");
    }

    /// Says something counted per access, if this node is allowed to.
    pub fn counted(&self, line: &str) {
        if self.level.says_per_access() {
            println!("{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_policy(level: &str) -> Policy {
        Policy {
            log_level: level.to_owned(),
            carrier_mode: "https".to_owned(),
        }
    }

    #[test]
    fn a_node_starts_quiet() {
        assert_eq!(Voice::new().level(), Level::Minimal);
        assert!(!Level::default().says_per_access());
    }

    #[test]
    fn the_policy_decides_the_level() {
        let mut voice = Voice::new();
        voice.follow(&a_policy("normal"));
        assert_eq!(voice.level(), Level::Normal);
        voice.follow(&a_policy("minimal"));
        assert_eq!(voice.level(), Level::Minimal);
    }

    #[test]
    fn a_node_that_is_not_serving_is_quiet() {
        // The level a configuration asked for does not outlive the
        // configuration: a node that has fallen back to the cover site has no
        // policy to follow.
        let quiet = Voice::following(&crate::posture::Posture::SiteOnly(
            crate::posture::Silent::NoConfig,
        ));
        assert_eq!(quiet.level(), Level::Minimal);
    }

    #[test]
    fn a_level_this_build_does_not_know_is_the_quiet_one() {
        // A newer panel naming a level this build has never heard of must not
        // be able to turn a node's logging up by accident.
        for unknown in ["verbose", "debug", "trace", "", "NORMAL"] {
            let mut voice = Voice::new();
            voice.follow(&a_policy(unknown));
            assert_eq!(
                voice.level(),
                Level::Minimal,
                "{unknown} was taken for something louder"
            );
        }
    }
}
