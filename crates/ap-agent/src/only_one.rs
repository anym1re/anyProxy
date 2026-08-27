use std::path::Path;

use crate::AgentError;
use crate::identity::Paths;

/// Refuses to start when another agent is already using this directory.
///
/// Two agents on one state directory is not a harmless duplicate. They draw
/// separate cache keys and overwrite each other's cache; they both report
/// telemetry, and the one that lost the race for the listeners reports an
/// empty set of counters over the top of the one that is actually serving. The
/// symptom is a node that plainly carries traffic and shows none.
pub fn claim(paths: &Paths) -> Result<Claim, AgentError> {
    std::fs::create_dir_all(&paths.dir)
        .map_err(|error| AgentError::file(paths.dir.display(), error))?;
    let path = paths.dir.join("agent.pid");

    if let Some(holder) = held_by(&path)
        && holder != std::process::id()
    {
        return Err(AgentError::Refused(format!(
            "another agent is already using {} as process {holder}",
            paths.dir.display()
        )));
    }

    crate::identity::write_owner_only(&path, std::process::id().to_string().as_bytes())?;
    Ok(Claim { path })
}

/// The process holding the directory, if one is alive.
fn held_by(path: &Path) -> Option<u32> {
    let recorded: u32 = std::fs::read_to_string(path).ok()?.trim().parse().ok()?;
    // A process identifier on its own proves nothing: the number is reused. It
    // has to still be an agent, or a node that was restarted badly could never
    // start again.
    let running = std::fs::read_to_string(format!("/proc/{recorded}/cmdline")).ok()?;
    running.contains("anyproxy-agent").then_some(recorded)
}

/// The directory this agent has taken.
pub struct Claim {
    path: std::path::PathBuf,
}

impl Drop for Claim {
    fn drop(&mut self) {
        // Best effort. A claim left behind by a process that was killed is
        // recognised as stale the next time, by its identifier no longer
        // belonging to an agent.
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_dir(name: &str) -> Paths {
        let dir = std::env::temp_dir()
            .join("anyproxy-agent-claim")
            .join(format!("{name}-{}", uuid::Uuid::now_v7().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        Paths::new(dir)
    }

    #[test]
    fn a_directory_nobody_holds_can_be_taken() {
        let paths = a_dir("free");
        let claim = claim(&paths).unwrap();
        assert!(paths.dir.join("agent.pid").exists());
        drop(claim);
        assert!(!paths.dir.join("agent.pid").exists());
    }

    #[test]
    fn a_claim_by_a_process_that_is_gone_is_not_in_the_way() {
        let paths = a_dir("stale");
        // An identifier no living agent has. Left behind by a machine that
        // was powered off rather than shut down.
        std::fs::write(paths.dir.join("agent.pid"), "4294967290").unwrap();
        assert!(
            claim(&paths).is_ok(),
            "a node could not start again after an unclean stop"
        );
    }

    #[test]
    fn a_claim_that_is_not_a_number_is_not_in_the_way() {
        let paths = a_dir("nonsense");
        std::fs::write(paths.dir.join("agent.pid"), "who knows").unwrap();
        assert!(claim(&paths).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_directory_this_process_holds_is_not_taken_twice() {
        let paths = a_dir("mine");
        let first = claim(&paths).unwrap();

        // The same process asking again is the agent restarting its own loop,
        // not a second one arriving.
        assert!(claim(&paths).is_ok());
        drop(first);
    }
}
