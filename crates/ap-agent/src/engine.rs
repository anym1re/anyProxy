use ap_engine::config::Settings;
use rand::RngCore;

use crate::AgentError;
use crate::identity::{self, Paths};

/// How often the node reads the engine's counters.
pub const READING_INTERVAL_SECS: u64 = 60;

/// Ports the engine answers on, on loopback and nowhere else.
const API_PORT: u16 = 9091;
const METRICS_PORT: u16 = 9090;

/// Reads the node's engine settings, making them on first use.
///
/// The token is drawn once and kept, because the engine outlives a restart of
/// the agent and the two have to go on agreeing. It is written where the
/// identity is, readable by its owner alone.
pub fn settings(paths: &Paths) -> Result<Settings, AgentError> {
    let path = paths.dir.join("engine.token");
    let token = match std::fs::read_to_string(&path) {
        Ok(token) => token.trim().to_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let token = format!("Bearer {}", fresh_token());
            identity::write_owner_only(&path, token.as_bytes())?;
            token
        }
        Err(error) => return Err(AgentError::file(path.display(), error)),
    };

    Ok(Settings {
        api_port: API_PORT,
        metrics_port: METRICS_PORT,
        api_token: token,
        data_path: paths.dir.join("engine").display().to_string(),
        middle_proxy: true,
    })
}

/// Thirty-two bytes of randomness, as hexadecimal.
fn fresh_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_dir(name: &str) -> Paths {
        let dir = std::env::temp_dir()
            .join("anyproxy-agent-engine")
            .join(format!("{name}-{}", uuid::Uuid::now_v7().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        Paths::new(dir)
    }

    #[test]
    fn the_token_survives_a_restart_of_the_agent() {
        let paths = a_dir("stable");
        let first = settings(&paths).unwrap();
        let second = settings(&paths).unwrap();
        assert_eq!(first.api_token, second.api_token);
    }

    #[test]
    fn two_nodes_do_not_share_a_token() {
        let first = settings(&a_dir("one")).unwrap();
        let second = settings(&a_dir("two")).unwrap();
        assert_ne!(first.api_token, second.api_token);
        assert!(first.api_token.starts_with("Bearer "));
    }

    #[cfg(unix)]
    #[test]
    fn the_token_is_readable_by_its_owner_alone() {
        use std::os::unix::fs::PermissionsExt;

        let paths = a_dir("mode");
        settings(&paths).unwrap();
        let mode = std::fs::metadata(paths.dir.join("engine.token"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o400);
    }
}
