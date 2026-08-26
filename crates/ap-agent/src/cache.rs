use std::path::Path;

use ap_core::{Encrypted, KeyStore};
use ap_proto::Config;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::AgentError;

/// The nonce a sealed file carries in front of its ciphertext.
const NONCE_LEN: usize = 24;

/// What the agent keeps so a restart does not need the panel to answer first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cached {
    /// The configuration as it arrived.
    pub config: Config,
    /// When the agent wrote it down, RFC 3339 in UTC.
    ///
    /// Inside the seal rather than beside it: the age decides whether the node
    /// keeps serving, so a file whose timestamp anyone can edit would let a
    /// withdrawn access outlive its withdrawal.
    pub sealed_at: String,
    /// How long the panel said this may be used without contact.
    pub ttl_secs: u32,
}

/// What was on disk when the agent looked.
#[derive(Debug, Clone, PartialEq)]
pub enum Stored {
    /// Nothing has been written yet.
    Absent,
    /// Written, and still within the life the panel gave it.
    Fresh(Box<Config>),
    /// Written, and older than the panel allowed.
    Expired {
        /// How far past its life it is.
        over_by_secs: i64,
    },
}

/// Seals the configuration under the key the panel sent for this connection.
pub fn write(
    path: &Path,
    config: &Config,
    ttl_secs: u32,
    key: &KeyStore,
    now: OffsetDateTime,
) -> Result<(), AgentError> {
    let cached = Cached {
        config: config.clone(),
        sealed_at: ap_core::time::format_rfc3339(now)
            .map_err(|error| AgentError::Refused(error.to_string()))?,
        ttl_secs,
    };
    let plaintext =
        serde_json::to_string(&cached).map_err(|error| AgentError::Refused(error.to_string()))?;
    let sealed = Encrypted::seal(&plaintext, key).map_err(|_| AgentError::Cache)?;

    let mut bytes = Vec::with_capacity(NONCE_LEN + sealed.ciphertext().len());
    bytes.extend_from_slice(sealed.nonce());
    bytes.extend_from_slice(sealed.ciphertext());
    crate::identity::write_owner_only(path, &bytes)
}

/// Opens the cache, if there is one and the key fits.
///
/// The key comes from the panel and is never written down, so an agent that
/// restarts without reaching the panel cannot open what it wrote itself. That
/// is the point: a node cut off from the panel stops serving once its cache
/// runs out, and a node whose disk is taken away serves nothing at all.
pub fn read(path: &Path, key: &KeyStore, now: OffsetDateTime) -> Result<Stored, AgentError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Stored::Absent),
        Err(error) => return Err(AgentError::file(path.display(), error)),
    };

    let Some(nonce) = bytes.get(..NONCE_LEN) else {
        return Err(AgentError::Cache);
    };
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| AgentError::Cache)?;
    let sealed: Encrypted<String> = Encrypted::from_parts(nonce, bytes[NONCE_LEN..].to_vec());

    let plaintext = sealed.open(key).map_err(|_| AgentError::Cache)?;
    let cached: Cached = serde_json::from_str(&plaintext).map_err(|_| AgentError::Cache)?;

    let sealed_at =
        ap_core::time::parse_rfc3339(&cached.sealed_at).map_err(|_| AgentError::Cache)?;
    let age = (now - sealed_at).whole_seconds();
    let ttl = i64::from(cached.ttl_secs);
    if age > ttl {
        return Ok(Stored::Expired {
            over_by_secs: age - ttl,
        });
    }
    Ok(Stored::Fresh(Box::new(cached.config)))
}

/// Reads the key the panel sent in `welcome`.
pub fn key_from_hex(text: &str) -> Result<KeyStore, AgentError> {
    let bytes = hex::decode(text).map_err(|_| AgentError::Unexpected("cache_key"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| AgentError::Unexpected("cache_key"))?;
    Ok(KeyStore::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap_proto::{NodeShape, Policy};
    use time::Duration;

    fn a_config() -> Config {
        Config {
            revision: uuid::Uuid::now_v7(),
            issued_at: "2026-08-26T10:00:00Z".to_owned(),
            node: NodeShape {
                kind: "stealth".to_owned(),
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

    fn a_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("anyproxy-agent-cache");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(format!("{name}-{}", uuid::Uuid::now_v7().simple()))
    }

    #[test]
    fn what_was_sealed_comes_back() {
        let path = a_path("round-trip");
        let key = KeyStore::from_bytes([7u8; 32]);
        let config = a_config();
        let now = OffsetDateTime::now_utc();

        write(&path, &config, 3600, &key, now).unwrap();
        let read_back = read(&path, &key, now).unwrap();
        assert_eq!(read_back, Stored::Fresh(Box::new(config)));
    }

    #[test]
    fn another_key_gives_an_error_and_not_a_guess() {
        let path = a_path("wrong-key");
        let now = OffsetDateTime::now_utc();
        write(
            &path,
            &a_config(),
            3600,
            &KeyStore::from_bytes([7u8; 32]),
            now,
        )
        .unwrap();

        let outcome = read(&path, &KeyStore::from_bytes([8u8; 32]), now);
        assert!(matches!(outcome, Err(AgentError::Cache)));
    }

    #[test]
    fn a_cache_past_its_life_is_reported_as_such() {
        let path = a_path("expired");
        let key = KeyStore::from_bytes([7u8; 32]);
        let sealed_at = OffsetDateTime::now_utc();
        write(&path, &a_config(), 60, &key, sealed_at).unwrap();

        let later = sealed_at + Duration::seconds(90);
        assert_eq!(
            read(&path, &key, later).unwrap(),
            Stored::Expired { over_by_secs: 30 }
        );
    }

    #[test]
    fn a_cache_exactly_at_its_life_is_still_usable() {
        let path = a_path("boundary");
        let key = KeyStore::from_bytes([7u8; 32]);
        let sealed_at = OffsetDateTime::now_utc();
        write(&path, &a_config(), 60, &key, sealed_at).unwrap();

        let at_the_edge = sealed_at + Duration::seconds(60);
        assert!(matches!(
            read(&path, &key, at_the_edge).unwrap(),
            Stored::Fresh(_)
        ));
    }

    #[test]
    fn nothing_written_reads_as_nothing_written() {
        let path = a_path("absent");
        let key = KeyStore::from_bytes([7u8; 32]);
        assert_eq!(
            read(&path, &key, OffsetDateTime::now_utc()).unwrap(),
            Stored::Absent
        );
    }

    #[test]
    fn a_timestamp_moved_forward_on_disk_does_not_extend_the_life() {
        let path = a_path("tamper");
        let key = KeyStore::from_bytes([7u8; 32]);
        let sealed_at = OffsetDateTime::now_utc();
        write(&path, &a_config(), 60, &key, sealed_at).unwrap();

        // Every byte of the file is under the seal, so changing one leaves
        // nothing that opens rather than a cache that lives longer.
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        crate::identity::write_owner_only(&path, &bytes).unwrap();

        let outcome = read(&path, &key, sealed_at);
        assert!(matches!(outcome, Err(AgentError::Cache)));
    }

    #[test]
    fn the_key_the_panel_sent_is_not_in_the_file() {
        let path = a_path("no-key-on-disk");
        let key_bytes = [0x5au8; 32];
        let key = KeyStore::from_bytes(key_bytes);
        write(&path, &a_config(), 3600, &key, OffsetDateTime::now_utc()).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.windows(key_bytes.len()).any(|w| w == key_bytes),
            "the cache key was written next to what it seals"
        );
        let hex = hex::encode(key_bytes);
        assert!(
            !String::from_utf8_lossy(&bytes).contains(&hex),
            "the cache key was written as text"
        );
    }

    #[test]
    fn a_key_that_is_not_thirty_two_bytes_is_refused() {
        assert!(key_from_hex("00").is_err());
        assert!(key_from_hex("not hexadecimal").is_err());
        assert!(key_from_hex(&hex::encode([1u8; 32])).is_ok());
    }
}
