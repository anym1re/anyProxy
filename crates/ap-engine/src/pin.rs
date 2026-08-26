use crate::EngineError;

/// The pin file, compiled in so a node cannot be pointed at another build by
/// editing something on disk.
const PIN: &str = include_str!("../../../deploy/telemt.pin");

/// A target the engine is published for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// Sixty-four bit Intel or AMD.
    X86_64,
    /// Sixty-four bit ARM.
    Aarch64,
}

impl Target {
    /// The name the pin file uses.
    pub fn key(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64-linux-musl",
            Self::Aarch64 => "aarch64-linux-musl",
        }
    }

    /// The target this build is running on, when it is one we publish for.
    pub fn current() -> Option<Self> {
        match std::env::consts::ARCH {
            "x86_64" => Some(Self::X86_64),
            "aarch64" => Some(Self::Aarch64),
            _ => None,
        }
    }
}

/// What the node is allowed to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    /// Release the digest belongs to.
    pub version: String,
    /// Digest of the release archive, 64 hexadecimal characters.
    pub digest: String,
}

impl Pinned {
    /// The name of the archive this pin names.
    pub fn archive(&self, target: Target) -> String {
        format!("telemt-{}.tar.gz", target.key())
    }
}

/// Reads the pin for a target.
pub fn pinned(target: Target) -> Result<Pinned, EngineError> {
    let mut version = None;
    let mut digest = None;

    for line in PIN.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(EngineError::Pin(format!("line is not a setting: {line}")));
        };
        let (key, value) = (key.trim(), value.trim());
        if key == "version" {
            version = Some(value.to_owned());
        } else if key == target.key() {
            digest = Some(value.to_owned());
        }
    }

    let version = version.ok_or_else(|| EngineError::Pin("no version".to_owned()))?;
    let digest =
        digest.ok_or_else(|| EngineError::Pin(format!("no digest for {}", target.key())))?;
    if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(EngineError::Pin(format!(
            "the digest for {} is not a sha-256",
            target.key()
        )));
    }
    Ok(Pinned { version, digest })
}

/// Whether an archive is the one the pin names.
///
/// Checked on the node before anything is unpacked: a download that arrived
/// over a hijacked connection, or from a release that was replaced under its
/// own tag, does not become the engine.
pub fn matches(archive: &[u8], pinned: &Pinned) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    let seen = Sha256::digest(archive);
    let Ok(expected) = hex::decode(&pinned.digest) else {
        return false;
    };
    seen.ct_eq(expected.as_slice()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_target_the_file_names_can_be_read() {
        for target in [Target::X86_64, Target::Aarch64] {
            let pinned = pinned(target).unwrap();
            assert_eq!(pinned.digest.len(), 64, "{}", target.key());
            assert!(!pinned.version.is_empty());
        }
    }

    #[test]
    fn the_two_targets_are_not_the_same_build() {
        let intel = pinned(Target::X86_64).unwrap();
        let arm = pinned(Target::Aarch64).unwrap();
        assert_eq!(intel.version, arm.version);
        assert_ne!(
            intel.digest, arm.digest,
            "two architectures share one digest"
        );
    }

    #[test]
    fn an_archive_that_is_not_the_pinned_one_is_refused() {
        use sha2::Digest as _;

        let pinned = Pinned {
            version: "3.5.3".to_owned(),
            digest: hex::encode(sha2::Sha256::digest(b"the engine")),
        };
        assert!(matches(b"the engine", &pinned));
        assert!(!matches(b"the engine ", &pinned));
        assert!(!matches(b"", &pinned));
    }

    #[test]
    fn a_digest_that_is_not_hexadecimal_is_refused() {
        let pinned = Pinned {
            version: "3.5.3".to_owned(),
            digest: "not a digest".to_owned(),
        };
        assert!(!matches(b"anything", &pinned));
    }

    #[test]
    fn the_archive_name_follows_the_target() {
        let pinned = pinned(Target::X86_64).unwrap();
        assert_eq!(
            pinned.archive(Target::X86_64),
            "telemt-x86_64-linux-musl.tar.gz"
        );
    }
}
