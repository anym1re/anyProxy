use std::path::{Path, PathBuf};

use rcgen::{CertificateParams, CertificateSigningRequest, DnType, KeyPair};

use crate::AgentError;

/// Where the agent keeps what it is.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Directory holding everything below.
    pub dir: PathBuf,
}

impl Paths {
    /// Uses one directory for the certificate, the key and the cache.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The certificate the panel signed.
    pub fn certificate(&self) -> PathBuf {
        self.dir.join("agent.crt")
    }

    /// The private key that certificate speaks for.
    pub fn key(&self) -> PathBuf {
        self.dir.join("agent.key")
    }

    /// The certificate of the panel authority.
    pub fn authority(&self) -> PathBuf {
        self.dir.join("panel-ca.crt")
    }

    /// The sealed configuration.
    pub fn cache(&self) -> PathBuf {
        self.dir.join("config.sealed")
    }

    /// The node the panel said this agent serves.
    pub fn node(&self) -> PathBuf {
        self.dir.join("node.id")
    }
}

/// A fresh key and the request that asks the panel to certify it.
pub struct Request {
    /// The private key, PEM. Never leaves the node.
    pub key_pem: String,
    /// The request to sign, PEM.
    pub csr_pem: String,
}

/// Draws a key and builds the request for it.
///
/// The subject says nothing that matters: the panel replaces it with the node
/// it decided on, so what an agent asks to be called has no effect.
pub fn request() -> Result<Request, AgentError> {
    let pair = KeyPair::generate().map_err(|error| AgentError::Refused(error.to_string()))?;
    let mut params = CertificateParams::new(Vec::new())
        .map_err(|error| AgentError::Refused(error.to_string()))?;
    params
        .distinguished_name
        .push(DnType::CommonName, "anyproxy agent");

    let csr: CertificateSigningRequest = params
        .serialize_request(&pair)
        .map_err(|error| AgentError::Refused(error.to_string()))?;

    Ok(Request {
        key_pem: pair.serialize_pem(),
        csr_pem: csr
            .pem()
            .map_err(|error| AgentError::Refused(error.to_string()))?,
    })
}

/// What the agent presents to the panel once it has enrolled.
#[derive(Debug, Clone)]
pub struct Identity {
    /// The node the panel decided this agent serves.
    pub node_id: uuid::Uuid,
    /// The signed certificate, PEM.
    pub certificate_pem: String,
    /// Its private key, PEM.
    pub key_pem: String,
    /// The panel authority, PEM.
    pub authority_pem: String,
}

impl Identity {
    /// The fingerprint of the authority this identity was signed by.
    ///
    /// Computed rather than remembered: after enrolment the agent holds the
    /// authority itself, so the operator does not carry the value twice.
    pub fn fingerprint(&self) -> Result<String, AgentError> {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        use sha2::{Digest, Sha256};

        CertificateDer::pem_slice_iter(self.authority_pem.as_bytes())
            .next()
            .and_then(Result::ok)
            .map(|der| hex::encode(Sha256::digest(der.as_ref())))
            .ok_or(AgentError::WrongPanel)
    }
}

/// Writes the identity, readable by its owner and nobody else.
pub fn store(paths: &Paths, identity: &Identity) -> Result<(), AgentError> {
    std::fs::create_dir_all(&paths.dir)
        .map_err(|error| AgentError::file(paths.dir.display(), error))?;
    write_owner_only(&paths.certificate(), identity.certificate_pem.as_bytes())?;
    write_owner_only(&paths.key(), identity.key_pem.as_bytes())?;
    write_owner_only(&paths.authority(), identity.authority_pem.as_bytes())?;
    write_owner_only(&paths.node(), identity.node_id.to_string().as_bytes())?;
    Ok(())
}

/// Reads the identity back, refusing one anyone else could have read.
pub fn load(paths: &Paths) -> Result<Identity, AgentError> {
    let node_id = read_owner_only(&paths.node())?;
    Ok(Identity {
        node_id: node_id
            .trim()
            .parse()
            .map_err(|_| AgentError::Refused("the stored node identifier is not one".to_owned()))?,
        certificate_pem: read_owner_only(&paths.certificate())?,
        key_pem: read_owner_only(&paths.key())?,
        authority_pem: read_owner_only(&paths.authority())?,
    })
}

/// Writes a file only its owner may read, replacing what was there.
///
/// The bytes go to a file beside the target and are moved onto it, for two
/// reasons. A file left at `0400` cannot be opened for writing again, and the
/// agent rewrites its cache every time the panel sends a revision — opening
/// the target in place works once and then fails for anyone who is not root.
/// And a move is atomic, so a reader never sees the file half written.
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), AgentError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| AgentError::file(parent.display(), error))?;
    }
    let staged = staging_path(path);

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&staged)
            .map_err(|error| AgentError::file(staged.display(), error))?;
        // An existing file keeps the mode it was created with, so say it again.
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| AgentError::file(staged.display(), error))?;
        file.write_all(bytes)
            .map_err(|error| AgentError::file(staged.display(), error))?;
        file.sync_all()
            .map_err(|error| AgentError::file(staged.display(), error))?;
        drop(file);
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o400))
            .map_err(|error| AgentError::file(staged.display(), error))?;
    }
    #[cfg(not(unix))]
    std::fs::write(&staged, bytes).map_err(|error| AgentError::file(staged.display(), error))?;

    std::fs::rename(&staged, path).map_err(|error| AgentError::file(path.display(), error))?;

    Ok(())
}

/// Where the bytes are assembled before they take the target's place.
fn staging_path(path: &Path) -> std::path::PathBuf {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_owned());
    path.with_file_name(format!(".{name}.new"))
}

/// Reads a file, refusing one the group or the world can read.
fn read_owner_only(path: &Path) -> Result<String, AgentError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata =
            std::fs::metadata(path).map_err(|error| AgentError::file(path.display(), error))?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(AgentError::Exposed(path.display().to_string()));
        }
    }
    std::fs::read_to_string(path).map_err(|error| AgentError::file(path.display(), error))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("anyproxy-agent-identity")
            .join(format!("{name}-{}", uuid::Uuid::now_v7().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn an_identity() -> Identity {
        Identity {
            node_id: uuid::Uuid::now_v7(),
            certificate_pem: "-----BEGIN CERTIFICATE-----\nleaf\n".to_owned(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nkey\n".to_owned(),
            authority_pem: "-----BEGIN CERTIFICATE-----\nroot\n".to_owned(),
        }
    }

    #[test]
    fn a_request_carries_a_key_and_asks_for_nothing_in_particular() {
        let first = request().unwrap();
        assert!(first.key_pem.contains("PRIVATE KEY"));
        assert!(first.csr_pem.contains("CERTIFICATE REQUEST"));

        let second = request().unwrap();
        assert_ne!(
            first.key_pem, second.key_pem,
            "two agents were given the same key"
        );
    }

    #[test]
    fn what_was_stored_comes_back() {
        let paths = Paths::new(a_dir("round-trip"));
        let identity = an_identity();
        store(&paths, &identity).unwrap();
        let read_back = load(&paths).unwrap();
        assert_eq!(read_back.node_id, identity.node_id);
        assert_eq!(read_back.certificate_pem, identity.certificate_pem);
        assert_eq!(read_back.key_pem, identity.key_pem);
        assert_eq!(read_back.authority_pem, identity.authority_pem);
    }

    #[cfg(unix)]
    #[test]
    fn a_key_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let paths = Paths::new(a_dir("exposed"));
        store(&paths, &an_identity()).unwrap();
        std::fs::set_permissions(paths.key(), std::fs::Permissions::from_mode(0o444)).unwrap();

        let outcome = load(&paths);
        assert!(
            matches!(outcome, Err(AgentError::Exposed(_))),
            "a world-readable key was accepted: {outcome:?}"
        );
    }

    #[test]
    fn writing_twice_replaces_what_was_there() {
        let paths = Paths::new(a_dir("rewrite"));
        store(&paths, &an_identity()).unwrap();

        let second = Identity {
            certificate_pem: "-----BEGIN CERTIFICATE-----
second
"
            .to_owned(),
            ..an_identity()
        };
        store(&paths, &second).unwrap();

        assert_eq!(
            load(&paths).unwrap().certificate_pem,
            second.certificate_pem
        );
    }

    #[test]
    fn nothing_is_left_beside_what_was_written() {
        let paths = Paths::new(a_dir("no-leftovers"));
        store(&paths, &an_identity()).unwrap();
        store(&paths, &an_identity()).unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(&paths.dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".new"))
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    }

    #[cfg(unix)]
    #[test]
    fn what_is_written_is_readable_by_its_owner_alone() {
        use std::os::unix::fs::PermissionsExt;

        let paths = Paths::new(a_dir("mode"));
        store(&paths, &an_identity()).unwrap();
        for path in [
            paths.certificate(),
            paths.key(),
            paths.authority(),
            paths.node(),
        ] {
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o400, "{} has mode {mode:o}", path.display());
        }
    }
}
