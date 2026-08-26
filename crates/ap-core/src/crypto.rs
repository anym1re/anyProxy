use std::fmt;
use std::marker::PhantomData;
use std::path::Path;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::{RngCore, rng};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const SECRET_LEN: usize = 16;
const PASSWORD_LEN: usize = 24;
const PASSWORD_ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// The sixteen bytes a client presents to reach the proxy.
///
/// Never printed. `Debug` and `Display` render a placeholder; the value comes
/// out only through [`Secret::expose_hex`], which is called when a link is
/// rendered and that is recorded in the audit log.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret([u8; SECRET_LEN]);

impl Secret {
    /// Draws a fresh secret from the system generator.
    pub fn generate() -> Self {
        let mut bytes = [0u8; SECRET_LEN];
        rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wraps bytes that were drawn elsewhere.
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self(bytes)
    }

    /// Reads a secret back from its hexadecimal form.
    pub fn from_hex(text: &str) -> Result<Self, Error> {
        let bytes = hex::decode(text).map_err(|_| Error::SecretForm)?;
        let bytes: [u8; SECRET_LEN] = bytes.try_into().map_err(|_| Error::SecretForm)?;
        Ok(Self(bytes))
    }

    /// Renders the secret as hexadecimal. The only way the value leaves.
    pub fn expose_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Secret {}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// The key that seals every encrypted column, held in memory only.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyStore([u8; KEY_LEN]);

impl KeyStore {
    /// Wraps key material that was obtained elsewhere.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Draws a fresh key from the system generator.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Reads the key from a file that only its owner may read.
    ///
    /// On Unix a file readable by anyone else is refused: a key the group or
    /// the world can read is not a key.
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let metadata = std::fs::metadata(path).map_err(|_| Error::KeyFileUnreadable)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::KeyFilePermissions);
            }
        }
        #[cfg(not(unix))]
        let _ = &metadata;

        let bytes = std::fs::read(path).map_err(|_| Error::KeyFileUnreadable)?;
        let bytes: [u8; KEY_LEN] = bytes.try_into().map_err(|_| Error::KeyFileLength)?;
        Ok(Self(bytes))
    }

    fn cipher(&self) -> Result<XChaCha20Poly1305, Error> {
        XChaCha20Poly1305::new_from_slice(&self.0).map_err(|_| Error::KeyFileLength)
    }

    /// Keyed digest of a value, so uniqueness can be checked without opening
    /// the ciphertext.
    pub fn digest(&self, data: &[u8]) -> [u8; 32] {
        let mut mac = match <Hmac<Sha256> as Mac>::new_from_slice(&self.0) {
            Ok(mac) => mac,
            Err(_) => return [0u8; 32],
        };
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}

impl PartialEq for KeyStore {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for KeyStore {}

impl fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyStore([redacted])")
    }
}

/// A value that can be sealed and opened again.
pub trait Sealable: Sized {
    /// Renders the value as the bytes that go under the seal.
    fn to_plaintext(&self) -> Vec<u8>;

    /// Rebuilds the value from bytes that came out from under the seal.
    fn from_plaintext(bytes: &[u8]) -> Result<Self, Error>;
}

impl Sealable for String {
    fn to_plaintext(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn from_plaintext(bytes: &[u8]) -> Result<Self, Error> {
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::SealedValue)
    }
}

impl Sealable for Secret {
    fn to_plaintext(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    fn from_plaintext(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; SECRET_LEN] = bytes.try_into().map_err(|_| Error::SealedValue)?;
        Ok(Self(bytes))
    }
}

/// A value kept under the key, with the nonce it was sealed with.
///
/// `Debug` renders a placeholder, and nothing here serialises the plaintext.
#[derive(Clone, PartialEq, Eq)]
pub struct Encrypted<T> {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
    marker: PhantomData<T>,
}

impl<T: Sealable> Encrypted<T> {
    /// Seals a value under the key with a fresh nonce.
    pub fn seal(value: &T, key: &KeyStore) -> Result<Self, Error> {
        let mut nonce = [0u8; NONCE_LEN];
        rng().fill_bytes(&mut nonce);
        let ciphertext = key
            .cipher()?
            .encrypt(XNonce::from_slice(&nonce), value.to_plaintext().as_slice())
            .map_err(|_| Error::SealedValue)?;
        Ok(Self {
            nonce,
            ciphertext,
            marker: PhantomData,
        })
    }

    /// Opens the value. A wrong key or a tampered byte gives an error, never
    /// a plausible-looking result.
    pub fn open(&self, key: &KeyStore) -> Result<T, Error> {
        let plaintext = key
            .cipher()?
            .decrypt(XNonce::from_slice(&self.nonce), self.ciphertext.as_slice())
            .map_err(|_| Error::SealedValue)?;
        T::from_plaintext(&plaintext)
    }
}

impl<T> Encrypted<T> {
    /// Rebuilds the value from what a row holds.
    pub fn from_parts(nonce: [u8; NONCE_LEN], ciphertext: Vec<u8>) -> Self {
        Self {
            nonce,
            ciphertext,
            marker: PhantomData,
        }
    }

    /// The nonce this value was sealed with.
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    /// The sealed bytes.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl<T> fmt::Debug for Encrypted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Encrypted([redacted])")
    }
}

/// What a client presents to be recognised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// Sixteen bytes, for the MTProto family.
    Secret(Secret),
    /// A name and a password, for SOCKS5 and HTTP.
    Login {
        /// Account name.
        user: String,
        /// Password drawn from the system generator.
        pass: String,
    },
}

impl Credential {
    /// Draws a fresh secret credential.
    pub fn generate_secret() -> Self {
        Self::Secret(Secret::generate())
    }

    /// Draws a fresh password for the given account name.
    pub fn generate_login(user: String) -> Result<Self, Error> {
        if user.is_empty() || user.len() > 64 {
            return Err(Error::CredentialForm);
        }
        let mut raw = [0u8; PASSWORD_LEN];
        rng().fill_bytes(&mut raw);
        let pass = raw
            .iter()
            .map(|byte| PASSWORD_ALPHABET[*byte as usize % PASSWORD_ALPHABET.len()] as char)
            .collect();
        Ok(Self::Login { user, pass })
    }

    /// The bytes a keyed digest is taken over, to check uniqueness without
    /// opening the ciphertext.
    pub fn digest_input(&self) -> Vec<u8> {
        match self {
            Self::Secret(secret) => {
                let mut out = Vec::with_capacity(1 + SECRET_LEN);
                out.push(0u8);
                out.extend_from_slice(&secret.0);
                out
            }
            Self::Login { user, pass } => {
                let mut out = vec![1u8];
                out.extend_from_slice(user.as_bytes());
                out.push(0u8);
                out.extend_from_slice(pass.as_bytes());
                out
            }
        }
    }
}

impl Sealable for Credential {
    fn to_plaintext(&self) -> Vec<u8> {
        self.digest_input()
    }

    fn from_plaintext(bytes: &[u8]) -> Result<Self, Error> {
        match bytes.split_first() {
            Some((0, rest)) => Ok(Self::Secret(Secret::from_plaintext(rest)?)),
            Some((1, rest)) => {
                let split = rest
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or(Error::SealedValue)?;
                let user =
                    String::from_utf8(rest[..split].to_vec()).map_err(|_| Error::SealedValue)?;
                let pass = String::from_utf8(rest[split + 1..].to_vec())
                    .map_err(|_| Error::SealedValue)?;
                Ok(Self::Login { user, pass })
            }
            _ => Err(Error::SealedValue),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> KeyStore {
        KeyStore::from_bytes([7u8; KEY_LEN])
    }

    #[test]
    fn a_secret_never_prints_itself() {
        let secret = Secret::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        assert!(!format!("{secret:?}").contains("0001"));
        assert!(!format!("{secret}").contains("0001"));
        assert_eq!(secret.expose_hex(), "000102030405060708090a0b0c0d0e0f");
    }

    #[test]
    fn a_secret_is_sixteen_bytes_of_hex() {
        assert!(Secret::from_hex("00").is_err());
        assert!(Secret::from_hex("").is_err());
        assert!(Secret::from_hex("zz0102030405060708090a0b0c0d0e0f").is_err());
        assert!(Secret::from_hex("000102030405060708090a0b0c0d0e0f00").is_err());
    }

    #[test]
    fn generated_secrets_differ() {
        assert_ne!(Secret::generate(), Secret::generate());
    }

    #[test]
    fn sealing_round_trips() {
        for text in ["", "a", &"x".repeat(4096)] {
            let sealed = Encrypted::seal(&text.to_owned(), &key()).unwrap();
            assert_eq!(sealed.open(&key()).unwrap(), text);
        }
    }

    #[test]
    fn a_sealed_value_never_prints_itself() {
        let sealed = Encrypted::seal(&"swordfish".to_owned(), &key()).unwrap();
        assert!(!format!("{sealed:?}").contains("swordfish"));
        assert!(!format!("{:?}", key()).contains('7'));
    }

    #[test]
    fn the_wrong_key_gives_an_error_not_rubbish() {
        let sealed = Encrypted::seal(&"swordfish".to_owned(), &key()).unwrap();
        let other = KeyStore::from_bytes([9u8; KEY_LEN]);
        assert_eq!(sealed.open(&other), Err(Error::SealedValue));
    }

    #[test]
    fn a_tampered_byte_is_refused() {
        let sealed = Encrypted::seal(&"swordfish".to_owned(), &key()).unwrap();

        let mut ciphertext = sealed.ciphertext().to_vec();
        ciphertext[0] ^= 1;
        let broken = Encrypted::<String>::from_parts(*sealed.nonce(), ciphertext);
        assert_eq!(broken.open(&key()), Err(Error::SealedValue));

        let mut nonce = *sealed.nonce();
        nonce[0] ^= 1;
        let broken = Encrypted::<String>::from_parts(nonce, sealed.ciphertext().to_vec());
        assert_eq!(broken.open(&key()), Err(Error::SealedValue));
    }

    #[test]
    fn two_seals_of_one_value_differ() {
        let first = Encrypted::seal(&"swordfish".to_owned(), &key()).unwrap();
        let second = Encrypted::seal(&"swordfish".to_owned(), &key()).unwrap();
        assert_ne!(first.ciphertext(), second.ciphertext());
    }

    #[test]
    fn a_credential_round_trips_under_seal() {
        for credential in [
            Credential::generate_secret(),
            Credential::generate_login("alice".to_owned()).unwrap(),
        ] {
            let sealed = Encrypted::seal(&credential, &key()).unwrap();
            assert_eq!(sealed.open(&key()).unwrap(), credential);
        }
    }

    #[test]
    fn a_generated_password_is_long_and_unpredictable() {
        let Credential::Login { pass: first, .. } =
            Credential::generate_login("alice".to_owned()).unwrap()
        else {
            unreachable!()
        };
        let Credential::Login { pass: second, .. } =
            Credential::generate_login("alice".to_owned()).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(first.chars().count(), PASSWORD_LEN);
        assert_ne!(first, second);
        assert!(Credential::generate_login(String::new()).is_err());
    }

    #[test]
    fn the_digest_separates_values_without_opening_them() {
        let key = key();
        let first = Credential::generate_secret();
        let second = Credential::generate_secret();
        assert_eq!(
            key.digest(&first.digest_input()),
            key.digest(&first.digest_input())
        );
        assert_ne!(
            key.digest(&first.digest_input()),
            key.digest(&second.digest_input())
        );
    }

    #[test]
    fn the_digest_depends_on_the_key() {
        let credential = Credential::generate_secret();
        let other = KeyStore::from_bytes([9u8; KEY_LEN]);
        assert_ne!(
            key().digest(&credential.digest_input()),
            other.digest(&credential.digest_input())
        );
    }

    // A key file is created world-readable by default on Unix, and the
    // permission check runs before the length check, so the file has to be
    // locked down first for this test to reach the length at all.
    fn write_owner_only(path: &std::path::Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
    }

    #[test]
    fn a_key_file_of_the_wrong_length_is_refused() {
        let dir = std::env::temp_dir().join(format!("ap-core-key-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("short.key");
        write_owner_only(&path, &[1u8; 8]);
        assert_eq!(KeyStore::from_file(&path), Err(Error::KeyFileLength));

        let path = dir.join("right.key");
        write_owner_only(&path, &[1u8; KEY_LEN]);
        assert!(KeyStore::from_file(&path).is_ok());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_key_file_is_refused() {
        let path = std::env::temp_dir().join("ap-core-key-absent.key");
        std::fs::remove_file(&path).ok();
        assert_eq!(KeyStore::from_file(&path), Err(Error::KeyFileUnreadable));
    }

    #[cfg(unix)]
    #[test]
    fn a_key_file_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ap-core-key-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("open.key");
        std::fs::write(&path, [1u8; KEY_LEN]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(KeyStore::from_file(&path), Err(Error::KeyFilePermissions));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(KeyStore::from_file(&path).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }
}
