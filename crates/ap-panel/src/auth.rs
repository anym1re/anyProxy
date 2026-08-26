use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand::{RngCore, rng};
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::ApiError;

/// A password verifier that no password matches.
///
/// Used when the login does not exist, so that the work done on a wrong login
/// matches the work done on a wrong password. Without it the difference in
/// timing tells an attacker which logins are real.
const ABSENT_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$\
                           N9C1z2Y0kZ8kQvQ8b3rJ1yQ4pM5nX7wL0aB2cD4eF6g";

/// A base32 secret used when the login does not exist, for the same reason.
const ABSENT_TOTP: &str = "JBSWY3DPEHPK3PXP";

/// Hashes a password for storage.
pub fn hash_password(password: &str) -> Result<String, ApiError> {
    let mut salt = [0u8; 16];
    rng().fill_bytes(&mut salt);
    let salt = SaltString::encode_b64(&salt).map_err(|_| ApiError::Internal("password_hash"))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| ApiError::Internal("password_hash"))
}

/// Checks a password against a stored verifier.
///
/// Returns false rather than an error on a malformed verifier: the caller must
/// not be able to tell a broken row from a wrong password.
pub fn verify_password(password: &str, stored: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Does the same work as a real check, and always fails.
pub fn verify_absent_password(password: &str) {
    let _ = verify_password(password, ABSENT_HASH);
}

fn totp(secret_base32: &str) -> Result<TOTP, ApiError> {
    let bytes = Secret::Encoded(secret_base32.to_owned())
        .to_bytes()
        .map_err(|_| ApiError::Internal("totp_secret"))?;
    TOTP::new(Algorithm::SHA1, 6, 1, 30, bytes).map_err(|_| ApiError::Internal("totp_secret"))
}

/// Checks a one-time code against a base32 secret.
pub fn verify_totp(secret_base32: &str, code: &str) -> bool {
    totp(secret_base32)
        .ok()
        .and_then(|totp| totp.check_current(code).ok())
        .unwrap_or(false)
}

/// Does the same work as a real check, and always fails.
pub fn verify_absent_totp(code: &str) {
    let _ = verify_totp(ABSENT_TOTP, code);
}

/// Draws a base32 secret for a new second factor.
pub fn new_totp_secret() -> String {
    let mut bytes = [0u8; 20];
    rng().fill_bytes(&mut bytes);
    Secret::Raw(bytes.to_vec()).to_encoded().to_string()
}

/// Draws a session token. Returned once, never stored as given.
pub fn new_token() -> String {
    let mut bytes = [0u8; 32];
    rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// The digest a token is stored under.
pub fn token_digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// How many attempts are allowed, and over what window.
const ATTEMPTS: usize = 5;
const WINDOW: Duration = Duration::from_secs(300);

/// Counts sign-in attempts per subject.
///
/// Kept in memory: it guards a single panel process, and a counter that
/// survives a restart would need a table whose only purpose is to be written to
/// on every failed guess.
#[derive(Debug, Default)]
pub struct Attempts {
    seen: Mutex<HashMap<String, Vec<Instant>>>,
}

impl Attempts {
    /// Records an attempt and reports how long to wait, if the subject is over
    /// the limit.
    pub fn record(&self, subject: &str) -> Option<u64> {
        let now = Instant::now();
        let Ok(mut seen) = self.seen.lock() else {
            return None;
        };
        let entries = seen.entry(subject.to_owned()).or_default();
        entries.retain(|at| now.duration_since(*at) < WINDOW);
        entries.push(now);

        if entries.len() > ATTEMPTS {
            let oldest = entries.first().copied().unwrap_or(now);
            let elapsed = now.duration_since(oldest);
            Some(WINDOW.saturating_sub(elapsed).as_secs().max(1))
        } else {
            None
        }
    }

    /// Forgets the attempts of a subject that has just succeeded.
    pub fn forget(&self, subject: &str) {
        if let Ok(mut seen) = self.seen.lock() {
            seen.remove(subject);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_survives_a_round_trip() {
        let hash = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &hash));
        assert!(!verify_password("wrong horse", &hash));
    }

    #[test]
    fn a_malformed_verifier_refuses_rather_than_errors() {
        assert!(!verify_password("anything", "not a hash"));
        assert!(!verify_password("anything", ""));
    }

    #[test]
    fn a_token_is_thirty_two_bytes_and_stored_as_a_digest() {
        let token = new_token();
        assert_eq!(token.len(), 64);
        assert_ne!(new_token(), new_token());
        assert_eq!(token_digest(&token).len(), 32);
        assert_ne!(token_digest(&token), token.as_bytes());
    }

    #[test]
    fn the_sixth_attempt_in_the_window_is_held_back() {
        let attempts = Attempts::default();
        for _ in 0..ATTEMPTS {
            assert_eq!(attempts.record("someone"), None);
        }
        let wait = attempts.record("someone").expect("held back");
        assert!(wait > 0 && wait <= WINDOW.as_secs());
    }

    #[test]
    fn subjects_are_counted_apart() {
        let attempts = Attempts::default();
        for _ in 0..ATTEMPTS {
            let _ = attempts.record("first");
        }
        assert_eq!(attempts.record("second"), None);
    }

    #[test]
    fn success_clears_the_count() {
        let attempts = Attempts::default();
        for _ in 0..ATTEMPTS {
            let _ = attempts.record("someone");
        }
        attempts.forget("someone");
        assert_eq!(attempts.record("someone"), None);
    }

    #[test]
    fn a_wrong_code_is_refused() {
        assert!(!verify_totp(ABSENT_TOTP, "000000"));
        assert!(!verify_totp(ABSENT_TOTP, ""));
        assert!(!verify_totp("not base32 !!", "123456"));
    }
}
