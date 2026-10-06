use rand::{RngCore, rng};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{ApiError, AppState};

/// How long a code stays usable. The interface says this figure where it
/// describes a code, and reads it from here rather than repeating it.
pub(crate) const MINUTES: i64 = 60;

/// What an operator is shown once.
pub struct Issued {
    /// The code itself. Not stored, not readable afterwards.
    pub code: String,
    /// Digest of the panel certificate, for the installer to pin.
    pub fingerprint: String,
    /// When the code stops working.
    pub expires_at: String,
}

/// Issues a code for a node.
///
/// Sixteen bytes from the system generator: the code is not a long-lived
/// secret, but it must not be guessable within the hour it lives.
pub async fn issue(state: &AppState, node_id: Uuid) -> Result<Issued, ApiError> {
    let mut bytes = [0u8; 16];
    rng().fill_bytes(&mut bytes);
    let code = hex::encode(bytes);

    let now = OffsetDateTime::now_utc();
    let expires_at = now + Duration::minutes(MINUTES);
    ap_store::EnrollmentRepo::issue(
        state.pool(),
        node_id,
        &Sha256::digest(code.as_bytes()),
        expires_at,
        now,
    )
    .await
    .map_err(ApiError::from)?;

    Ok(Issued {
        code,
        fingerprint: state.authority().fingerprint()?,
        expires_at: ap_core::time::format_rfc3339(expires_at)?,
    })
}
