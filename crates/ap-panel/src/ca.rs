use ap_core::{Encrypted, KeyStore};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};

use crate::ApiError;

/// How long an agent certificate is good for.
const AGENT_DAYS: i64 = 90;

/// How long the panel authority is good for.
const AUTHORITY_YEARS: i64 = 10;

/// The authority the panel signs agent certificates with.
pub struct Authority {
    certificate_pem: String,
    key_pem: String,
}

impl Authority {
    /// Reads the authority, creating it on first use.
    ///
    /// The private key is sealed with the same key as every other secret, so a
    /// database dump without the key file cannot impersonate the panel.
    pub async fn load_or_create(pool: &PgPool, key: &KeyStore) -> Result<Self, String> {
        if let Some(stored) = ap_store::PanelIdentityRepo::read(pool)
            .await
            .map_err(|error| error.to_string())?
        {
            let key_pem = stored.key.open(key).map_err(|error| error.to_string())?;
            return Ok(Self {
                certificate_pem: stored.certificate,
                key_pem,
            });
        }

        let pair = KeyPair::generate().map_err(|error| error.to_string())?;
        let mut params = CertificateParams::new(Vec::new()).map_err(|error| error.to_string())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, "anyproxy panel");
        params.not_before = OffsetDateTime::now_utc() - Duration::hours(1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(AUTHORITY_YEARS * 365);

        let certificate = params
            .self_signed(&pair)
            .map_err(|error| error.to_string())?;
        let identity = ap_store::PanelIdentity {
            certificate: certificate.pem(),
            key: Encrypted::seal(&pair.serialize_pem(), key).map_err(|error| error.to_string())?,
        };
        ap_store::PanelIdentityRepo::write(pool, &identity, OffsetDateTime::now_utc())
            .await
            .map_err(|error| error.to_string())?;

        Ok(Self {
            certificate_pem: identity.certificate,
            key_pem: pair.serialize_pem(),
        })
    }

    /// The certificate agents pin.
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    /// The fingerprint an operator passes to the installer alongside the code.
    ///
    /// Taken over the encoded certificate rather than its PEM wrapper, so the
    /// agent arrives at the same value from what the handshake gives it and
    /// nothing depends on how the text was wrapped.
    ///
    /// A failure is a failure, not an empty string: a pin nobody can compute
    /// would be handed to an operator as a pin of nothing, and the agent would
    /// then have nothing to recognise the panel by.
    pub fn fingerprint(&self) -> Result<String, ApiError> {
        CertificateDer::pem_slice_iter(self.certificate_pem.as_bytes())
            .next()
            .and_then(Result::ok)
            .map(|der| hex::encode(Sha256::digest(der.as_ref())))
            .ok_or(ApiError::Internal("authority_cert"))
    }

    /// Issues the chain the panel presents to agents, and its key.
    ///
    /// A leaf signed by the authority rather than the authority itself: the
    /// agent pins the authority and validates the chain, so the key that signs
    /// certificates is not also the key that terminates connections. The
    /// authority follows the leaf, because an agent that has not enrolled yet
    /// holds nothing but the fingerprint and has nowhere else to get it from.
    pub fn server_certificate(&self) -> Result<(String, String), String> {
        let pair = KeyPair::generate().map_err(|error| error.to_string())?;
        let mut params = CertificateParams::new(vec!["anyproxy-panel".to_owned()])
            .map_err(|error| error.to_string())?;
        params
            .distinguished_name
            .push(DnType::CommonName, "anyproxy panel channel");
        params.not_before = OffsetDateTime::now_utc() - Duration::hours(1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(AGENT_DAYS);

        let authority_key = KeyPair::from_pem(&self.key_pem).map_err(|error| error.to_string())?;
        let issuer = Issuer::from_ca_cert_pem(&self.certificate_pem, authority_key)
            .map_err(|error| error.to_string())?;
        let certificate = params
            .signed_by(&pair, &issuer)
            .map_err(|error| error.to_string())?;
        Ok((
            format!("{}{}", certificate.pem(), self.certificate_pem),
            pair.serialize_pem(),
        ))
    }

    /// Signs a request from an agent.
    ///
    /// The subject is replaced with the node identifier the panel decided on.
    /// Whatever the request asked to be called is discarded: an agent does not
    /// get to name itself, because that name is what later grants it access to
    /// one node's configuration and no other.
    pub fn sign(&self, csr_pem: &str, node_id: uuid::Uuid) -> Result<String, ApiError> {
        let pair =
            KeyPair::from_pem(&self.key_pem).map_err(|_| ApiError::Internal("authority_key"))?;
        let issuer = Issuer::from_ca_cert_pem(&self.certificate_pem, pair)
            .map_err(|_| ApiError::Internal("authority_cert"))?;

        let mut request = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|_| ApiError::BadRequest("malformed_csr"))?;
        request.params.distinguished_name = rcgen::DistinguishedName::new();
        request
            .params
            .distinguished_name
            .push(DnType::CommonName, node_id.to_string());
        request.params.is_ca = IsCa::NoCa;
        request.params.not_before = OffsetDateTime::now_utc() - Duration::hours(1);
        request.params.not_after = OffsetDateTime::now_utc() + Duration::days(AGENT_DAYS);

        request
            .signed_by(&issuer)
            .map(|certificate| certificate.pem())
            .map_err(|_| ApiError::BadRequest("malformed_csr"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_presented_chain_ends_at_the_pinned_authority() {
        let pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        let root = params.self_signed(&pair).unwrap();
        let authority = Authority {
            certificate_pem: root.pem(),
            key_pem: pair.serialize_pem(),
        };

        let (chain, _) = authority.server_certificate().unwrap();
        let presented: Vec<_> = CertificateDer::pem_slice_iter(chain.as_bytes())
            .map(Result::unwrap)
            .collect();
        assert_eq!(presented.len(), 2, "the authority was not sent");

        assert_eq!(
            hex::encode(Sha256::digest(presented[1].as_ref())),
            authority.fingerprint().unwrap()
        );
        assert_ne!(
            hex::encode(Sha256::digest(presented[0].as_ref())),
            authority.fingerprint().unwrap(),
            "the leaf answered to the pin"
        );
    }
}
