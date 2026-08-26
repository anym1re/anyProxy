use std::sync::Arc;

use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::AgentError;

/// The name the panel's channel certificate answers to.
///
/// Fixed rather than taken from the address: the agent may reach the panel by
/// an address that changes, and what it verifies is the pinned authority.
pub const PANEL_NAME: &str = "anyproxy-panel";

/// Accepts the panel only if the chain it presents contains the pinned
/// certificate and stands up as a chain.
///
/// The pin is checked before anything is sent, which is the whole point: an
/// enrolment code handed to a stranger is a node handed to a stranger, and the
/// agent has nothing else to recognise the panel by on its first connection.
#[derive(Debug)]
pub struct PinnedAuthority {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl PinnedAuthority {
    /// Takes the fingerprint as the operator was given it.
    pub fn from_hex(text: &str, provider: Arc<CryptoProvider>) -> Result<Self, AgentError> {
        let bytes = hex::decode(text.trim()).map_err(|_| AgentError::WrongPanel)?;
        let pin: [u8; 32] = bytes.try_into().map_err(|_| AgentError::WrongPanel)?;
        Ok(Self { pin, provider })
    }

    fn anchor<'a>(
        &self,
        end_entity: &'a CertificateDer<'a>,
        intermediates: &'a [CertificateDer<'a>],
    ) -> Option<&'a CertificateDer<'a>> {
        std::iter::once(end_entity)
            .chain(intermediates)
            .find(|certificate| {
                let digest = Sha256::digest(certificate.as_ref());
                digest.ct_eq(&self.pin).into()
            })
    }
}

impl ServerCertVerifier for PinnedAuthority {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let anchor = self
            .anchor(end_entity, intermediates)
            .ok_or(rustls::Error::General(
                "the pinned authority is not in the presented chain".to_owned(),
            ))?;

        let mut roots = RootCertStore::empty();
        roots.add(anchor.clone().into_owned()).map_err(|_| {
            rustls::Error::General(
                "the pinned certificate is not usable as an authority".to_owned(),
            )
        })?;

        // The pin says which authority; webpki still has to say the chain is
        // sound, in date and issued for this name.
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&self.provider))
            .build()
            .map_err(|error| rustls::Error::General(error.to_string()))?
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    #[test]
    fn a_fingerprint_that_is_not_a_digest_is_refused() {
        assert!(PinnedAuthority::from_hex("beef", provider()).is_err());
        assert!(PinnedAuthority::from_hex("not hexadecimal", provider()).is_err());
        assert!(PinnedAuthority::from_hex(&hex::encode([0u8; 32]), provider()).is_ok());
    }

    #[test]
    fn surrounding_whitespace_does_not_change_a_fingerprint() {
        let text = hex::encode([9u8; 32]);
        let padded = format!("  {text}\n");
        assert!(PinnedAuthority::from_hex(&padded, provider()).is_ok());
    }

    #[test]
    fn the_pin_is_found_wherever_it_sits_in_the_chain() {
        let leaf = CertificateDer::from(vec![1u8, 2, 3]);
        let root = CertificateDer::from(vec![4u8, 5, 6]);

        let on_root =
            PinnedAuthority::from_hex(&hex::encode(Sha256::digest(root.as_ref())), provider())
                .unwrap();
        assert!(on_root.anchor(&leaf, std::slice::from_ref(&root)).is_some());

        let on_nothing =
            PinnedAuthority::from_hex(&hex::encode(Sha256::digest([7u8, 8, 9])), provider())
                .unwrap();
        assert!(
            on_nothing
                .anchor(&leaf, std::slice::from_ref(&root))
                .is_none(),
            "a chain without the pin was accepted"
        );
    }
}
