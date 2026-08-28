use crate::{Domain, Error, OpenMethod, Secret, StealthMethod};

/// Link for a method a masked node serves.
///
/// Both name the node's one name. FakeTLS puts it in the secret so the client
/// presents it as the name it is asking for, which for this kind is a name
/// borrowed from somebody else; WEB names the host directly, because the
/// transport is real HTTPS to a site of ours that answers to it.
pub fn stealth_link(
    method: StealthMethod,
    host: &str,
    domain: &Domain,
    secret: &Secret,
) -> Result<String, Error> {
    if host.is_empty() {
        return Err(Error::LinkHost);
    }
    Ok(match method {
        StealthMethod::FakeTls => format!(
            "https://t.me/proxy?server={host}&port=443&secret=ee{}{}",
            secret.expose_hex(),
            hex::encode(domain.as_str())
        ),
        StealthMethod::Web => format!(
            "https://t.me/webproxy?server={}&secret={}",
            domain.as_str(),
            secret.expose_hex()
        ),
    })
}

/// Link for unmasked MTProto on an open node.
///
/// SOCKS5 and HTTP have no link form: Telegram takes host, port and
/// credentials in its own fields.
pub fn mtproto_link(host: &str, port: u16, secret: &Secret) -> Result<String, Error> {
    if host.is_empty() {
        return Err(Error::LinkHost);
    }
    Ok(format!(
        "https://t.me/proxy?server={host}&port={port}&secret=dd{}",
        secret.expose_hex()
    ))
}

/// Whether a method of an open node has a link form at all.
pub fn has_link(method: OpenMethod) -> bool {
    matches!(method, OpenMethod::Mtproto)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Secret {
        Secret::from_hex("000102030405060708090a0b0c0d0e0f").unwrap()
    }

    fn domain() -> Domain {
        Domain::try_from("cover.example.com").unwrap()
    }

    #[test]
    fn fake_tls_carries_the_cover_domain_in_the_secret() {
        assert_eq!(
            stealth_link(StealthMethod::FakeTls, "203.0.113.7", &domain(), &secret()).unwrap(),
            "https://t.me/proxy?server=203.0.113.7&port=443&secret=ee000102030405060708090a0b0c0d0e0f636f7665722e6578616d706c652e636f6d"
        );
    }

    #[test]
    fn web_names_the_domain_directly() {
        assert_eq!(
            stealth_link(StealthMethod::Web, "203.0.113.7", &domain(), &secret()).unwrap(),
            "https://t.me/webproxy?server=cover.example.com&secret=000102030405060708090a0b0c0d0e0f"
        );
    }

    #[test]
    fn unmasked_mtproto_uses_the_dd_prefix() {
        assert_eq!(
            mtproto_link("203.0.113.7", 8443, &secret()).unwrap(),
            "https://t.me/proxy?server=203.0.113.7&port=8443&secret=dd000102030405060708090a0b0c0d0e0f"
        );
    }

    #[test]
    fn an_empty_host_is_refused() {
        assert_eq!(
            stealth_link(StealthMethod::FakeTls, "", &domain(), &secret()),
            Err(Error::LinkHost)
        );
        assert_eq!(mtproto_link("", 8443, &secret()), Err(Error::LinkHost));
    }

    #[test]
    fn only_mtproto_has_a_link_among_the_open_methods() {
        assert!(has_link(OpenMethod::Mtproto));
        assert!(!has_link(OpenMethod::Socks5));
        assert!(!has_link(OpenMethod::Http));
    }
}
