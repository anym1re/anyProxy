//! What a client is handed to connect with (0088).
//!
//! Built in one place and handed out by two: the link endpoint and the bot.
//! Which port SOCKS5 is on and what a masked node puts in its link are
//! decided here and nowhere else.

use ap_core::{AnyAccess, Credential, NodeKind, OpenMethod};

use crate::ApiError;

/// The port an open method is served on.
///
/// One number for both SOCKS5 and HTTP would send everyone holding an HTTP
/// account to the SOCKS5 listener, which refuses them for speaking the wrong
/// protocol.
pub fn port_of(method: OpenMethod) -> u16 {
    match method {
        OpenMethod::Socks5 => 1080,
        OpenMethod::Http => 3128,
        OpenMethod::Mtproto => 8443,
    }
}

/// What leaves the panel for one access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handout {
    /// A link Telegram opens by itself.
    Link {
        /// The link.
        link: String,
        /// The method, in its stored form.
        method: &'static str,
    },
    /// An account Telegram takes in its own fields: SOCKS5 and HTTP have no
    /// link form.
    Account {
        /// Where to connect.
        host: String,
        /// On which port.
        port: u16,
        /// Account name.
        user: String,
        /// Password.
        password: String,
        /// The method, in its stored form.
        method: &'static str,
    },
}

impl Handout {
    /// The method, in its stored form.
    pub fn method(&self) -> &'static str {
        match self {
            Self::Link { method, .. } | Self::Account { method, .. } => method,
        }
    }
}

/// Builds what is handed out for an access on a node, dialled at a host.
///
/// The credential is the opened one; the caller has already written the
/// handing out to the journal, because nothing here leaves without that.
pub fn handout(
    access: &AnyAccess,
    credential: &Credential,
    kind: &NodeKind,
    host: &str,
) -> Result<Handout, ApiError> {
    match (access, credential) {
        (AnyAccess::Stealth(access), Credential::Secret(secret)) => {
            let domain = kind
                .domain()
                .ok_or(ApiError::Internal("node_without_domain"))?;
            Ok(Handout::Link {
                link: ap_core::stealth_link(*access.method(), host, domain, secret)?,
                method: access.method().as_stored(),
            })
        }
        (AnyAccess::Open(access), Credential::Secret(secret))
            if matches!(access.method(), OpenMethod::Mtproto) =>
        {
            Ok(Handout::Link {
                link: ap_core::mtproto_link(host, port_of(*access.method()), secret)?,
                method: access.method().as_stored(),
            })
        }
        (AnyAccess::Open(access), Credential::Login { user, pass }) => Ok(Handout::Account {
            host: host.to_owned(),
            port: port_of(*access.method()),
            user: user.clone(),
            password: pass.clone(),
            method: access.method().as_stored(),
        }),
        _ => Err(ApiError::Internal("credential_mismatch")),
    }
}

/// The host a node is dialled at, when the panel knows one.
///
/// A node that answers to a name is dialled by that name. Otherwise the
/// address its agent last called from stands in — which is what the link
/// dialog on the screen offers too.
pub fn host_of(node: &ap_core::Node) -> Option<String> {
    node.kind()
        .domain()
        .map(|domain| domain.as_str().to_owned())
        .or_else(|| node.address().map(|address| address.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ap_core::{Access, AccessCommon, Holder, Open, Secret, Stealth, StealthMethod};

    fn common() -> AccessCommon {
        AccessCommon::new(
            Holder::Client(uuid::Uuid::now_v7()),
            uuid::Uuid::now_v7(),
            time::OffsetDateTime::UNIX_EPOCH,
        )
    }

    fn secret() -> Credential {
        Credential::Secret(Secret::from_hex("000102030405060708090a0b0c0d0e0f").unwrap())
    }

    #[test]
    fn a_masked_node_puts_its_name_in_the_link() {
        let access = AnyAccess::Stealth(Access::<Stealth>::new(common(), StealthMethod::FakeTls));
        let kind = NodeKind::from_parts(
            ap_core::NodeKindTag::FakeTls,
            Some(ap_core::Domain::try_from("dns.google").unwrap()),
        )
        .unwrap();
        let made = handout(&access, &secret(), &kind, "203.0.113.7").unwrap();
        match made {
            Handout::Link { link, method } => {
                assert!(link.starts_with("https://t.me/proxy?server=203.0.113.7&port=443"));
                assert_eq!(method, "faketls");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_account_is_offered_on_the_port_its_method_is_served_on() {
        for (method, port) in [(OpenMethod::Socks5, 1080), (OpenMethod::Http, 3128)] {
            let access = AnyAccess::Open(Access::<Open>::new(common(), method));
            let credential = Credential::Login {
                user: "u".to_owned(),
                pass: "p".to_owned(),
            };
            let kind = NodeKind::from_parts(
                match method {
                    OpenMethod::Socks5 => ap_core::NodeKindTag::Socks5,
                    _ => ap_core::NodeKindTag::Http,
                },
                None,
            )
            .unwrap();
            match handout(&access, &credential, &kind, "203.0.113.7").unwrap() {
                Handout::Account {
                    port: served, user, ..
                } => {
                    assert_eq!(served, port);
                    assert_eq!(user, "u");
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn a_secret_on_an_account_method_is_a_mismatch() {
        let access = AnyAccess::Open(Access::<Open>::new(common(), OpenMethod::Socks5));
        let kind = NodeKind::from_parts(ap_core::NodeKindTag::Socks5, None).unwrap();
        assert_eq!(
            handout(&access, &secret(), &kind, "203.0.113.7"),
            Err(ApiError::Internal("credential_mismatch"))
        );
    }
}
