//! Stored spellings of the enumerations, so no other crate invents its own.

use crate::{
    AccessState, AdminState, ClientState, Error, NodeKindTag, NodeState, OpenMethod, Role,
    StealthMethod,
};

macro_rules! spelling {
    ($type:ty, $error:expr, $(($variant:path, $text:literal)),+ $(,)?) => {
        impl $type {
            /// The text this value is stored as.
            pub fn as_stored(&self) -> &'static str {
                match self {
                    $($variant => $text,)+
                }
            }

            /// Reads the value back from its stored text.
            pub fn from_stored(text: &str) -> Result<Self, Error> {
                match text {
                    $($text => Ok($variant),)+
                    _ => Err($error),
                }
            }
        }
    };
}

spelling!(
    ClientState,
    Error::StoredValue,
    (Self::Active, "active"),
    (Self::Suspended, "suspended"),
    (Self::Archived, "archived"),
);

spelling!(
    NodeState,
    Error::StoredValue,
    (Self::Pending, "pending"),
    (Self::Active, "active"),
    (Self::Disabled, "disabled"),
    (Self::Burned, "burned"),
);

spelling!(
    NodeKindTag,
    Error::StoredValue,
    (Self::Stealth, "stealth"),
    (Self::Open, "open"),
);

spelling!(
    AccessState,
    Error::StoredValue,
    (Self::Active, "active"),
    (Self::Disabled, "disabled"),
    (Self::Revoked, "revoked"),
);

spelling!(
    StealthMethod,
    Error::StoredValue,
    (Self::FakeTls, "faketls"),
    (Self::Web, "web"),
);

spelling!(
    OpenMethod,
    Error::StoredValue,
    (Self::Mtproto, "mtproto"),
    (Self::Socks5, "socks5"),
    (Self::Http, "http"),
);

spelling!(
    Role,
    Error::StoredValue,
    (Self::Superadmin, "superadmin"),
    (Self::Operator, "operator"),
    (Self::Reseller, "reseller"),
);

spelling!(
    AdminState,
    Error::StoredValue,
    (Self::Active, "active"),
    (Self::Disabled, "disabled"),
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_spelling_round_trips() {
        assert_eq!(ClientState::from_stored("active"), Ok(ClientState::Active));
        assert_eq!(NodeState::from_stored("burned"), Ok(NodeState::Burned));
        assert_eq!(
            NodeKindTag::from_stored("stealth"),
            Ok(NodeKindTag::Stealth)
        );
        assert_eq!(
            AccessState::from_stored("revoked"),
            Ok(AccessState::Revoked)
        );
        assert_eq!(StealthMethod::from_stored("web"), Ok(StealthMethod::Web));
        assert_eq!(OpenMethod::from_stored("socks5"), Ok(OpenMethod::Socks5));
        assert_eq!(Role::from_stored("reseller"), Ok(Role::Reseller));
        assert_eq!(
            AdminState::from_stored("disabled"),
            Ok(AdminState::Disabled)
        );
    }

    #[test]
    fn an_unknown_spelling_is_refused() {
        assert_eq!(ClientState::from_stored("gone"), Err(Error::StoredValue));
        assert_eq!(
            StealthMethod::from_stored("socks5"),
            Err(Error::StoredValue)
        );
        assert_eq!(OpenMethod::from_stored("web"), Err(Error::StoredValue));
    }

    #[test]
    fn the_spelling_matches_the_schema_constraint() {
        assert_eq!(StealthMethod::FakeTls.as_stored(), "faketls");
        assert_eq!(NodeKindTag::Open.as_stored(), "open");
    }
}
