//! Making an access for a node.
//!
//! A node serves the one method its kind names and nothing else, so the node
//! decides what an access on it is. The panel's own endpoint and the bot's
//! sign-up (0105) both come here, so an access made by either is the same
//! access with the same kind of credential.

use ap_core::{
    Access, AccessCommon, AnyAccess, Credential, Node, Open, OpenMethod, Served, Stealth,
    StealthMethod,
};

use crate::ApiError;

/// Most accesses a WEB node is configured with (0105).
///
/// telemt writes a profile for every one of them and refuses the whole
/// configuration when there are more than thirty-two — measured on
/// 16.09.2026 against 3.5.3, and not raised by any setting that was tried.
/// One access past this takes the node away from everybody on it.
pub(crate) const WEB_CEILING: i64 = 32;

/// The access a node gives, and the credential that goes with it.
///
/// A caller that named a method is held to it — an access for another method
/// could never be served, and refusing is better than storing one and
/// wondering later — but naming it is not required.
pub(crate) fn for_node(
    node: &Node,
    common: AccessCommon,
    asked: Option<&str>,
) -> Result<(AnyAccess, Credential), ApiError> {
    let access = match node.kind().tag().served() {
        Served::Masked(only) => {
            if let Some(asked) = asked {
                let asked = StealthMethod::from_stored(asked)
                    .map_err(|_| ApiError::Unprocessable("method_not_served"))?;
                if asked != only {
                    return Err(ApiError::Unprocessable("method_not_served"));
                }
            }
            AnyAccess::Stealth(Access::<Stealth>::new(common, only))
        }
        Served::Open(only) => {
            if let Some(asked) = asked {
                let asked = OpenMethod::from_stored(asked)
                    .map_err(|_| ApiError::Unprocessable("method_not_served"))?;
                if asked != only {
                    return Err(ApiError::Unprocessable("method_not_served"));
                }
            }
            AnyAccess::Open(Access::<Open>::new(common, only))
        }
    };

    let credential = match &access {
        AnyAccess::Open(open) if !matches!(open.method(), OpenMethod::Mtproto) => {
            // Named by the access, not by the client that holds it. A client
            // with two accesses would otherwise have one name for both, and a
            // node keyed by name would serve whichever it stored last while
            // charging the traffic to whichever it happened to keep.
            Credential::generate_login(access.common().id().simple().to_string())?
        }
        _ => Credential::generate_secret(),
    };
    Ok((access, credential))
}

/// Whether an access is one of the kind a node can hold only so many of.
pub(crate) fn is_web(access: &AnyAccess) -> bool {
    matches!(access, AnyAccess::Stealth(stealth) if *stealth.method() == StealthMethod::Web)
}

/// Whether a node that already keeps this many accesses has no room for one
/// more of this kind.
pub(crate) fn is_full(web: bool, kept: i64) -> bool {
    web && kept >= WEB_CEILING
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_web_node_takes_thirty_two_and_not_one_more() {
        assert!(!is_full(true, 31));
        assert!(is_full(true, 32));
        assert!(
            is_full(true, 40),
            "a node already over is not grown further"
        );
    }

    #[test]
    fn the_other_kinds_have_no_such_ceiling() {
        assert!(!is_full(false, 32));
        assert!(!is_full(false, 5000));
    }
}
