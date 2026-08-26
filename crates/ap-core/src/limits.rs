use ::time::OffsetDateTime;

use crate::{AccessCommon, AccessState, Client, ClientState};

/// Ceilings that apply to an access, kept apart because they count different
/// sums: the client one covers every access the client holds, the access one
/// covers this access alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaLimits {
    /// Ceiling across every access of the client.
    pub client: Option<i64>,
    /// Ceiling for this access alone.
    pub access: Option<i64>,
}

/// Bytes already spent, against the two ceilings of [`QuotaLimits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    /// Total across every access of the client.
    pub client_bytes: i64,
    /// Total for this access alone.
    pub access_bytes: i64,
}

/// Why an access is not served.
///
/// Kept for the panel and the audit log. It never reaches the client: on a
/// stealth node every refusal looks the same from outside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// The client is suspended.
    ClientSuspended,
    /// The client is archived.
    ClientArchived,
    /// The access is disabled.
    AccessDisabled,
    /// The access is revoked.
    AccessRevoked,
    /// The effective expiry has passed.
    Expired,
    /// The client spent its ceiling across all accesses.
    ClientQuotaExhausted,
    /// The access spent its own ceiling.
    AccessQuotaExhausted,
}

/// Whether an access is served, and why not when it is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Servable {
    /// Served.
    Yes,
    /// Not served, for this reason.
    No(Reason),
}

impl Servable {
    /// Whether the access is served.
    pub fn is_yes(&self) -> bool {
        matches!(self, Self::Yes)
    }

    /// The reason, when the access is not served.
    pub fn reason(&self) -> Option<Reason> {
        match self {
            Self::Yes => None,
            Self::No(reason) => Some(*reason),
        }
    }
}

/// The earlier of the two expiries. An absent one does not take part.
pub fn effective_expiry(client: &Client, access: &AccessCommon) -> Option<OffsetDateTime> {
    match (client.expires_at(), access.expires_at()) {
        (Some(from_client), Some(from_access)) => Some(from_client.min(from_access)),
        (Some(only), None) | (None, Some(only)) => Some(only),
        (None, None) => None,
    }
}

/// Both ceilings, unchanged. They are not merged: they count different sums.
pub fn effective_quota(client: &Client, access: &AccessCommon) -> QuotaLimits {
    QuotaLimits {
        client: client.quota_bytes(),
        access: access.quota_bytes(),
    }
}

/// Whether the access is served at this moment, given what it has spent.
///
/// Reasons are checked in a fixed order, so an access failing several at once
/// always reports the same one: client state, access state, expiry, then the
/// client ceiling before the access ceiling.
pub fn is_servable(
    client: &Client,
    access: &AccessCommon,
    usage: Usage,
    now: OffsetDateTime,
) -> Servable {
    match client.state() {
        ClientState::Archived => return Servable::No(Reason::ClientArchived),
        ClientState::Suspended => return Servable::No(Reason::ClientSuspended),
        ClientState::Active => {}
    }

    match access.state() {
        AccessState::Revoked => return Servable::No(Reason::AccessRevoked),
        AccessState::Disabled => return Servable::No(Reason::AccessDisabled),
        AccessState::Active => {}
    }

    if let Some(expiry) = effective_expiry(client, access)
        && now >= expiry
    {
        return Servable::No(Reason::Expired);
    }

    let quota = effective_quota(client, access);
    if let Some(limit) = quota.client
        && usage.client_bytes >= limit
    {
        return Servable::No(Reason::ClientQuotaExhausted);
    }
    if let Some(limit) = quota.access
        && usage.access_bytes >= limit
    {
        return Servable::No(Reason::AccessQuotaExhausted);
    }

    Servable::Yes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::parse_rfc3339;
    use crate::{Label, StealthMethod};
    use uuid::Uuid;

    fn at(text: &str) -> OffsetDateTime {
        parse_rfc3339(text).unwrap()
    }

    fn client() -> Client {
        Client::new(
            Label::try_from("alice").unwrap(),
            OffsetDateTime::UNIX_EPOCH,
        )
    }

    fn access() -> AccessCommon {
        AccessCommon::new(Uuid::now_v7(), Uuid::now_v7(), OffsetDateTime::UNIX_EPOCH)
    }

    #[test]
    fn expiry_absent_on_both_sides() {
        assert_eq!(effective_expiry(&client(), &access()), None);
    }

    #[test]
    fn expiry_from_one_side_only() {
        let when = at("2026-12-31T23:59:59Z");
        assert_eq!(
            effective_expiry(&client().with_expiry(when), &access()),
            Some(when)
        );
        assert_eq!(
            effective_expiry(&client(), &access().with_expiry(when)),
            Some(when)
        );
    }

    #[test]
    fn the_earlier_expiry_wins() {
        let early = at("2026-06-30T23:59:59Z");
        let late = at("2026-12-31T23:59:59Z");
        assert_eq!(
            effective_expiry(&client().with_expiry(late), &access().with_expiry(early)),
            Some(early)
        );
        assert_eq!(
            effective_expiry(&client().with_expiry(early), &access().with_expiry(late)),
            Some(early)
        );
    }

    #[test]
    fn equal_expiries_collapse_to_the_same_value() {
        let when = at("2026-12-31T23:59:59Z");
        assert_eq!(
            effective_expiry(&client().with_expiry(when), &access().with_expiry(when)),
            Some(when)
        );
    }

    #[test]
    fn both_ceilings_are_reported_separately() {
        assert_eq!(
            effective_quota(&client(), &access()),
            QuotaLimits {
                client: None,
                access: None
            }
        );
        assert_eq!(
            effective_quota(&client().with_quota(10).unwrap(), &access()),
            QuotaLimits {
                client: Some(10),
                access: None
            }
        );
        assert_eq!(
            effective_quota(&client(), &access().with_quota(20).unwrap()),
            QuotaLimits {
                client: None,
                access: Some(20)
            }
        );
        assert_eq!(
            effective_quota(
                &client().with_quota(10).unwrap(),
                &access().with_quota(20).unwrap()
            ),
            QuotaLimits {
                client: Some(10),
                access: Some(20)
            }
        );
    }

    #[test]
    fn an_unlimited_access_is_served() {
        assert_eq!(
            is_servable(
                &client(),
                &access(),
                Usage::default(),
                at("2026-08-26T00:00:00Z")
            ),
            Servable::Yes
        );
    }

    #[test]
    fn every_reason_is_reachable() {
        let now = at("2026-08-26T00:00:00Z");
        let past = at("2026-01-01T00:00:00Z");

        let mut archived = client();
        archived.set_state(ClientState::Archived);
        assert_eq!(
            is_servable(&archived, &access(), Usage::default(), now).reason(),
            Some(Reason::ClientArchived)
        );

        let mut suspended = client();
        suspended.set_state(ClientState::Suspended);
        assert_eq!(
            is_servable(&suspended, &access(), Usage::default(), now).reason(),
            Some(Reason::ClientSuspended)
        );

        let mut revoked = access();
        revoked.revoke();
        assert_eq!(
            is_servable(&client(), &revoked, Usage::default(), now).reason(),
            Some(Reason::AccessRevoked)
        );

        let mut disabled = access();
        disabled.disable();
        assert_eq!(
            is_servable(&client(), &disabled, Usage::default(), now).reason(),
            Some(Reason::AccessDisabled)
        );

        assert_eq!(
            is_servable(
                &client(),
                &access().with_expiry(past),
                Usage::default(),
                now
            )
            .reason(),
            Some(Reason::Expired)
        );

        let spent = Usage {
            client_bytes: 10,
            access_bytes: 0,
        };
        assert_eq!(
            is_servable(&client().with_quota(10).unwrap(), &access(), spent, now).reason(),
            Some(Reason::ClientQuotaExhausted)
        );

        let spent = Usage {
            client_bytes: 0,
            access_bytes: 20,
        };
        assert_eq!(
            is_servable(&client(), &access().with_quota(20).unwrap(), spent, now).reason(),
            Some(Reason::AccessQuotaExhausted)
        );
    }

    #[test]
    fn the_moment_of_expiry_is_already_past() {
        let when = at("2026-12-31T23:59:59Z");
        let access = access().with_expiry(when);
        assert_eq!(
            is_servable(&client(), &access, Usage::default(), when).reason(),
            Some(Reason::Expired)
        );
        assert_eq!(
            is_servable(
                &client(),
                &access,
                Usage::default(),
                at("2026-12-31T23:59:58Z")
            ),
            Servable::Yes
        );
    }

    #[test]
    fn a_ceiling_bites_on_the_byte_that_reaches_it() {
        let now = at("2026-08-26T00:00:00Z");
        let access = access().with_quota(20).unwrap();
        let below = Usage {
            client_bytes: 0,
            access_bytes: 19,
        };
        let reached = Usage {
            client_bytes: 0,
            access_bytes: 20,
        };
        assert_eq!(is_servable(&client(), &access, below, now), Servable::Yes);
        assert_eq!(
            is_servable(&client(), &access, reached, now).reason(),
            Some(Reason::AccessQuotaExhausted)
        );
    }

    #[test]
    fn the_reported_reason_is_stable_when_several_apply() {
        let now = at("2026-08-26T00:00:00Z");
        let past = at("2026-01-01T00:00:00Z");
        let mut suspended = client().with_quota(1).unwrap();
        suspended.set_state(ClientState::Suspended);
        let mut access = access().with_expiry(past).with_quota(1).unwrap();
        access.revoke();
        let spent = Usage {
            client_bytes: 99,
            access_bytes: 99,
        };
        assert_eq!(
            is_servable(&suspended, &access, spent, now).reason(),
            Some(Reason::ClientSuspended)
        );
    }

    #[test]
    fn the_surface_of_an_access_does_not_change_the_answer() {
        let now = at("2026-08-26T00:00:00Z");
        let common = access();
        let stealth = crate::Access::<crate::Stealth>::new(common.clone(), StealthMethod::Web);
        assert_eq!(
            is_servable(&client(), stealth.common(), Usage::default(), now),
            is_servable(&client(), &common, Usage::default(), now)
        );
    }
}
