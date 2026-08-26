use std::fmt;

use ::time::OffsetDateTime;
use uuid::Uuid;

use crate::Error;

/// Methods a stealth node serves, all behind one port and one domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StealthMethod {
    /// MTProto wearing a forged TLS handshake.
    FakeTls,
    /// MTProto carried by genuine HTTPS to the cover site.
    Web,
}

/// Methods an open node serves, each on its own port and without cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenMethod {
    /// MTProto with no masking.
    Mtproto,
    /// SOCKS5.
    Socks5,
    /// HTTP CONNECT.
    Http,
}

/// What a node exposes, carried as a type parameter so an access cannot hold
/// a method its node does not serve.
pub trait Surface {
    /// The methods this surface serves.
    type Method: fmt::Debug + Clone + Copy + PartialEq + Eq;

    /// Stored form of the surface.
    const TAG: &'static str;
}

/// Marker for a node that hides behind a cover site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Stealth;

impl Surface for Stealth {
    type Method = StealthMethod;
    const TAG: &'static str = "stealth";
}

/// Marker for a node that serves unmasked methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Open;

impl Surface for Open {
    type Method = OpenMethod;
    const TAG: &'static str = "open";
}

/// Lifecycle of an access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessState {
    /// Served, subject to quota and expiry.
    Active,
    /// Not served. Reversible.
    Disabled,
    /// Withdrawn. The credential counts as compromised and is never reissued.
    Revoked,
}

/// The part of an access that does not depend on the surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessCommon {
    id: Uuid,
    client_id: Uuid,
    node_id: Uuid,
    tag_id: Option<Uuid>,
    quota_bytes: Option<i64>,
    expires_at: Option<OffsetDateTime>,
    max_devices: Option<i32>,
    state: AccessState,
    created_at: OffsetDateTime,
}

impl AccessCommon {
    /// Creates an active access with no limits of its own.
    pub fn new(client_id: Uuid, node_id: Uuid, created_at: OffsetDateTime) -> Self {
        Self {
            id: Uuid::now_v7(),
            client_id,
            node_id,
            tag_id: None,
            quota_bytes: None,
            expires_at: None,
            max_devices: None,
            state: AccessState::Active,
            created_at,
        }
    }

    /// Puts the access in a tag, for selection and bulk withdrawal.
    pub fn with_tag(mut self, tag_id: Uuid) -> Self {
        self.tag_id = Some(tag_id);
        self
    }

    /// Sets a ceiling for this access alone.
    pub fn with_quota(mut self, bytes: i64) -> Result<Self, Error> {
        if bytes <= 0 {
            return Err(Error::Quota);
        }
        self.quota_bytes = Some(bytes);
        Ok(self)
    }

    /// Sets the moment after which this access is no longer served.
    pub fn with_expiry(mut self, at: OffsetDateTime) -> Self {
        self.expires_at = Some(at);
        self
    }

    /// Limits how many distinct devices may use this access.
    pub fn with_max_devices(mut self, devices: i32) -> Result<Self, Error> {
        if !(1..=1000).contains(&devices) {
            return Err(Error::MaxDevices);
        }
        self.max_devices = Some(devices);
        Ok(self)
    }

    /// Identifier assigned at creation.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Client this access belongs to.
    pub fn client_id(&self) -> Uuid {
        self.client_id
    }

    /// Node this access lives on.
    pub fn node_id(&self) -> Uuid {
        self.node_id
    }

    /// Tag this access is in, if any.
    pub fn tag_id(&self) -> Option<Uuid> {
        self.tag_id
    }

    /// Ceiling for this access alone, if one is set.
    pub fn quota_bytes(&self) -> Option<i64> {
        self.quota_bytes
    }

    /// Expiry for this access alone, if one is set.
    pub fn expires_at(&self) -> Option<OffsetDateTime> {
        self.expires_at
    }

    /// Device limit, if one is set.
    pub fn max_devices(&self) -> Option<i32> {
        self.max_devices
    }

    /// Current lifecycle state.
    pub fn state(&self) -> AccessState {
        self.state
    }

    /// When the access was created.
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Stops serving the access. A revoked access stays revoked.
    pub fn disable(&mut self) {
        if self.state == AccessState::Active {
            self.state = AccessState::Disabled;
        }
    }

    /// Resumes serving a disabled access. A revoked one is never resumed.
    pub fn enable(&mut self) -> Result<(), Error> {
        match self.state {
            AccessState::Revoked => Err(Error::AccessRevoked),
            _ => {
                self.state = AccessState::Active;
                Ok(())
            }
        }
    }

    /// Withdraws the access for good.
    pub fn revoke(&mut self) {
        self.state = AccessState::Revoked;
    }
}

/// A connection issued to a client, bound to one node and one method.
///
/// The method is tied to the surface, so a method the node does not serve is
/// a compile error rather than a check that can be forgotten:
///
/// ```
/// use ap_core::{Access, Stealth, StealthMethod};
///
/// fn method_of(access: &Access<Stealth>) -> StealthMethod {
///     *access.method()
/// }
/// ```
///
/// ```compile_fail
/// use ap_core::{Access, OpenMethod, Stealth};
///
/// // Socks5 belongs to an open node and has no place on a stealth one.
/// fn method_of(access: &Access<Stealth>) -> OpenMethod {
///     *access.method()
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access<S: Surface> {
    common: AccessCommon,
    method: S::Method,
}

impl<S: Surface> Access<S> {
    /// Issues an access carrying a method of this surface.
    pub fn new(common: AccessCommon, method: S::Method) -> Self {
        Self { common, method }
    }

    /// The method this access is reached by.
    pub fn method(&self) -> &S::Method {
        &self.method
    }

    /// The part that does not depend on the surface.
    pub fn common(&self) -> &AccessCommon {
        &self.common
    }

    /// The part that does not depend on the surface, for modification.
    pub fn common_mut(&mut self) -> &mut AccessCommon {
        &mut self.common
    }

    /// Stored form of the surface.
    pub fn surface_tag(&self) -> &'static str {
        S::TAG
    }
}

/// An access whose surface is known at run time, for storage and transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyAccess {
    /// An access on a stealth node.
    Stealth(Access<Stealth>),
    /// An access on an open node.
    Open(Access<Open>),
}

impl AnyAccess {
    /// The part that does not depend on the surface.
    pub fn common(&self) -> &AccessCommon {
        match self {
            Self::Stealth(access) => access.common(),
            Self::Open(access) => access.common(),
        }
    }

    /// Stored form of the surface.
    pub fn surface_tag(&self) -> &'static str {
        match self {
            Self::Stealth(_) => Stealth::TAG,
            Self::Open(_) => Open::TAG,
        }
    }
}

impl From<Access<Stealth>> for AnyAccess {
    fn from(access: Access<Stealth>) -> Self {
        Self::Stealth(access)
    }
}

impl From<Access<Open>> for AnyAccess {
    fn from(access: Access<Open>) -> Self {
        Self::Open(access)
    }
}

impl TryFrom<AnyAccess> for Access<Stealth> {
    type Error = Error;

    fn try_from(value: AnyAccess) -> Result<Self, Error> {
        match value {
            AnyAccess::Stealth(access) => Ok(access),
            AnyAccess::Open(_) => Err(Error::SurfaceMismatch {
                expected: Stealth::TAG,
                actual: Open::TAG,
            }),
        }
    }
}

impl TryFrom<AnyAccess> for Access<Open> {
    type Error = Error;

    fn try_from(value: AnyAccess) -> Result<Self, Error> {
        match value {
            AnyAccess::Open(access) => Ok(access),
            AnyAccess::Stealth(_) => Err(Error::SurfaceMismatch {
                expected: Open::TAG,
                actual: Stealth::TAG,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn common() -> AccessCommon {
        AccessCommon::new(Uuid::now_v7(), Uuid::now_v7(), OffsetDateTime::UNIX_EPOCH)
    }

    #[test]
    fn a_new_access_is_active_and_unlimited() {
        let access = Access::<Stealth>::new(common(), StealthMethod::FakeTls);
        assert_eq!(access.common().state(), AccessState::Active);
        assert_eq!(access.common().quota_bytes(), None);
        assert_eq!(access.common().max_devices(), None);
        assert_eq!(access.surface_tag(), "stealth");
    }

    #[test]
    fn limits_are_validated() {
        assert_eq!(common().with_quota(0), Err(Error::Quota));
        assert_eq!(common().with_max_devices(0), Err(Error::MaxDevices));
        assert_eq!(common().with_max_devices(1001), Err(Error::MaxDevices));
        assert_eq!(common().with_max_devices(1).unwrap().max_devices(), Some(1));
        assert_eq!(
            common().with_max_devices(1000).unwrap().max_devices(),
            Some(1000)
        );
    }

    #[test]
    fn a_disabled_access_comes_back() {
        let mut c = common();
        c.disable();
        assert_eq!(c.state(), AccessState::Disabled);
        assert_eq!(c.enable(), Ok(()));
        assert_eq!(c.state(), AccessState::Active);
    }

    #[test]
    fn a_revoked_access_never_comes_back() {
        let mut c = common();
        c.revoke();
        assert_eq!(c.enable(), Err(Error::AccessRevoked));
        c.disable();
        assert_eq!(c.state(), AccessState::Revoked);
    }

    #[test]
    fn erasing_and_restoring_the_surface_round_trips() {
        let stealth = Access::<Stealth>::new(common(), StealthMethod::Web);
        let any = AnyAccess::from(stealth.clone());
        assert_eq!(any.surface_tag(), "stealth");
        assert_eq!(Access::<Stealth>::try_from(any), Ok(stealth));

        let open = Access::<Open>::new(common(), OpenMethod::Socks5);
        let any = AnyAccess::from(open.clone());
        assert_eq!(any.surface_tag(), "open");
        assert_eq!(Access::<Open>::try_from(any), Ok(open));
    }

    #[test]
    fn restoring_the_wrong_surface_is_refused() {
        let any = AnyAccess::from(Access::<Open>::new(common(), OpenMethod::Http));
        assert_eq!(
            Access::<Stealth>::try_from(any),
            Err(Error::SurfaceMismatch {
                expected: "stealth",
                actual: "open",
            })
        );
    }
}
