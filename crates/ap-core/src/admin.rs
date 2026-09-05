use ::time::OffsetDateTime;
use uuid::Uuid;

use crate::{AdminLogin, Encrypted, Error};

/// What an administrator is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Everything, including nodes, the audit log and other administrators.
    Superadmin,
    /// Clients and accesses on every node; may read nodes.
    Operator,
    /// Clients and accesses of their own only; never sees nodes.
    Reseller,
}

impl Role {
    /// Whether this role may read the audit log.
    pub fn reads_audit(self) -> bool {
        matches!(self, Self::Superadmin)
    }

    /// Whether this role may see that a node exists.
    pub fn sees_nodes(self) -> bool {
        matches!(self, Self::Superadmin | Self::Operator)
    }

    /// Whether this role may register or destroy a node.
    pub fn manages_nodes(self) -> bool {
        matches!(self, Self::Superadmin)
    }

    /// Whether this role reaches every client, or only the ones it owns.
    pub fn reaches_every_client(self) -> bool {
        matches!(self, Self::Superadmin | Self::Operator)
    }
}

/// Lifecycle of an administrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdminState {
    /// May sign in.
    Active,
    /// Kept, cannot sign in.
    Disabled,
}

/// Someone who operates the panel.
///
/// The second factor is optional (0060). An account that has one cannot be
/// entered without it; an account that has none is entered with a password
/// alone, and whoever creates it says so at that moment.
#[derive(Debug, Clone, PartialEq)]
pub struct AdminUser {
    id: Uuid,
    login: AdminLogin,
    password_hash: String,
    totp_secret: Option<Encrypted<String>>,
    role: Role,
    state: AdminState,
    created_at: OffsetDateTime,
}

impl AdminUser {
    /// Registers an active administrator.
    pub fn new(
        login: AdminLogin,
        password_hash: String,
        totp_secret: Option<Encrypted<String>>,
        role: Role,
        created_at: OffsetDateTime,
    ) -> Result<Self, Error> {
        if password_hash.is_empty() {
            return Err(Error::PasswordHash);
        }
        Ok(Self {
            id: Uuid::now_v7(),
            login,
            password_hash,
            totp_secret,
            role,
            state: AdminState::Active,
            created_at,
        })
    }

    /// Rebuilds an administrator from a stored row.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: Uuid,
        login: AdminLogin,
        password_hash: String,
        totp_secret: Option<Encrypted<String>>,
        role: Role,
        state: AdminState,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            login,
            password_hash,
            totp_secret,
            role,
            state,
            created_at,
        }
    }

    /// Identifier assigned at registration.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Name this administrator signs in with.
    pub fn login(&self) -> &AdminLogin {
        &self.login
    }

    /// Stored password verifier.
    pub fn password_hash(&self) -> &str {
        &self.password_hash
    }

    /// The sealed second-factor secret, if this account has one.
    pub fn totp_secret(&self) -> Option<&Encrypted<String>> {
        self.totp_secret.as_ref()
    }

    /// What this administrator may do.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Whether this administrator may sign in.
    pub fn state(&self) -> AdminState {
        self.state
    }

    /// When the account was registered.
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyStore;

    fn secret() -> Encrypted<String> {
        Encrypted::seal(
            &"JBSWY3DPEHPK3PXP".to_owned(),
            &KeyStore::from_bytes([1u8; 32]),
        )
        .unwrap()
    }

    #[test]
    fn a_new_administrator_is_active() {
        let admin = AdminUser::new(
            AdminLogin::try_from("root").unwrap(),
            "$argon2id$v=19$…".to_owned(),
            Some(secret()),
            Role::Superadmin,
            OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();
        assert_eq!(admin.state(), AdminState::Active);
        assert_eq!(admin.role(), Role::Superadmin);
        assert!(admin.totp_secret().is_some());
    }

    #[test]
    fn an_administrator_may_be_registered_without_a_second_factor() {
        let admin = AdminUser::new(
            AdminLogin::try_from("root").unwrap(),
            "$argon2id$v=19$…".to_owned(),
            None,
            Role::Superadmin,
            OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap();
        assert_eq!(admin.state(), AdminState::Active);
        assert!(admin.totp_secret().is_none());
    }

    #[test]
    fn an_empty_password_hash_is_refused() {
        assert_eq!(
            AdminUser::new(
                AdminLogin::try_from("root").unwrap(),
                String::new(),
                Some(secret()),
                Role::Superadmin,
                OffsetDateTime::UNIX_EPOCH,
            ),
            Err(Error::PasswordHash)
        );
    }

    #[test]
    fn a_reseller_never_sees_nodes() {
        assert!(!Role::Reseller.sees_nodes());
        assert!(!Role::Reseller.manages_nodes());
        assert!(!Role::Reseller.reads_audit());
        assert!(!Role::Reseller.reaches_every_client());
    }

    #[test]
    fn an_operator_reads_nodes_but_does_not_manage_them() {
        assert!(Role::Operator.sees_nodes());
        assert!(!Role::Operator.manages_nodes());
        assert!(!Role::Operator.reads_audit());
        assert!(Role::Operator.reaches_every_client());
    }

    #[test]
    fn only_a_superadmin_reads_the_audit_log() {
        assert!(Role::Superadmin.reads_audit());
        assert!(Role::Superadmin.manages_nodes());
    }
}
