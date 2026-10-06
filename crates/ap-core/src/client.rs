use ::time::OffsetDateTime;
use uuid::Uuid;

use crate::{Encrypted, Error, Label, TelegramAccount};

/// Lifecycle of a client as the panel sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientState {
    /// Served, subject to quota and expiry.
    Active,
    /// Kept, not served. Reversible.
    Suspended,
    /// Kept for the record only.
    Archived,
}

/// A person the panel accounts for. Holds no secret and no client address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    id: Uuid,
    label: Label,
    state: ClientState,
    note: Option<Encrypted<String>>,
    quota_bytes: Option<i64>,
    expires_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    telegram_linked_at: Option<OffsetDateTime>,
    telegram_account: Option<Encrypted<TelegramAccount>>,
    /// Whether the bot made this client for an account that wrote to it,
    /// rather than an operator in the panel (0105).
    via_bot: bool,
}

impl Client {
    /// Registers an active client with no limits of its own.
    pub fn new(label: Label, created_at: OffsetDateTime) -> Self {
        Self {
            id: Uuid::now_v7(),
            label,
            state: ClientState::Active,
            note: None,
            quota_bytes: None,
            expires_at: None,
            created_at,
            telegram_linked_at: None,
            telegram_account: None,
            via_bot: false,
        }
    }

    /// Rebuilds a client from a stored row. Values are taken as given: they
    /// were validated when the row was written.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        id: Uuid,
        label: Label,
        state: ClientState,
        note: Option<Encrypted<String>>,
        quota_bytes: Option<i64>,
        expires_at: Option<OffsetDateTime>,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            label,
            state,
            note,
            quota_bytes,
            expires_at,
            created_at,
            telegram_linked_at: None,
            telegram_account: None,
            via_bot: false,
        }
    }

    /// Attaches an operator note. It is sealed because it may name a person.
    pub fn with_note(mut self, note: Encrypted<String>) -> Self {
        self.note = Some(note);
        self
    }

    /// Records when a Telegram account was tied to this client (0082).
    ///
    /// Only the moment: the account itself is known to the panel as a keyed
    /// digest, and that digest is not a property of the client in memory.
    pub fn with_telegram_linked(mut self, at: Option<OffsetDateTime>) -> Self {
        self.telegram_linked_at = at;
        self
    }

    /// When a Telegram account was tied to this client, if one is.
    pub fn telegram_linked_at(&self) -> Option<OffsetDateTime> {
        self.telegram_linked_at
    }

    /// Records who is behind the tied account, sealed (0103).
    pub fn with_telegram_account(mut self, account: Option<Encrypted<TelegramAccount>>) -> Self {
        self.telegram_account = account;
        self
    }

    /// Who is behind the tied account, sealed, when the bot has heard from
    /// them since the account was tied. Its presence is also what lets the
    /// bot write to them first (0102).
    pub fn telegram_account(&self) -> Option<&Encrypted<TelegramAccount>> {
        self.telegram_account.as_ref()
    }

    /// Marks the client as made by the bot (0105).
    pub fn with_bot_origin(mut self, via_bot: bool) -> Self {
        self.via_bot = via_bot;
        self
    }

    /// Whether the bot made this client. Such a client is given an access
    /// on every node that can take one; an operator's client holds what
    /// the operator gave it.
    pub fn came_through_bot(&self) -> bool {
        self.via_bot
    }

    /// The sealed operator note, if one is set.
    pub fn note(&self) -> Option<&Encrypted<String>> {
        self.note.as_ref()
    }

    /// Sets a ceiling across every access this client holds.
    pub fn with_quota(mut self, bytes: i64) -> Result<Self, Error> {
        if bytes <= 0 {
            return Err(Error::Quota);
        }
        self.quota_bytes = Some(bytes);
        Ok(self)
    }

    /// Sets the moment after which no access of this client is served.
    pub fn with_expiry(mut self, at: OffsetDateTime) -> Self {
        self.expires_at = Some(at);
        self
    }

    /// Identifier assigned at registration.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Operator-facing name.
    pub fn label(&self) -> &Label {
        &self.label
    }

    /// Current lifecycle state.
    pub fn state(&self) -> ClientState {
        self.state
    }

    /// Ceiling across every access, if one is set.
    pub fn quota_bytes(&self) -> Option<i64> {
        self.quota_bytes
    }

    /// Expiry across every access, if one is set.
    pub fn expires_at(&self) -> Option<OffsetDateTime> {
        self.expires_at
    }

    /// When the client was registered.
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Moves the client to a new state.
    pub fn set_state(&mut self, state: ClientState) {
        self.state = state;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::parse_rfc3339;

    fn label() -> Label {
        Label::try_from("alice").unwrap()
    }

    #[test]
    fn a_new_client_is_active_and_unlimited() {
        let client = Client::new(label(), OffsetDateTime::UNIX_EPOCH);
        assert_eq!(client.state(), ClientState::Active);
        assert_eq!(client.quota_bytes(), None);
        assert_eq!(client.expires_at(), None);
    }

    #[test]
    fn quota_must_be_positive() {
        let client = Client::new(label(), OffsetDateTime::UNIX_EPOCH);
        assert_eq!(client.clone().with_quota(0), Err(Error::Quota));
        assert_eq!(client.clone().with_quota(-1), Err(Error::Quota));
        assert_eq!(client.with_quota(50).unwrap().quota_bytes(), Some(50));
    }

    #[test]
    fn expiry_is_stored_as_given() {
        let at = parse_rfc3339("2026-12-31T23:59:59Z").unwrap();
        let client = Client::new(label(), OffsetDateTime::UNIX_EPOCH).with_expiry(at);
        assert_eq!(client.expires_at(), Some(at));
    }

    #[test]
    fn identifiers_are_unique() {
        let first = Client::new(label(), OffsetDateTime::UNIX_EPOCH);
        let second = Client::new(label(), OffsetDateTime::UNIX_EPOCH);
        assert_ne!(first.id(), second.id());
    }
}
