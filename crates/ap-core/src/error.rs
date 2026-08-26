/// Rejections raised while constructing domain types.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A label or tag name outside the allowed alphabet or length.
    #[error("name must be 1 to {max} characters of a-z, 0-9, '_' or '-'")]
    Name {
        /// Longest accepted name for the field that rejected the value.
        max: usize,
    },

    /// A domain that is not a lowercase hostname with at least two labels.
    #[error("domain must be a lowercase hostname such as example.com")]
    Domain,

    /// A color outside the lowercase hex triplet form.
    #[error("color must be a lowercase hex triplet such as #1a2b3c")]
    Color,

    /// Free text longer than the field allows.
    #[error("text must be at most {max} characters")]
    TextTooLong {
        /// Longest accepted text for the field that rejected the value.
        max: usize,
    },

    /// A quota of zero or less, which would deny service outright.
    #[error("quota must be greater than zero")]
    Quota,

    /// A timestamp that is not valid RFC 3339.
    #[error("timestamp must be RFC 3339, for example 2026-12-31T23:59:59Z")]
    Timestamp,

    /// A stealth node without the domain its cover site needs.
    #[error("a stealth node requires a domain")]
    StealthWithoutDomain,

    /// An open node carrying a domain, which it never serves.
    #[error("an open node cannot carry a domain")]
    OpenWithDomain,
}
