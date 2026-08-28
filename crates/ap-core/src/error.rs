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

    /// A secret that is not sixteen bytes of hexadecimal.
    #[error("a secret is exactly 32 hexadecimal characters")]
    SecretForm,

    /// A credential whose account name is empty or too long.
    #[error("an account name is 1 to 64 characters")]
    CredentialForm,

    /// A sealed value that would not open, or would not parse once open.
    #[error("the sealed value could not be opened")]
    SealedValue,

    /// A key file that cannot be read.
    #[error("the key file cannot be read")]
    KeyFileUnreadable,

    /// A key file readable by anyone but its owner.
    #[error("the key file must not be readable by group or others")]
    KeyFilePermissions,

    /// A key file that does not hold exactly the key.
    #[error("the key file must hold exactly 32 bytes")]
    KeyFileLength,

    /// A catalogue that will not parse.
    #[error("the message catalogue could not be parsed")]
    Catalogue,

    /// A message key the catalogue does not define.
    #[error("the message catalogue has no such key")]
    MessageMissing,

    /// An administrator without a password verifier.
    #[error("an administrator needs a password")]
    PasswordHash,

    /// A stored value that no variant is spelled by.
    #[error("the stored value is not a known variant")]
    StoredValue,

    /// A link asked for without a host to point at.
    #[error("a connection link needs a host")]
    LinkHost,

    /// A timestamp that is not valid RFC 3339.
    #[error("timestamp must be RFC 3339, for example 2026-12-31T23:59:59Z")]
    Timestamp,

    /// A masked node without the domain it answers to.
    #[error("a masked node requires a domain")]
    StealthWithoutDomain,

    /// A node serving in the open carrying a domain, which it never serves.
    #[error("a node serving in the open cannot carry a domain")]
    OpenWithDomain,

    /// Masking asked for on a transport that is not offered with it.
    ///
    /// An operator picks among four transports, and only MTProto is offered
    /// both ways. WEB is carried inside a real site and hides by construction;
    /// SOCKS5 and HTTP do not hide at all.
    #[error("only mtproto is offered with and without masking")]
    MaskingNotOffered,

    /// A device limit outside the range an access accepts.
    #[error("device limit must be between 1 and 1000")]
    MaxDevices,

    /// An attempt to resume an access that was withdrawn for good.
    #[error("a revoked access is never resumed")]
    AccessRevoked,

    /// An access read back as the wrong surface.
    #[error("expected a {expected} access, found {actual}")]
    SurfaceMismatch {
        /// Surface the caller asked for.
        expected: &'static str,
        /// Surface the value actually carries.
        actual: &'static str,
    },
}
