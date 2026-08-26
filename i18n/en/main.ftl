# Rejections raised while constructing domain types.
error-name = name must be 1 to { $max } characters of a-z, 0-9, underscore or hyphen
error-domain = domain must be a lowercase hostname such as example.com
error-color = color must be a lowercase hex triplet such as #1a2b3c
error-text-too-long = text must be at most { $max } characters
error-quota = quota must be greater than zero
error-timestamp = timestamp must be RFC 3339, for example 2026-12-31T23:59:59Z
error-stealth-without-domain = a stealth node requires a domain
error-open-with-domain = an open node cannot carry a domain
error-max-devices = device limit must be between 1 and 1000
error-access-revoked = a revoked access is never resumed
error-surface-mismatch = expected a { $expected } access, found { $actual }
error-secret-form = a secret is exactly 32 hexadecimal characters
error-credential-form = an account name is 1 to 64 characters
error-sealed-value = the sealed value could not be opened
error-key-file-unreadable = the key file cannot be read
error-key-file-permissions = the key file must not be readable by group or others
error-key-file-length = the key file must hold exactly 32 bytes
error-link-host = a connection link needs a host

# Why an access is not served.
reason-client-suspended = the client is suspended
reason-client-archived = the client is archived
reason-access-disabled = the access is disabled
reason-access-revoked = the access is revoked
reason-expired = the term has ended
reason-client-quota-exhausted = the client used up its total allowance
reason-access-quota-exhausted = this connection used up its allowance

access-count =
    { $count ->
        [one] { $count } connection
       *[other] { $count } connections
    }
