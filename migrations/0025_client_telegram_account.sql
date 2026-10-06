-- Who is behind a Telegram account tied to a client, and where the bot writes
-- to them first (0102, 0103).
--
-- One sealed record: the account, its chat, the username, the name and the
-- language. Sealed under the panel's key like an access credential, so a dump
-- without the key says nothing about whose it is. It exists only while an
-- account is tied to the client, and goes when the tie does.

alter table client add column if not exists telegram_account_nonce bytea;
alter table client add column if not exists telegram_account_ciphertext bytea;

alter table client add constraint client_telegram_account_sealed
    check ((telegram_account_nonce is null) = (telegram_account_ciphertext is null));

alter table client add constraint client_telegram_account_tied
    check (telegram_account_nonce is null or telegram_digest is not null);
