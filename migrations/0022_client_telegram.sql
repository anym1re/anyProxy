-- A client may be reached through the bot, and the panel knows them by a
-- keyed digest of their Telegram account, never by the account itself (0082).
--
-- The digest is an HMAC under the encryption key: a dump without the key
-- says nothing about whose account it is, and with the key it can confirm
-- a guess but not enumerate. One account answers to one client, so the
-- digest is unique where it is set.

alter table client add column if not exists telegram_digest bytea;
alter table client add column if not exists telegram_linked_at timestamptz;

alter table client add constraint client_telegram_paired
    check ((telegram_digest is null) = (telegram_linked_at is null));

create unique index if not exists client_telegram_unique
    on client (telegram_digest) where telegram_digest is not null;
