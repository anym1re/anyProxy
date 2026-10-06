-- A client that came through the bot, and the account it came with (0105).
--
-- `origin` says who made the client: an operator in the panel, or the bot for
-- an account that wrote to it. `signup_digest` is the keyed digest of that
-- account, kept even after the account is untied, so the same account comes
-- back to the same client instead of to a fresh one with a fresh allowance.
-- Like `telegram_digest` it says nothing about the account without the key.

alter table client add column if not exists origin text not null default 'operator';

alter table client add constraint client_origin_known
    check (origin in ('operator', 'bot'));

alter table client add column if not exists signup_digest bytea;

create unique index if not exists client_signup_digest
    on client (signup_digest) where signup_digest is not null;
