-- One-time codes that tie a Telegram account to a client (0082).
--
-- Only the digest of the code is kept, as with enrolment codes: it cannot
-- be read back, only replaced. Claiming one is a single update carrying the
-- conditions, so two presentations of the same code cannot both succeed.

create table if not exists bot_code (
    id         uuid primary key,
    client_id  uuid not null references client (id) on delete cascade,
    code_hash  bytea not null unique,
    expires_at timestamptz not null,
    created_at timestamptz not null,
    used_at    timestamptz
);

create index if not exists bot_code_by_client on bot_code (client_id);

grant select, insert, update, delete on bot_code to anyproxy_app;
