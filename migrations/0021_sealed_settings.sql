-- A setting that is a secret is kept under the key, not in the open (0084).
--
-- The bot token is the first. It sits beside `setting` rather than in it:
-- a text column that sometimes holds a ciphertext is a column somebody will
-- read as text. The value is opened only by the code that needs it and
-- never leaves the panel; the settings endpoint says only that it is set.

create table if not exists sealed_setting (
    name       text primary key,
    nonce      bytea not null,
    ciphertext bytea not null,
    changed_at timestamptz not null default now(),
    changed_by uuid references admin_user (id) on delete set null,
    constraint sealed_setting_name check (name ~ '^[a-z][a-z0-9_]{1,40}$')
);

grant select, insert, update, delete on sealed_setting to anyproxy_app;
