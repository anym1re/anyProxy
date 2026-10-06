-- What the bot is to write to people first, until it has (0102).
--
-- The intent, not the text: a "links" row carries nothing, and the links are
-- built when it is sent, so no access secret is ever written here. A warning
-- carries which one it is; an operator message carries its text, which is not
-- a secret. A row is deleted once sent, or once it is given up on.

create table if not exists bot_outbox (
    id          uuid primary key,
    client_id   uuid not null references client (id) on delete cascade,
    kind        text not null check (kind in ('links', 'warning', 'operator')),
    body        jsonb not null default '{}'::jsonb,
    created_at  timestamptz not null,
    attempts    integer not null default 0,
    next_try_at timestamptz not null,
    -- Bumped by each change that comes while a "links" row waits or is being
    -- sent. A row is taken off only at the revision that was sent, so a change
    -- landing mid-send is sent again with the links as they now are.
    revision    integer not null default 0
);

-- Several changes in a row come to one message saying where things ended up.
create unique index if not exists bot_outbox_one_links
    on bot_outbox (client_id) where kind = 'links';

create index if not exists bot_outbox_due on bot_outbox (next_try_at);

grant select, insert, update, delete on bot_outbox to anyproxy_app;
