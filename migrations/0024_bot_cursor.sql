-- How far the bot has read (0087).
--
-- One row. Telegram hands out updates from the number the caller names and
-- treats everything before it as acknowledged; a number kept in memory
-- would have every restart read the last batch again and answer it twice.

create table if not exists bot_cursor (
    lone        boolean primary key default true,
    next_update bigint not null default 0,
    moved_at    timestamptz not null default now(),
    constraint bot_cursor_single check (lone)
);

grant select, insert, update, delete on bot_cursor to anyproxy_app;
