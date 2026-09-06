-- What the panel is set to, instead of what it was compiled with (0069).
--
-- One row per setting. The value is text whatever the setting is: the panel
-- knows how to read each of its own, and a column per type would be a table
-- that changes shape every time a setting is added.

create table if not exists setting (
    name       text primary key,
    value      text not null,
    changed_at timestamptz not null default now(),
    changed_by uuid references admin_user (id) on delete set null,
    constraint setting_name check (name ~ '^[a-z][a-z0-9_]{1,40}$')
);

grant select, insert, update, delete on setting to anyproxy_app;
