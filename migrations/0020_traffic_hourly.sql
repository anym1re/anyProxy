-- Traffic by the hour, for the day view of the traffic card (0072).
--
-- The hour is the one the panel took the delivery in, not one the node
-- counted: the node counts by day, and changing that would mean changing the
-- key that keeps a delivery from being counted twice.
--
-- Three days are kept. This answers one range on one screen; the daily table
-- stays the record.

create table if not exists traffic_hourly (
    access_id uuid not null references access (id) on delete cascade,
    at_hour   timestamptz not null,
    bytes_in  bigint not null default 0,
    bytes_out bigint not null default 0,
    primary key (access_id, at_hour),
    constraint traffic_hourly_not_negative check (bytes_in >= 0 and bytes_out >= 0)
);

create index if not exists traffic_hourly_recent on traffic_hourly (at_hour);

grant select, insert, update, delete on traffic_hourly to anyproxy_app;
