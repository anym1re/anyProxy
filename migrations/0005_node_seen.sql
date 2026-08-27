-- What a node reports about itself once its agent is talking to the panel.
--
-- Without this a node that is serving clients reads as pending forever, and an
-- operator looking for a node that stopped has nothing to look at.

alter table node add column if not exists health_engine text;
alter table node add column if not exists health_site text;
alter table node add column if not exists cert_not_after timestamptz;

-- How many distinct devices used one access in one period.
--
-- The count and nothing else. The addresses it was derived from stay in the
-- engine's memory on the node and never travel; there is no column here that
-- could hold one.
create table device_count (
    access_id  uuid not null references access (id) on delete cascade,
    period     date not null,
    devices    integer not null,
    revision   uuid not null,
    updated_at timestamptz not null,
    primary key (access_id, period),
    constraint device_count_not_negative check (devices >= 0)
);

create index device_count_recent on device_count (period desc);
