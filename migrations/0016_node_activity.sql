-- What the node is doing, beside what it is short of.
--
-- The figures of 0056 said how close the machine was to its limits. These
-- say what it is busy with: processors, connections, the wire, and how long
-- it has been up (0064).

alter table node add column if not exists machine_cpu_percent real;
alter table node add column if not exists machine_uptime_seconds bigint;
alter table node add column if not exists machine_connections bigint;
alter table node add column if not exists machine_rx_bps bigint;
alter table node add column if not exists machine_tx_bps bigint;

-- One row per process the agent knows by name. Rewritten whole on every
-- report: the screen shows what is running now, and a process that stopped
-- being reported has stopped running.
create table if not exists node_process (
    node_id     uuid not null references node (id) on delete cascade,
    name        text not null,
    cpu_percent real,
    memory_mb   bigint not null,
    restarts    integer not null,
    primary key (node_id, name),
    constraint node_process_name check (name ~ '^[a-z0-9_-]{1,32}$')
);
