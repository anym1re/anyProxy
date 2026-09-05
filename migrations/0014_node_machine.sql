-- What the node last said about the machine under it.
--
-- Health said whether the engine, the site and the path out were alive; none
-- of it said whether the machine was about to run out of memory or of file
-- descriptors, which is what actually takes a small node down under a crowd.
-- The agent now reads that from its own cgroup and reports it (0056); this is
-- where the panel keeps the last word.
--
-- Typed columns rather than a document: the pressure word is filtered and
-- sorted on, and a column cannot be handed an arbitrary shape by an agent.

alter table node add column if not exists machine_pressure text;
alter table node add column if not exists machine_cpus integer;
alter table node add column if not exists machine_memory_used_mb bigint;
alter table node add column if not exists machine_memory_limit_mb bigint;
alter table node add column if not exists machine_memory_stall real;
alter table node add column if not exists machine_cpu_stall real;
alter table node add column if not exists machine_open_files bigint;
alter table node add column if not exists machine_file_limit bigint;

alter table node drop constraint if exists node_machine_pressure_check;
alter table node add constraint node_machine_pressure_check
    check (machine_pressure is null or machine_pressure in ('calm', 'strained', 'critical'));
