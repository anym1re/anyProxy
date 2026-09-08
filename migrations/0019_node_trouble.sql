-- When a node's trouble started (0071).
--
-- Set the moment the health it reports stops being well, cleared the moment it
-- is well again. Null on a node that is fine.

alter table node add column if not exists trouble_since timestamptz;
