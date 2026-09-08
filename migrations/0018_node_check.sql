-- An operator can ask a node to look at itself now (0070).
--
-- One column: when the asking happened. It is cleared the moment the request
-- is handed to the node, so a second press is a second check rather than a
-- queue of them.

alter table node add column if not exists check_asked_at timestamptz;
