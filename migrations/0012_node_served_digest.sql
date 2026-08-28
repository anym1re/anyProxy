-- What the node was last told to serve, as a fingerprint.
--
-- The panel sent a configuration in answer to a greeting and at no other time,
-- so a change reached a node only when its agent next opened a session. An
-- agent holding a live channel went on serving what it had: a withdrawn access
-- kept working, and burning a node revoked its accesses in the database while
-- the node carried on serving them. The one thing this system must be able to
-- do quickly is stop serving something.
--
-- The fingerprint is compared on every heartbeat against what the node should
-- be serving now. They differ, the node is sent a fresh configuration; they
-- agree, it is left alone.
--
-- Taken this way rather than by marking a node changed at each place that
-- changes one: a mark has to be set at every such place, and the one that is
-- forgotten is a silent hole of exactly the kind this closes.

alter table node add column if not exists served_digest bytea;
