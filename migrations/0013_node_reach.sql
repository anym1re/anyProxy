-- Whether the node could still reach Telegram when it last looked.
--
-- A node that cannot is serving nobody, and until now nothing said so: the
-- engine reported itself up, the port was open, the link looked right, and
-- every client failed. It was found by hand, with a script, after the clients
-- had already failed for hours.
--
-- Kept beside the other two health words rather than folded into them,
-- because the three fail apart and the difference says where to look. A dead
-- engine is a node that lost its process; a dead site is what a probe is
-- looking for; a blocked path out is not the node's fault at all and is fixed
-- somewhere else entirely.

alter table node add column if not exists health_reach text;
