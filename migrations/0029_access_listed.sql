-- Whether a public link is shown on the landing page (0108).
--
-- A public link that is not listed still works and is still handed out by the
-- operator; it is only left off the page anyone can read. Every link made
-- before this was shown, so that is what a row without a word says. The
-- column means nothing on a client's own access, which no page ever shows.

alter table access add column if not exists listed boolean not null default true;
