-- The tag Telegram issues to a proxy that carries a sponsored channel.
--
-- Thirty-two hex characters from @MTProxybot, kept per node because that is
-- what the bot issues one for: a proxy is registered by the address, port and
-- secret it answers on, and the tag it gets back stands for that proxy.
--
-- Not a secret. It says which proxy the traffic arrived through, so a
-- sponsored channel is credited to the right one, and it goes out with every
-- connection.
--
-- Nullable, and null is the ordinary case. Carrying a tag means routing
-- through Telegram's middle proxies, which is an extra hop; a node with no tag
-- reaches the data centres directly and pays nothing for a sponsorship it does
-- not have. Until now every node was configured with a tag of thirty-two
-- zeros and the middle proxies switched on, which paid that cost for nothing.

alter table node add column if not exists ad_tag text;

alter table node add constraint node_ad_tag_form
    check (ad_tag is null or ad_tag ~ '^[0-9a-f]{32}$');
