-- A node serving a recognisable method serves nothing else.
--
-- The kinds were two: stealth, which hides behind a cover site, and open,
-- which served MTProto, SOCKS5 and HTTP in any combination. That combination
-- is what decision 0004 forbids for the masked case and, on the same
-- reasoning, forbids here: an address answering as a proxy on any port is
-- flagged as a proxy on all of them, and separating them by port does not
-- break the link. The masked methods still share a node, because from outside
-- there is nothing to see.
--
-- An open node becomes the kind of the method its accesses use. Where its
-- accesses used more than one, the oldest decides and the rest are withdrawn:
-- they name a method the node no longer serves, and a link that cannot be
-- served is worse than one that was taken away.

alter table node drop constraint if exists node_kind_known;
alter table node drop constraint if exists node_domain_matches_kind;
alter table node drop constraint if exists node_alibi_needs_a_domain;

update node set kind = coalesce(
    (select a.method from access a
     where a.node_id = node.id and a.state = 'active'
     order by a.created_at, a.id limit 1),
    'socks5')
where kind = 'open';

update access set state = 'revoked'
where state <> 'revoked'
  and node_id in (select id from node where kind <> 'stealth')
  and method <> (select kind from node where node.id = access.node_id);

alter table node add constraint node_domain_matches_kind
    check ((kind = 'stealth') = (domain is not null));
alter table node add constraint node_alibi_needs_a_domain
    check (alibi is null or domain is not null);
alter table node add constraint node_kind_known
    check (kind in ('stealth', 'mtproto', 'socks5', 'http'));
