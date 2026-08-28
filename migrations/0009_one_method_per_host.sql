-- One method to a host, including the two that hide.
--
-- The masked methods shared a node because from outside there was nothing to
-- see: the front door on 443 told a forged handshake from a real site by the
-- name the client asked for. That holds only while nobody compares the two.
-- A node serving both answers one name with a certificate it owns and another
-- with a handshake it forged for a site hosted elsewhere, from one address, and
-- whoever notices the second has the first to pull on. Splitting them costs a
-- host and removes the pair.
--
-- A node keeps the method its accesses use, the oldest deciding where they
-- disagree, and the rest are withdrawn: they name a method the node no longer
-- serves, and a link that cannot be served is worse than one that was taken
-- away. A node with nothing active on it keeps the forged handshake, the
-- method a borrowed name is for.
--
-- The name follows the method. A forged handshake claims a name belonging to
-- somebody else, which is `alibi` where the node had one and `domain` where it
-- did not; a site of our own answers to `domain` and nothing else. With one
-- method to a node there is one name, so `alibi` goes.

alter table node drop constraint if exists node_kind_known;
alter table node drop constraint if exists node_domain_matches_kind;
alter table node drop constraint if exists node_alibi_needs_a_domain;

update node set kind = coalesce(
    (select a.method from access a
     where a.node_id = node.id and a.state = 'active'
       and a.method in ('faketls', 'web')
     order by a.created_at, a.id limit 1),
    'faketls')
where kind = 'stealth';

update node set domain = coalesce(alibi, domain)
where kind = 'faketls';

update access set state = 'revoked'
where state <> 'revoked'
  and method <> (select kind from node where node.id = access.node_id);

alter table node drop column if exists alibi;

alter table node add constraint node_domain_matches_kind
    check ((kind in ('faketls', 'web')) = (domain is not null));
alter table node add constraint node_kind_known
    check (kind in ('faketls', 'web', 'mtproto', 'socks5', 'http'));

-- A name a node owns is unique; a name it borrows is not.
--
-- The old index made every domain unique, which was right when the column held
-- only names a node answered to as its own. A forged handshake borrows a name
-- belonging to somebody else, and two nodes may borrow the same one — imitating
-- one popular site from several addresses is ordinary, and forbidding it here
-- would be a restriction the old shape, where the borrowed name lived in its
-- own column, never imposed. Uniqueness now holds only where the name is the
-- node's own: a site it holds a certificate for, which one host answers to.
drop index if exists node_domain_unique;
create unique index node_domain_unique on node (domain) where kind = 'web';
