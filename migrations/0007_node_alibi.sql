-- What the forged handshake claims to be, when it is not the node's own name.
--
-- A node serving only the forged handshake borrows a name and has nothing of
-- its own: `domain` is somebody else's site and this stays empty. A node that
-- also serves a site of its own needs both, because the site answers to a name
-- it holds a certificate for while the handshake goes on borrowing. The front
-- door on 443 tells the two apart by which one a client asks for, so a link
-- naming the wrong one is answered by the wrong thing.

alter table node add column if not exists alibi text;

alter table node add constraint node_alibi_needs_a_domain
    check (alibi is null or domain is not null);
