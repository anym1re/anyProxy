-- Identity the panel signs agent certificates with. One row.
-- The private key is sealed with the same key as every other secret, so a
-- database dump without the key file cannot impersonate the panel.
create table panel_identity (
    id             uuid primary key,
    certificate    text not null,
    key_nonce      bytea not null,
    key_ciphertext bytea not null,
    created_at     timestamptz not null
);

-- One-time codes that bind an installation to a node record.
-- Only the digest is kept: a dump does not let anyone enrol.
create table node_enrollment (
    id         uuid primary key,
    node_id    uuid not null references node (id) on delete cascade,
    code_hash  bytea not null unique,
    expires_at timestamptz not null,
    used_at    timestamptz,
    created_at timestamptz not null
);

create index node_enrollment_node on node_enrollment (node_id);

-- The certificate an agent presented, so a burned node can be refused even if
-- its certificate has not expired.
alter table node add column agent_cert_fingerprint bytea;
alter table node add column last_revision uuid;

create unique index node_agent_fingerprint
    on node (agent_cert_fingerprint) where agent_cert_fingerprint is not null;

grant select, insert, update, delete on panel_identity, node_enrollment to anyproxy_app;
