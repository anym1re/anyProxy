create table client (
    id              uuid primary key,
    label           text not null unique,
    note_nonce      bytea,
    note_ciphertext bytea,
    state           text not null,
    quota_bytes     bigint,
    expires_at      timestamptz,
    created_at      timestamptz not null,
    constraint client_label_form check (label ~ '^[a-z0-9_-]{1,32}$'),
    constraint client_state_known check (state in ('active', 'suspended', 'archived')),
    constraint client_quota_positive check (quota_bytes is null or quota_bytes > 0),
    constraint client_note_paired check ((note_nonce is null) = (note_ciphertext is null))
);

-- No column holds a client address, and none is to be added: the link between
-- a person, an address and a time is the heaviest asset this system could
-- lose. A test reads information_schema to keep it that way.

create table node (
    id            uuid primary key,
    label         text not null unique,
    kind          text not null,
    domain        text,
    address       text,
    agent_version text,
    last_seen_at  timestamptz,
    state         text not null,
    created_at    timestamptz not null,
    constraint node_label_form check (label ~ '^[a-z0-9_-]{1,32}$'),
    constraint node_kind_known check (kind in ('stealth', 'open')),
    constraint node_state_known check (state in ('pending', 'active', 'disabled', 'burned')),
    constraint node_domain_matches_kind check ((kind = 'stealth') = (domain is not null))
);

create unique index node_domain_unique on node (domain) where domain is not null;

create table tag (
    id    uuid primary key,
    name  text not null unique,
    color text,
    note  text,
    constraint tag_name_form check (name ~ '^[a-z0-9_-]{1,24}$'),
    constraint tag_color_form check (color is null or color ~ '^#[0-9a-f]{6}$'),
    constraint tag_note_length check (note is null or length(note) <= 128)
);

create table access (
    id                    uuid primary key,
    client_id             uuid not null references client (id) on delete restrict,
    node_id               uuid not null references node (id) on delete restrict,
    surface               text not null,
    method                text not null,
    credential_nonce      bytea not null,
    credential_ciphertext bytea not null,
    credential_digest     bytea not null,
    tag_id                uuid references tag (id) on delete set null,
    quota_bytes           bigint,
    expires_at            timestamptz,
    max_devices           integer,
    state                 text not null,
    created_at            timestamptz not null,
    constraint access_surface_known check (surface in ('stealth', 'open')),
    constraint access_state_known check (state in ('active', 'disabled', 'revoked')),
    constraint access_method_matches_surface check (
        (surface = 'stealth' and method in ('faketls', 'web'))
        or (surface = 'open' and method in ('mtproto', 'socks5', 'http'))
    ),
    constraint access_quota_positive check (quota_bytes is null or quota_bytes > 0),
    constraint access_devices_range check (max_devices is null or max_devices between 1 and 1000)
);

create unique index access_credential_unique on access (node_id, credential_digest);
create index access_by_client on access (client_id);
create index access_by_node_state on access (node_id, state);
create index access_by_tag on access (tag_id) where tag_id is not null;

create table traffic_daily (
    access_id uuid not null references access (id) on delete cascade,
    day       date not null,
    bytes_in  bigint not null default 0,
    bytes_out bigint not null default 0,
    primary key (access_id, day),
    constraint traffic_not_negative check (bytes_in >= 0 and bytes_out >= 0)
);

-- An agent may deliver the same delta twice after a lost acknowledgement.
-- The revision is remembered so the counter moves once.
create table traffic_delta (
    revision   uuid primary key,
    access_id  uuid not null references access (id) on delete cascade,
    day        date not null,
    applied_at timestamptz not null
);

create table audit_log (
    id       uuid primary key,
    actor_id uuid,
    action   text not null,
    target   text,
    at       timestamptz not null,
    details  jsonb not null default '{}'::jsonb
);

create index audit_log_recent on audit_log (at desc);
