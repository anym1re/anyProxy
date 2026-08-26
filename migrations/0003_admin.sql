create table admin_user (
    id              uuid primary key,
    login           text not null unique,
    password_hash   text not null,
    totp_nonce      bytea not null,
    totp_ciphertext bytea not null,
    role            text not null,
    state           text not null,
    created_at      timestamptz not null,
    constraint admin_login_form check (login ~ '^[a-z0-9_-]{1,32}$'),
    constraint admin_role_known check (role in ('superadmin', 'operator', 'reseller')),
    constraint admin_state_known check (state in ('active', 'disabled'))
);

-- The second factor is not nullable. An account without one cannot exist, so
-- the check at sign-in never has to ask whether one was configured.

create table admin_session (
    id         uuid primary key,
    admin_id   uuid not null references admin_user (id) on delete cascade,
    token_hash bytea not null unique,
    created_at timestamptz not null,
    expires_at timestamptz not null
);

create index admin_session_expiry on admin_session (expires_at);
create index admin_session_admin on admin_session (admin_id);

-- A reseller reaches only the clients it owns. A null owner is a house
-- account, reachable by superadmin and operator alone.
alter table client add column owner_id uuid references admin_user (id) on delete restrict;
create index client_by_owner on client (owner_id) where owner_id is not null;

grant select, insert, update, delete on admin_user, admin_session to anyproxy_app;
