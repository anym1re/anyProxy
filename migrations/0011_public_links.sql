-- A link the operator hands out belongs to nobody, and is known by a name.
--
-- Every access had to name a client, so the only way to express a link an
-- operator issues and gives to whoever asks was to invent a client to hold it.
-- That client then carried a quota, a state and an owner that meant nothing,
-- and the link had no name of its own — nothing on it said which of them it
-- was. The tag beside it is a grouping for withdrawal, not a name.
--
-- So the owner becomes optional and a name appears next to it, with exactly
-- one of the two set: a client's link answers to that client, a public one
-- answers to nobody and is known by what it was called.

alter table access alter column client_id drop not null;
alter table access add column if not exists name text;

alter table access add constraint access_belongs_to_one_or_is_named
    check ((client_id is null) <> (name is null));

alter table access add constraint access_name_form
    check (name is null or (length(name) between 1 and 64 and name !~ '[\n\r\t]'));

-- A name says which link is which, so two of them saying the same thing says
-- nothing. Only among the public ones: a client's link has no name at all.
create unique index access_public_name_unique on access (name) where name is not null;
