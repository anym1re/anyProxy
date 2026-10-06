-- Warnings the bot has already given, so each is given once (0102).
--
-- Kept by what the warning was about: a term that was extended or a quota that
-- was raised is a new value, and the warning becomes possible again. The
-- subject is a client or one of its accesses.

create table if not exists bot_warning (
    subject_id uuid not null,
    kind       text not null
        check (kind in ('quota-near', 'quota-spent', 'term-near', 'term-over')),
    about      text not null,
    sent_at    timestamptz not null,
    primary key (subject_id, kind, about)
);

grant select, insert, delete on bot_warning to anyproxy_app;
