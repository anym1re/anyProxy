-- The application connects as a role that cannot rewrite history: the audit
-- log accepts inserts and reads, nothing else. Without this the compromised
-- administrator of the threat model erases their own trail.
do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'anyproxy_app') then
        create role anyproxy_app nologin;
    end if;
end
$$;

grant usage on schema public to anyproxy_app;

grant select, insert, update, delete on client, node, tag, access, traffic_daily, traffic_delta
    to anyproxy_app;

grant select, insert on audit_log to anyproxy_app;
revoke update, delete on audit_log from anyproxy_app;
