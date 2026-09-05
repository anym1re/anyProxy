-- The second factor stops being a condition of an account existing.
--
-- It was not nullable because an account without one could not be
-- constructed (0010). It can be now (0060), so the column has to hold its
-- absence — and hold it whole: half a secret would look like a configured
-- factor and check against nothing.

alter table admin_user alter column totp_nonce drop not null;
alter table admin_user alter column totp_ciphertext drop not null;

alter table admin_user drop constraint if exists admin_totp_whole;
alter table admin_user add constraint admin_totp_whole
    check ((totp_nonce is null) = (totp_ciphertext is null));
