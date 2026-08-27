use ap_core::Encrypted;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::StoreError;

/// The certificate the panel presents and the key it signs with.
#[derive(Debug, Clone)]
pub struct PanelIdentity {
    /// Certificate of the panel authority, PEM.
    pub certificate: String,
    /// Its private key, sealed.
    pub key: Encrypted<String>,
}

/// Reads and writes the panel identity. There is exactly one.
pub struct PanelIdentityRepo;

impl PanelIdentityRepo {
    /// Reads the identity, if the panel has one yet.
    pub async fn read(pool: &PgPool) -> Result<Option<PanelIdentity>, StoreError> {
        let row = sqlx::query(
            "select certificate, key_nonce, key_ciphertext from panel_identity \
             order by created_at limit 1",
        )
        .fetch_optional(pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let nonce: Vec<u8> = row.try_get("key_nonce")?;
        let nonce: [u8; 24] = nonce
            .try_into()
            .map_err(|_| StoreError::Domain(ap_core::Error::SealedValue))?;
        Ok(Some(PanelIdentity {
            certificate: row.try_get("certificate")?,
            key: Encrypted::from_parts(nonce, row.try_get("key_ciphertext")?),
        }))
    }

    /// Writes the identity, once.
    pub async fn write(
        pool: &PgPool,
        identity: &PanelIdentity,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "insert into panel_identity (id, certificate, key_nonce, key_ciphertext, created_at) \
             values ($1, $2, $3, $4, $5)",
        )
        .bind(Uuid::now_v7())
        .bind(&identity.certificate)
        .bind(identity.key.nonce().to_vec())
        .bind(identity.key.ciphertext().to_vec())
        .bind(at)
        .execute(pool)
        .await?;
        Ok(())
    }
}

/// Reads and writes enrolment codes.
pub struct EnrollmentRepo;

impl EnrollmentRepo {
    /// Records a code for a node. Only the digest is kept.
    pub async fn issue(
        pool: &PgPool,
        node_id: Uuid,
        code_hash: &[u8],
        expires_at: OffsetDateTime,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "insert into node_enrollment (id, node_id, code_hash, expires_at, created_at) \
             values ($1, $2, $3, $4, $5)",
        )
        .bind(Uuid::now_v7())
        .bind(node_id)
        .bind(code_hash)
        .bind(expires_at)
        .bind(at)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Claims a code, once.
    ///
    /// The update carries the conditions, so two agents presenting the same
    /// code at the same moment cannot both succeed: the second finds no row to
    /// update. A read followed by a write would let both through.
    pub async fn claim(
        pool: &PgPool,
        code_hash: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>, StoreError> {
        let row = sqlx::query(
            "update node_enrollment set used_at = $2 \
             where code_hash = $1 and used_at is null and expires_at > $2 \
             returning node_id",
        )
        .bind(code_hash)
        .bind(now)
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| row.get("node_id")))
    }

    /// Records the certificate an agent now presents.
    pub async fn bind_certificate(
        pool: &PgPool,
        node_id: Uuid,
        fingerprint: &[u8],
    ) -> Result<(), StoreError> {
        sqlx::query("update node set agent_cert_fingerprint = $2 where id = $1")
            .bind(node_id)
            .bind(fingerprint)
            .execute(pool)
            .await?;
        Ok(())
    }

    /// Finds the node an agent certificate belongs to, if it is still allowed.
    ///
    /// A burned node is never returned: its certificate may not have expired,
    /// and expiry is not what withdraws it.
    pub async fn node_of_certificate(
        pool: &PgPool,
        fingerprint: &[u8],
    ) -> Result<Option<Uuid>, StoreError> {
        let row = sqlx::query(
            "select id from node where agent_cert_fingerprint = $1 and state <> 'burned'",
        )
        .bind(fingerprint)
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| row.get("id")))
    }

    /// The last revision issued to a node.
    pub async fn last_revision(pool: &PgPool, node_id: Uuid) -> Result<Option<Uuid>, StoreError> {
        let row = sqlx::query("select last_revision from node where id = $1")
            .bind(node_id)
            .fetch_optional(pool)
            .await?;
        Ok(row.and_then(|row| row.try_get("last_revision").ok()))
    }

    /// Records the revision just handed out.
    pub async fn set_revision(
        pool: &PgPool,
        node_id: Uuid,
        revision: Uuid,
    ) -> Result<(), StoreError> {
        sqlx::query("update node set last_revision = $2 where id = $1")
            .bind(node_id)
            .bind(revision)
            .execute(pool)
            .await?;
        Ok(())
    }

    /// Whether an access belongs to a node, checked before its telemetry is
    /// believed.
    pub async fn access_belongs(
        pool: &PgPool,
        access_id: Uuid,
        node_id: Uuid,
    ) -> Result<bool, StoreError> {
        let row = sqlx::query("select 1 as ok from access where id = $1 and node_id = $2")
            .bind(access_id)
            .bind(node_id)
            .fetch_optional(pool)
            .await?;
        Ok(row.is_some())
    }
}

/// What a node says about itself while its agent is connected.
pub struct PresenceRepo;

impl PresenceRepo {
    /// Records that the agent is talking to the panel, and what it reports.
    ///
    /// A node that is serving clients should not read as pending: an operator
    /// looking for one that stopped has to be able to tell the two apart.
    pub async fn seen(
        pool: &PgPool,
        node_id: Uuid,
        agent_version: &str,
        health: Option<(&str, &str, Option<OffsetDateTime>)>,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let (engine, site, cert_not_after) = match health {
            Some((engine, site, expiry)) => (Some(engine), Some(site), expiry),
            None => (None, None, None),
        };

        sqlx::query(
            "update node set last_seen_at = $2, agent_version = $3, \
             health_engine = coalesce($4, health_engine), \
             health_site = coalesce($5, health_site), \
             cert_not_after = coalesce($6, cert_not_after), \
             state = case when state = 'pending' then 'active' else state end \
             where id = $1 and state <> 'burned'",
        )
        .bind(node_id)
        .bind(at)
        .bind(agent_version)
        .bind(engine)
        .bind(site)
        .bind(cert_not_after)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Records how many devices used one access in a period.
    ///
    /// A count, applied once per delivery. What it was derived from stays in
    /// the engine's memory on the node: there is no column here that could
    /// hold an address.
    pub async fn devices(
        pool: &PgPool,
        revision: Uuid,
        access_id: Uuid,
        period: time::Date,
        devices: i64,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "insert into device_count (access_id, period, devices, revision, updated_at) \
             values ($1, $2, $3, $4, $5) \
             on conflict (access_id, period) do update \
                set devices = greatest(device_count.devices, excluded.devices), \
                    revision = excluded.revision, \
                    updated_at = excluded.updated_at \
             where device_count.revision <> excluded.revision",
        )
        .bind(access_id)
        .bind(period)
        .bind(i32::try_from(devices).unwrap_or(i32::MAX))
        .bind(revision)
        .bind(at)
        .execute(pool)
        .await?;
        Ok(())
    }
}
