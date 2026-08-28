use ap_core::{
    Access, AccessCommon, AccessState, AnyAccess, Credential, Encrypted, Holder, KeyStore,
    LinkName, Open, OpenMethod, Stealth, StealthMethod,
};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::StoreError;

const COLUMNS: &str = "id, client_id, name, node_id, surface, method, credential_nonce, \
     credential_ciphertext, tag_id, quota_bytes, expires_at, max_devices, state, created_at";

/// Reads and writes accesses.
pub struct AccessRepo;

impl AccessRepo {
    /// Issues an access, sealing its credential and storing a keyed digest so
    /// a duplicate on the same node is refused without opening anything.
    pub async fn insert(
        pool: &PgPool,
        access: &AnyAccess,
        credential: &Credential,
        key: &KeyStore,
    ) -> Result<(), StoreError> {
        let common = access.common();
        let sealed = Encrypted::seal(credential, key)?;
        let digest = key.digest(&credential.digest_input());
        sqlx::query(
            "insert into access (id, client_id, name, node_id, surface, method, \
             credential_nonce, credential_ciphertext, credential_digest, tag_id, quota_bytes, \
             expires_at, max_devices, state, created_at) values ($1, $2, $3, $4, $5, $6, $7, \
             $8, $9, $10, $11, $12, $13, $14, $15)",
        )
        .bind(common.id())
        .bind(common.client_id())
        .bind(common.name().map(LinkName::as_str))
        .bind(common.node_id())
        .bind(access.surface_tag())
        .bind(method_of(access))
        .bind(sealed.nonce().to_vec())
        .bind(sealed.ciphertext().to_vec())
        .bind(digest.to_vec())
        .bind(common.tag_id())
        .bind(common.quota_bytes())
        .bind(common.expires_at())
        .bind(common.max_devices())
        .bind(common.state().as_stored())
        .bind(common.created_at())
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Finds an access by identifier.
    pub async fn by_id(pool: &PgPool, id: Uuid) -> Result<Option<AnyAccess>, StoreError> {
        let row = sqlx::query(&format!("select {COLUMNS} from access where id = $1"))
            .bind(id)
            .fetch_optional(pool)
            .await?;
        row.map(read_access).transpose()
    }

    /// Every link that belongs to no client, by name.
    pub async fn public(pool: &PgPool) -> Result<Vec<AnyAccess>, StoreError> {
        let rows = sqlx::query(&format!(
            "select {COLUMNS} from access where client_id is null order by name"
        ))
        .fetch_all(pool)
        .await?;
        rows.into_iter().map(read_access).collect()
    }

    /// Every access a client holds, oldest first.
    pub async fn by_client(pool: &PgPool, client_id: Uuid) -> Result<Vec<AnyAccess>, StoreError> {
        let rows = sqlx::query(&format!(
            "select {COLUMNS} from access where client_id = $1 order by created_at, id"
        ))
        .bind(client_id)
        .fetch_all(pool)
        .await?;
        rows.into_iter().map(read_access).collect()
    }

    /// Every access a node serves, oldest first.
    pub async fn by_node(pool: &PgPool, node_id: Uuid) -> Result<Vec<AnyAccess>, StoreError> {
        let rows = sqlx::query(&format!(
            "select {COLUMNS} from access where node_id = $1 order by created_at, id"
        ))
        .bind(node_id)
        .fetch_all(pool)
        .await?;
        rows.into_iter().map(read_access).collect()
    }

    /// Opens the credential of one access.
    pub async fn credential(
        pool: &PgPool,
        id: Uuid,
        key: &KeyStore,
    ) -> Result<Option<Credential>, StoreError> {
        let row =
            sqlx::query("select credential_nonce, credential_ciphertext from access where id = $1")
                .bind(id)
                .fetch_optional(pool)
                .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let nonce: Vec<u8> = row.try_get("credential_nonce")?;
        let nonce: [u8; 24] = nonce
            .try_into()
            .map_err(|_| StoreError::Domain(ap_core::Error::SealedValue))?;
        let ciphertext: Vec<u8> = row.try_get("credential_ciphertext")?;
        Ok(Some(
            Encrypted::<Credential>::from_parts(nonce, ciphertext).open(key)?,
        ))
    }

    /// Moves an access to a new state. A revoked one is never moved out of it.
    pub async fn set_state(
        pool: &PgPool,
        id: Uuid,
        state: AccessState,
    ) -> Result<bool, StoreError> {
        let result =
            sqlx::query("update access set state = $2 where id = $1 and state <> 'revoked'")
                .bind(id)
                .bind(state.as_stored())
                .execute(pool)
                .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Withdraws every access on a node, in one statement.
    pub async fn revoke_by_node(pool: &PgPool, node_id: Uuid) -> Result<u64, StoreError> {
        let result = sqlx::query("update access set state = 'revoked' where node_id = $1")
            .bind(node_id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Withdraws every access carrying a tag, in one statement.
    pub async fn revoke_by_tag(pool: &PgPool, tag_id: Uuid) -> Result<u64, StoreError> {
        let result = sqlx::query("update access set state = 'revoked' where tag_id = $1")
            .bind(tag_id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }
}

fn method_of(access: &AnyAccess) -> &'static str {
    match access {
        AnyAccess::Stealth(access) => access.method().as_stored(),
        AnyAccess::Open(access) => access.method().as_stored(),
    }
}

fn read_access(row: sqlx::postgres::PgRow) -> Result<AnyAccess, StoreError> {
    let holder = match (
        row.try_get::<Option<Uuid>, _>("client_id")?,
        row.try_get::<Option<String>, _>("name")?,
    ) {
        (Some(client_id), None) => Holder::Client(client_id),
        (None, Some(name)) => Holder::Public(LinkName::try_from(name.as_str())?),
        // The schema forbids both and neither. Reaching here means that
        // constraint is gone, and guessing which half to believe could hand
        // one client's link to another.
        _ => {
            return Err(StoreError::Impossible(
                "an access that is neither a client's nor public".to_owned(),
            ));
        }
    };
    let common = AccessCommon::from_parts(
        row.try_get("id")?,
        holder,
        row.try_get("node_id")?,
        row.try_get("tag_id")?,
        row.try_get("quota_bytes")?,
        row.try_get::<Option<OffsetDateTime>, _>("expires_at")?,
        row.try_get("max_devices")?,
        AccessState::from_stored(&row.try_get::<String, _>("state")?)?,
        row.try_get("created_at")?,
    );
    let method: String = row.try_get("method")?;
    match row.try_get::<String, _>("surface")?.as_str() {
        "stealth" => Ok(AnyAccess::Stealth(Access::<Stealth>::new(
            common,
            StealthMethod::from_stored(&method)?,
        ))),
        "open" => Ok(AnyAccess::Open(Access::<Open>::new(
            common,
            OpenMethod::from_stored(&method)?,
        ))),
        _ => Err(StoreError::Domain(ap_core::Error::StoredValue)),
    }
}
