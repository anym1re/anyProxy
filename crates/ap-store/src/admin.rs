use ap_core::{AdminLogin, AdminState, AdminUser, Encrypted, Role};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::StoreError;

const COLUMNS: &str =
    "id, login, password_hash, totp_nonce, totp_ciphertext, role, state, created_at";

/// Reads and writes administrators.
pub struct AdminRepo;

impl AdminRepo {
    /// Registers an administrator.
    pub async fn insert(pool: &PgPool, admin: &AdminUser) -> Result<(), StoreError> {
        sqlx::query(
            "insert into admin_user (id, login, password_hash, totp_nonce, totp_ciphertext, \
             role, state, created_at) values ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(admin.id())
        .bind(admin.login().as_str())
        .bind(admin.password_hash())
        .bind(admin.totp_secret().map(|secret| secret.nonce().to_vec()))
        .bind(
            admin
                .totp_secret()
                .map(|secret| secret.ciphertext().to_vec()),
        )
        .bind(admin.role().as_stored())
        .bind(admin.state().as_stored())
        .bind(admin.created_at())
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Finds an administrator by the name they sign in with.
    pub async fn by_login(
        pool: &PgPool,
        login: &AdminLogin,
    ) -> Result<Option<AdminUser>, StoreError> {
        let row = sqlx::query(&format!(
            "select {COLUMNS} from admin_user where login = $1"
        ))
        .bind(login.as_str())
        .fetch_optional(pool)
        .await?;
        row.map(read_admin).transpose()
    }

    /// Finds an administrator by identifier.
    pub async fn by_id(pool: &PgPool, id: Uuid) -> Result<Option<AdminUser>, StoreError> {
        let row = sqlx::query(&format!("select {COLUMNS} from admin_user where id = $1"))
            .bind(id)
            .fetch_optional(pool)
            .await?;
        row.map(read_admin).transpose()
    }

    /// How many administrators exist, to decide whether a first one is needed.
    pub async fn count(pool: &PgPool) -> Result<i64, StoreError> {
        let row = sqlx::query("select count(*)::bigint as total from admin_user")
            .fetch_one(pool)
            .await?;
        Ok(row.try_get("total")?)
    }
}

fn read_admin(row: sqlx::postgres::PgRow) -> Result<AdminUser, StoreError> {
    let login = AdminLogin::try_from(row.try_get::<String, _>("login")?)?;
    // Both halves or neither; the schema holds it to that, and a row that
    // somehow carried one would be an account with an unusable second factor
    // rather than one without it.
    let nonce: Option<Vec<u8>> = row.try_get("totp_nonce")?;
    let ciphertext: Option<Vec<u8>> = row.try_get("totp_ciphertext")?;
    let totp_secret = match (nonce, ciphertext) {
        (Some(nonce), Some(ciphertext)) => {
            let nonce: [u8; 24] = nonce
                .try_into()
                .map_err(|_| StoreError::Domain(ap_core::Error::SealedValue))?;
            Some(Encrypted::<String>::from_parts(nonce, ciphertext))
        }
        (None, None) => None,
        _ => return Err(StoreError::Domain(ap_core::Error::SealedValue)),
    };
    Ok(AdminUser::from_parts(
        row.try_get("id")?,
        login,
        row.try_get("password_hash")?,
        totp_secret,
        Role::from_stored(&row.try_get::<String, _>("role")?)?,
        AdminState::from_stored(&row.try_get::<String, _>("state")?)?,
        row.try_get("created_at")?,
    ))
}

/// Reads and writes sessions.
///
/// Only the digest of a token is stored. A dump of this table does not let
/// anyone sign in.
pub struct SessionRepo;

impl SessionRepo {
    /// Opens a session for an administrator.
    pub async fn open(
        pool: &PgPool,
        admin_id: Uuid,
        token_hash: &[u8],
        created_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Uuid, StoreError> {
        let id = Uuid::now_v7();
        sqlx::query(
            "insert into admin_session (id, admin_id, token_hash, created_at, expires_at) \
             values ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(admin_id)
        .bind(token_hash)
        .bind(created_at)
        .bind(expires_at)
        .execute(pool)
        .await?;
        Ok(id)
    }

    /// Finds the administrator a live token belongs to.
    pub async fn holder(
        pool: &PgPool,
        token_hash: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<AdminUser>, StoreError> {
        let row = sqlx::query(&format!(
            "select {} from admin_user a join admin_session s on s.admin_id = a.id \
             where s.token_hash = $1 and s.expires_at > $2",
            COLUMNS
                .split(", ")
                .map(|column| format!("a.{column}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .bind(token_hash)
        .bind(now)
        .fetch_optional(pool)
        .await?;
        row.map(read_admin).transpose()
    }

    /// Closes one session.
    pub async fn close(pool: &PgPool, token_hash: &[u8]) -> Result<bool, StoreError> {
        let result = sqlx::query("delete from admin_session where token_hash = $1")
            .bind(token_hash)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Removes sessions that have run out.
    pub async fn sweep(pool: &PgPool, now: OffsetDateTime) -> Result<u64, StoreError> {
        let result = sqlx::query("delete from admin_session where expires_at <= $1")
            .bind(now)
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }
}
