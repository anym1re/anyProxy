use ap_core::{Encrypted, KeyStore};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::StoreError;

/// A setting kept under the key: what it is called and when it was set,
/// never what it says (0084).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedSetting {
    /// What it is called, in the panel's own words.
    pub name: String,
    /// When it was last changed.
    pub changed_at: OffsetDateTime,
    /// Who changed it, when that is still known.
    pub changed_by: Option<Uuid>,
}

/// Reads and writes the settings that are secrets.
pub struct SealedSettingRepo;

impl SealedSettingRepo {
    /// Which of them are set, and when. The values stay sealed.
    pub async fn all(pool: &PgPool) -> Result<Vec<SealedSetting>, StoreError> {
        let rows =
            sqlx::query("select name, changed_at, changed_by from sealed_setting order by name")
                .fetch_all(pool)
                .await?;
        rows.into_iter()
            .map(|row| {
                Ok(SealedSetting {
                    name: row.try_get("name")?,
                    changed_at: row.try_get("changed_at")?,
                    changed_by: row.try_get("changed_by")?,
                })
            })
            .collect()
    }

    /// Opens one. Absent when nobody has set it.
    pub async fn open(
        pool: &PgPool,
        name: &str,
        key: &KeyStore,
    ) -> Result<Option<String>, StoreError> {
        let row = sqlx::query("select nonce, ciphertext from sealed_setting where name = $1")
            .bind(name)
            .fetch_optional(pool)
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let nonce: Vec<u8> = row.try_get("nonce")?;
        let nonce: [u8; 24] = nonce
            .try_into()
            .map_err(|_| StoreError::Domain(ap_core::Error::SealedValue))?;
        let ciphertext: Vec<u8> = row.try_get("ciphertext")?;
        Ok(Some(
            Encrypted::<String>::from_parts(nonce, ciphertext).open(key)?,
        ))
    }

    /// Seals one under a fresh nonce, remembering when and by whom.
    pub async fn put(
        pool: &PgPool,
        name: &str,
        value: &str,
        key: &KeyStore,
        by: Option<Uuid>,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let sealed = Encrypted::seal(&value.to_owned(), key)?;
        sqlx::query(
            "insert into sealed_setting (name, nonce, ciphertext, changed_at, changed_by) \
             values ($1, $2, $3, $4, $5) \
             on conflict (name) do update \
                set nonce = excluded.nonce, \
                    ciphertext = excluded.ciphertext, \
                    changed_at = excluded.changed_at, \
                    changed_by = excluded.changed_by",
        )
        .bind(name)
        .bind(sealed.nonce().to_vec())
        .bind(sealed.ciphertext().to_vec())
        .bind(at)
        .bind(by)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Forgets one. Whether there was anything to forget.
    pub async fn clear(pool: &PgPool, name: &str) -> Result<bool, StoreError> {
        let result = sqlx::query("delete from sealed_setting where name = $1")
            .bind(name)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }
}
