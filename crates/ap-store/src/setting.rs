use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::StoreError;

/// One setting, as it was last left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// What it is called, in the panel's own words.
    pub name: String,
    /// What it is set to. Text whatever the setting is (0069).
    pub value: String,
    /// When it was last changed.
    pub changed_at: OffsetDateTime,
    /// Who changed it, when that is still known.
    pub changed_by: Option<Uuid>,
}

/// Reads and writes what the panel is set to.
pub struct SettingRepo;

impl SettingRepo {
    /// Everything that has ever been set, by name.
    ///
    /// A setting nobody has touched is absent rather than default: the
    /// default belongs to the panel, which knows what it means, and writing
    /// it here would freeze today's default into the database.
    pub async fn all(pool: &PgPool) -> Result<Vec<Setting>, StoreError> {
        let rows =
            sqlx::query("select name, value, changed_at, changed_by from setting order by name")
                .fetch_all(pool)
                .await?;
        rows.into_iter()
            .map(|row| {
                Ok(Setting {
                    name: row.try_get("name")?,
                    value: row.try_get("value")?,
                    changed_at: row.try_get("changed_at")?,
                    changed_by: row.try_get("changed_by")?,
                })
            })
            .collect()
    }

    /// Sets one, remembering when and by whom.
    pub async fn put(
        pool: &PgPool,
        name: &str,
        value: &str,
        by: Option<Uuid>,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "insert into setting (name, value, changed_at, changed_by) \
             values ($1, $2, $3, $4) \
             on conflict (name) do update \
                set value = excluded.value, \
                    changed_at = excluded.changed_at, \
                    changed_by = excluded.changed_by",
        )
        .bind(name)
        .bind(value)
        .bind(at)
        .bind(by)
        .execute(pool)
        .await?;
        Ok(())
    }
}
