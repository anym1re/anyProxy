use ap_core::{Color, Note, Tag, TagName};
use sqlx::{PgPool, Row};

use crate::StoreError;

/// Reads and writes tags.
pub struct TagRepo;

impl TagRepo {
    /// Creates a tag.
    pub async fn insert(pool: &PgPool, tag: &Tag) -> Result<(), StoreError> {
        sqlx::query("insert into tag (id, name, color, note) values ($1, $2, $3, $4)")
            .bind(tag.id())
            .bind(tag.name().as_str())
            .bind(tag.color().map(Color::as_str))
            .bind(tag.note().map(Note::as_str))
            .execute(pool)
            .await?;
        Ok(())
    }

    /// Finds a tag by name.
    pub async fn by_name(pool: &PgPool, name: &TagName) -> Result<Option<Tag>, StoreError> {
        let row = sqlx::query("select id, name, color, note from tag where name = $1")
            .bind(name.as_str())
            .fetch_optional(pool)
            .await?;
        row.map(read_tag).transpose()
    }

    /// Every tag, by name.
    pub async fn list(pool: &PgPool) -> Result<Vec<Tag>, StoreError> {
        let rows = sqlx::query("select id, name, color, note from tag order by name")
            .fetch_all(pool)
            .await?;
        rows.into_iter().map(read_tag).collect()
    }
}

fn read_tag(row: sqlx::postgres::PgRow) -> Result<Tag, StoreError> {
    let name = TagName::try_from(row.try_get::<String, _>("name")?)?;
    let color = row
        .try_get::<Option<String>, _>("color")?
        .map(|text| Color::try_from(text.as_str()))
        .transpose()?;
    let note = row
        .try_get::<Option<String>, _>("note")?
        .map(|text| Note::try_from(text.as_str()))
        .transpose()?;
    Ok(Tag::from_parts(row.try_get("id")?, name, color, note))
}
