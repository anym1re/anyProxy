fn stamp(at: OffsetDateTime) -> Result<String, Error> {
    format_rfc3339(at)
}

async fn query(pool: &PgPool, label: &str) -> Result<Uuid, Error> {
    sqlx::query!("select id from client where label = $1", label)
        .fetch_one(pool)
        .await
        .map(|row| row.id)
        .map_err(|_| Error::Storage)
}
