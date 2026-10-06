use ap_core::{Client, ClientState, Encrypted, Label, TelegramAccount};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::StoreError;

pub(crate) const COLUMNS: &str = "id, label, note_nonce, note_ciphertext, state, quota_bytes, expires_at, \n     created_at, owner_id, telegram_linked_at, telegram_account_nonce, \n     telegram_account_ciphertext, origin";

/// Reads and writes clients.
pub struct ClientRepo;

impl ClientRepo {
    /// Writes a new client.
    pub async fn insert(
        pool: &PgPool,
        client: &Client,
        owner: Option<Uuid>,
    ) -> Result<(), StoreError> {
        let (nonce, ciphertext) = split_note(client);
        sqlx::query(
            "insert into client (id, label, note_nonce, note_ciphertext, state, quota_bytes, \
             expires_at, created_at, owner_id) values ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(client.id())
        .bind(client.label().as_str())
        .bind(nonce)
        .bind(ciphertext)
        .bind(client.state().as_stored())
        .bind(client.quota_bytes())
        .bind(client.expires_at())
        .bind(client.created_at())
        .bind(owner)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Finds a client by the name an operator knows it by.
    pub async fn by_label(pool: &PgPool, label: &Label) -> Result<Option<Client>, StoreError> {
        let row = sqlx::query(&format!("select {COLUMNS} from client where label = $1"))
            .bind(label.as_str())
            .fetch_optional(pool)
            .await?;
        row.map(read_client).transpose()
    }

    /// Finds a client by identifier.
    pub async fn by_id(pool: &PgPool, id: Uuid) -> Result<Option<Client>, StoreError> {
        let row = sqlx::query(&format!("select {COLUMNS} from client where id = $1"))
            .bind(id)
            .fetch_optional(pool)
            .await?;
        row.map(read_client).transpose()
    }

    /// Clients, newest first. A limit is always applied, and with people
    /// signing up through the bot (0105) the list outgrows it: what an
    /// operator is shown is who came last, not who came first.
    pub async fn list(pool: &PgPool, limit: i64) -> Result<Vec<Client>, StoreError> {
        let rows = sqlx::query(&format!(
            "select {COLUMNS} from client order by created_at desc, id desc limit $1"
        ))
        .bind(limit)
        .fetch_all(pool)
        .await?;
        rows.into_iter().map(read_client).collect()
    }

    /// The clients one owner holds, newest first.
    pub async fn list_owned(
        pool: &PgPool,
        owner: Uuid,
        limit: i64,
    ) -> Result<Vec<Client>, StoreError> {
        let rows = sqlx::query(&format!(
            "select {COLUMNS} from client where owner_id = $1 \
             order by created_at desc, id desc limit $2"
        ))
        .bind(owner)
        .bind(limit)
        .fetch_all(pool)
        .await?;
        rows.into_iter().map(read_client).collect()
    }

    /// Who owns a client, when anyone does.
    pub async fn owner_of(pool: &PgPool, id: Uuid) -> Result<Option<Uuid>, StoreError> {
        let row = sqlx::query("select owner_id from client where id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
        Ok(row.and_then(|row| row.try_get("owner_id").ok()))
    }

    /// Moves a client to a new state.
    pub async fn set_state(
        pool: &PgPool,
        id: Uuid,
        state: ClientState,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query("update client set state = $2 where id = $1")
            .bind(id)
            .bind(state.as_stored())
            .execute(pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Removes a client. Refused by the database while it holds any access.
    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, StoreError> {
        let result = sqlx::query("delete from client where id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }
}

fn split_note(client: &Client) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    match client.note() {
        Some(note) => (
            Some(note.nonce().to_vec()),
            Some(note.ciphertext().to_vec()),
        ),
        None => (None, None),
    }
}

/// A sealed value from the two columns it is kept in, when both are set.
pub(crate) fn sealed<T>(
    nonce: Option<Vec<u8>>,
    ciphertext: Option<Vec<u8>>,
) -> Result<Option<Encrypted<T>>, StoreError> {
    match (nonce, ciphertext) {
        (Some(nonce), Some(ciphertext)) => {
            let nonce: [u8; 24] = nonce
                .try_into()
                .map_err(|_| StoreError::Domain(ap_core::Error::SealedValue))?;
            Ok(Some(Encrypted::<T>::from_parts(nonce, ciphertext)))
        }
        _ => Ok(None),
    }
}

pub(crate) fn read_client(row: sqlx::postgres::PgRow) -> Result<Client, StoreError> {
    let label = Label::try_from(row.try_get::<String, _>("label")?)?;
    let state = ClientState::from_stored(&row.try_get::<String, _>("state")?)?;
    let note = sealed::<String>(row.try_get("note_nonce")?, row.try_get("note_ciphertext")?)?;
    let account = sealed::<TelegramAccount>(
        row.try_get("telegram_account_nonce")?,
        row.try_get("telegram_account_ciphertext")?,
    )?;
    Ok(Client::from_parts(
        row.try_get("id")?,
        label,
        state,
        note,
        row.try_get("quota_bytes")?,
        row.try_get::<Option<OffsetDateTime>, _>("expires_at")?,
        row.try_get("created_at")?,
    )
    .with_telegram_linked(row.try_get::<Option<OffsetDateTime>, _>("telegram_linked_at")?)
    .with_telegram_account(account)
    .with_bot_origin(row.try_get::<String, _>("origin")? == "bot"))
}
