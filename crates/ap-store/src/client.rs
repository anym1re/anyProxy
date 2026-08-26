use ap_core::{Client, ClientState, Encrypted, Label};
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::StoreError;

const COLUMNS: &str =
    "id, label, note_nonce, note_ciphertext, state, quota_bytes, expires_at, created_at";

/// Reads and writes clients.
pub struct ClientRepo;

impl ClientRepo {
    /// Writes a new client.
    pub async fn insert(pool: &PgPool, client: &Client) -> Result<(), StoreError> {
        let (nonce, ciphertext) = split_note(client);
        sqlx::query(
            "insert into client (id, label, note_nonce, note_ciphertext, state, quota_bytes, \
             expires_at, created_at) values ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(client.id())
        .bind(client.label().as_str())
        .bind(nonce)
        .bind(ciphertext)
        .bind(client.state().as_stored())
        .bind(client.quota_bytes())
        .bind(client.expires_at())
        .bind(client.created_at())
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

    /// Every client, oldest first.
    pub async fn list(pool: &PgPool) -> Result<Vec<Client>, StoreError> {
        let rows = sqlx::query(&format!(
            "select {COLUMNS} from client order by created_at, id"
        ))
        .fetch_all(pool)
        .await?;
        rows.into_iter().map(read_client).collect()
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

fn read_client(row: sqlx::postgres::PgRow) -> Result<Client, StoreError> {
    let label = Label::try_from(row.try_get::<String, _>("label")?)?;
    let state = ClientState::from_stored(&row.try_get::<String, _>("state")?)?;
    let nonce: Option<Vec<u8>> = row.try_get("note_nonce")?;
    let ciphertext: Option<Vec<u8>> = row.try_get("note_ciphertext")?;
    let note = match (nonce, ciphertext) {
        (Some(nonce), Some(ciphertext)) => {
            let nonce: [u8; 24] = nonce
                .try_into()
                .map_err(|_| StoreError::Domain(ap_core::Error::SealedValue))?;
            Some(Encrypted::<String>::from_parts(nonce, ciphertext))
        }
        _ => None,
    };
    Ok(Client::from_parts(
        row.try_get("id")?,
        label,
        state,
        note,
        row.try_get("quota_bytes")?,
        row.try_get::<Option<OffsetDateTime>, _>("expires_at")?,
        row.try_get("created_at")?,
    ))
}
