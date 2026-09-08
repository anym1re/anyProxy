use ap_core::Client;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::StoreError;
use crate::client::{COLUMNS, read_client};

/// What tying an account to a client came to (0082).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Linked {
    /// The client the account now answers to.
    pub client_id: Uuid,
    /// The label of the client it answered to before, when it was moved
    /// rather than tied for the first time.
    pub moved_from: Option<String>,
}

/// What the bot keeps: codes, the tie between an account and a client, and
/// how far it has read.
pub struct BotRepo;

impl BotRepo {
    /// Records a code for a client. Only the digest is kept.
    pub async fn issue_code(
        pool: &PgPool,
        client_id: Uuid,
        code_hash: &[u8],
        expires_at: OffsetDateTime,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "insert into bot_code (id, client_id, code_hash, expires_at, created_at) \
             values ($1, $2, $3, $4, $5)",
        )
        .bind(Uuid::now_v7())
        .bind(client_id)
        .bind(code_hash)
        .bind(expires_at)
        .bind(at)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Claims a code, once, and says which client it was for.
    ///
    /// The update carries the conditions, so two presentations of one code
    /// at the same moment cannot both succeed: the second finds no row.
    pub async fn claim_code(
        pool: &PgPool,
        code_hash: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>, StoreError> {
        let row = sqlx::query(
            "update bot_code set used_at = $2 \
             where code_hash = $1 and used_at is null and expires_at > $2 \
             returning client_id",
        )
        .bind(code_hash)
        .bind(now)
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|row| row.get("client_id")))
    }

    /// Ties an account, known by its digest, to a client.
    ///
    /// One account answers to one client: if the digest already stands on
    /// another client it is taken off there first, in the same transaction,
    /// and that client's label comes back so the move can be written down.
    pub async fn link(
        pool: &PgPool,
        client_id: Uuid,
        digest: &[u8],
        at: OffsetDateTime,
    ) -> Result<Linked, StoreError> {
        let mut transaction = pool.begin().await?;
        let moved_from: Option<String> = sqlx::query(
            "update client set telegram_digest = null, telegram_linked_at = null \
             where telegram_digest = $1 and id <> $2 returning label",
        )
        .bind(digest)
        .bind(client_id)
        .fetch_optional(&mut *transaction)
        .await?
        .map(|row| row.try_get("label"))
        .transpose()?;
        sqlx::query(
            "update client set telegram_digest = $2, telegram_linked_at = $3 where id = $1",
        )
        .bind(client_id)
        .bind(digest)
        .bind(at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(Linked {
            client_id,
            moved_from,
        })
    }

    /// Takes the account off a client. Whether there was one to take off.
    pub async fn unlink(pool: &PgPool, client_id: Uuid) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "update client set telegram_digest = null, telegram_linked_at = null \
             where id = $1 and telegram_digest is not null",
        )
        .bind(client_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// The client an account answers to, if any.
    pub async fn client_of(pool: &PgPool, digest: &[u8]) -> Result<Option<Client>, StoreError> {
        let row = sqlx::query(&format!(
            "select {COLUMNS} from client where telegram_digest = $1"
        ))
        .bind(digest)
        .fetch_optional(pool)
        .await?;
        row.map(read_client).transpose()
    }

    /// The first update the bot has not read yet (0087).
    pub async fn cursor(pool: &PgPool) -> Result<i64, StoreError> {
        let row = sqlx::query("select next_update from bot_cursor where lone")
            .fetch_optional(pool)
            .await?;
        Ok(row.map(|row| row.get("next_update")).unwrap_or(0))
    }

    /// Remembers that everything before an update has been read.
    pub async fn move_cursor(
        pool: &PgPool,
        next_update: i64,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "insert into bot_cursor (lone, next_update, moved_at) values (true, $1, $2) \
             on conflict (lone) do update \
                set next_update = excluded.next_update, moved_at = excluded.moved_at",
        )
        .bind(next_update)
        .bind(at)
        .execute(pool)
        .await?;
        Ok(())
    }
}
