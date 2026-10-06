use ap_core::{Client, Encrypted, TelegramAccount};
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

/// A message waiting to be sent (0102).
#[derive(Debug, Clone, PartialEq)]
pub struct Outgoing {
    /// The row.
    pub id: Uuid,
    /// Whom it is for.
    pub client_id: Uuid,
    /// `links`, `warning` or `operator`.
    pub kind: String,
    /// What it is about. Never an access secret: links are built when sent.
    pub body: serde_json::Value,
    /// How many times sending it has failed so far.
    pub attempts: i32,
    /// Which change it was read at; see [`BotRepo::done`].
    pub revision: i32,
}

/// What the bot keeps: codes, the tie between an account and a client, and
/// how far it has read; what it is to send, and which warnings it has given.
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

    /// Ties an account, known by its digest, to a client, with the sealed
    /// record of who is behind it (0103).
    ///
    /// One account answers to one client: if the digest already stands on
    /// another client it is taken off there first, together with everything
    /// the panel knew about the account there, in the same transaction, and
    /// that client's label comes back so the move can be written down.
    pub async fn link(
        pool: &PgPool,
        client_id: Uuid,
        digest: &[u8],
        account: &Encrypted<TelegramAccount>,
        at: OffsetDateTime,
    ) -> Result<Linked, StoreError> {
        let mut transaction = pool.begin().await?;
        let moved_from: Option<String> = sqlx::query(
            "update client set telegram_digest = null, telegram_linked_at = null, \
                telegram_account_nonce = null, telegram_account_ciphertext = null \
             where telegram_digest = $1 and id <> $2 returning label",
        )
        .bind(digest)
        .bind(client_id)
        .fetch_optional(&mut *transaction)
        .await?
        .map(|row| row.try_get("label"))
        .transpose()?;
        sqlx::query(
            "update client set telegram_digest = $2, telegram_linked_at = $3, \
                telegram_account_nonce = $4, telegram_account_ciphertext = $5 \
             where id = $1",
        )
        .bind(client_id)
        .bind(digest)
        .bind(at)
        .bind(account.nonce().to_vec())
        .bind(account.ciphertext().to_vec())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(Linked {
            client_id,
            moved_from,
        })
    }

    /// Takes the account off a client, and everything known about it with
    /// it. Whether there was one to take off.
    pub async fn unlink(pool: &PgPool, client_id: Uuid) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "update client set telegram_digest = null, telegram_linked_at = null, \
                telegram_account_nonce = null, telegram_account_ciphertext = null \
             where id = $1 and telegram_digest is not null",
        )
        .bind(client_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Replaces the record of who is behind a tied account: names and
    /// usernames change, and the latest message says what they are now.
    /// Nothing happens to a client whose account has been untied meanwhile.
    pub async fn remember_account(
        pool: &PgPool,
        client_id: Uuid,
        account: &Encrypted<TelegramAccount>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "update client set telegram_account_nonce = $2, telegram_account_ciphertext = $3 \
             where id = $1 and telegram_digest is not null",
        )
        .bind(client_id)
        .bind(account.nonce().to_vec())
        .bind(account.ciphertext().to_vec())
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Forgets who is behind an account without untying it: Telegram said
    /// the person blocked the bot. The next message from them brings it back.
    pub async fn forget_account(pool: &PgPool, client_id: Uuid) -> Result<(), StoreError> {
        sqlx::query(
            "update client set telegram_account_nonce = null, telegram_account_ciphertext = null \
             where id = $1",
        )
        .bind(client_id)
        .execute(pool)
        .await?;
        Ok(())
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

    // ── signing up (0105) ────────────────────────────────────────────────

    /// The client an account signed up as, whether or not it is still tied
    /// to it. The same account comes back to the same client, with what it
    /// has used and the state it was left in.
    pub async fn signed_up_as(pool: &PgPool, digest: &[u8]) -> Result<Option<Client>, StoreError> {
        let row = sqlx::query(&format!(
            "select {COLUMNS} from client where signup_digest = $1"
        ))
        .bind(digest)
        .fetch_optional(pool)
        .await?;
        row.map(read_client).transpose()
    }

    /// Registers a client for an account that wrote to the bot: made, tied to
    /// the account and remembered as its own, in one statement. A name that
    /// is taken is a constraint violation, and the caller picks another.
    pub async fn sign_up(
        pool: &PgPool,
        client: &Client,
        digest: &[u8],
        account: &Encrypted<TelegramAccount>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "insert into client (id, label, state, quota_bytes, expires_at, created_at, origin, \
                telegram_digest, telegram_linked_at, telegram_account_nonce, \
                telegram_account_ciphertext, signup_digest) \
             values ($1, $2, $3, $4, $5, $6, 'bot', $7, $6, $8, $9, $7)",
        )
        .bind(client.id())
        .bind(client.label().as_str())
        .bind(client.state().as_stored())
        .bind(client.quota_bytes())
        .bind(client.expires_at())
        .bind(client.created_at())
        .bind(digest)
        .bind(account.nonce().to_vec())
        .bind(account.ciphertext().to_vec())
        .execute(pool)
        .await?;
        Ok(())
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

    // ── who can be written to ────────────────────────────────────────────

    /// Clients the bot can write to — tied, and heard from — that hold an
    /// access on a node which is not revoked (0102).
    pub async fn reachable_on_node(pool: &PgPool, node_id: Uuid) -> Result<Vec<Uuid>, StoreError> {
        let rows = sqlx::query(
            "select distinct client.id from client \
             join access on access.client_id = client.id \
             where access.node_id = $1 and access.state <> 'revoked' \
               and client.telegram_account_nonce is not null",
        )
        .bind(node_id)
        .fetch_all(pool)
        .await?;
        rows.iter().map(|row| Ok(row.try_get("id")?)).collect()
    }

    /// Every client the bot can write to, or only one owner's.
    pub async fn reachable(pool: &PgPool, owner: Option<Uuid>) -> Result<Vec<Client>, StoreError> {
        let rows = sqlx::query(&format!(
            "select {COLUMNS} from client \
             where telegram_account_nonce is not null \
               and ($1::uuid is null or owner_id = $1) \
             order by created_at, id"
        ))
        .bind(owner)
        .fetch_all(pool)
        .await?;
        rows.into_iter().map(read_client).collect()
    }

    /// Clients the bot can write to that hold an access under a tag, which
    /// is not revoked; or only one owner's.
    pub async fn reachable_with_tag(
        pool: &PgPool,
        tag_id: Uuid,
        owner: Option<Uuid>,
    ) -> Result<Vec<Uuid>, StoreError> {
        let rows = sqlx::query(
            "select distinct client.id from client \
             join access on access.client_id = client.id \
             where access.tag_id = $1 and access.state <> 'revoked' \
               and client.telegram_account_nonce is not null \
               and ($2::uuid is null or client.owner_id = $2)",
        )
        .bind(tag_id)
        .bind(owner)
        .fetch_all(pool)
        .await?;
        rows.iter().map(|row| Ok(row.try_get("id")?)).collect()
    }

    // ── what is to be sent ───────────────────────────────────────────────

    /// Queues «your links changed» for a client. Several in a row come to one
    /// message: while one is waiting, another only bumps its revision, so
    /// one being sent at that moment is sent again with the newer links.
    pub async fn queue_links(
        pool: &PgPool,
        client_id: Uuid,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "insert into bot_outbox (id, client_id, kind, created_at, next_try_at) \
             values ($1, $2, 'links', $3, $3) \
             on conflict (client_id) where kind = 'links' \
             do update set revision = bot_outbox.revision + 1",
        )
        .bind(Uuid::now_v7())
        .bind(client_id)
        .bind(at)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Queues a warning or an operator's message for a client.
    pub async fn queue(
        pool: &PgPool,
        client_id: Uuid,
        kind: &str,
        body: &serde_json::Value,
        at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "insert into bot_outbox (id, client_id, kind, body, created_at, next_try_at) \
             values ($1, $2, $3, $4, $5, $5)",
        )
        .bind(Uuid::now_v7())
        .bind(client_id)
        .bind(kind)
        .bind(body)
        .bind(at)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Messages whose time has come, oldest first.
    pub async fn due(
        pool: &PgPool,
        now: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<Outgoing>, StoreError> {
        let rows = sqlx::query(
            "select id, client_id, kind, body, attempts, revision from bot_outbox \
             where next_try_at <= $1 order by next_try_at, created_at, id limit $2",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(Outgoing {
                    id: row.try_get("id")?,
                    client_id: row.try_get("client_id")?,
                    kind: row.try_get("kind")?,
                    body: row.try_get("body")?,
                    attempts: row.try_get("attempts")?,
                    revision: row.try_get("revision")?,
                })
            })
            .collect()
    }

    /// How many messages are waiting, due or not.
    pub async fn waiting(pool: &PgPool) -> Result<i64, StoreError> {
        let row = sqlx::query("select count(*) as waiting from bot_outbox")
            .fetch_one(pool)
            .await?;
        Ok(row.try_get("waiting")?)
    }

    /// Takes a message off the queue: sent, or given up on — at the revision
    /// it was read at. One changed since stays, and goes out again as it is
    /// now.
    pub async fn done(pool: &PgPool, id: Uuid, revision: i32) -> Result<(), StoreError> {
        sqlx::query("delete from bot_outbox where id = $1 and revision = $2")
            .bind(id)
            .bind(revision)
            .execute(pool)
            .await?;
        Ok(())
    }

    /// Puts a message back for later, counting the failure.
    pub async fn retry(
        pool: &PgPool,
        id: Uuid,
        next_try_at: OffsetDateTime,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "update bot_outbox set attempts = attempts + 1, next_try_at = $2 where id = $1",
        )
        .bind(id)
        .bind(next_try_at)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Holds every waiting message back until a moment, without counting a
    /// failure: Telegram asked the bot to slow down, which is nobody's fault.
    pub async fn hold(pool: &PgPool, until: OffsetDateTime) -> Result<(), StoreError> {
        sqlx::query("update bot_outbox set next_try_at = greatest(next_try_at, $1)")
            .bind(until)
            .execute(pool)
            .await?;
        Ok(())
    }

    // ── which warnings were given ────────────────────────────────────────

    /// Remembers a warning about a subject and the value it was about.
    /// Whether it is new: `false` means it was given already.
    pub async fn warn_once(
        pool: &PgPool,
        subject_id: Uuid,
        kind: &str,
        about: &str,
        at: OffsetDateTime,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "insert into bot_warning (subject_id, kind, about, sent_at) values ($1, $2, $3, $4) \
             on conflict do nothing",
        )
        .bind(subject_id)
        .bind(kind)
        .bind(about)
        .bind(at)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }
}
