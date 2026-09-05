use sqlx::{PgPool, Row};
use time::{Date, OffsetDateTime};
use uuid::Uuid;

use crate::StoreError;

/// What an access has spent, and what its client has spent across all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrafficTotals {
    /// Bytes received by the client.
    pub bytes_in: i64,
    /// Bytes sent by the client.
    pub bytes_out: i64,
}

impl TrafficTotals {
    /// The sum of both directions, which is what a quota counts.
    pub fn total(self) -> i64 {
        self.bytes_in.saturating_add(self.bytes_out)
    }
}

/// What every access together spent on one day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DailyTraffic {
    /// The day, UTC.
    pub day: Date,
    /// Bytes received by clients.
    pub bytes_in: i64,
    /// Bytes sent by clients.
    pub bytes_out: i64,
}

/// Reads and writes traffic counters. Aggregated by day; no record is kept of
/// individual connections.
pub struct TrafficRepo;

impl TrafficRepo {
    /// Adds a delta to a day, once.
    ///
    /// An agent may resend a delta after a lost acknowledgement, so what was
    /// applied is recorded first and the counter moves only if that insert was
    /// the first. Returns whether the delta was applied.
    ///
    /// What is remembered is the delta and not the delivery: one delivery
    /// carries a delta for every access the node serves, and remembering only
    /// the revision let the first of them stand for all the rest.
    pub async fn apply_delta(
        pool: &PgPool,
        revision: Uuid,
        access_id: Uuid,
        day: Date,
        bytes_in: i64,
        bytes_out: i64,
        at: OffsetDateTime,
    ) -> Result<bool, StoreError> {
        let mut transaction = pool.begin().await?;

        let claimed = sqlx::query(
            "insert into traffic_delta (revision, access_id, day, applied_at) \
             values ($1, $2, $3, $4) \
             on conflict (revision, access_id, day) do nothing",
        )
        .bind(revision)
        .bind(access_id)
        .bind(day)
        .bind(at)
        .execute(&mut *transaction)
        .await?;

        if claimed.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(false);
        }

        sqlx::query(
            "insert into traffic_daily (access_id, day, bytes_in, bytes_out) \
             values ($1, $2, $3, $4) \
             on conflict (access_id, day) do update set \
             bytes_in = traffic_daily.bytes_in + excluded.bytes_in, \
             bytes_out = traffic_daily.bytes_out + excluded.bytes_out",
        )
        .bind(access_id)
        .bind(day)
        .bind(bytes_in)
        .bind(bytes_out)
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
        Ok(true)
    }

    /// What one access has spent in total.
    pub async fn for_access(pool: &PgPool, access_id: Uuid) -> Result<TrafficTotals, StoreError> {
        let row = sqlx::query(
            "select coalesce(sum(bytes_in), 0)::bigint as bytes_in, \
             coalesce(sum(bytes_out), 0)::bigint as bytes_out \
             from traffic_daily where access_id = $1",
        )
        .bind(access_id)
        .fetch_one(pool)
        .await?;
        Ok(TrafficTotals {
            bytes_in: row.try_get("bytes_in")?,
            bytes_out: row.try_get("bytes_out")?,
        })
    }

    /// A day-by-day series from a date on, across every access — or, given
    /// an owner, across the accesses of the clients that owner created.
    ///
    /// A day nobody used is absent, not zero: the caller lays the series over
    /// its own calendar. Public links have no client and so no owner; they
    /// are counted only in the unscoped series.
    pub async fn daily(
        pool: &PgPool,
        since: Date,
        owner: Option<Uuid>,
    ) -> Result<Vec<DailyTraffic>, StoreError> {
        let rows = sqlx::query(
            "select t.day, sum(t.bytes_in)::bigint as bytes_in,              sum(t.bytes_out)::bigint as bytes_out              from traffic_daily t              join access a on a.id = t.access_id              left join client c on c.id = a.client_id              where t.day >= $1 and ($2::uuid is null or c.owner_id = $2)              group by t.day order by t.day",
        )
        .bind(since)
        .bind(owner)
        .fetch_all(pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(DailyTraffic {
                    day: row.try_get("day")?,
                    bytes_in: row.try_get("bytes_in")?,
                    bytes_out: row.try_get("bytes_out")?,
                })
            })
            .collect()
    }

    /// What each access carried over a window, and the last day it carried
    /// anything at all.
    ///
    /// The window bounds the sum only: an access quiet for a year still says
    /// when it was last busy, which is what the screen asks (0066).
    pub async fn by_access(
        pool: &PgPool,
        since: Date,
        owner: Option<Uuid>,
    ) -> Result<Vec<(Uuid, i64, Date)>, StoreError> {
        let rows = sqlx::query(
            "select t.access_id, \
             coalesce(sum(t.bytes_in + t.bytes_out) \
                      filter (where t.day >= $1), 0)::bigint as bytes, \
             max(t.day) as last_day \
             from traffic_daily t \
             join access a on a.id = t.access_id \
             left join client c on c.id = a.client_id \
             where $2::uuid is null or c.owner_id = $2 \
             group by t.access_id",
        )
        .bind(since)
        .bind(owner)
        .fetch_all(pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok((
                    row.try_get("access_id")?,
                    row.try_get("bytes")?,
                    row.try_get("last_day")?,
                ))
            })
            .collect()
    }

    /// What a client has spent across every access it holds.
    pub async fn for_client(pool: &PgPool, client_id: Uuid) -> Result<TrafficTotals, StoreError> {
        let row = sqlx::query(
            "select coalesce(sum(t.bytes_in), 0)::bigint as bytes_in, \
             coalesce(sum(t.bytes_out), 0)::bigint as bytes_out \
             from traffic_daily t join access a on a.id = t.access_id \
             where a.client_id = $1",
        )
        .bind(client_id)
        .fetch_one(pool)
        .await?;
        Ok(TrafficTotals {
            bytes_in: row.try_get("bytes_in")?,
            bytes_out: row.try_get("bytes_out")?,
        })
    }
}
