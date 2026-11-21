use sqlx::{Row, SqlitePool};

use crate::server::monitoring::{ActivityBucket, OperationCounts};

pub const MAX_HISTORY_ROWS: u16 = 1_440;

const BUCKET_COLUMNS: &str =
    "instance_id, instance_generation, bucket_start_unix, duration_seconds,
    stats_epoch, gap, operations_observed,
    accepted_read, accepted_write, accepted_ddl, accepted_other,
    rejected_read, rejected_write, rejected_ddl, rejected_other,
    active_connections, opened_connections, rx_bytes, tx_bytes,
    cpu_time_micros, peak_query_memory_bytes";

#[derive(Debug, Clone)]
pub struct ActivityRepository {
    pool: SqlitePool,
}

impl ActivityRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Stores a sampler batch atomically. Replaying the same batch replaces
    /// the same minute rows instead of adding the counters twice.
    pub async fn save(&self, buckets: &[ActivityBucket]) -> Result<(), ActivityStorageError> {
        if buckets.is_empty() {
            return Ok(());
        }

        // Keep each statement below 999 bound parameters, including the input position.
        let mut transaction = self.pool.begin().await?;
        for batch in buckets.chunks(32) {
            let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(format!(
                "WITH incoming (position, {BUCKET_COLUMNS}) AS ("
            ));
            query.push_values(batch.iter().enumerate(), |mut row, (position, bucket)| {
                row.push_bind(position as i64)
                    .push_bind(&bucket.instance_id)
                    .push_bind(&bucket.instance_generation)
                    .push_bind(bucket.bucket_start_unix)
                    .push_bind(i64::from(bucket.duration_seconds))
                    .push_bind(&bucket.stats_epoch)
                    .push_bind(bucket.gap)
                    .push_bind(bucket.operations_observed)
                    .push_bind(clamp_to_i64(bucket.accepted.read))
                    .push_bind(clamp_to_i64(bucket.accepted.write))
                    .push_bind(clamp_to_i64(bucket.accepted.ddl))
                    .push_bind(clamp_to_i64(bucket.accepted.other))
                    .push_bind(clamp_to_i64(bucket.rejected.read))
                    .push_bind(clamp_to_i64(bucket.rejected.write))
                    .push_bind(clamp_to_i64(bucket.rejected.ddl))
                    .push_bind(clamp_to_i64(bucket.rejected.other))
                    .push_bind(clamp_to_i64(bucket.active_connections))
                    .push_bind(clamp_to_i64(bucket.opened_connections))
                    .push_bind(clamp_to_i64(bucket.rx_bytes))
                    .push_bind(clamp_to_i64(bucket.tx_bytes))
                    .push_bind(bucket.cpu_time_micros.map(clamp_to_i64))
                    .push_bind(bucket.peak_query_memory_bytes.map(clamp_to_i64));
            });
            // Apply repeated keys in input order so the last sample wins on replay.
            query.push(format_args!(
                r#")
                INSERT INTO tenant_activity_buckets ({BUCKET_COLUMNS})
                SELECT {BUCKET_COLUMNS} FROM incoming
                WHERE EXISTS (
                    SELECT 1 FROM instance_metadata
                    WHERE instance_id = incoming.instance_id
                      AND created_at = incoming.instance_generation
                )
                ORDER BY position
                ON CONFLICT(instance_id, instance_generation, bucket_start_unix) DO UPDATE SET
                    duration_seconds = excluded.duration_seconds,
                    stats_epoch = excluded.stats_epoch,
                    gap = excluded.gap,
                    operations_observed = excluded.operations_observed,
                    accepted_read = excluded.accepted_read,
                    accepted_write = excluded.accepted_write,
                    accepted_ddl = excluded.accepted_ddl,
                    accepted_other = excluded.accepted_other,
                    rejected_read = excluded.rejected_read,
                    rejected_write = excluded.rejected_write,
                    rejected_ddl = excluded.rejected_ddl,
                    rejected_other = excluded.rejected_other,
                    active_connections = excluded.active_connections,
                    opened_connections = excluded.opened_connections,
                    rx_bytes = excluded.rx_bytes,
                    tx_bytes = excluded.tx_bytes,
                    cpu_time_micros = excluded.cpu_time_micros,
                    peak_query_memory_bytes = excluded.peak_query_memory_bytes
                "#
            ));
            query.build().execute(&mut *transaction).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Returns up to one day of buckets in chronological order. `before` is
    /// exclusive and supports stable backwards pagination.
    pub async fn history(
        &self,
        instance_id: &str,
        instance_generation: &str,
        before: Option<i64>,
        limit: u16,
    ) -> Result<Vec<ActivityBucket>, ActivityStorageError> {
        let limit = limit.clamp(1, MAX_HISTORY_ROWS);
        let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(format!(
            "SELECT {BUCKET_COLUMNS} FROM tenant_activity_buckets WHERE instance_id = "
        ));
        query
            .push_bind(instance_id)
            .push(" AND instance_generation = ")
            .push_bind(instance_generation);
        if let Some(before) = before {
            query.push(" AND bucket_start_unix < ").push_bind(before);
        }
        let rows = query
            .push(" ORDER BY bucket_start_unix DESC LIMIT ")
            .push_bind(i64::from(limit))
            .build()
            .fetch_all(&self.pool)
            .await?;

        let mut buckets = rows
            .into_iter()
            .map(row_to_bucket)
            .collect::<Result<Vec<_>, _>>()?;
        buckets.reverse();
        Ok(buckets)
    }
}

fn row_to_bucket(row: sqlx::sqlite::SqliteRow) -> Result<ActivityBucket, ActivityStorageError> {
    Ok(ActivityBucket {
        instance_id: row.try_get("instance_id")?,
        instance_generation: row.try_get("instance_generation")?,
        bucket_start_unix: row.try_get("bucket_start_unix")?,
        duration_seconds: as_u32(row.try_get("duration_seconds")?, "duration_seconds")?,
        stats_epoch: row.try_get("stats_epoch")?,
        gap: row.try_get("gap")?,
        operations_observed: row.try_get("operations_observed")?,
        accepted: OperationCounts {
            read: as_u64(row.try_get("accepted_read")?, "accepted_read")?,
            write: as_u64(row.try_get("accepted_write")?, "accepted_write")?,
            ddl: as_u64(row.try_get("accepted_ddl")?, "accepted_ddl")?,
            other: as_u64(row.try_get("accepted_other")?, "accepted_other")?,
        },
        rejected: OperationCounts {
            read: as_u64(row.try_get("rejected_read")?, "rejected_read")?,
            write: as_u64(row.try_get("rejected_write")?, "rejected_write")?,
            ddl: as_u64(row.try_get("rejected_ddl")?, "rejected_ddl")?,
            other: as_u64(row.try_get("rejected_other")?, "rejected_other")?,
        },
        active_connections: as_u64(row.try_get("active_connections")?, "active_connections")?,
        opened_connections: as_u64(row.try_get("opened_connections")?, "opened_connections")?,
        rx_bytes: as_u64(row.try_get("rx_bytes")?, "rx_bytes")?,
        tx_bytes: as_u64(row.try_get("tx_bytes")?, "tx_bytes")?,
        cpu_time_micros: optional_u64(row.try_get("cpu_time_micros")?, "cpu_time_micros")?,
        peak_query_memory_bytes: optional_u64(
            row.try_get("peak_query_memory_bytes")?,
            "peak_query_memory_bytes",
        )?,
    })
}

fn clamp_to_i64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

fn as_u64(value: i64, column: &'static str) -> Result<u64, ActivityStorageError> {
    u64::try_from(value).map_err(|_| ActivityStorageError::InvalidValue { column })
}

fn optional_u64(
    value: Option<i64>,
    column: &'static str,
) -> Result<Option<u64>, ActivityStorageError> {
    value.map(|value| as_u64(value, column)).transpose()
}

fn as_u32(value: i64, column: &'static str) -> Result<u32, ActivityStorageError> {
    u32::try_from(value).map_err(|_| ActivityStorageError::InvalidValue { column })
}

#[derive(Debug, thiserror::Error)]
pub enum ActivityStorageError {
    #[error("sqlite activity query failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("activity history contains an invalid {column} value")]
    InvalidValue { column: &'static str },
}

#[cfg(test)]
mod tests {
    use sqlx::sqlite::SqlitePoolOptions;

    use super::*;

    async fn repository() -> (SqlitePool, ActivityRepository) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect should succeed");
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .expect("execute should succeed");
        sqlx::raw_sql(
            "CREATE TABLE instance_metadata (instance_id TEXT PRIMARY KEY NOT NULL, created_at TEXT NOT NULL);",
        )
            .execute(&pool)
            .await
            .expect("execute should succeed");
        sqlx::raw_sql(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/20260901120000_create_tenant_activity.sql"
        )))
        .execute(&pool)
        .await
        .expect("execute should succeed");
        sqlx::raw_sql(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/20261121120000_optimize_activity_retention.sql"
        )))
        .execute(&pool)
        .await
        .expect("execute should succeed");
        (pool.clone(), ActivityRepository::new(pool))
    }

    async fn seed(pool: &SqlitePool, instance_id: &str, generation: &str) {
        sqlx::query("INSERT INTO instance_metadata (instance_id, created_at) VALUES (?1, ?2)")
            .bind(instance_id)
            .bind(generation)
            .execute(pool)
            .await
            .expect("execute should succeed");
    }

    fn bucket(instance_id: &str, start: i64) -> ActivityBucket {
        ActivityBucket {
            instance_id: instance_id.to_string(),
            instance_generation: "generation-a".to_string(),
            bucket_start_unix: start,
            duration_seconds: 60,
            stats_epoch: "epoch-a".to_string(),
            gap: false,
            operations_observed: true,
            accepted: OperationCounts {
                read: start as u64,
                ..OperationCounts::default()
            },
            rejected: OperationCounts::default(),
            active_connections: 1,
            opened_connections: 2,
            rx_bytes: 3,
            tx_bytes: 4,
            cpu_time_micros: None,
            peak_query_memory_bytes: Some(0),
        }
    }

    #[tokio::test]
    async fn save_is_idempotent_and_history_is_chronological() -> anyhow::Result<()> {
        let (pool, repository) = repository().await;
        seed(&pool, "tenant-a", "generation-a").await;
        let mut first = bucket("tenant-a", 60);
        repository.save(&[first.clone()]).await?;
        first.accepted.read = 9;
        let mut earlier = first.clone();
        earlier.accepted.read = 3;
        repository.save(&[earlier, first]).await?;
        repository
            .save(&[bucket("tenant-a", 120), bucket("tenant-a", 180)])
            .await?;

        let history = repository
            .history("tenant-a", "generation-a", Some(180), 10)
            .await?;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].bucket_start_unix, 60);
        assert_eq!(history[0].accepted.read, 9);
        assert!(history[0].operations_observed);
        assert_eq!(history[1].bucket_start_unix, 120);
        assert_eq!(history[0].cpu_time_micros, None);
        assert_eq!(history[0].peak_query_memory_bytes, Some(0));

        Ok(())
    }

    #[tokio::test]
    async fn later_chunk_failure_rolls_back_the_whole_batch() -> anyhow::Result<()> {
        let (pool, repository) = repository().await;
        seed(&pool, "tenant-a", "generation-a").await;
        let mut samples: Vec<_> = (0..64).map(|n| bucket("tenant-a", n * 60)).collect();
        samples[40].duration_seconds = 0;
        assert!(repository.save(&samples).await.is_err());
        assert!(
            repository
                .history("tenant-a", "generation-a", None, 1)
                .await?
                .is_empty()
        );
        Ok(())
    }

    #[tokio::test]
    async fn late_buckets_use_the_newest_stored_timestamp_for_retention() -> anyhow::Result<()> {
        let (pool, repository) = repository().await;
        seed(&pool, "tenant-a", "generation-a").await;
        repository
            .save(&[
                bucket("tenant-a", 90_000),
                bucket("tenant-a", 3_599),
                bucket("tenant-a", 3_600),
            ])
            .await?;

        let starts: Vec<i64> = sqlx::query_scalar(
            "SELECT bucket_start_unix FROM tenant_activity_buckets ORDER BY bucket_start_unix",
        )
        .fetch_all(&pool)
        .await?;
        assert_eq!(starts, [3_600, 90_000]);

        Ok(())
    }

    #[tokio::test]
    async fn retention_and_foreign_key_are_enforced_by_sqlite() -> anyhow::Result<()> {
        let (pool, repository) = repository().await;
        seed(&pool, "tenant-a", "generation-a").await;
        let buckets = (0..1_445)
            .map(|index| bucket("tenant-a", i64::from(index) * 60))
            .collect::<Vec<_>>();
        repository.save(&buckets).await?;

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tenant_activity_buckets WHERE instance_id = 'tenant-a'",
        )
        .fetch_one(&pool)
        .await?;
        let oldest: i64 = sqlx::query_scalar(
            "SELECT MIN(bucket_start_unix) FROM tenant_activity_buckets WHERE instance_id = 'tenant-a'",
        )
        .fetch_one(&pool)
        .await
        ?;
        assert_eq!(count, i64::from(MAX_HISTORY_ROWS));
        assert_eq!(oldest, 5 * 60);

        repository.save(&[bucket("tenant-a", 3 * 86_400)]).await?;
        let stale: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tenant_activity_buckets WHERE instance_id = 'tenant-a' AND bucket_start_unix < 172800",
        )
        .fetch_one(&pool)
        .await
        ?;
        assert_eq!(stale, 0);

        sqlx::query("DELETE FROM instance_metadata WHERE instance_id = 'tenant-a'")
            .execute(&pool)
            .await?;
        let after_delete: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_activity_buckets")
            .fetch_one(&pool)
            .await?;
        assert_eq!(after_delete, 0);

        Ok(())
    }

    #[tokio::test]
    async fn deleted_instance_does_not_poison_the_batch() -> anyhow::Result<()> {
        let (pool, repository) = repository().await;
        seed(&pool, "tenant-live", "generation-a").await;

        repository
            .save(&[bucket("tenant-deleted", 60), bucket("tenant-live", 60)])
            .await?;

        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT instance_id FROM tenant_activity_buckets ORDER BY instance_id",
        )
        .fetch_all(&pool)
        .await?;
        assert_eq!(rows, ["tenant-live"]);

        Ok(())
    }

    #[tokio::test]
    async fn delayed_bucket_cannot_attach_to_a_recreated_instance() -> anyhow::Result<()> {
        let (pool, repository) = repository().await;
        seed(&pool, "tenant-a", "generation-a").await;
        let delayed = bucket("tenant-a", 60);

        sqlx::query("DELETE FROM instance_metadata WHERE instance_id = 'tenant-a'")
            .execute(&pool)
            .await?;
        seed(&pool, "tenant-a", "generation-b").await;
        repository.save(&[delayed]).await?;

        assert!(
            repository
                .history("tenant-a", "generation-b", None, 10)
                .await?
                .is_empty()
        );

        Ok(())
    }
}
