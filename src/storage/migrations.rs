use sqlx::SqlitePool;

pub async fn run(pool: &SqlitePool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

#[cfg(test)]
mod tests {
    use sqlx::Row;

    use super::*;

    #[tokio::test]
    async fn legacy_route_duplicates_are_quarantined_before_unique_indexes() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::raw_sql(
            r#"
            CREATE TABLE instance_metadata (
                instance_id TEXT PRIMARY KEY NOT NULL,
                protocol TEXT NOT NULL,
                status TEXT NOT NULL,
                database_name TEXT NOT NULL,
                database_username TEXT NOT NULL,
                metadata_json TEXT NOT NULL
            );
            INSERT INTO instance_metadata VALUES
                ('inst_a', 'postgres', 'running', 'shared', 'user_a', '{"status":"running"}'),
                ('inst_b', 'postgres', 'stopped', 'shared', 'user_a', '{"status":"stopped"}'),
                ('inst_c', 'postgres', 'failed', 'shared', 'user_a', '{"status":"failed"}');
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::raw_sql(include_str!(
            "../../migrations/20260709120000_enforce_unique_instance_routes.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();

        let rows = sqlx::query(
            "SELECT instance_id, status, json_extract(metadata_json, '$.status') AS json_status \
             FROM instance_metadata ORDER BY instance_id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(rows[0].get::<String, _>("status"), "running");
        assert_eq!(rows[1].get::<String, _>("status"), "quarantined");
        assert_eq!(rows[2].get::<String, _>("status"), "quarantined");
        assert_eq!(rows[1].get::<String, _>("json_status"), "quarantined");

        let restart_conflict = sqlx::query(
            "UPDATE instance_metadata SET status = 'running' WHERE instance_id = 'inst_b'",
        )
        .execute(&pool)
        .await;
        assert!(restart_conflict.is_err());
    }

    #[tokio::test]
    async fn legacy_valkey_username_duplicates_are_quarantined_before_unique_index() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::raw_sql(
            r#"
            CREATE TABLE instance_metadata (
                instance_id TEXT PRIMARY KEY NOT NULL,
                protocol TEXT NOT NULL,
                status TEXT NOT NULL,
                database_name TEXT NOT NULL,
                database_username TEXT NOT NULL,
                metadata_json TEXT NOT NULL
            );
            CREATE UNIQUE INDEX uq_instance_metadata_protocol_database
                ON instance_metadata(protocol, database_username, database_name)
                WHERE protocol NOT IN ('redis', 'qdrant')
                  AND status <> 'quarantined';
            INSERT INTO instance_metadata VALUES
                ('inst_a', 'valkey', 'running', 'cache_a', 'shared', '{"status":"running"}'),
                ('inst_b', 'valkey', 'stopped', 'cache_b', 'shared', '{"status":"stopped"}');
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::raw_sql(include_str!(
            "../../migrations/20260808120000_add_valkey_route_uniqueness.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();

        let rows =
            sqlx::query("SELECT instance_id, status FROM instance_metadata ORDER BY instance_id")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(rows[0].get::<String, _>("status"), "running");
        assert_eq!(rows[1].get::<String, _>("status"), "quarantined");

        let restart_conflict = sqlx::query(
            "UPDATE instance_metadata SET status = 'running' WHERE instance_id = 'inst_b'",
        )
        .execute(&pool)
        .await;
        assert!(restart_conflict.is_err());
    }

    #[tokio::test]
    async fn desired_state_migration_preserves_stops_and_retries_failures() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::raw_sql(
            r#"
            CREATE TABLE instance_metadata (
                instance_id TEXT PRIMARY KEY NOT NULL,
                status TEXT NOT NULL
            );
            INSERT INTO instance_metadata VALUES
                ('running', 'running'),
                ('booting', 'booting'),
                ('creating', 'creating'),
                ('failed', 'failed'),
                ('stopped', 'stopped'),
                ('quarantined', 'quarantined'),
                ('deleting', 'deleting');
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::raw_sql(include_str!(
            "../../migrations/20260809180000_add_instance_desired_state.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();

        let rows = sqlx::query(
            "SELECT instance_id, desired_state FROM instance_metadata ORDER BY instance_id",
        )
        .fetch_all(&pool)
        .await
        .unwrap()
        .into_iter()
        .map(|row| {
            (
                row.get::<String, _>("instance_id"),
                row.get::<String, _>("desired_state"),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();
        for instance_id in ["booting", "creating", "failed", "running"] {
            assert_eq!(rows.get(instance_id).map(String::as_str), Some("running"));
        }
        for instance_id in ["deleting", "quarantined", "stopped"] {
            assert_eq!(rows.get(instance_id).map(String::as_str), Some("stopped"));
        }
    }
}
