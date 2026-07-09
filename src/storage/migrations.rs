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
}
