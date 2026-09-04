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

        sqlx::raw_sql(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/20260709120000_enforce_unique_instance_routes.sql"
        )))
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

        sqlx::raw_sql(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/20260808120000_add_valkey_route_uniqueness.sql"
        )))
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

        sqlx::raw_sql(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/20260809180000_add_instance_desired_state.sql"
        )))
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

    #[tokio::test]
    async fn disk_limit_block_migration_does_not_conflate_operator_stops() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::raw_sql(
            r#"
            CREATE TABLE instance_metadata (
                instance_id TEXT PRIMARY KEY NOT NULL,
                status TEXT NOT NULL
            );
            INSERT INTO instance_metadata VALUES
                ('running', 'running'),
                ('stopped', 'stopped'),
                ('failed', 'failed');
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::raw_sql(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/20260809190000_add_disk_limit_blocked.sql"
        )))
        .execute(&pool)
        .await
        .unwrap();

        let blocked = sqlx::query("SELECT disk_limit_blocked FROM instance_metadata")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert!(
            blocked
                .iter()
                .all(|row| !row.get::<bool, _>("disk_limit_blocked"))
        );
    }

    #[tokio::test]
    async fn placement_migration_preserves_legacy_runtime_and_restricts_deletion() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(
            r#"
            CREATE TABLE instance_metadata (
                instance_id TEXT PRIMARY KEY NOT NULL,
                schema_version INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                status TEXT NOT NULL,
                public_host TEXT NOT NULL,
                public_port INTEGER NOT NULL,
                backend_kind TEXT NOT NULL,
                backend_socket_path TEXT,
                backend_host TEXT,
                backend_port INTEGER,
                runtime_kind TEXT NOT NULL,
                container_name TEXT NOT NULL,
                network TEXT NOT NULL,
                database_name TEXT NOT NULL,
                database_username TEXT NOT NULL,
                limits_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT INTO instance_metadata VALUES (
                'legacy_one', 1, 'postgres', 'running', 'db.example.test', 5432,
                'unix_socket', '/run/legacy/.s.PGSQL.5432', NULL, NULL,
                'docker', 'dbe-postgres-legacy-one', 'none', 'app', 'app_user',
                '{"cpu_cores":2.0,"memory_mib":2048,"disk_mib":8192,"disk_enforced":true,"disk_enforcement_method":"fusequota"}',
                '{"schema_version":1,"instance_id":"legacy_one","protocol":"postgres","status":"running","database_version":{"current":"18.4","error":null}}',
                '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z'
            );
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        for status in [
            "creating",
            "booting",
            "stopped",
            "failed",
            "quarantined",
            "deleting",
        ] {
            let instance_id = format!("legacy_{status}");
            sqlx::query(
                r#"
                INSERT INTO instance_metadata VALUES (
                    ?1, 1, 'postgres', ?2, 'db.example.test', 5432,
                    'unix_socket', ?3, NULL, NULL,
                    'docker', ?4, 'none', ?5, ?6,
                    '{"cpu_cores":1.0,"memory_mib":1024,"disk_mib":4096,"disk_enforced":true,"disk_enforcement_method":"fusequota"}',
                    ?7, '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z'
                )
                "#,
            )
            .bind(&instance_id)
            .bind(status)
            .bind(format!("/run/{instance_id}/.s.PGSQL.5432"))
            .bind(format!("dbe-postgres-{instance_id}"))
            .bind(format!("db_{status}"))
            .bind(format!("user_{status}"))
            .bind(format!(
                r#"{{"schema_version":1,"instance_id":"{instance_id}","protocol":"postgres","status":"{status}"}}"#
            ))
            .execute(&pool)
            .await
            .unwrap();
        }

        sqlx::raw_sql(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/migrations/20260827120000_add_engine_runtimes.sql"
        )))
        .execute(&pool)
        .await
        .unwrap();

        let placement: (String, String) = sqlx::query_as(
            "SELECT deployment_mode, runtime_id FROM instance_metadata WHERE instance_id = 'legacy_one'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            placement,
            ("dedicated".to_string(), "legacy_one".to_string())
        );
        let migrated_statuses = sqlx::query(
            r#"
            SELECT instance.instance_id, instance.status AS instance_status,
                   instance.deployment_mode, instance.runtime_id,
                   runtime.status AS runtime_status
            FROM instance_metadata AS instance
            JOIN engine_runtimes AS runtime ON runtime.runtime_id = instance.runtime_id
            ORDER BY instance.instance_id
            "#,
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(migrated_statuses.len(), 7);
        for row in migrated_statuses {
            let instance_id = row.get::<String, _>("instance_id");
            let expected = if instance_id == "legacy_one" {
                "running"
            } else {
                instance_id.strip_prefix("legacy_").unwrap()
            };
            assert_eq!(row.get::<String, _>("instance_status"), expected);
            assert_eq!(row.get::<String, _>("runtime_status"), expected);
            assert_eq!(row.get::<String, _>("deployment_mode"), "dedicated");
            assert_eq!(row.get::<String, _>("runtime_id"), instance_id);
        }
        let runtime: (String, String, String, String, String, Option<String>) = sqlx::query_as(
            r#"
            SELECT protocol, runtime_kind, container_name, network, backend_socket_path,
                   database_version
            FROM engine_runtimes WHERE runtime_id = 'legacy_one'
            "#,
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            runtime,
            (
                "postgres".to_string(),
                "docker".to_string(),
                "dbe-postgres-legacy-one".to_string(),
                "none".to_string(),
                "/run/legacy/.s.PGSQL.5432".to_string(),
                Some("18.4".to_string())
            )
        );
        assert!(
            sqlx::query("DELETE FROM engine_runtimes WHERE runtime_id = 'legacy_one'")
                .execute(&pool)
                .await
                .is_err()
        );
    }
}
