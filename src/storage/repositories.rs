use sqlx::{Row, SqlitePool};

use crate::{
    instances::metadata::{InstanceMetadata, SCHEMA_VERSION},
    shared::backend::BackendEndpoint,
};

#[derive(Debug, Clone)]
pub struct InstanceRepository {
    pool: SqlitePool,
}

impl InstanceRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn list(&self) -> Result<Vec<InstanceMetadata>, RepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT
                instance_metadata.metadata_json,
                instance_route_auth.mariadb_native_password_sha1_stage2,
                instance_route_auth.mariadb_root_password,
                instance_route_auth.mongodb_root_password
            FROM instance_metadata
            LEFT JOIN instance_route_auth
                ON instance_route_auth.instance_id = instance_metadata.instance_id
            ORDER BY instance_metadata.instance_id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let metadata_json: String = row.try_get("metadata_json")?;
                let mut metadata = serde_json::from_str::<InstanceMetadata>(&metadata_json)?;
                metadata.mariadb_native_password_sha1_stage2 =
                    row.try_get("mariadb_native_password_sha1_stage2")?;
                metadata.mariadb_root_password = row.try_get("mariadb_root_password")?;
                metadata.mongodb_root_password = row.try_get("mongodb_root_password")?;
                validate_metadata_schema(&metadata)?;
                Ok(metadata)
            })
            .collect()
    }

    pub async fn get(
        &self,
        instance_id: &str,
    ) -> Result<Option<InstanceMetadata>, RepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT
                instance_metadata.metadata_json,
                instance_route_auth.mariadb_native_password_sha1_stage2,
                instance_route_auth.mariadb_root_password,
                instance_route_auth.mongodb_root_password
            FROM instance_metadata
            LEFT JOIN instance_route_auth
                ON instance_route_auth.instance_id = instance_metadata.instance_id
            WHERE instance_metadata.instance_id = ?1
            LIMIT 1
            "#,
        )
        .bind(instance_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let metadata_json: String = row.try_get("metadata_json")?;
        let mut metadata = serde_json::from_str::<InstanceMetadata>(&metadata_json)?;
        metadata.mariadb_native_password_sha1_stage2 =
            row.try_get("mariadb_native_password_sha1_stage2")?;
        metadata.mariadb_root_password = row.try_get("mariadb_root_password")?;
        metadata.mongodb_root_password = row.try_get("mongodb_root_password")?;
        validate_metadata_schema(&metadata)?;
        Ok(Some(metadata))
    }

    pub async fn upsert(&self, metadata: &InstanceMetadata) -> Result<(), RepositoryError> {
        validate_metadata_schema(metadata)?;
        let backend = BackendColumns::from(&metadata.backend);
        let runtime_kind = metadata.runtime.kind.as_str();
        let limits_json = serde_json::to_string(&metadata.limits)?;
        let metadata_json = serde_json::to_string(metadata)?;

        sqlx::query(
            r#"
            INSERT INTO instance_metadata (
                instance_id,
                schema_version,
                protocol,
                status,
                public_host,
                public_port,
                backend_kind,
                backend_socket_path,
                backend_host,
                backend_port,
                runtime_kind,
                container_name,
                network,
                database_name,
                database_username,
                limits_json,
                metadata_json,
                created_at,
                updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
            ON CONFLICT(instance_id) DO UPDATE SET
                schema_version = excluded.schema_version,
                protocol = excluded.protocol,
                status = excluded.status,
                public_host = excluded.public_host,
                public_port = excluded.public_port,
                backend_kind = excluded.backend_kind,
                backend_socket_path = excluded.backend_socket_path,
                backend_host = excluded.backend_host,
                backend_port = excluded.backend_port,
                runtime_kind = excluded.runtime_kind,
                container_name = excluded.container_name,
                network = excluded.network,
                database_name = excluded.database_name,
                database_username = excluded.database_username,
                limits_json = excluded.limits_json,
                metadata_json = excluded.metadata_json,
                created_at = excluded.created_at,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&metadata.instance_id)
        .bind(i64::from(metadata.schema_version))
        .bind(metadata.protocol.to_string())
        .bind(metadata.status.as_str())
        .bind(&metadata.public.host)
        .bind(i64::from(metadata.public.port))
        .bind(backend.kind)
        .bind(backend.socket_path)
        .bind(backend.host)
        .bind(backend.port.map(i64::from))
        .bind(runtime_kind)
        .bind(&metadata.runtime.container_name)
        .bind(&metadata.runtime.network)
        .bind(&metadata.database.name)
        .bind(&metadata.database.username)
        .bind(limits_json)
        .bind(metadata_json)
        .bind(&metadata.created_at)
        .bind(&metadata.updated_at)
        .execute(&self.pool)
        .await?;

        if metadata.mariadb_native_password_sha1_stage2.is_some()
            || metadata.mariadb_root_password.is_some()
            || metadata.mongodb_root_password.is_some()
        {
            sqlx::query(
                r#"
                INSERT INTO instance_route_auth (
                    instance_id,
                    mariadb_native_password_sha1_stage2,
                    mariadb_root_password,
                    mongodb_root_password,
                    updated_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(instance_id) DO UPDATE SET
                    mariadb_native_password_sha1_stage2 = excluded.mariadb_native_password_sha1_stage2,
                    mariadb_root_password = excluded.mariadb_root_password,
                    mongodb_root_password = excluded.mongodb_root_password,
                    updated_at = excluded.updated_at
                "#,
            )
            .bind(&metadata.instance_id)
            .bind(&metadata.mariadb_native_password_sha1_stage2)
            .bind(&metadata.mariadb_root_password)
            .bind(&metadata.mongodb_root_password)
            .bind(&metadata.updated_at)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query("DELETE FROM instance_route_auth WHERE instance_id = ?1")
                .bind(&metadata.instance_id)
                .execute(&self.pool)
                .await?;
        }

        Ok(())
    }

    pub async fn delete(&self, instance_id: &str) -> Result<bool, RepositoryError> {
        sqlx::query("DELETE FROM instance_route_auth WHERE instance_id = ?1")
            .bind(instance_id)
            .execute(&self.pool)
            .await?;

        let result = sqlx::query("DELETE FROM instance_metadata WHERE instance_id = ?1")
            .bind(instance_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[derive(Debug)]
struct BackendColumns {
    kind: &'static str,
    socket_path: Option<String>,
    host: Option<String>,
    port: Option<u16>,
}

impl From<&BackendEndpoint> for BackendColumns {
    fn from(endpoint: &BackendEndpoint) -> Self {
        match endpoint {
            BackendEndpoint::UnixSocket { socket_path } => Self {
                kind: "unix_socket",
                socket_path: Some(socket_path.clone()),
                host: None,
                port: None,
            },
            BackendEndpoint::DockerTcp { host, port } => Self {
                kind: "docker_tcp",
                socket_path: None,
                host: Some(host.clone()),
                port: Some(*port),
            },
        }
    }
}

fn validate_metadata_schema(metadata: &InstanceMetadata) -> Result<(), RepositoryError> {
    if metadata.schema_version == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(RepositoryError::UnsupportedSchema {
            actual: metadata.schema_version,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("sqlite query failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("metadata json serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("metadata schema version {actual} is not supported")]
    UnsupportedSchema { actual: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        instances::metadata::{
            DatabaseIdentity, InstanceStatus, PublicEndpoint, RuntimeKind, RuntimeMetadata,
        },
        shared::{limits::InstanceLimits, protocol::Protocol},
        storage::sqlite,
    };

    #[tokio::test]
    async fn upserts_and_lists_instance_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::new(pool);
        let metadata = sample_metadata();

        repository.upsert(&metadata).await.unwrap();
        let instances = repository.list().await.unwrap();

        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].instance_id, "inst_abc");
        assert_eq!(instances[0].database.username, "app");
    }

    #[tokio::test]
    async fn get_returns_none_for_missing_instance() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::new(pool);

        let metadata = repository.get("missing").await.unwrap();

        assert!(metadata.is_none());
    }

    #[tokio::test]
    async fn delete_removes_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::new(pool);
        let metadata = sample_metadata();
        repository.upsert(&metadata).await.unwrap();

        assert!(repository.delete("inst_abc").await.unwrap());
        assert!(repository.get("inst_abc").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn persists_hidden_mariadb_auth_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::new(pool);
        let mut metadata = sample_metadata();
        metadata.protocol = Protocol::Mariadb;
        metadata.mariadb_native_password_sha1_stage2 =
            Some("0123456789abcdef0123456789abcdef01234567".to_string());
        metadata.mariadb_root_password = Some("internal-root-password".to_string());

        repository.upsert(&metadata).await.unwrap();

        let loaded = repository.get("inst_abc").await.unwrap().unwrap();
        assert_eq!(
            loaded.mariadb_native_password_sha1_stage2.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!(
            loaded.mariadb_root_password.as_deref(),
            Some("internal-root-password")
        );
        let public_json = serde_json::to_string(&loaded).unwrap();
        assert!(!public_json.contains("mariadb_native_password_sha1_stage2"));
        assert!(!public_json.contains("mariadb_root_password"));
    }

    #[tokio::test]
    async fn persists_hidden_mongodb_root_password() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::new(pool);
        let mut metadata = sample_metadata();
        metadata.protocol = Protocol::Mongodb;
        metadata.mongodb_root_password = Some("internal-mongo-root-password".to_string());

        repository.upsert(&metadata).await.unwrap();

        let loaded = repository.get("inst_abc").await.unwrap().unwrap();
        assert_eq!(
            loaded.mongodb_root_password.as_deref(),
            Some("internal-mongo-root-password")
        );
        let public_json = serde_json::to_string(&loaded).unwrap();
        assert!(!public_json.contains("mongodb_root_password"));
    }

    fn sample_metadata() -> InstanceMetadata {
        InstanceMetadata {
            schema_version: SCHEMA_VERSION,
            instance_id: "inst_abc".to_string(),
            protocol: Protocol::Postgres,
            status: InstanceStatus::Running,
            public: PublicEndpoint {
                host: "db.example.com".to_string(),
                port: 5433,
            },
            backend: BackendEndpoint::DockerTcp {
                host: "dbe-postgres-inst-abc".to_string(),
                port: 5432,
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: "dbe-postgres-inst-abc".to_string(),
                network: "databases-everywhere".to_string(),
            },
            database: DatabaseIdentity {
                name: "app_db".to_string(),
                username: "app".to_string(),
            },
            route_key_sha256: None,
            mariadb_native_password_sha1_stage2: None,
            mariadb_root_password: None,
            mongodb_root_password: None,
            limits: InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "2026-01-01T12:00:00Z".to_string(),
            updated_at: "2026-01-01T12:00:00Z".to_string(),
        }
    }
}
