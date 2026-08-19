use std::path::Path;

use sqlx::{Row, SqlitePool};

use crate::{
    instances::metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus, SCHEMA_VERSION},
    shared::{backend::BackendEndpoint, protocol::Protocol},
    storage::secrets::{SecretStore, SecretStoreError},
};

mod auth_hardening;
mod compatibility;
mod protected_secrets;

pub(crate) use compatibility::CompatibilityAttestation;
pub use protected_secrets::{
    DaemonInstanceLoad, ProtectedSecretField, ProtectedSecretIncident, ProtectedSecretRepair,
};

#[derive(Debug, Clone)]
pub struct InstanceRepository {
    pool: SqlitePool,
    secrets: Option<SecretStore>,
}

impl InstanceRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            secrets: None,
        }
    }

    pub fn encrypted(pool: SqlitePool, metadata_root: &Path) -> Result<Self, RepositoryError> {
        Ok(Self {
            pool,
            secrets: Some(SecretStore::open_or_create(metadata_root)?),
        })
    }

    pub async fn list(&self) -> Result<Vec<InstanceMetadata>, RepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT
                instance_metadata.metadata_json,
                instance_metadata.desired_state,
                instance_metadata.disk_limit_blocked,
                instance_route_auth.mariadb_native_password_sha1_stage2,
                instance_route_auth.mariadb_root_password,
                instance_route_auth.mysql_native_password_sha1_stage2,
                instance_route_auth.mysql_root_password,
                instance_route_auth.mongodb_root_password,
                instance_route_auth.postgres_admin_password,
                instance_route_auth.tenant_password
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
                self.load_desired_state(&mut metadata, &row)?;
                self.load_disk_limit_blocked(&mut metadata, &row)?;
                self.load_route_auth(&mut metadata, &row)?;
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
                instance_metadata.desired_state,
                instance_metadata.disk_limit_blocked,
                instance_route_auth.mariadb_native_password_sha1_stage2,
                instance_route_auth.mariadb_root_password,
                instance_route_auth.mysql_native_password_sha1_stage2,
                instance_route_auth.mysql_root_password,
                instance_route_auth.mongodb_root_password,
                instance_route_auth.postgres_admin_password,
                instance_route_auth.tenant_password
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
        self.load_desired_state(&mut metadata, &row)?;
        self.load_disk_limit_blocked(&mut metadata, &row)?;
        self.load_route_auth(&mut metadata, &row)?;
        validate_metadata_schema(&metadata)?;
        Ok(Some(metadata))
    }

    pub async fn upsert(&self, metadata: &InstanceMetadata) -> Result<(), RepositoryError> {
        self.upsert_with_protected_secret_replacement(metadata, false)
            .await
    }

    /// Atomically replaces protected route authentication and clears an
    /// existing recovery marker. Callers must verify the replacement against
    /// the live database before using this path.
    pub(crate) async fn upsert_recovered_protected_secrets(
        &self,
        metadata: &InstanceMetadata,
    ) -> Result<(), RepositoryError> {
        self.upsert_with_protected_secret_replacement(metadata, true)
            .await
    }

    async fn upsert_with_protected_secret_replacement(
        &self,
        metadata: &InstanceMetadata,
        clear_protected_secret_recovery: bool,
    ) -> Result<(), RepositoryError> {
        validate_metadata_schema(metadata)?;
        if clear_protected_secret_recovery {
            validate_complete_protected_secret_recovery(metadata)?;
        }
        let backend = BackendColumns::from(&metadata.backend);
        let runtime_kind = metadata.runtime.kind.as_str();
        let limits_json = serde_json::to_string(&metadata.limits)?;
        let metadata_json = serde_json::to_string(metadata)?;
        let mariadb_native_password_sha1_stage2 = self.protect_route_secret(
            "mariadb_native_password_sha1_stage2",
            &metadata.instance_id,
            metadata.mariadb_native_password_sha1_stage2.as_deref(),
        )?;
        let mariadb_root_password = self.protect_route_secret(
            "mariadb_root_password",
            &metadata.instance_id,
            metadata.mariadb_root_password.as_deref(),
        )?;
        let mysql_native_password_sha1_stage2 = self.protect_route_secret(
            "mysql_native_password_sha1_stage2",
            &metadata.instance_id,
            metadata.mysql_native_password_sha1_stage2.as_deref(),
        )?;
        let mysql_root_password = self.protect_route_secret(
            "mysql_root_password",
            &metadata.instance_id,
            metadata.mysql_root_password.as_deref(),
        )?;
        let mongodb_root_password = self.protect_route_secret(
            "mongodb_root_password",
            &metadata.instance_id,
            metadata.mongodb_root_password.as_deref(),
        )?;
        let postgres_admin_password = self.protect_route_secret(
            "postgres_admin_password",
            &metadata.instance_id,
            metadata.postgres_admin_password.as_deref(),
        )?;
        let tenant_password = self.protect_route_secret(
            "tenant_password",
            &metadata.instance_id,
            metadata.tenant_password.as_deref(),
        )?;
        let mut transaction = self.pool.begin().await?;
        let preserve_route_auth = if clear_protected_secret_recovery {
            false
        } else {
            sqlx::query_scalar::<_, bool>(
                "SELECT protected_secret_recovery_required FROM instance_metadata WHERE instance_id = ?1",
            )
            .bind(&metadata.instance_id)
            .fetch_optional(&mut *transaction)
            .await?
            .unwrap_or(false)
        };

        sqlx::query(
            r#"
            INSERT INTO instance_metadata (
                instance_id,
                schema_version,
                protocol,
                status,
                desired_state,
                disk_limit_blocked,
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
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)
            ON CONFLICT(instance_id) DO UPDATE SET
                schema_version = excluded.schema_version,
                protocol = excluded.protocol,
                status = excluded.status,
                desired_state = excluded.desired_state,
                disk_limit_blocked = excluded.disk_limit_blocked,
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
        .bind(metadata.desired_state.as_str())
        .bind(metadata.disk_limit_blocked)
        .bind(&metadata.public.host)
        .bind(i64::from(metadata.public.port))
        .bind(backend.kind)
        .bind(backend.socket_path)
        .bind(backend.host)
        .bind(backend.port.map(i64::from))
        .bind(runtime_kind)
        .bind(&metadata.runtime.container_name)
        .bind(&metadata.runtime.network_mode)
        .bind(&metadata.database.name)
        .bind(&metadata.database.username)
        .bind(limits_json)
        .bind(metadata_json)
        .bind(&metadata.created_at)
        .bind(&metadata.updated_at)
            .execute(&mut *transaction)
            .await?;

        if !preserve_route_auth
            && (metadata.mariadb_native_password_sha1_stage2.is_some()
                || metadata.mariadb_root_password.is_some()
                || metadata.mysql_native_password_sha1_stage2.is_some()
                || metadata.mysql_root_password.is_some()
                || metadata.mongodb_root_password.is_some()
                || metadata.postgres_admin_password.is_some()
                || metadata.tenant_password.is_some())
        {
            sqlx::query(
                r#"
                INSERT INTO instance_route_auth (
                    instance_id,
                    mariadb_native_password_sha1_stage2,
                    mariadb_root_password,
                    mysql_native_password_sha1_stage2,
                    mysql_root_password,
                    mongodb_root_password,
                    postgres_admin_password,
                    tenant_password,
                    updated_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ON CONFLICT(instance_id) DO UPDATE SET
                    mariadb_native_password_sha1_stage2 = excluded.mariadb_native_password_sha1_stage2,
                    mariadb_root_password = excluded.mariadb_root_password,
                    mysql_native_password_sha1_stage2 = excluded.mysql_native_password_sha1_stage2,
                    mysql_root_password = excluded.mysql_root_password,
                    mongodb_root_password = excluded.mongodb_root_password,
                    postgres_admin_password = excluded.postgres_admin_password,
                    tenant_password = excluded.tenant_password,
                    updated_at = excluded.updated_at
                "#,
            )
            .bind(&metadata.instance_id)
            .bind(&mariadb_native_password_sha1_stage2)
            .bind(&mariadb_root_password)
            .bind(&mysql_native_password_sha1_stage2)
            .bind(&mysql_root_password)
            .bind(&mongodb_root_password)
            .bind(&postgres_admin_password)
            .bind(&tenant_password)
            .bind(&metadata.updated_at)
            .execute(&mut *transaction)
            .await?;
        } else if !preserve_route_auth {
            sqlx::query("DELETE FROM instance_route_auth WHERE instance_id = ?1")
                .bind(&metadata.instance_id)
                .execute(&mut *transaction)
                .await?;
        }

        if clear_protected_secret_recovery {
            sqlx::query(
                "UPDATE instance_metadata SET protected_secret_recovery_required = 0 WHERE instance_id = ?1",
            )
            .bind(&metadata.instance_id)
            .execute(&mut *transaction)
            .await?;
        }

        transaction.commit().await?;
        Ok(())
    }

    fn load_desired_state(
        &self,
        metadata: &mut InstanceMetadata,
        row: &sqlx::sqlite::SqliteRow,
    ) -> Result<(), RepositoryError> {
        let value: String = row.try_get("desired_state")?;
        metadata.desired_state = DesiredInstanceState::parse(&value).ok_or_else(|| {
            RepositoryError::InvalidDesiredState {
                instance_id: metadata.instance_id.clone(),
                value,
            }
        })?;
        Ok(())
    }

    fn load_disk_limit_blocked(
        &self,
        metadata: &mut InstanceMetadata,
        row: &sqlx::sqlite::SqliteRow,
    ) -> Result<(), RepositoryError> {
        metadata.disk_limit_blocked = row.try_get("disk_limit_blocked")?;
        Ok(())
    }

    pub async fn rewrite_protected_route_auth(
        &self,
        metadata: &[InstanceMetadata],
    ) -> Result<usize, RepositoryError> {
        if self.secrets.is_none() {
            return Ok(0);
        }
        let mut rewritten = 0;
        for metadata in metadata.iter().filter(|metadata| {
            metadata.mariadb_native_password_sha1_stage2.is_some()
                || metadata.mariadb_root_password.is_some()
                || metadata.mysql_native_password_sha1_stage2.is_some()
                || metadata.mysql_root_password.is_some()
                || metadata.mongodb_root_password.is_some()
                || metadata.postgres_admin_password.is_some()
                || metadata.tenant_password.is_some()
        }) {
            self.upsert(metadata).await?;
            rewritten += 1;
        }
        Ok(rewritten)
    }

    fn load_route_auth(
        &self,
        metadata: &mut InstanceMetadata,
        row: &sqlx::sqlite::SqliteRow,
    ) -> Result<(), RepositoryError> {
        metadata.mariadb_native_password_sha1_stage2 = self.unprotect_route_secret(
            "mariadb_native_password_sha1_stage2",
            &metadata.instance_id,
            row.try_get("mariadb_native_password_sha1_stage2")?,
        )?;
        metadata.mariadb_root_password = self.unprotect_route_secret(
            "mariadb_root_password",
            &metadata.instance_id,
            row.try_get("mariadb_root_password")?,
        )?;
        metadata.mysql_native_password_sha1_stage2 = self.unprotect_route_secret(
            "mysql_native_password_sha1_stage2",
            &metadata.instance_id,
            row.try_get("mysql_native_password_sha1_stage2")?,
        )?;
        metadata.mysql_root_password = self.unprotect_route_secret(
            "mysql_root_password",
            &metadata.instance_id,
            row.try_get("mysql_root_password")?,
        )?;
        metadata.mongodb_root_password = self.unprotect_route_secret(
            "mongodb_root_password",
            &metadata.instance_id,
            row.try_get("mongodb_root_password")?,
        )?;
        metadata.postgres_admin_password = self.unprotect_route_secret(
            "postgres_admin_password",
            &metadata.instance_id,
            row.try_get("postgres_admin_password")?,
        )?;
        metadata.tenant_password = self.unprotect_route_secret(
            "tenant_password",
            &metadata.instance_id,
            row.try_get("tenant_password")?,
        )?;
        Ok(())
    }

    fn protect_route_secret(
        &self,
        field: &str,
        instance_id: &str,
        value: Option<&str>,
    ) -> Result<Option<String>, RepositoryError> {
        value
            .map(|value| {
                self.secrets
                    .as_ref()
                    .map(|secrets| secrets.encrypt(field, instance_id, value))
                    .unwrap_or_else(|| Ok(value.to_string()))
            })
            .transpose()
            .map_err(RepositoryError::Secrets)
    }

    fn unprotect_route_secret(
        &self,
        field: &str,
        instance_id: &str,
        value: Option<String>,
    ) -> Result<Option<String>, RepositoryError> {
        let Some(value) = value else {
            return Ok(None);
        };
        let Some(secrets) = self.secrets.as_ref() else {
            return Ok(Some(value));
        };

        match secrets.decrypt(field, instance_id, &value) {
            Ok(value) => Ok(Some(value)),
            Err(source @ SecretStoreError::InvalidCiphertext) => {
                Err(RepositoryError::InvalidProtectedSecret {
                    instance_id: instance_id.to_string(),
                    field: field.to_string(),
                    source,
                })
            }
            Err(error) => Err(RepositoryError::Secrets(error)),
        }
    }

    pub async fn delete(&self, instance_id: &str) -> Result<bool, RepositoryError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DELETE FROM instance_route_auth WHERE instance_id = ?1")
            .bind(instance_id)
            .execute(&mut *transaction)
            .await?;

        let result = sqlx::query("DELETE FROM instance_metadata WHERE instance_id = ?1")
            .bind(instance_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;

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

fn validate_complete_protected_secret_recovery(
    metadata: &InstanceMetadata,
) -> Result<(), RepositoryError> {
    let mut missing = Vec::new();
    if metadata.status != InstanceStatus::Running {
        missing.push("running_status");
    }
    if metadata.desired_state != DesiredInstanceState::Running {
        missing.push("running_desired_state");
    }
    if protected_secret_missing(metadata.tenant_password.as_deref()) {
        missing.push("tenant_password");
    }
    match metadata.protocol {
        Protocol::Postgres => {
            if protected_secret_missing(metadata.postgres_admin_password.as_deref()) {
                missing.push("postgres_admin_password");
            }
        }
        Protocol::Mariadb => {
            if protected_secret_missing(metadata.mariadb_root_password.as_deref()) {
                missing.push("mariadb_root_password");
            }
            if !valid_hex_secret(metadata.mariadb_native_password_sha1_stage2.as_deref(), 40) {
                missing.push("mariadb_native_password_sha1_stage2");
            }
        }
        Protocol::Mysql => {
            if protected_secret_missing(metadata.mysql_root_password.as_deref()) {
                missing.push("mysql_root_password");
            }
            if !valid_hex_secret(metadata.mysql_native_password_sha1_stage2.as_deref(), 40) {
                missing.push("mysql_native_password_sha1_stage2");
            }
        }
        Protocol::Mongodb => {
            if protected_secret_missing(metadata.mongodb_root_password.as_deref()) {
                missing.push("mongodb_root_password");
            }
        }
        Protocol::Qdrant => {
            if !valid_hex_secret(metadata.route_key_sha256.as_deref(), 64) {
                missing.push("route_key_sha256");
            }
        }
        Protocol::Redis | Protocol::Valkey | Protocol::Clickhouse => {}
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(RepositoryError::IncompleteProtectedSecretRecovery {
            instance_id: metadata.instance_id.clone(),
            missing: missing.join(","),
        })
    }
}

fn protected_secret_missing(value: Option<&str>) -> bool {
    value.is_none_or(str::is_empty)
}

fn valid_hex_secret(value: Option<&str>, expected_len: usize) -> bool {
    value.is_some_and(|value| {
        value.len() == expected_len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("sqlite query failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("metadata json serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("metadata secret storage failed: {0}")]
    Secrets(#[from] SecretStoreError),
    #[error(
        "instance {instance_id} field {field} contains an invalid or ambiguous protected secret; refusing to interpret it as plaintext"
    )]
    InvalidProtectedSecret {
        instance_id: String,
        field: String,
        #[source]
        source: SecretStoreError,
    },
    #[error("encrypted metadata storage is required for protected-secret repair")]
    EncryptedRepositoryRequired,
    #[error("encrypted metadata storage is required for authentication hardening attestations")]
    AuthHardeningAttestationRequiresEncryption,
    #[error(
        "instance {instance_id} cannot be bound to an authentication hardening attestation because protected field {field} is missing"
    )]
    AuthHardeningCredentialMissing {
        instance_id: String,
        field: &'static str,
    },
    #[error("instance {instance_id} has an invalid compatibility attestation: {reason}")]
    InvalidCompatibilityAttestation { instance_id: String, reason: String },
    #[error("instance {0} does not exist")]
    InstanceNotFound(String),
    #[error("instance {instance_id} has no stored value for protected field {field}")]
    ProtectedSecretMissing { instance_id: String, field: String },
    #[error("instance {instance_id} field {field} already contains valid protected ciphertext")]
    ProtectedSecretAlreadyValid { instance_id: String, field: String },
    #[error(
        "the supplied plaintext does not exactly match the ambiguous stored value for instance {instance_id} field {field}"
    )]
    ProtectedSecretPlaintextMismatch { instance_id: String, field: String },
    #[error(
        "instance {instance_id} protected-secret recovery is incomplete; missing verified fields: {missing}"
    )]
    IncompleteProtectedSecretRecovery {
        instance_id: String,
        missing: String,
    },
    #[error("metadata schema version {actual} is not supported")]
    UnsupportedSchema { actual: u32 },
    #[error("instance {instance_id} has unsupported desired state {value:?}")]
    InvalidDesiredState { instance_id: String, value: String },
    #[error(
        "instance metadata identity mismatch: durable row {durable_instance_id} embeds {embedded_instance_id}"
    )]
    MetadataIdentityMismatch {
        durable_instance_id: String,
        embedded_instance_id: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        instances::metadata::{
            DatabaseIdentity, InstanceStatus, PublicEndpoint, RuntimeKind, RuntimeMetadata,
        },
        shared::{limits::InstanceLimits, protocol::Protocol},
        storage::{secrets::is_encrypted, sqlite},
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
    async fn persists_desired_state_outside_public_metadata_json() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::new(pool.clone());
        let mut metadata = sample_metadata();
        metadata.desired_state = DesiredInstanceState::Stopped;
        metadata.disk_limit_blocked = true;

        repository.upsert(&metadata).await.unwrap();

        let (desired_state, disk_limit_blocked, metadata_json): (String, bool, String) =
            sqlx::query_as(
            "SELECT desired_state, disk_limit_blocked, metadata_json FROM instance_metadata WHERE instance_id = ?1",
        )
        .bind("inst_abc")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(desired_state, "stopped");
        assert!(disk_limit_blocked);
        assert!(!metadata_json.contains("desired_state"));
        assert!(!metadata_json.contains("disk_limit_blocked"));
        let loaded = repository.get("inst_abc").await.unwrap().unwrap();
        assert_eq!(loaded.desired_state, DesiredInstanceState::Stopped);
        assert!(loaded.disk_limit_blocked);
        assert!(
            !serde_json::to_string(&loaded)
                .unwrap()
                .contains("desired_state")
        );
        assert!(
            !serde_json::to_string(&loaded)
                .unwrap()
                .contains("disk_limit_blocked")
        );
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
    async fn durable_metadata_rejects_duplicate_database_routes() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::new(pool);
        let first = sample_metadata();
        let mut duplicate = sample_metadata();
        duplicate.instance_id = "inst_other".to_string();
        duplicate.runtime.container_name = "dbe-postgres-inst_other".to_string();

        repository.upsert(&first).await.unwrap();

        assert!(matches!(
            repository.upsert(&duplicate).await,
            Err(RepositoryError::Sqlx(sqlx::Error::Database(_)))
        ));
    }

    #[tokio::test]
    async fn durable_metadata_allows_same_database_for_a_distinct_user() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::new(pool);
        let first = sample_metadata();
        let mut distinct_route = sample_metadata();
        distinct_route.instance_id = "inst_other".to_string();
        distinct_route.database.username = "other_user".to_string();
        distinct_route.runtime.container_name = "dbe-postgres-inst_other".to_string();

        repository.upsert(&first).await.unwrap();
        repository.upsert(&distinct_route).await.unwrap();
    }

    #[tokio::test]
    async fn durable_metadata_rejects_duplicate_redis_usernames() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::new(pool);
        let mut first = sample_metadata();
        first.protocol = Protocol::Redis;
        let mut duplicate = first.clone();
        duplicate.instance_id = "inst_other".to_string();
        duplicate.database.name = "another_database".to_string();
        duplicate.runtime.container_name = "dbe-redis-inst_other".to_string();

        repository.upsert(&first).await.unwrap();

        assert!(repository.upsert(&duplicate).await.is_err());
    }

    #[tokio::test]
    async fn durable_metadata_rejects_duplicate_valkey_usernames() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::new(pool);
        let mut first = sample_metadata();
        first.protocol = Protocol::Valkey;
        let mut duplicate = first.clone();
        duplicate.instance_id = "inst_other".to_string();
        duplicate.database.name = "another_database".to_string();
        duplicate.runtime.container_name = "dbe-valkey-inst_other".to_string();

        repository.upsert(&first).await.unwrap();

        assert!(repository.upsert(&duplicate).await.is_err());
    }

    #[tokio::test]
    async fn durable_metadata_rejects_duplicate_qdrant_route_keys() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::new(pool);
        let mut first = sample_metadata();
        first.protocol = Protocol::Qdrant;
        first.route_key_sha256 = Some("same-route-key".to_string());
        let mut duplicate = first.clone();
        duplicate.instance_id = "inst_other".to_string();
        duplicate.database.name = "another_database".to_string();
        duplicate.runtime.container_name = "dbe-qdrant-inst_other".to_string();

        repository.upsert(&first).await.unwrap();

        assert!(repository.upsert(&duplicate).await.is_err());
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
    async fn encrypted_repository_stores_hidden_mysql_auth_material_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
        let mut metadata = sample_metadata();
        metadata.protocol = Protocol::Mysql;
        metadata.mysql_native_password_sha1_stage2 =
            Some("0123456789abcdef0123456789abcdef01234567".to_string());
        metadata.mysql_root_password = Some("internal-mysql-root-password".to_string());

        repository.upsert(&metadata).await.unwrap();

        let (raw_verifier, raw_root): (String, String) = sqlx::query_as(
            "SELECT mysql_native_password_sha1_stage2, mysql_root_password FROM instance_route_auth WHERE instance_id = ?1",
        )
        .bind("inst_abc")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(is_encrypted(&raw_verifier));
        assert!(is_encrypted(&raw_root));
        assert!(!raw_root.contains("internal-mysql-root-password"));

        let loaded = repository.get("inst_abc").await.unwrap().unwrap();
        assert_eq!(
            loaded.mysql_native_password_sha1_stage2.as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!(
            loaded.mysql_root_password.as_deref(),
            Some("internal-mysql-root-password")
        );
        let public_json = serde_json::to_string(&loaded).unwrap();
        assert!(!public_json.contains("mysql_native_password_sha1_stage2"));
        assert!(!public_json.contains("mysql_root_password"));
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

    #[tokio::test]
    async fn encrypted_repository_stores_hidden_route_auth_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
        let mut metadata = sample_metadata();
        metadata.protocol = Protocol::Mongodb;
        metadata.mongodb_root_password = Some("internal-mongo-root-password".to_string());

        repository.upsert(&metadata).await.unwrap();

        let raw: String = sqlx::query_scalar(
            "SELECT mongodb_root_password FROM instance_route_auth WHERE instance_id = ?1",
        )
        .bind("inst_abc")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(is_encrypted(&raw));
        assert!(!raw.contains("internal-mongo-root-password"));

        let loaded = repository.get("inst_abc").await.unwrap().unwrap();
        assert_eq!(
            loaded.mongodb_root_password.as_deref(),
            Some("internal-mongo-root-password")
        );
    }

    #[tokio::test]
    async fn encrypted_repository_stores_tenant_password_outside_public_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
        let mut metadata = sample_metadata();
        // A caller-controlled secret may legitimately begin with the storage
        // envelope marker. It must still be encrypted rather than mistaken
        // for an already protected repository value.
        metadata.tenant_password = Some("dbev1:current-tenant-password".to_string());

        repository.upsert(&metadata).await.unwrap();

        let raw: String = sqlx::query_scalar(
            "SELECT tenant_password FROM instance_route_auth WHERE instance_id = ?1",
        )
        .bind("inst_abc")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(is_encrypted(&raw));
        assert_ne!(raw, "dbev1:current-tenant-password");
        assert!(!raw.contains("current-tenant-password"));

        let loaded = repository.get("inst_abc").await.unwrap().unwrap();
        assert_eq!(
            loaded.tenant_password.as_deref(),
            Some("dbev1:current-tenant-password")
        );
        let public_json = serde_json::to_string(&loaded).unwrap();
        assert!(!public_json.contains("tenant_password"));
        assert!(!public_json.contains("dbev1:current-tenant-password"));
    }

    #[tokio::test]
    async fn encrypted_repository_stores_postgres_admin_password_outside_public_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
        let mut metadata = sample_metadata();
        metadata.protocol = Protocol::Postgres;
        metadata.postgres_admin_password = Some("internal-postgres-admin-secret".to_string());

        repository.upsert(&metadata).await.unwrap();

        let raw: String = sqlx::query_scalar(
            "SELECT postgres_admin_password FROM instance_route_auth WHERE instance_id = ?1",
        )
        .bind("inst_abc")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(is_encrypted(&raw));
        assert!(!raw.contains("internal-postgres-admin-secret"));

        let loaded = repository.get("inst_abc").await.unwrap().unwrap();
        assert_eq!(
            loaded.postgres_admin_password.as_deref(),
            Some("internal-postgres-admin-secret")
        );
        let public_json = serde_json::to_string(&loaded).unwrap();
        assert!(!public_json.contains("postgres_admin_password"));
        assert!(!public_json.contains("internal-postgres-admin-secret"));
    }

    #[tokio::test]
    async fn encrypted_repository_rejects_ambiguous_prefixed_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let plain_repository = InstanceRepository::new(pool.clone());
        let mut metadata = sample_metadata();
        let ambiguous = "dbev1:chosen-by-the-user";
        metadata.tenant_password = Some(ambiguous.to_string());
        plain_repository.upsert(&metadata).await.unwrap();

        let encrypted_repository = InstanceRepository::encrypted(pool, dir.path()).unwrap();
        let error = encrypted_repository.get("inst_abc").await.unwrap_err();

        assert_invalid_protected_secret(error, "tenant_password", ambiguous);
    }

    #[tokio::test]
    async fn encrypted_repository_rejects_corrupted_ciphertext_without_plaintext_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
        let mut metadata = sample_metadata();
        metadata.tenant_password = Some("secret-before-corruption".to_string());
        repository.upsert(&metadata).await.unwrap();

        let raw: String = sqlx::query_scalar(
            "SELECT tenant_password FROM instance_route_auth WHERE instance_id = ?1",
        )
        .bind("inst_abc")
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut corrupted = raw.into_bytes();
        let ciphertext_offset = corrupted.iter().rposition(|byte| *byte == b':').unwrap() + 1;
        corrupted[ciphertext_offset] = if corrupted[ciphertext_offset] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let corrupted = String::from_utf8(corrupted).unwrap();
        sqlx::query("UPDATE instance_route_auth SET tenant_password = ?1 WHERE instance_id = ?2")
            .bind(&corrupted)
            .bind("inst_abc")
            .execute(&pool)
            .await
            .unwrap();

        let error = repository.get("inst_abc").await.unwrap_err();
        assert_invalid_protected_secret(error, "tenant_password", &corrupted);
    }

    #[tokio::test]
    async fn encrypted_repository_rejects_ciphertext_bound_to_the_wrong_field() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
        let mut metadata = sample_metadata();
        metadata.tenant_password = Some("field-bound-secret".to_string());
        repository.upsert(&metadata).await.unwrap();

        let raw: String = sqlx::query_scalar(
            "SELECT tenant_password FROM instance_route_auth WHERE instance_id = ?1",
        )
        .bind("inst_abc")
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE instance_route_auth SET mongodb_root_password = ?1, tenant_password = NULL WHERE instance_id = ?2",
        )
        .bind(&raw)
        .bind("inst_abc")
        .execute(&pool)
        .await
        .unwrap();

        let error = repository.get("inst_abc").await.unwrap_err();
        assert_invalid_protected_secret(error, "mongodb_root_password", &raw);
    }

    #[tokio::test]
    async fn encrypted_repository_rewrites_legacy_plaintext_route_auth() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let plain_repository = InstanceRepository::new(pool.clone());
        let mut metadata = sample_metadata();
        metadata.protocol = Protocol::Mongodb;
        metadata.mongodb_root_password = Some("legacy-plain-root".to_string());
        plain_repository.upsert(&metadata).await.unwrap();

        let encrypted_repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
        let loaded = encrypted_repository.list().await.unwrap();
        let rewritten = encrypted_repository
            .rewrite_protected_route_auth(&loaded)
            .await
            .unwrap();

        assert_eq!(rewritten, 1);
        let raw: String = sqlx::query_scalar(
            "SELECT mongodb_root_password FROM instance_route_auth WHERE instance_id = ?1",
        )
        .bind("inst_abc")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(is_encrypted(&raw));
        assert!(!raw.contains("legacy-plain-root"));
    }

    #[tokio::test]
    async fn hardening_attestation_is_bound_to_container_generation_and_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
        let mut metadata = sample_metadata();
        metadata.tenant_password = Some("tenant-secret".to_string());
        metadata.postgres_admin_password = Some("admin-secret".to_string());
        repository.upsert(&metadata).await.unwrap();

        repository
            .record_auth_hardening_attestation(
                &metadata,
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "2026-08-13T12:00:00Z",
                1,
            )
            .await
            .unwrap();

        assert!(
            repository
                .auth_hardening_attestation_is_current(
                    &metadata,
                    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                    "2026-08-13T12:00:00Z",
                    1,
                )
                .await
                .unwrap()
        );
        assert!(
            !repository
                .auth_hardening_attestation_is_current(
                    &metadata,
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "2026-08-13T12:00:00Z",
                    1,
                )
                .await
                .unwrap()
        );
        assert!(
            !repository
                .auth_hardening_attestation_is_current(
                    &metadata,
                    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                    "2026-08-13T12:01:00Z",
                    1,
                )
                .await
                .unwrap()
        );
        assert!(
            !repository
                .auth_hardening_attestation_is_current(
                    &metadata,
                    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                    "2026-08-13T12:00:00Z",
                    2,
                )
                .await
                .unwrap()
        );
        metadata.tenant_password = Some("rotated-tenant-secret".to_string());
        assert!(
            !repository
                .auth_hardening_attestation_is_current(
                    &metadata,
                    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                    "2026-08-13T12:00:00Z",
                    1,
                )
                .await
                .unwrap()
        );
        metadata.tenant_password = Some("tenant-secret".to_string());
        sqlx::query(
            "UPDATE instance_auth_hardening_attestations SET container_id = ?1, container_started_at = ?2, hardening_revision = 2 WHERE instance_id = ?3",
        )
        .bind("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        .bind("2026-08-13T12:01:00Z")
        .bind("inst_abc")
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            !repository
                .auth_hardening_attestation_is_current(
                    &metadata,
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "2026-08-13T12:01:00Z",
                    2,
                )
                .await
                .unwrap()
        );

        let binding: String = sqlx::query_scalar(
            "SELECT credential_binding FROM instance_auth_hardening_attestations WHERE instance_id = ?1",
        )
        .bind("inst_abc")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(binding.starts_with("dbevh1:"));
        assert!(!binding.contains("tenant-secret"));
        assert!(!binding.contains("admin-secret"));
    }

    #[tokio::test]
    async fn hardening_attestation_cascades_when_instance_is_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::encrypted(pool.clone(), dir.path()).unwrap();
        let mut metadata = sample_metadata();
        metadata.tenant_password = Some("tenant-secret".to_string());
        metadata.postgres_admin_password = Some("admin-secret".to_string());
        repository.upsert(&metadata).await.unwrap();
        repository
            .record_auth_hardening_attestation(
                &metadata,
                "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "2026-08-13T12:00:00Z",
                1,
            )
            .await
            .unwrap();

        assert!(repository.delete("inst_abc").await.unwrap());
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM instance_auth_hardening_attestations WHERE instance_id = ?1",
        )
        .bind("inst_abc")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(remaining, 0);
    }

    fn assert_invalid_protected_secret(
        error: RepositoryError,
        expected_field: &str,
        protected_value: &str,
    ) {
        let message = error.to_string();
        assert!(message.contains("inst_abc"));
        assert!(message.contains(expected_field));
        assert!(!message.contains(protected_value));
        match error {
            RepositoryError::InvalidProtectedSecret {
                instance_id,
                field,
                source: SecretStoreError::InvalidCiphertext,
            } => {
                assert_eq!(instance_id, "inst_abc");
                assert_eq!(field, expected_field);
            }
            error => panic!("unexpected repository error: {error}"),
        }
    }

    fn sample_metadata() -> InstanceMetadata {
        InstanceMetadata {
            schema_version: SCHEMA_VERSION,
            instance_id: "inst_abc".to_string(),
            protocol: Protocol::Postgres,
            status: InstanceStatus::Running,
            desired_state: DesiredInstanceState::Running,
            disk_limit_blocked: false,
            public: PublicEndpoint {
                host: "db.example.com".to_string(),
                port: 5433,
            },
            backend: BackendEndpoint::UnixSocket {
                socket_path: "/run/dbev/sockets/inst_abc/.s.PGSQL.5432".to_string(),
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: "dbe-postgres-inst-abc".to_string(),
                network_mode: "none".to_string(),
            },
            database: DatabaseIdentity {
                name: "app_db".to_string(),
                username: "app".to_string(),
            },
            route_key_sha256: None,
            mariadb_native_password_sha1_stage2: None,
            mariadb_root_password: None,
            mysql_native_password_sha1_stage2: None,
            mysql_root_password: None,
            mongodb_root_password: None,
            postgres_admin_password: None,
            tenant_password: None,
            limits: InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "2026-01-01T12:00:00Z".to_string(),
            updated_at: "2026-01-01T12:00:00Z".to_string(),
        }
    }
}
