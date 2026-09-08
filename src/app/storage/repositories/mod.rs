use std::path::Path;

use sqlx::{Row, SqlitePool};

use crate::{
    instances::metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus, SCHEMA_VERSION},
    placement::DeploymentMode,
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
                instance_metadata.deployment_mode,
                instance_metadata.runtime_id,
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
                self.load_placement(&mut metadata, &row)?;
                self.load_desired_state(&mut metadata, &row)?;
                self.load_disk_block(&mut metadata, &row)?;
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
                instance_metadata.deployment_mode,
                instance_metadata.runtime_id,
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
        self.load_placement(&mut metadata, &row)?;
        self.load_desired_state(&mut metadata, &row)?;
        self.load_disk_block(&mut metadata, &row)?;
        self.load_route_auth(&mut metadata, &row)?;
        validate_metadata_schema(&metadata)?;
        Ok(Some(metadata))
    }

    pub async fn upsert(&self, metadata: &InstanceMetadata) -> Result<(), RepositoryError> {
        self.upsert_protected_secrets(metadata, false).await
    }

    /// Atomically replaces protected route authentication and clears an
    /// existing recovery marker. Callers must verify the replacement against
    /// the live database before using this path.
    pub(crate) async fn upsert_recovered_secrets(
        &self,
        metadata: &InstanceMetadata,
    ) -> Result<(), RepositoryError> {
        self.upsert_protected_secrets(metadata, true).await
    }

    /// Persists only a provisional dedicated runtime's maintenance secrets.
    /// The live instance metadata and tenant credential stay untouched, so a
    /// prepared migration target cannot become routable before cutover.
    pub(crate) async fn stage_dedicated_admin_secrets(
        &self,
        target: &InstanceMetadata,
    ) -> Result<(), RepositoryError> {
        if target.deployment_mode != DeploymentMode::Dedicated
            || target.runtime_id() != target.instance_id
        {
            return Err(RepositoryError::InvalidDedicatedRuntime {
                instance_id: target.instance_id.clone(),
                runtime_id: target.runtime_id().to_string(),
            });
        }
        let mariadb = self.protect_route_secret(
            "mariadb_root_password",
            &target.instance_id,
            target.mariadb_root_password.as_deref(),
        )?;
        let mysql = self.protect_route_secret(
            "mysql_root_password",
            &target.instance_id,
            target.mysql_root_password.as_deref(),
        )?;
        let mongodb = self.protect_route_secret(
            "mongodb_root_password",
            &target.instance_id,
            target.mongodb_root_password.as_deref(),
        )?;
        let postgres = self.protect_route_secret(
            "postgres_admin_password",
            &target.instance_id,
            target.postgres_admin_password.as_deref(),
        )?;
        let result = sqlx::query(
            r#"
            UPDATE instance_route_auth
            SET mariadb_root_password = ?1,
                mysql_root_password = ?2,
                mongodb_root_password = ?3,
                postgres_admin_password = ?4,
                updated_at = ?5
            WHERE instance_id = ?6
            "#,
        )
        .bind(mariadb)
        .bind(mysql)
        .bind(mongodb)
        .bind(postgres)
        .bind(&target.updated_at)
        .bind(&target.instance_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(RepositoryError::InstanceNotFound(
                target.instance_id.clone(),
            ));
        }
        Ok(())
    }

    /// Clears maintenance secrets staged for a dedicated migration target
    /// while retaining the authoritative shared tenant credential/verifiers.
    pub(crate) async fn clear_staged_admin_secrets(
        &self,
        instance_id: &str,
    ) -> Result<(), RepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE instance_route_auth
            SET mariadb_root_password = NULL,
                mysql_root_password = NULL,
                mongodb_root_password = NULL,
                postgres_admin_password = NULL,
                updated_at = ?1
            WHERE instance_id = ?2
            "#,
        )
        .bind(crate::shared::time::now_rfc3339())
        .bind(instance_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(RepositoryError::InstanceNotFound(instance_id.to_string()));
        }
        Ok(())
    }

    async fn upsert_protected_secrets(
        &self,
        metadata: &InstanceMetadata,
        clear_protected_secret_recovery: bool,
    ) -> Result<(), RepositoryError> {
        validate_metadata_schema(metadata)?;
        if clear_protected_secret_recovery {
            validate_secret_recovery(metadata)?;
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
        // Take the writer slot before reading the recovery fence. A deferred
        // WAL snapshot cannot wait when upgraded after another writer commits.
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if metadata.deployment_mode == DeploymentMode::Dedicated {
            self.save_dedicated_runtime(&mut transaction, metadata, &backend, &limits_json)
                .await?;
        }
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
                deployment_mode,
                runtime_id,
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
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)
            ON CONFLICT(instance_id) DO UPDATE SET
                schema_version = excluded.schema_version,
                protocol = excluded.protocol,
                status = excluded.status,
                deployment_mode = excluded.deployment_mode,
                runtime_id = excluded.runtime_id,
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
        .bind(metadata.deployment_mode.as_str())
        .bind(metadata.runtime_id())
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

    fn load_placement(
        &self,
        metadata: &mut InstanceMetadata,
        row: &sqlx::sqlite::SqliteRow,
    ) -> Result<(), RepositoryError> {
        let mode: String = row.try_get("deployment_mode")?;
        metadata.deployment_mode =
            DeploymentMode::parse(&mode).ok_or_else(|| RepositoryError::InvalidDeploymentMode {
                instance_id: metadata.instance_id.clone(),
                value: mode,
            })?;
        metadata.runtime_id = row.try_get("runtime_id")?;
        Ok(())
    }

    async fn save_dedicated_runtime(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        metadata: &InstanceMetadata,
        backend: &BackendColumns,
        limits_json: &str,
    ) -> Result<(), RepositoryError> {
        if metadata.runtime_id() != metadata.instance_id {
            return Err(RepositoryError::InvalidDedicatedRuntime {
                instance_id: metadata.instance_id.clone(),
                runtime_id: metadata.runtime_id().to_string(),
            });
        }
        let image = metadata
            .image
            .as_ref()
            .map(|image| image.configured.as_str())
            .unwrap_or_default();
        let database_version = metadata
            .database_version
            .as_ref()
            .and_then(|version| version.current.as_deref());
        if let Some(version) = database_version
            && crate::compatibility::normalize_database_version(metadata.protocol, version)
                .as_deref()
                != Some(version)
        {
            return Err(RepositoryError::InvalidDatabaseVersion {
                instance_id: metadata.instance_id.clone(),
                value: version.to_string(),
            });
        }
        sqlx::query(
            r#"
            INSERT INTO engine_runtimes (
                runtime_id, schema_version, protocol, deployment_mode, status,
                backend_kind, backend_socket_path, backend_host, backend_port,
                runtime_kind, container_name, network, limits_json,
                limit_cpu_cores, limit_memory_mib, limit_disk_mib,
                image, database_version, max_tenants, created_at, updated_at, owner_panel, owner_server
            ) VALUES (
                ?1, 1, ?2, 'dedicated', ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15, ?16, 1, ?17, ?18, ?19, ?20
            )
            ON CONFLICT(runtime_id) DO UPDATE SET
                status = excluded.status,
                owner_panel = excluded.owner_panel,
                owner_server = excluded.owner_server,
                backend_kind = excluded.backend_kind,
                backend_socket_path = excluded.backend_socket_path,
                backend_host = excluded.backend_host,
                backend_port = excluded.backend_port,
                runtime_kind = excluded.runtime_kind,
                container_name = excluded.container_name,
                network = excluded.network,
                limits_json = excluded.limits_json,
                limit_cpu_cores = excluded.limit_cpu_cores,
                limit_memory_mib = excluded.limit_memory_mib,
                limit_disk_mib = excluded.limit_disk_mib,
                image = excluded.image,
                database_version = excluded.database_version,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&metadata.instance_id)
        .bind(metadata.protocol.as_str())
        .bind(metadata.status.as_str())
        .bind(backend.kind)
        .bind(&backend.socket_path)
        .bind(&backend.host)
        .bind(backend.port.map(i64::from))
        .bind(metadata.runtime.kind.as_str())
        .bind(&metadata.runtime.container_name)
        .bind(&metadata.runtime.network_mode)
        .bind(limits_json)
        .bind(metadata.limits.cpu_cores)
        .bind(
            i64::try_from(metadata.limits.memory_mib)
                .map_err(|_| RepositoryError::LimitTooLarge("memory_mib"))?,
        )
        .bind(
            i64::try_from(metadata.limits.disk_mib)
                .map_err(|_| RepositoryError::LimitTooLarge("disk_mib"))?,
        )
        .bind(image)
        .bind(database_version)
        .bind(&metadata.created_at)
        .bind(&metadata.updated_at)
        .bind(metadata.owner.as_ref().map(|owner| owner.panel_id.as_str()))
        .bind(metadata.owner.as_ref().map(|owner| owner.server_id.as_str()))
        .execute(&mut **transaction)
        .await?;
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

    fn load_disk_block(
        &self,
        metadata: &mut InstanceMetadata,
        row: &sqlx::sqlite::SqliteRow,
    ) -> Result<(), RepositoryError> {
        metadata.disk_limit_blocked = row.try_get("disk_limit_blocked")?;
        Ok(())
    }

    pub async fn rewrite_route_auth(
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

fn validate_secret_recovery(metadata: &InstanceMetadata) -> Result<(), RepositoryError> {
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
    #[error("instance {instance_id} has unsupported deployment mode {value:?}")]
    InvalidDeploymentMode { instance_id: String, value: String },
    #[error("dedicated instance {instance_id} cannot use runtime {runtime_id}")]
    InvalidDedicatedRuntime {
        instance_id: String,
        runtime_id: String,
    },
    #[error("instance resource limit {0} exceeds SQLite integer capacity")]
    LimitTooLarge(&'static str),
    #[error("instance {instance_id} database version {value:?} is not normalized")]
    InvalidDatabaseVersion { instance_id: String, value: String },
    #[error(
        "instance metadata identity mismatch: durable row {durable_instance_id} embeds {embedded_instance_id}"
    )]
    MetadataIdentityMismatch {
        durable_instance_id: String,
        embedded_instance_id: String,
    },
}

#[cfg(test)]
mod tests;
