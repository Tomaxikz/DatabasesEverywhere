use std::path::Path;

use sqlx::{Row, SqlitePool, sqlite::SqliteRow};

use super::{
    PlacementRepository, PlacementRepositoryError, i64_to_u64, parse_protocol, u64_to_i64,
};
use crate::{
    instances::metadata::RuntimeMetadata,
    placement::model::{
        EngineRuntime, RuntimeCompatibility, RuntimeReservation, parse_mode, parse_runtime_kind,
        parse_status,
    },
    shared::{backend::BackendEndpoint, limits::InstanceLimits, protocol::Protocol},
    storage::secrets::SecretStore,
};

const ADMIN_SECRET_FIELD: &str = "engine_runtime_admin_secret";

impl PlacementRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            secrets: None,
        }
    }

    pub fn migrations(&self) -> crate::placement::DeploymentMigrationRepository {
        crate::placement::DeploymentMigrationRepository::new(self.pool.clone())
    }

    pub fn encrypted(
        pool: SqlitePool,
        metadata_root: &Path,
    ) -> Result<Self, PlacementRepositoryError> {
        Ok(Self {
            pool,
            secrets: Some(SecretStore::open_or_create(metadata_root)?),
        })
    }

    pub async fn list(&self) -> Result<Vec<EngineRuntime>, PlacementRepositoryError> {
        let rows = sqlx::query(&runtime_select("ORDER BY runtime.runtime_id"))
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(|row| self.read_runtime(row)).collect()
    }

    pub async fn get(
        &self,
        runtime_id: &str,
    ) -> Result<Option<EngineRuntime>, PlacementRepositoryError> {
        let row = sqlx::query(&runtime_select("WHERE runtime.runtime_id = ?1 LIMIT 1"))
            .bind(runtime_id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(|row| self.read_runtime(row)).transpose()
    }

    pub async fn save(&self, runtime: &EngineRuntime) -> Result<(), PlacementRepositoryError> {
        runtime.check()?;
        let backend = BackendColumns::from(&runtime.backend);
        let limits = &runtime.limits;
        let limits_json = serde_json::to_string(&limits)?;
        let protected_admin = runtime
            .admin_secret
            .as_deref()
            .map(|secret| self.protect_admin(&runtime.runtime_id, secret))
            .transpose()?;
        let mut transaction = self.pool.begin().await?;

        sqlx::query(
            r#"
            INSERT INTO engine_runtimes (
                runtime_id, schema_version, protocol, deployment_mode, status,
                backend_kind, backend_socket_path, backend_host, backend_port,
                runtime_kind, container_name, network, limits_json,
                limit_cpu_cores, limit_memory_mib, limit_disk_mib,
                image, database_version, compatibility_container_id,
                compatibility_image_id, compatibility_probe_revision,
                max_tenants, tenant_count,
                reserved_disk_mib,
                created_at, updated_at, owner_panel, owner_server, desired_state, pending_image
            )
            VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25,
                ?26, ?27, ?28, ?29, ?30
            )
            ON CONFLICT(runtime_id) DO UPDATE SET
                schema_version = excluded.schema_version,
                owner_panel = excluded.owner_panel,
                owner_server = excluded.owner_server,
                protocol = excluded.protocol,
                deployment_mode = excluded.deployment_mode,
                status = excluded.status,
                desired_state = excluded.desired_state,
                pending_image = excluded.pending_image,
                backend_kind = excluded.backend_kind,
                backend_socket_path = excluded.backend_socket_path,
                backend_host = excluded.backend_host,
                backend_port = excluded.backend_port,
                runtime_kind = excluded.runtime_kind,
                container_name = excluded.container_name,
                network = excluded.network,
                limits_json = CASE
                    WHEN engine_runtimes.tenant_count = excluded.tenant_count
                     AND engine_runtimes.reserved_disk_mib = excluded.reserved_disk_mib
                    THEN excluded.limits_json
                    ELSE engine_runtimes.limits_json
                END,
                limit_cpu_cores = CASE
                    WHEN engine_runtimes.tenant_count = excluded.tenant_count
                     AND engine_runtimes.reserved_disk_mib = excluded.reserved_disk_mib
                    THEN excluded.limit_cpu_cores
                    ELSE engine_runtimes.limit_cpu_cores
                END,
                limit_memory_mib = CASE
                    WHEN engine_runtimes.tenant_count = excluded.tenant_count
                     AND engine_runtimes.reserved_disk_mib = excluded.reserved_disk_mib
                    THEN excluded.limit_memory_mib
                    ELSE engine_runtimes.limit_memory_mib
                END,
                limit_disk_mib = CASE
                    WHEN engine_runtimes.tenant_count = excluded.tenant_count
                     AND engine_runtimes.reserved_disk_mib = excluded.reserved_disk_mib
                    THEN excluded.limit_disk_mib
                    ELSE engine_runtimes.limit_disk_mib
                END,
                image = excluded.image,
                database_version = excluded.database_version,
                compatibility_container_id = excluded.compatibility_container_id,
                compatibility_image_id = excluded.compatibility_image_id,
                compatibility_probe_revision = excluded.compatibility_probe_revision,
                max_tenants = excluded.max_tenants,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&runtime.runtime_id)
        .bind(i64::from(runtime.schema_version))
        .bind(runtime.protocol.as_str())
        .bind(runtime.deployment_mode.as_str())
        .bind(runtime.status.as_str())
        .bind(backend.kind)
        .bind(backend.socket_path)
        .bind(backend.host)
        .bind(backend.port.map(i64::from))
        .bind(runtime.runtime.kind.as_str())
        .bind(&runtime.runtime.container_name)
        .bind(&runtime.runtime.network_mode)
        .bind(limits_json)
        .bind(limits.cpu_cores)
        .bind(u64_to_i64(limits.memory_mib, "memory_mib")?)
        .bind(u64_to_i64(limits.disk_mib, "disk_mib")?)
        .bind(&runtime.image)
        .bind(&runtime.database_version)
        .bind(
            runtime
                .compatibility
                .as_ref()
                .map(|compatibility| compatibility.container_id.as_str()),
        )
        .bind(
            runtime
                .compatibility
                .as_ref()
                .map(|compatibility| compatibility.image_id.as_str()),
        )
        .bind(
            runtime
                .compatibility
                .as_ref()
                .map(|compatibility| i64::from(compatibility.probe_revision)),
        )
        .bind(i64::from(runtime.max_tenants))
        .bind(i64::from(runtime.reserved.tenants))
        .bind(u64_to_i64(runtime.reserved.disk_mib, "reserved_disk_mib")?)
        .bind(&runtime.created_at)
        .bind(&runtime.updated_at)
        .bind(runtime.owner.as_ref().map(|owner| owner.panel_id.as_str()))
        .bind(runtime.owner.as_ref().map(|owner| owner.server_id.as_str()))
        .bind(runtime.desired_state.as_str())
        .bind(&runtime.pending_image)
        .execute(&mut *transaction)
        .await?;

        if let Some(protected_admin) = protected_admin {
            sqlx::query(
                r#"
                INSERT INTO engine_runtime_auth (runtime_id, admin_secret, updated_at)
                VALUES (?1, ?2, ?3)
                ON CONFLICT(runtime_id) DO UPDATE SET
                    admin_secret = excluded.admin_secret,
                    updated_at = excluded.updated_at
                "#,
            )
            .bind(&runtime.runtime_id)
            .bind(protected_admin)
            .bind(&runtime.updated_at)
            .execute(&mut *transaction)
            .await?;
        }

        transaction.commit().await?;
        Ok(())
    }

    pub async fn server_pool(
        &self,
        protocol: Protocol,
        owner: &crate::placement::PoolOwner,
    ) -> Result<Option<EngineRuntime>, PlacementRepositoryError> {
        owner
            .check()
            .map_err(PlacementRepositoryError::InvalidReservation)?;
        let row = sqlx::query(&runtime_select(
            "WHERE runtime.deployment_mode = 'shared' AND runtime.protocol = ?1 AND runtime.owner_panel = ?2 AND runtime.owner_server = ?3",
        ))
        .bind(protocol.as_str())
        .bind(&owner.panel_id)
        .bind(&owner.server_id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(|row| self.read_runtime(row)).transpose()
    }

    pub async fn delete(&self, runtime_id: &str) -> Result<bool, PlacementRepositoryError> {
        let result = sqlx::query("DELETE FROM engine_runtimes WHERE runtime_id = ?1")
            .bind(runtime_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    fn read_runtime(&self, row: &SqliteRow) -> Result<EngineRuntime, PlacementRepositoryError> {
        let runtime_id: String = row.try_get("runtime_id")?;
        let protocol = parse_protocol(row.try_get("protocol")?)?;
        let mode_value: String = row.try_get("deployment_mode")?;
        let deployment_mode =
            parse_mode(&mode_value).ok_or_else(|| PlacementRepositoryError::InvalidValue {
                field: "deployment_mode",
                value: mode_value,
            })?;
        let status_value: String = row.try_get("status")?;
        let status =
            parse_status(&status_value).ok_or_else(|| PlacementRepositoryError::InvalidValue {
                field: "status",
                value: status_value,
            })?;
        let runtime_kind_value: String = row.try_get("runtime_kind")?;
        let runtime_kind = parse_runtime_kind(&runtime_kind_value).ok_or_else(|| {
            PlacementRepositoryError::InvalidValue {
                field: "runtime_kind",
                value: runtime_kind_value,
            }
        })?;
        let limits_json: String = row.try_get("limits_json")?;
        let admin_secret = row
            .try_get::<Option<String>, _>("admin_secret")?
            .map(|secret| self.unprotect_admin(&runtime_id, &secret))
            .transpose()?;
        let backend = read_backend(row)?;
        let tenant_count: i64 = row.try_get("tenant_count")?;
        let reserved_disk_mib: i64 = row.try_get("reserved_disk_mib")?;
        let schema_version: i64 = row.try_get("schema_version")?;
        let max_tenants: i64 = row.try_get("max_tenants")?;

        let reserved_disk_mib = i64_to_u64(reserved_disk_mib, "reserved_disk_mib")?;
        let limits: InstanceLimits = serde_json::from_str(&limits_json)?;
        let runtime = EngineRuntime {
            pending_image: row.try_get("pending_image")?,
            desired_state: crate::instances::metadata::DesiredInstanceState::parse(
                &row.try_get::<String, _>("desired_state")?,
            )
            .ok_or_else(|| {
                PlacementRepositoryError::InvalidReservation("invalid pool desired state".into())
            })?,
            owner: match (
                row.try_get::<Option<String>, _>("owner_panel")?,
                row.try_get::<Option<String>, _>("owner_server")?,
            ) {
                (Some(panel_id), Some(server_id)) => Some(crate::placement::PoolOwner {
                    panel_id,
                    server_id,
                }),
                (None, None) => None,
                _ => {
                    return Err(PlacementRepositoryError::InvalidReservation(
                        "incomplete pool owner".into(),
                    ));
                }
            },
            schema_version: u32::try_from(schema_version).map_err(|_| {
                PlacementRepositoryError::InvalidInteger {
                    field: "schema_version",
                    value: schema_version,
                }
            })?,
            runtime_id,
            protocol,
            deployment_mode,
            status,
            backend,
            runtime: RuntimeMetadata {
                kind: runtime_kind,
                container_name: row.try_get("container_name")?,
                network_mode: row.try_get("network")?,
            },
            limits,
            image: row.try_get("image")?,
            database_version: row.try_get("database_version")?,
            compatibility: read_compatibility(row)?,
            max_tenants: u32::try_from(max_tenants).map_err(|_| {
                PlacementRepositoryError::InvalidInteger {
                    field: "max_tenants",
                    value: max_tenants,
                }
            })?,
            reserved: RuntimeReservation {
                tenants: u32::try_from(tenant_count).map_err(|_| {
                    PlacementRepositoryError::InvalidInteger {
                        field: "tenant_count",
                        value: tenant_count,
                    }
                })?,
                disk_mib: reserved_disk_mib,
            },
            admin_secret,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        };
        runtime.check()?;
        Ok(runtime)
    }

    fn protect_admin(
        &self,
        runtime_id: &str,
        secret: &str,
    ) -> Result<String, PlacementRepositoryError> {
        self.secrets
            .as_ref()
            .map(|secrets| secrets.encrypt(ADMIN_SECRET_FIELD, runtime_id, secret))
            .unwrap_or_else(|| Ok(secret.to_string()))
            .map_err(PlacementRepositoryError::Secrets)
    }

    fn unprotect_admin(
        &self,
        runtime_id: &str,
        secret: &str,
    ) -> Result<String, PlacementRepositoryError> {
        self.secrets
            .as_ref()
            .map(|secrets| secrets.decrypt(ADMIN_SECRET_FIELD, runtime_id, secret))
            .unwrap_or_else(|| Ok(secret.to_string()))
            .map_err(|source| PlacementRepositoryError::InvalidAdminSecret {
                runtime_id: runtime_id.to_string(),
                source,
            })
    }
}

fn runtime_select(suffix: &str) -> String {
    format!(
        r#"
        SELECT
            runtime.*,
            auth.admin_secret
        FROM engine_runtimes AS runtime
        LEFT JOIN engine_runtime_auth AS auth ON auth.runtime_id = runtime.runtime_id
        {suffix}
        "#
    )
}

fn read_backend(row: &SqliteRow) -> Result<BackendEndpoint, PlacementRepositoryError> {
    let kind: String = row.try_get("backend_kind")?;
    match kind.as_str() {
        "unix_socket" => Ok(BackendEndpoint::UnixSocket {
            socket_path: row.try_get("backend_socket_path")?,
        }),
        "docker_tcp" => {
            let port: i64 = row.try_get("backend_port")?;
            Ok(BackendEndpoint::DockerTcp {
                host: row.try_get("backend_host")?,
                port: u16::try_from(port).map_err(|_| {
                    PlacementRepositoryError::InvalidInteger {
                        field: "backend_port",
                        value: port,
                    }
                })?,
            })
        }
        _ => Err(PlacementRepositoryError::InvalidValue {
            field: "backend_kind",
            value: kind,
        }),
    }
}

fn read_compatibility(
    row: &SqliteRow,
) -> Result<Option<RuntimeCompatibility>, PlacementRepositoryError> {
    let container_id: Option<String> = row.try_get("compatibility_container_id")?;
    let image_id: Option<String> = row.try_get("compatibility_image_id")?;
    let revision: Option<i64> = row.try_get("compatibility_probe_revision")?;
    match (container_id, image_id, revision) {
        (None, None, None) => Ok(None),
        (Some(container_id), Some(image_id), Some(revision)) => {
            let probe_revision =
                u32::try_from(revision).map_err(|_| PlacementRepositoryError::InvalidInteger {
                    field: "compatibility_probe_revision",
                    value: revision,
                })?;
            Ok(Some(RuntimeCompatibility {
                container_id,
                image_id,
                probe_revision,
            }))
        }
        _ => Err(PlacementRepositoryError::InvalidValue {
            field: "compatibility",
            value: "partial runtime compatibility identity".to_string(),
        }),
    }
}

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
