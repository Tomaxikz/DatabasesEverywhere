use std::{fmt, str::FromStr};

use secrecy::{ExposeSecret, SecretString};
use sqlx::Row;
use subtle::ConstantTimeEq;

use crate::{
    instances::metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus},
    shared::time::now_rfc3339,
    storage::secrets::SecretStoreError,
};

use super::{InstanceRepository, RepositoryError, validate_metadata_schema};

#[derive(Debug, Clone)]
pub struct DaemonInstanceLoad {
    pub metadata: Vec<InstanceMetadata>,
    pub protected_secret_incidents: Vec<ProtectedSecretIncident>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedSecretIncident {
    pub instance_id: String,
    pub fields: Vec<ProtectedSecretField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedSecretRepair {
    pub remaining_fields: Vec<ProtectedSecretField>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectedSecretField {
    MariadbNativePasswordSha1Stage2,
    MariadbRootPassword,
    MysqlNativePasswordSha1Stage2,
    MysqlRootPassword,
    MongodbRootPassword,
    PostgresAdminPassword,
    TenantPassword,
}

impl ProtectedSecretField {
    pub const ALL: [Self; 7] = [
        Self::MariadbNativePasswordSha1Stage2,
        Self::MariadbRootPassword,
        Self::MysqlNativePasswordSha1Stage2,
        Self::MysqlRootPassword,
        Self::MongodbRootPassword,
        Self::PostgresAdminPassword,
        Self::TenantPassword,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MariadbNativePasswordSha1Stage2 => "mariadb_native_password_sha1_stage2",
            Self::MariadbRootPassword => "mariadb_root_password",
            Self::MysqlNativePasswordSha1Stage2 => "mysql_native_password_sha1_stage2",
            Self::MysqlRootPassword => "mysql_root_password",
            Self::MongodbRootPassword => "mongodb_root_password",
            Self::PostgresAdminPassword => "postgres_admin_password",
            Self::TenantPassword => "tenant_password",
        }
    }

    fn assign(self, metadata: &mut InstanceMetadata, value: Option<String>) {
        match self {
            Self::MariadbNativePasswordSha1Stage2 => {
                metadata.mariadb_native_password_sha1_stage2 = value;
            }
            Self::MariadbRootPassword => metadata.mariadb_root_password = value,
            Self::MysqlNativePasswordSha1Stage2 => {
                metadata.mysql_native_password_sha1_stage2 = value;
            }
            Self::MysqlRootPassword => metadata.mysql_root_password = value,
            Self::MongodbRootPassword => metadata.mongodb_root_password = value,
            Self::PostgresAdminPassword => metadata.postgres_admin_password = value,
            Self::TenantPassword => metadata.tenant_password = value,
        }
    }
}

impl fmt::Display for ProtectedSecretField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ProtectedSecretField {
    type Err = ProtectedSecretFieldParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.replace('-', "_");
        Self::ALL
            .into_iter()
            .find(|field| field.as_str() == normalized)
            .ok_or_else(|| ProtectedSecretFieldParseError(value.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unsupported protected secret field {0:?}")]
pub struct ProtectedSecretFieldParseError(String);

impl InstanceRepository {
    pub async fn load_for_daemon(&self) -> Result<DaemonInstanceLoad, RepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT
                instance_metadata.instance_id AS durable_instance_id,
                instance_metadata.metadata_json,
                instance_metadata.desired_state,
                instance_metadata.disk_limit_blocked,
                instance_metadata.protected_secret_recovery_required,
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

        let mut metadata_rows = Vec::with_capacity(rows.len());
        let mut incidents = Vec::new();
        let mut quarantine_updates = Vec::new();
        let mut cleared_recovery_markers = Vec::new();

        for row in rows {
            let durable_instance_id: String = row.try_get("durable_instance_id")?;
            let metadata_json: String = row.try_get("metadata_json")?;
            let mut metadata = serde_json::from_str::<InstanceMetadata>(&metadata_json)?;
            validate_metadata_identity(&durable_instance_id, &metadata)?;
            self.load_desired_state(&mut metadata, &row)?;
            self.load_disk_limit_blocked(&mut metadata, &row)?;
            validate_metadata_schema(&metadata)?;
            let recovery_required: bool = row.try_get("protected_secret_recovery_required")?;
            let invalid_fields = self.load_route_auth_tolerant(&mut metadata, &row)?;

            if invalid_fields.is_empty() {
                if recovery_required {
                    metadata.status = InstanceStatus::Stopped;
                    metadata.desired_state = DesiredInstanceState::Stopped;
                    metadata.updated_at = now_rfc3339();
                    cleared_recovery_markers.push((
                        metadata.instance_id.clone(),
                        serde_json::to_string(&metadata)?,
                        metadata.updated_at.clone(),
                    ));
                }
            } else {
                clear_route_auth(&mut metadata);
                metadata.status = InstanceStatus::Quarantined;
                metadata.desired_state = DesiredInstanceState::Stopped;
                metadata.updated_at = now_rfc3339();
                quarantine_updates.push((
                    metadata.instance_id.clone(),
                    serde_json::to_string(&metadata)?,
                    metadata.updated_at.clone(),
                ));
                incidents.push(ProtectedSecretIncident {
                    instance_id: metadata.instance_id.clone(),
                    fields: invalid_fields,
                });
            }
            metadata_rows.push(metadata);
        }

        if !quarantine_updates.is_empty() || !cleared_recovery_markers.is_empty() {
            let mut transaction = self.pool.begin().await?;
            for (instance_id, metadata_json, updated_at) in quarantine_updates {
                sqlx::query(
                    r#"
                    UPDATE instance_metadata
                    SET status = 'quarantined',
                        desired_state = 'stopped',
                        protected_secret_recovery_required = 1,
                        metadata_json = ?2,
                        updated_at = ?3
                    WHERE instance_id = ?1
                    "#,
                )
                .bind(instance_id)
                .bind(metadata_json)
                .bind(updated_at)
                .execute(&mut *transaction)
                .await?;
            }
            for (instance_id, metadata_json, updated_at) in cleared_recovery_markers {
                sqlx::query(
                    r#"
                    UPDATE instance_metadata
                    SET status = 'stopped',
                        desired_state = 'stopped',
                        protected_secret_recovery_required = 0,
                        metadata_json = ?2,
                        updated_at = ?3
                    WHERE instance_id = ?1
                    "#,
                )
                .bind(instance_id)
                .bind(metadata_json)
                .bind(updated_at)
                .execute(&mut *transaction)
                .await?;
            }
            transaction.commit().await?;
        }

        Ok(DaemonInstanceLoad {
            metadata: metadata_rows,
            protected_secret_incidents: incidents,
        })
    }

    pub async fn repair_ambiguous_protected_secret(
        &self,
        instance_id: &str,
        field: ProtectedSecretField,
        known_plaintext: &SecretString,
    ) -> Result<ProtectedSecretRepair, RepositoryError> {
        let secrets = self
            .secrets
            .as_ref()
            .ok_or(RepositoryError::EncryptedRepositoryRequired)?;
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            r#"
            SELECT
                instance_metadata.metadata_json,
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
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| RepositoryError::InstanceNotFound(instance_id.to_string()))?;

        let raw: Option<String> = row.try_get(field.as_str())?;
        let raw = raw.ok_or_else(|| RepositoryError::ProtectedSecretMissing {
            instance_id: instance_id.to_string(),
            field: field.to_string(),
        })?;
        match secrets.decrypt(field.as_str(), instance_id, &raw) {
            Ok(_) => {
                return Err(RepositoryError::ProtectedSecretAlreadyValid {
                    instance_id: instance_id.to_string(),
                    field: field.to_string(),
                });
            }
            Err(SecretStoreError::InvalidCiphertext) => {}
            Err(error) => return Err(RepositoryError::Secrets(error)),
        }
        if !bool::from(
            raw.as_bytes()
                .ct_eq(known_plaintext.expose_secret().as_bytes()),
        ) {
            return Err(RepositoryError::ProtectedSecretPlaintextMismatch {
                instance_id: instance_id.to_string(),
                field: field.to_string(),
            });
        }

        let encrypted =
            secrets.encrypt(field.as_str(), instance_id, known_plaintext.expose_secret())?;
        let update = format!(
            "UPDATE instance_route_auth SET {} = ?1, updated_at = ?2 WHERE instance_id = ?3",
            field.as_str()
        );
        let updated_at = now_rfc3339();
        let result = sqlx::query(&update)
            .bind(encrypted)
            .bind(&updated_at)
            .bind(instance_id)
            .execute(&mut *transaction)
            .await?;
        if result.rows_affected() != 1 {
            return Err(RepositoryError::ProtectedSecretMissing {
                instance_id: instance_id.to_string(),
                field: field.to_string(),
            });
        }

        let route_auth = sqlx::query(
            r#"
            SELECT
                mariadb_native_password_sha1_stage2,
                mariadb_root_password,
                mysql_native_password_sha1_stage2,
                mysql_root_password,
                mongodb_root_password,
                postgres_admin_password,
                tenant_password
            FROM instance_route_auth
            WHERE instance_id = ?1
            "#,
        )
        .bind(instance_id)
        .fetch_one(&mut *transaction)
        .await?;
        let remaining_fields = invalid_fields(secrets, instance_id, &route_auth)?;

        let metadata_json: String = row.try_get("metadata_json")?;
        let mut metadata = serde_json::from_str::<InstanceMetadata>(&metadata_json)?;
        validate_metadata_identity(instance_id, &metadata)?;
        validate_metadata_schema(&metadata)?;
        metadata.status = if remaining_fields.is_empty() {
            InstanceStatus::Stopped
        } else {
            InstanceStatus::Quarantined
        };
        metadata.desired_state = DesiredInstanceState::Stopped;
        metadata.updated_at = updated_at;
        let metadata_json = serde_json::to_string(&metadata)?;
        sqlx::query(
            r#"
            UPDATE instance_metadata
            SET status = ?2,
                desired_state = 'stopped',
                protected_secret_recovery_required = ?3,
                metadata_json = ?4,
                updated_at = ?5
            WHERE instance_id = ?1
            "#,
        )
        .bind(instance_id)
        .bind(metadata.status.as_str())
        .bind(!remaining_fields.is_empty())
        .bind(metadata_json)
        .bind(&metadata.updated_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;

        Ok(ProtectedSecretRepair { remaining_fields })
    }

    fn load_route_auth_tolerant(
        &self,
        metadata: &mut InstanceMetadata,
        row: &sqlx::sqlite::SqliteRow,
    ) -> Result<Vec<ProtectedSecretField>, RepositoryError> {
        let mut invalid = Vec::new();
        for field in ProtectedSecretField::ALL {
            let raw: Option<String> = row.try_get(field.as_str())?;
            match self.unprotect_route_secret(field.as_str(), &metadata.instance_id, raw) {
                Ok(value) => field.assign(metadata, value),
                Err(RepositoryError::InvalidProtectedSecret { .. }) => {
                    field.assign(metadata, None);
                    invalid.push(field);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(invalid)
    }
}

fn invalid_fields(
    secrets: &crate::storage::secrets::SecretStore,
    instance_id: &str,
    row: &sqlx::sqlite::SqliteRow,
) -> Result<Vec<ProtectedSecretField>, RepositoryError> {
    let mut invalid = Vec::new();
    for field in ProtectedSecretField::ALL {
        let raw: Option<String> = row.try_get(field.as_str())?;
        let Some(raw) = raw else {
            continue;
        };
        match secrets.decrypt(field.as_str(), instance_id, &raw) {
            Ok(_) => {}
            Err(SecretStoreError::InvalidCiphertext) => invalid.push(field),
            Err(error) => return Err(RepositoryError::Secrets(error)),
        }
    }
    Ok(invalid)
}

fn clear_route_auth(metadata: &mut InstanceMetadata) {
    for field in ProtectedSecretField::ALL {
        field.assign(metadata, None);
    }
}

fn validate_metadata_identity(
    durable_instance_id: &str,
    metadata: &InstanceMetadata,
) -> Result<(), RepositoryError> {
    if metadata.instance_id == durable_instance_id {
        Ok(())
    } else {
        Err(RepositoryError::MetadataIdentityMismatch {
            durable_instance_id: durable_instance_id.to_string(),
            embedded_instance_id: metadata.instance_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
