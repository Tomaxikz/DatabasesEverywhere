use sqlx::Row;

use super::{InstanceRepository, RepositoryError};
use crate::shared::protocol::Protocol;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompatibilityAttestation {
    pub(crate) instance_id: String,
    pub(crate) protocol: Protocol,
    pub(crate) container_id: String,
    pub(crate) image_id: String,
    pub(crate) probe_revision: u32,
    pub(crate) version: String,
    pub(crate) compatible: bool,
    pub(crate) diagnostic: Option<String>,
}

impl InstanceRepository {
    pub(crate) async fn delete_compatibility_attestation(
        &self,
        instance_id: &str,
    ) -> Result<(), RepositoryError> {
        sqlx::query("DELETE FROM instance_compatibility_attestations WHERE instance_id = ?1")
            .bind(instance_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub(crate) async fn compatibility_attestation(
        &self,
        instance_id: &str,
    ) -> Result<Option<CompatibilityAttestation>, RepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT
                instance_id,
                protocol,
                container_id,
                image_id,
                probe_revision,
                version,
                compatible,
                diagnostic
            FROM instance_compatibility_attestations
            WHERE instance_id = ?1
            LIMIT 1
            "#,
        )
        .bind(instance_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(compatibility_attestation_from_row).transpose()
    }

    pub(crate) async fn record_compatibility_attestation(
        &self,
        attestation: &CompatibilityAttestation,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            r#"
            INSERT INTO instance_compatibility_attestations (
                instance_id,
                protocol,
                container_id,
                image_id,
                probe_revision,
                version,
                compatible,
                diagnostic,
                probed_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(instance_id) DO UPDATE SET
                protocol = excluded.protocol,
                container_id = excluded.container_id,
                image_id = excluded.image_id,
                probe_revision = excluded.probe_revision,
                version = excluded.version,
                compatible = excluded.compatible,
                diagnostic = excluded.diagnostic,
                probed_at = excluded.probed_at
            "#,
        )
        .bind(&attestation.instance_id)
        .bind(attestation.protocol.as_str())
        .bind(&attestation.container_id)
        .bind(&attestation.image_id)
        .bind(i64::from(attestation.probe_revision))
        .bind(&attestation.version)
        .bind(attestation.compatible)
        .bind(&attestation.diagnostic)
        .bind(crate::shared::time::now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

fn compatibility_attestation_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<CompatibilityAttestation, RepositoryError> {
    let protocol_text = row.try_get::<String, _>("protocol")?;
    let protocol = protocol_text.parse::<Protocol>().map_err(|_| {
        RepositoryError::InvalidCompatibilityAttestation {
            instance_id: row
                .try_get::<String, _>("instance_id")
                .unwrap_or_else(|_| "<unknown>".to_string()),
            reason: format!("unsupported protocol {protocol_text}"),
        }
    })?;
    let instance_id = row.try_get::<String, _>("instance_id")?;
    let revision = row.try_get::<i64, _>("probe_revision")?;
    let probe_revision =
        u32::try_from(revision).map_err(|_| RepositoryError::InvalidCompatibilityAttestation {
            instance_id: instance_id.clone(),
            reason: format!("invalid probe revision {revision}"),
        })?;
    Ok(CompatibilityAttestation {
        instance_id,
        protocol,
        container_id: row.try_get("container_id")?,
        image_id: row.try_get("image_id")?,
        probe_revision,
        version: row.try_get("version")?,
        compatible: row.try_get("compatible")?,
        diagnostic: row.try_get("diagnostic")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        instances::metadata::{
            DatabaseIdentity, DesiredInstanceState, InstanceMetadata, InstanceStatus,
            PublicEndpoint, RuntimeKind, RuntimeMetadata, SCHEMA_VERSION,
        },
        shared::{backend::BackendEndpoint, limits::InstanceLimits},
        storage::sqlite,
    };

    #[tokio::test]
    async fn attestation_is_replaced_atomically_and_deleted_with_the_instance() {
        let directory = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(directory.path()).await.unwrap();
        let repository = InstanceRepository::new(pool);
        let metadata = sample_metadata();
        repository.upsert(&metadata).await.unwrap();

        repository
            .record_compatibility_attestation(&CompatibilityAttestation {
                instance_id: metadata.instance_id.clone(),
                protocol: metadata.protocol,
                container_id: "123456789012abcdef".to_string(),
                image_id: "sha256:old-image-id".to_string(),
                probe_revision: 1,
                version: "8.4.6".to_string(),
                compatible: true,
                diagnostic: None,
            })
            .await
            .unwrap();
        repository
            .record_compatibility_attestation(&CompatibilityAttestation {
                instance_id: metadata.instance_id.clone(),
                protocol: metadata.protocol,
                container_id: "abcdef123456789012".to_string(),
                image_id: "sha256:new-image-id".to_string(),
                probe_revision: 2,
                version: "9.7.0".to_string(),
                compatible: false,
                diagnostic: Some("unsupported test version".to_string()),
            })
            .await
            .unwrap();

        let attestation = repository
            .compatibility_attestation(&metadata.instance_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(attestation.container_id, "abcdef123456789012");
        assert_eq!(attestation.image_id, "sha256:new-image-id");
        assert_eq!(attestation.probe_revision, 2);
        assert_eq!(attestation.version, "9.7.0");
        assert!(!attestation.compatible);

        repository.delete(&metadata.instance_id).await.unwrap();
        assert!(
            repository
                .compatibility_attestation(&metadata.instance_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    fn sample_metadata() -> InstanceMetadata {
        InstanceMetadata {
            schema_version: SCHEMA_VERSION,
            instance_id: "inst_compatibility".to_string(),
            protocol: Protocol::Mysql,
            status: InstanceStatus::Running,
            desired_state: DesiredInstanceState::Running,
            disk_limit_blocked: false,
            public: PublicEndpoint {
                host: "db.example.test".to_string(),
                port: 3306,
            },
            backend: BackendEndpoint::UnixSocket {
                socket_path: "/run/dbev/mysql.sock".to_string(),
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: "dbe-mysql-inst_compatibility".to_string(),
                network_mode: "none".to_string(),
            },
            database: DatabaseIdentity {
                name: "app".to_string(),
                username: "tenant".to_string(),
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
            created_at: "2026-08-19T00:00:00Z".to_string(),
            updated_at: "2026-08-19T00:00:00Z".to_string(),
        }
    }
}
