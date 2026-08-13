use sqlx::Row;

use super::{InstanceRepository, RepositoryError};
use crate::{instances::metadata::InstanceMetadata, shared::protocol::Protocol};

impl InstanceRepository {
    pub(crate) async fn auth_hardening_attestation_is_current(
        &self,
        metadata: &InstanceMetadata,
        container_id: &str,
        container_started_at: &str,
        hardening_revision: u32,
    ) -> Result<bool, RepositoryError> {
        let credential_binding = self.auth_hardening_credential_binding(
            metadata,
            container_id,
            container_started_at,
            hardening_revision,
        )?;
        let row = sqlx::query(
            r#"
            SELECT
                protocol,
                container_id,
                container_started_at,
                hardening_revision,
                credential_binding
            FROM instance_auth_hardening_attestations
            WHERE instance_id = ?1
            LIMIT 1
            "#,
        )
        .bind(&metadata.instance_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(false);
        };
        Ok(
            row.try_get::<String, _>("protocol")? == metadata.protocol.as_str()
                && row.try_get::<String, _>("container_id")? == container_id
                && row.try_get::<String, _>("container_started_at")? == container_started_at
                && row.try_get::<i64, _>("hardening_revision")? == i64::from(hardening_revision)
                && row.try_get::<String, _>("credential_binding")? == credential_binding,
        )
    }

    pub(crate) async fn record_auth_hardening_attestation(
        &self,
        metadata: &InstanceMetadata,
        container_id: &str,
        container_started_at: &str,
        hardening_revision: u32,
    ) -> Result<(), RepositoryError> {
        let credential_binding = self.auth_hardening_credential_binding(
            metadata,
            container_id,
            container_started_at,
            hardening_revision,
        )?;
        sqlx::query(
            r#"
            INSERT INTO instance_auth_hardening_attestations (
                instance_id,
                protocol,
                container_id,
                container_started_at,
                hardening_revision,
                credential_binding,
                hardened_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(instance_id) DO UPDATE SET
                protocol = excluded.protocol,
                container_id = excluded.container_id,
                container_started_at = excluded.container_started_at,
                hardening_revision = excluded.hardening_revision,
                credential_binding = excluded.credential_binding,
                hardened_at = excluded.hardened_at
            "#,
        )
        .bind(&metadata.instance_id)
        .bind(metadata.protocol.as_str())
        .bind(container_id)
        .bind(container_started_at)
        .bind(i64::from(hardening_revision))
        .bind(credential_binding)
        .bind(crate::shared::time::now_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn auth_hardening_credential_binding(
        &self,
        metadata: &InstanceMetadata,
        container_id: &str,
        container_started_at: &str,
        hardening_revision: u32,
    ) -> Result<String, RepositoryError> {
        let secret_store = self
            .secrets
            .as_ref()
            .ok_or(RepositoryError::AuthHardeningAttestationRequiresEncryption)?;
        let tenant_password = required_credential(metadata, "tenant_password", || {
            metadata.tenant_password.as_deref()
        })?;
        let hardening_revision = hardening_revision.to_string();
        let mut fields = vec![
            metadata.protocol.as_str(),
            container_id,
            container_started_at,
            hardening_revision.as_str(),
            metadata.database.name.as_str(),
            metadata.database.username.as_str(),
            tenant_password,
        ];
        match metadata.protocol {
            Protocol::Postgres => fields.push(required_credential(
                metadata,
                "postgres_admin_password",
                || metadata.postgres_admin_password.as_deref(),
            )?),
            Protocol::Mysql => {
                fields.extend([
                    required_credential(metadata, "mysql_root_password", || {
                        metadata.mysql_root_password.as_deref()
                    })?,
                    required_credential(metadata, "mysql_native_password_sha1_stage2", || {
                        metadata.mysql_native_password_sha1_stage2.as_deref()
                    })?,
                ]);
            }
            _ => {
                return Err(RepositoryError::AuthHardeningCredentialMissing {
                    instance_id: metadata.instance_id.clone(),
                    field: "supported_protocol",
                });
            }
        }
        Ok(secret_store.fingerprint(
            "instance-auth-hardening-attestation-v1",
            &metadata.instance_id,
            &fields,
        ))
    }
}

fn required_credential<'a>(
    metadata: &InstanceMetadata,
    field: &'static str,
    value: impl FnOnce() -> Option<&'a str>,
) -> Result<&'a str, RepositoryError> {
    value().filter(|value| !value.is_empty()).ok_or_else(|| {
        RepositoryError::AuthHardeningCredentialMissing {
            instance_id: metadata.instance_id.clone(),
            field,
        }
    })
}
