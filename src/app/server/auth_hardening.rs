use super::{manager::InstanceManager, metadata::InstanceMetadata};
use crate::runtime::docker::{DockerRuntime, ManagedContainerIdentity};

/// Revision 1 attested local SCRAM. Revision 2 adds the daemon-owned
/// replication role and its local HBA line, so a revision 1 attestation is
/// stale and `harden_postgres` runs the script again on daemon upgrade.
pub(crate) const POSTGRES_HARDENING_REVISION: u32 = 2;
pub(crate) const MYSQL_HARDENING_REVISION: u32 = 1;

#[derive(Debug, Clone)]
pub(crate) struct AuthHardeningCheck {
    pub(crate) current: bool,
    pub(crate) cache_warning: Option<String>,
    generation: AuthHardeningGeneration,
}

#[derive(Debug, Clone)]
pub(crate) struct AuthHardeningGeneration {
    identity: ManagedContainerIdentity,
    revision: u32,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AuthHardeningCompletionError {
    #[error("managed container disappeared while authentication hardening was in progress")]
    ContainerMissing,
    #[error("managed container generation changed while authentication hardening was in progress")]
    ContainerChanged,
    #[error("managed container identity could not be verified after authentication hardening: {0}")]
    Runtime(String),
    #[error("authentication hardening attestation could not be persisted: {0}")]
    Storage(String),
}

impl AuthHardeningCompletionError {
    pub(crate) fn is_storage(&self) -> bool {
        matches!(self, Self::Storage(_))
    }
}

pub(crate) async fn begin_attestation(
    manager: &InstanceManager,
    docker: &DockerRuntime,
    metadata: &InstanceMetadata,
) -> Result<AuthHardeningCheck, String> {
    let revision = metadata
        .protocol
        .engine()
        .auth_hardening_revision()
        .ok_or_else(|| {
            format!(
                "{} does not use authentication hardening attestations",
                metadata.protocol
            )
        })?;
    let identity = required_identity(docker, metadata).await?;
    let (cached_as_current, cache_warning) = match manager
        .hardening_is_current(metadata, &identity, revision)
        .await
    {
        Ok(current) => (current, None),
        Err(error) => (false, Some(error.to_string())),
    };

    // The SQLite lookup above is an await point. Re-read Docker before a
    // cached proof is allowed to skip live hardening.
    let confirmed = required_identity(docker, metadata).await?;
    let current = cached_as_current && confirmed == identity;
    if current {
        tracing::info!(
            event = "audit auth_hardening_attestation_reused",
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            container_id = %confirmed.id,
            container_started_at = %confirmed.started_at,
            hardening_revision = revision,
            "skipped repeat authentication hardening for an unchanged container generation"
        );
    }
    Ok(AuthHardeningCheck {
        current,
        cache_warning,
        generation: AuthHardeningGeneration {
            identity: confirmed,
            revision,
        },
    })
}

pub(crate) async fn complete_attestation(
    manager: &InstanceManager,
    docker: &DockerRuntime,
    metadata: &InstanceMetadata,
    generation: &AuthHardeningGeneration,
) -> Result<(), AuthHardeningCompletionError> {
    if metadata.protocol.engine().auth_hardening_revision() != Some(generation.revision) {
        return Err(AuthHardeningCompletionError::ContainerChanged);
    }
    ensure_generation(docker, metadata, &generation.identity).await?;
    let recorded = manager
        .record_hardening_attestation(metadata, &generation.identity, generation.revision)
        .await
        .map_err(|error| AuthHardeningCompletionError::Storage(error.to_string()));
    // A restart can race the SQLite write. A stale row is harmless because it
    // is identity-bound, but the caller must not publish a route to the new
    // generation as if the old process had been hardened.
    ensure_generation(docker, metadata, &generation.identity).await?;
    recorded?;
    tracing::info!(
        event = "audit auth_hardening_attested",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        container_id = %generation.identity.id,
        container_started_at = %generation.identity.started_at,
        hardening_revision = generation.revision,
        "persisted successful authentication hardening for this exact container generation"
    );
    Ok(())
}

impl AuthHardeningCheck {
    pub(crate) fn generation(&self) -> &AuthHardeningGeneration {
        &self.generation
    }
}

async fn required_identity(
    docker: &DockerRuntime,
    metadata: &InstanceMetadata,
) -> Result<ManagedContainerIdentity, String> {
    docker
        .verified_container_identity(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "the managed container is missing".to_string())
}

async fn ensure_generation(
    docker: &DockerRuntime,
    metadata: &InstanceMetadata,
    expected: &ManagedContainerIdentity,
) -> Result<(), AuthHardeningCompletionError> {
    let actual = docker
        .verified_container_identity(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(|error| AuthHardeningCompletionError::Runtime(error.to_string()))?
        .ok_or(AuthHardeningCompletionError::ContainerMissing)?;
    if &actual != expected {
        return Err(AuthHardeningCompletionError::ContainerChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::POSTGRES_HARDENING_REVISION;
    use crate::{
        databases::protocol::Protocol,
        runtime::docker::ManagedContainerIdentity,
        server::{manager::InstanceManager, state::InstanceStore, test_support},
        storage::{repositories::InstanceRepository, sqlite},
    };

    #[test]
    fn postgres_hardening_revision_includes_the_replication_role() {
        assert_eq!(
            Protocol::Postgres.engine().auth_hardening_revision(),
            Some(POSTGRES_HARDENING_REVISION)
        );
        assert_ne!(
            Protocol::Postgres.engine().auth_hardening_revision(),
            Some(1)
        );
        assert_eq!(
            Protocol::Mysql.engine().auth_hardening_revision(),
            Some(super::MYSQL_HARDENING_REVISION)
        );
    }

    /// `begin_attestation` reports `current: false` when this lookup is false.
    /// That is the signal `harden_postgres` uses to run the script again.
    #[tokio::test]
    async fn revision_one_attestation_is_not_current() {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let repository = InstanceRepository::encrypted(pool, dir.path()).unwrap();
        let manager = InstanceManager::new(InstanceStore::default(), repository);
        let mut metadata = test_support::metadata("inst_pg_rev", Protocol::Postgres);
        metadata.tenant_password = Some("tenant-secret".to_string());
        metadata.postgres_admin_password = Some("admin-secret".to_string());
        manager.upsert(metadata.clone()).await.unwrap();
        let identity = ManagedContainerIdentity {
            id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
            started_at: "2026-08-13T12:00:00Z".into(),
        };
        manager
            .record_hardening_attestation(&metadata, &identity, 1)
            .await
            .unwrap();
        assert!(
            !manager
                .hardening_is_current(&metadata, &identity, POSTGRES_HARDENING_REVISION)
                .await
                .unwrap()
        );
        manager
            .record_hardening_attestation(&metadata, &identity, POSTGRES_HARDENING_REVISION)
            .await
            .unwrap();
        assert!(
            manager
                .hardening_is_current(&metadata, &identity, POSTGRES_HARDENING_REVISION)
                .await
                .unwrap()
        );
    }
}
