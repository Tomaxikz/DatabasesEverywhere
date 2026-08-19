use super::{manager::InstanceManager, metadata::InstanceMetadata};
use crate::{
    runtime::docker::{DockerRuntime, ManagedContainerIdentity},
    shared::protocol::Protocol,
};

pub(crate) const POSTGRES_HARDENING_REVISION: u32 = 1;
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
    let revision = revision(metadata.protocol).ok_or_else(|| {
        format!(
            "{} does not use authentication hardening attestations",
            metadata.protocol
        )
    })?;
    let identity = required_identity(docker, metadata).await?;
    let (mut current, cache_warning) = match manager
        .auth_hardening_attestation_is_current(metadata, &identity, revision)
        .await
    {
        Ok(current) => (current, None),
        Err(error) => (false, Some(error.to_string())),
    };

    // The SQLite lookup above is an await point. Re-read Docker before a
    // cached proof is allowed to skip live hardening.
    let confirmed = required_identity(docker, metadata).await?;
    if confirmed != identity {
        current = false;
    }
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
    if revision(metadata.protocol) != Some(generation.revision) {
        return Err(AuthHardeningCompletionError::ContainerChanged);
    }
    ensure_generation(docker, metadata, &generation.identity).await?;
    let storage = manager
        .record_auth_hardening_attestation(metadata, &generation.identity, generation.revision)
        .await
        .map_err(|error| AuthHardeningCompletionError::Storage(error.to_string()));
    // A restart can race the SQLite write. A stale row is harmless because it
    // is identity-bound, but the caller must not publish a route to the new
    // generation as if the old process had been hardened.
    ensure_generation(docker, metadata, &generation.identity).await?;
    storage?;
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
        .verified_managed_container_identity(metadata.protocol, &metadata.instance_id)
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
        .verified_managed_container_identity(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(|error| AuthHardeningCompletionError::Runtime(error.to_string()))?
        .ok_or(AuthHardeningCompletionError::ContainerMissing)?;
    if &actual != expected {
        return Err(AuthHardeningCompletionError::ContainerChanged);
    }
    Ok(())
}

pub(crate) fn revision(protocol: Protocol) -> Option<u32> {
    match protocol {
        Protocol::Postgres => Some(POSTGRES_HARDENING_REVISION),
        Protocol::Mysql => Some(MYSQL_HARDENING_REVISION),
        _ => None,
    }
}
