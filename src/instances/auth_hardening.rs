use super::{manager::InstanceManager, metadata::InstanceMetadata};
use crate::{runtime::docker::DockerRuntime, shared::protocol::Protocol};

pub(crate) const POSTGRES_HARDENING_REVISION: u32 = 1;
pub(crate) const MYSQL_HARDENING_REVISION: u32 = 1;

pub(crate) async fn attestation_is_current(
    manager: &InstanceManager,
    docker: &DockerRuntime,
    metadata: &InstanceMetadata,
) -> Result<bool, String> {
    let Some(revision) = revision(metadata.protocol) else {
        return Ok(false);
    };
    let Some(identity) = docker
        .verified_managed_container_identity(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(|error| error.to_string())?
    else {
        return Ok(false);
    };
    let current = manager
        .auth_hardening_attestation_is_current(metadata, &identity, revision)
        .await
        .map_err(|error| error.to_string())?;
    if current {
        tracing::info!(
            event = "audit auth_hardening_attestation_reused",
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            container_id = %identity.id,
            container_started_at = %identity.started_at,
            hardening_revision = revision,
            "skipped repeat authentication hardening for an unchanged container generation"
        );
    }
    Ok(current)
}

pub(crate) async fn record_attestation(
    manager: &InstanceManager,
    docker: &DockerRuntime,
    metadata: &InstanceMetadata,
) -> Result<(), String> {
    let Some(revision) = revision(metadata.protocol) else {
        return Ok(());
    };
    let identity = docker
        .verified_managed_container_identity(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            "the managed container disappeared before hardening was recorded".to_string()
        })?;
    manager
        .record_auth_hardening_attestation(metadata, &identity, revision)
        .await
        .map_err(|error| error.to_string())?;
    tracing::info!(
        event = "audit auth_hardening_attested",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        container_id = %identity.id,
        container_started_at = %identity.started_at,
        hardening_revision = revision,
        "persisted successful authentication hardening for this exact container generation"
    );
    Ok(())
}

pub(crate) fn revision(protocol: Protocol) -> Option<u32> {
    match protocol {
        Protocol::Postgres => Some(POSTGRES_HARDENING_REVISION),
        Protocol::Mysql => Some(MYSQL_HARDENING_REVISION),
        _ => None,
    }
}
