use crate::{
    compatibility::{
        COMPATIBILITY_PROBE_REVISION, compatibility_profile, database_version_script,
        normalize_database_version,
    },
    instances::{manager::InstanceManager, metadata::InstanceMetadata},
    runtime::docker::DockerRuntime,
    storage::repositories::CompatibilityAttestation,
};

const COMPATIBILITY_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompatibilityProbeOutcome {
    pub(crate) version: String,
    pub(crate) compatible: bool,
    pub(crate) diagnostic: Option<String>,
    pub(crate) reused: bool,
}

impl From<CompatibilityAttestation> for CompatibilityProbeOutcome {
    fn from(attestation: CompatibilityAttestation) -> Self {
        Self {
            version: attestation.version,
            compatible: attestation.compatible,
            diagnostic: attestation.diagnostic,
            reused: true,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CompatibilityProbeError {
    #[error("managed container identity could not be inspected: {0}")]
    Runtime(String),
    #[error("managed container disappeared before its compatibility probe")]
    ContainerMissing,
    #[error("managed container changed while its database version was being probed")]
    ContainerChanged,
    #[error("database version probe failed: {0}")]
    Probe(String),
    #[error("database version command returned no parseable output")]
    Unparseable,
    #[error("compatibility attestation storage failed: {0}")]
    Storage(String),
}

pub(crate) async fn compatibility_attestation(
    manager: &InstanceManager,
    docker: &DockerRuntime,
    metadata: &InstanceMetadata,
) -> Result<Option<CompatibilityProbeOutcome>, CompatibilityProbeError> {
    let attestation = manager
        .compatibility_attestation(&metadata.instance_id)
        .await
        .map_err(|error| CompatibilityProbeError::Storage(error.to_string()))?
        .filter(|attestation| {
            attestation.protocol == metadata.protocol
                && attestation.probe_revision == COMPATIBILITY_PROBE_REVISION
        });
    let Some(attestation) = attestation else {
        return Ok(None);
    };
    let Some(identity) = docker
        .verified_managed_compatibility_identity(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(|error| CompatibilityProbeError::Runtime(error.to_string()))?
    else {
        return Ok(None);
    };
    if attestation.container_id != identity.id || attestation.image_id != identity.image_id {
        return Ok(None);
    }
    Ok(Some(attestation.into()))
}

pub(crate) async fn probe_instance_compatibility(
    manager: &InstanceManager,
    docker: &DockerRuntime,
    metadata: &InstanceMetadata,
    force: bool,
) -> Result<CompatibilityProbeOutcome, CompatibilityProbeError> {
    let mut identity = docker
        .verified_managed_compatibility_identity(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(|error| CompatibilityProbeError::Runtime(error.to_string()))?
        .ok_or(CompatibilityProbeError::ContainerMissing)?;

    if !force
        && let Some(attestation) = manager
            .compatibility_attestation(&metadata.instance_id)
            .await
            .map_err(|error| CompatibilityProbeError::Storage(error.to_string()))?
        && attestation.protocol == metadata.protocol
        && attestation.container_id == identity.id
        && attestation.image_id == identity.image_id
        && attestation.probe_revision == COMPATIBILITY_PROBE_REVISION
    {
        let confirmed = docker
            .verified_managed_compatibility_identity(metadata.protocol, &metadata.instance_id)
            .await
            .map_err(|error| CompatibilityProbeError::Runtime(error.to_string()))?
            .ok_or(CompatibilityProbeError::ContainerMissing)?;
        if confirmed == identity {
            tracing::debug!(
                event = "audit compatibility_attestation_reused",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                version = %attestation.version,
                "reused the compatibility probe for an unchanged container and image"
            );
            return Ok(attestation.into());
        }
        identity = confirmed;
    }

    if force {
        // A forced lifecycle trigger deliberately invalidates the previous
        // proof before executing. If the command then fails, callers and the
        // next boot see "not attested" rather than trusting stale evidence.
        manager
            .delete_compatibility_attestation(&metadata.instance_id)
            .await
            .map_err(|error| CompatibilityProbeError::Storage(error.to_string()))?;
    }

    let output = docker
        .exec_shell_with_timeout(
            metadata.protocol,
            &metadata.instance_id,
            database_version_script(metadata.protocol),
            COMPATIBILITY_PROBE_TIMEOUT,
        )
        .await
        .map_err(|error| CompatibilityProbeError::Probe(error.to_string()))?;
    let version = normalize_database_version(metadata.protocol, &output.stdout)
        .ok_or(CompatibilityProbeError::Unparseable)?;
    if version.len() > 128 || version.chars().any(char::is_control) {
        return Err(CompatibilityProbeError::Unparseable);
    }
    let confirmed_identity = docker
        .verified_managed_compatibility_identity(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(|error| CompatibilityProbeError::Runtime(error.to_string()))?
        .ok_or(CompatibilityProbeError::ContainerMissing)?;
    if confirmed_identity != identity {
        return Err(CompatibilityProbeError::ContainerChanged);
    }
    let policy = compatibility_profile(metadata.protocol, &version);
    let (compatible, diagnostic) = match policy {
        Ok(_) => (true, None),
        Err(error) => (false, Some(error.to_string())),
    };
    manager
        .record_compatibility_attestation(&CompatibilityAttestation {
            instance_id: metadata.instance_id.clone(),
            protocol: metadata.protocol,
            container_id: identity.id.clone(),
            image_id: identity.image_id.clone(),
            probe_revision: COMPATIBILITY_PROBE_REVISION,
            version: version.clone(),
            compatible,
            diagnostic: diagnostic.clone(),
        })
        .await
        .map_err(|error| CompatibilityProbeError::Storage(error.to_string()))?;
    let recorded_identity = docker
        .verified_managed_compatibility_identity(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(|error| CompatibilityProbeError::Runtime(error.to_string()))?
        .ok_or(CompatibilityProbeError::ContainerMissing)?;
    if recorded_identity != identity {
        return Err(CompatibilityProbeError::ContainerChanged);
    }
    tracing::info!(
        event = "audit compatibility_attested",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        container_id = %identity.id,
        image_id = %identity.image_id,
        %version,
        compatible,
        forced = force,
        "persisted the database engine compatibility result for this exact container image"
    );
    Ok(CompatibilityProbeOutcome {
        version,
        compatible,
        diagnostic,
        reused: false,
    })
}
