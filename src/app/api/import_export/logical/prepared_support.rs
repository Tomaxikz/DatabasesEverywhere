use super::super::{
    LOGICAL_STREAM_EXEC_TIMEOUT, files::cleanup_path, files::logical_staging_root,
    logical_exec_recovery, protocol::wipe_logical_target,
};
use crate::{
    api::{
        http::{response::ApiError, router::AppState},
        import_export::remote::ImportMode,
    },
    instances::{credentials::logical_import_env, metadata::InstanceMetadata},
    placement::DeploymentMode,
    shared::protocol::Protocol,
};
use std::{
    path::{Path as FsPath, PathBuf},
    time::{Duration, Instant},
};

#[derive(Debug)]
pub(super) struct LogicalApplyError {
    error: ApiError,
    helper_uncertain: bool,
}

impl LogicalApplyError {
    pub(super) fn helper(error: ApiError) -> Self {
        Self {
            error,
            helper_uncertain: true,
        }
    }

    pub(super) fn helper_uncertain(&self) -> bool {
        self.helper_uncertain
    }

    pub(super) fn into_api_error(self) -> ApiError {
        self.error
    }
}

impl From<ApiError> for LogicalApplyError {
    fn from(error: ApiError) -> Self {
        Self {
            error,
            helper_uncertain: false,
        }
    }
}

pub(super) struct PreparedLogicalImport {
    pub(super) protocol: Protocol,
    pub(super) host_temp: PathBuf,
    pub(super) owns_host_temp: bool,
    pub(super) script: String,
    pub(super) exec_timeout: Option<Duration>,
    pub(super) database_definition_in_dump: bool,
    pub(super) prepared_source_bytes: u64,
    pub(super) expected_sha256: Option<[u8; 32]>,
    pub(super) pinned_input: Option<super::super::shared_restore::PinnedInput>,
    pub(super) staged_source_bytes: Option<u64>,
    pub(super) target: PreparedTarget,
}

impl std::fmt::Display for LogicalApplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct PreparedTarget {
    instance_id: String,
    created_at: String,
    deployment_mode: DeploymentMode,
    runtime_id: String,
    database: String,
    username: String,
}

pub(super) fn check_prepared_batch<'a>(
    metadata: &InstanceMetadata,
    prepared: &'a [PreparedLogicalImport],
) -> Result<&'a PreparedLogicalImport, ApiError> {
    check_batch(&PreparedTarget::new(metadata), metadata.protocol, prepared)
}

fn check_batch<'a>(
    target: &PreparedTarget,
    protocol: Protocol,
    prepared: &'a [PreparedLogicalImport],
) -> Result<&'a PreparedLogicalImport, ApiError> {
    let first = prepared.first().ok_or_else(|| {
        ApiError::Runtime("logical import did not contain any prepared artifacts".to_string())
    })?;
    if prepared.iter().any(|artifact| {
        artifact.protocol != protocol
            || artifact.exec_timeout != first.exec_timeout
            || artifact.database_definition_in_dump != first.database_definition_in_dump
            || artifact.target != *target
    }) {
        return Err(ApiError::Runtime(
            "logical import artifacts had inconsistent execution controls or target identity"
                .to_string(),
        ));
    }
    if target.deployment_mode == DeploymentMode::Shared
        && prepared
            .iter()
            .any(|artifact| artifact.expected_sha256.is_none() || artifact.pinned_input.is_none())
    {
        return Err(ApiError::Runtime(
            "shared restore is missing its inspected digest or private input snapshot".to_string(),
        ));
    }
    Ok(first)
}

impl PreparedTarget {
    pub(super) fn new(metadata: &InstanceMetadata) -> Self {
        Self {
            instance_id: metadata.instance_id.clone(),
            created_at: metadata.created_at.clone(),
            deployment_mode: metadata.deployment_mode,
            runtime_id: metadata.runtime_id().to_string(),
            database: metadata.database.name.clone(),
            username: metadata.database.username.clone(),
        }
    }
}

pub(super) fn parse_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16)? as u8;
        let low = (pair[1] as char).to_digit(16)? as u8;
        digest[index] = (high << 4) | low;
    }
    Some(digest)
}

pub(in crate::api::import_export) fn staging_reservation_bytes(
    deployment_mode: DeploymentMode,
    prepared_bytes: u64,
    rollback_bytes: u64,
) -> Result<u64, ApiError> {
    let bytes = prepared_bytes
        .checked_add(rollback_bytes)
        .ok_or_else(|| ApiError::Conflict("logical import staging overflowed".to_string()))?;
    if deployment_mode == DeploymentMode::Shared {
        bytes.checked_mul(2).ok_or_else(|| {
            ApiError::Conflict("shared import snapshot staging overflowed".to_string())
        })
    } else {
        Ok(bytes)
    }
}

pub(super) async fn pin_prepared_source(
    state: &AppState,
    path: &FsPath,
    bytes: u64,
    digest: Option<[u8; 32]>,
    remove_source_on_error: bool,
) -> Result<Option<super::super::shared_restore::PinnedInput>, ApiError> {
    let Some(digest) = digest else {
        return Ok(None);
    };
    let sandbox_parent = logical_staging_root(state).await?;
    match super::super::shared_restore::pin_input(path, &sandbox_parent, bytes, &digest).await {
        Ok(input) => Ok(Some(input)),
        Err(error) => {
            if remove_source_on_error {
                cleanup_path(path).await;
            }
            Err(error)
        }
    }
}

pub(super) async fn cleanup_prepared_logical_import(
    _state: &AppState,
    _metadata: &InstanceMetadata,
    prepared: &PreparedLogicalImport,
) {
    if let Some(input) = prepared.pinned_input.as_ref()
        && let Err(error) = input.cleanup().await
    {
        tracing::warn!(
            path = %input.root.display(),
            %error,
            "shared restore sandbox cleanup failed; drop and boot recovery will retry it"
        );
    }
    if prepared.owns_host_temp {
        cleanup_path(&prepared.host_temp).await;
    }
}

pub(super) async fn cleanup_prepared_logical_imports(
    state: &AppState,
    metadata: &InstanceMetadata,
    prepared: &[PreparedLogicalImport],
) {
    for artifact in prepared {
        cleanup_prepared_logical_import(state, metadata, artifact).await;
    }
}

pub(super) async fn apply_prepared_logical_import(
    state: &AppState,
    metadata: &InstanceMetadata,
    prepared: &PreparedLogicalImport,
    mode: ImportMode,
) -> Result<(), LogicalApplyError> {
    apply_prepared_logical_imports(state, metadata, std::slice::from_ref(prepared), mode).await
}

pub(super) async fn apply_prepared_logical_imports(
    state: &AppState,
    metadata: &InstanceMetadata,
    prepared: &[PreparedLogicalImport],
    mode: ImportMode,
) -> Result<(), LogicalApplyError> {
    let first = check_prepared_batch(metadata, prepared)?;
    let prepared_bytes = prepared
        .iter()
        .try_fold(0_u64, |total, artifact| {
            total.checked_add(artifact.prepared_source_bytes)
        })
        .ok_or_else(|| ApiError::BadRequest("prepared import size overflowed".to_string()))?;
    super::super::shared_security::admit_import(state, metadata, prepared_bytes, mode).await?;
    let runtime_id = metadata.runtime_id();
    if mode == ImportMode::Wipe {
        wipe_logical_target(
            state,
            metadata,
            first.exec_timeout,
            first.database_definition_in_dump,
        )
        .await?;
    }
    let credentials = logical_import_env(metadata, first.database_definition_in_dump)
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    let environment = credentials.references();
    let import_started = Instant::now();
    for artifact in prepared {
        let timeout = match artifact.exec_timeout {
            Some(total) => total
                .checked_sub(import_started.elapsed())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| {
                    ApiError::Runtime(format!(
                        "{} import timed out while applying multiple artifacts",
                        metadata.protocol.as_str()
                    ))
                })?,
            None => LOGICAL_STREAM_EXEC_TIMEOUT,
        };
        if metadata.deployment_mode == DeploymentMode::Shared {
            let input = artifact.pinned_input.as_ref().ok_or_else(|| {
                ApiError::Runtime("shared import lost its pinned input before mutation".to_string())
            })?;
            let result = super::super::shared_restore::run(
                state,
                super::super::shared_restore::RestoreRequest {
                    metadata,
                    script: &artifact.script,
                    environment: &environment,
                    input,
                    timeout,
                },
            )
            .await;
            if let Err(error) = result {
                let helper_uncertain = error.helper_uncertain();
                let error = error.into_api_error();
                return Err(if helper_uncertain {
                    LogicalApplyError::helper(error)
                } else {
                    error.into()
                });
            }
        } else {
            state
                .docker
                .exec_shell_with_input(
                    artifact.protocol,
                    runtime_id,
                    &artifact.script,
                    &environment,
                    &artifact.host_temp,
                    artifact.prepared_source_bytes,
                    artifact.expected_sha256,
                    timeout,
                    logical_exec_recovery(metadata),
                )
                .await
                .map_err(|error| ApiError::Runtime(error.to_string()))?;
        }
    }
    super::super::shared_security::verify_import_size(state, metadata).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(instance_id: &str, mode: DeploymentMode) -> PreparedTarget {
        PreparedTarget {
            instance_id: instance_id.to_string(),
            created_at: "created".to_string(),
            deployment_mode: mode,
            runtime_id: format!("runtime-{instance_id}"),
            database: format!("db-{instance_id}"),
            username: format!("user-{instance_id}"),
        }
    }

    fn artifact(target: PreparedTarget, digest: Option<[u8; 32]>) -> PreparedLogicalImport {
        PreparedLogicalImport {
            protocol: Protocol::Postgres,
            host_temp: PathBuf::from("prepared.dump"),
            owns_host_temp: false,
            script: "restore".to_string(),
            exec_timeout: None,
            database_definition_in_dump: false,
            prepared_source_bytes: 1,
            expected_sha256: digest,
            pinned_input: None,
            staged_source_bytes: None,
            target,
        }
    }

    #[test]
    fn shared_digest_and_target_are_checked_before_mutation() {
        let expected = target("one", DeploymentMode::Shared);
        let missing = artifact(expected.clone(), None);
        let error = match check_batch(&expected, Protocol::Postgres, &[missing]) {
            Ok(_) => panic!("shared restore without a digest was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("private input snapshot"));

        let wrong = artifact(target("two", DeploymentMode::Shared), Some([7; 32]));
        assert!(check_batch(&expected, Protocol::Postgres, &[wrong]).is_err());
    }

    #[test]
    fn shared_staging_reserves_private_source_and_rollback_snapshots() {
        assert_eq!(
            staging_reservation_bytes(DeploymentMode::Dedicated, 4, 6).unwrap(),
            10
        );
        assert_eq!(
            staging_reservation_bytes(DeploymentMode::Shared, 4, 6).unwrap(),
            20
        );
        assert!(staging_reservation_bytes(DeploymentMode::Shared, u64::MAX, 1).is_err());
    }

    #[test]
    fn dedicated_restore_does_not_require_an_inspection_digest() {
        let expected = target("one", DeploymentMode::Dedicated);
        let prepared = artifact(expected.clone(), None);
        assert!(check_batch(&expected, Protocol::Postgres, &[prepared]).is_ok());
    }

    #[test]
    fn helper_uncertainty_survives_apply_error_conversion() {
        let error = LogicalApplyError::helper(ApiError::Runtime("cleanup uncertain".to_string()));
        assert!(error.helper_uncertain());
        assert!(
            error
                .into_api_error()
                .to_string()
                .contains("cleanup uncertain")
        );
    }
}
