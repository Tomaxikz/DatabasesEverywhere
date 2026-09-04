use super::rollback::upgrade_temp_instance_id;
use super::*;
use futures::FutureExt;

pub(in crate::api::instances) async fn run_upgrade_supervisor(
    state: AppState,
    operation: tokio::sync::OwnedMutexGuard<()>,
    metadata: InstanceMetadata,
    current_image: String,
    image: String,
    password: Option<String>,
) -> Result<UpdateInstanceImageResponse, ApiError> {
    let instance_id = metadata.instance_id.clone();
    let supervisor =
        spawn_upgrade_supervisor(state, operation, metadata, current_image, image, password);
    match supervisor.await {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(
                %instance_id,
                worker_cancelled = error.is_cancelled(),
                worker_panicked = error.is_panic(),
                "major-upgrade supervisor stopped unexpectedly"
            );
            Err(ApiError::Runtime(
                "the major-upgrade supervisor stopped unexpectedly; inspect the instance and retry only after confirming its runtime and data-volume state"
                    .to_string(),
            ))
        }
    }
}

fn spawn_upgrade_supervisor(
    state: AppState,
    operation: tokio::sync::OwnedMutexGuard<()>,
    metadata: InstanceMetadata,
    current_image: String,
    image: String,
    password: Option<String>,
) -> tokio::task::JoinHandle<Result<UpdateInstanceImageResponse, ApiError>> {
    spawn_upgrade_task(async move {
        let _operation = operation;
        let admission = state
            .import_export_jobs
            .try_admit_exclusive(&metadata.instance_id)
            .map_err(|error| {
                fail_image_update_api(
                    &state,
                    &metadata.instance_id,
                    upgrade_admission_error(&metadata.instance_id, error),
                )
            })?;
        let (execution, staged_capacity) = acquire_upgrade_resources(&state, &metadata).await?;
        let recovery_metadata = metadata.clone();
        let recovery_instance_id = metadata.instance_id.clone();
        let result = std::panic::AssertUnwindSafe(run_major_upgrade(
            &state,
            metadata,
            current_image,
            image,
            password,
        ))
        .catch_unwind()
        .await;

        let result = match result {
            Ok(result) => result,
            Err(_) => {
                let quarantine_metadata = state
                    .manager
                    .get_persisted(&recovery_instance_id)
                    .await
                    .ok()
                    .flatten()
                    .or(state.instances.get(&recovery_instance_id).await)
                    .unwrap_or(recovery_metadata);
                let quarantine = quarantine_image_update(
                    &state,
                    &quarantine_metadata,
                    "major-upgrade worker panicked while runtime or volume state may be uncertain",
                )
                .await;
                tracing::error!(
                    instance_id = %recovery_instance_id,
                    protocol = %quarantine_metadata.protocol,
                    quarantine_complete = quarantine.is_ok(),
                    "major-upgrade worker panicked; the target was fenced and quarantined"
                );
                Err(fail_image_update_runtime(
                    &state,
                    &recovery_instance_id,
                    format!(
                        "the major-upgrade worker stopped unexpectedly; {}",
                        image_quarantine_summary(&quarantine)
                    ),
                ))
            }
        };

        drop(staged_capacity);
        drop(execution);
        drop(admission);
        result
    })
}

pub(in crate::api::instances) fn spawn_upgrade_task<F, T>(future: F) -> tokio::task::JoinHandle<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(future)
}

async fn acquire_upgrade_resources(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<
    (
        crate::jobs::import_export::ExecutionPermit,
        crate::api::import_export::DiskCapacityReservation,
    ),
    ApiError,
> {
    let staged_capacity_bytes = metadata
        .limits
        .disk_mib
        .checked_mul(1024 * 1024)
        .filter(|bytes| *bytes > 0)
        .ok_or_else(|| {
            fail_image_update_runtime(
                state,
                &metadata.instance_id,
                "major-upgrade staging capacity is zero or overflowed".to_string(),
            )
        })?;
    let execution = state
        .import_export_jobs
        .acquire_execution(crate::jobs::import_export::JobResourceCost::estimate(
            crate::jobs::import_export::JobEstimateInput {
                protocol: metadata.protocol,
                input_size_bytes: staged_capacity_bytes,
                rollback_size_bytes: 0,
                wipe: false,
                compressed: true,
                export: false,
            },
        ))
        .await
        .map_err(|error| {
            let error = match error {
                crate::jobs::import_export::SchedulerAcquireError::Closed => {
                    ApiError::ServiceUnavailable("the daemon is shutting down".to_string())
                }
                crate::jobs::import_export::SchedulerAcquireError::InsufficientCapacity => {
                    ApiError::Conflict(
                        "the major-upgrade migration exceeds a fixed dynamic import/export scheduler budget; increase the configured budget or reduce the instance allocation"
                            .to_string(),
                    )
                }
            };
            fail_image_update_api(state, &metadata.instance_id, error)
        })?;
    let staged_instance_id = upgrade_temp_instance_id(&metadata.instance_id);
    let staged_paths = InstancePaths::new(&state.config.paths, &staged_instance_id)
        .map_err(|error| fail_image_update_bad_request(state, &metadata.instance_id, error))?;
    let staged_parent = staged_paths.data.parent().ok_or_else(|| {
        fail_image_update_runtime(
            state,
            &metadata.instance_id,
            "major-upgrade staging directory has no parent".to_string(),
        )
    })?;
    let staged_capacity = state
        .import_uploads
        .reserve_output_capacity(staged_parent, staged_capacity_bytes)
        .await
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    Ok((execution, staged_capacity))
}

fn upgrade_admission_error(
    instance_id: &str,
    error: crate::jobs::import_export::JobAdmissionError,
) -> ApiError {
    match error {
        crate::jobs::import_export::JobAdmissionError::GlobalCapacity => ApiError::RateLimited,
        crate::jobs::import_export::JobAdmissionError::InstanceCapacity => ApiError::Conflict(
            format!("instance {instance_id} already has a queued data operation"),
        ),
        crate::jobs::import_export::JobAdmissionError::ShuttingDown => {
            ApiError::ServiceUnavailable("the daemon is shutting down".to_string())
        }
    }
}
