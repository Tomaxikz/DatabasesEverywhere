use std::{path::PathBuf, time::Duration};

use futures::FutureExt;
use tokio::sync::OwnedMutexGuard;

use super::{migration_admission_error, migration_error};
use crate::{
    api::{
        http::{
            response::ApiError,
            router::{AppState, MutationPermit},
        },
        import_export,
        instances::{
            create::{
                attest_dedicated_target, build_dedicated_target, build_shared_metadata,
                claim_shared_runtime, destroy_empty_shared_runtime, enforce_node_allocation_policy,
                launch_dedicated_target, resolve_image,
            },
            requests::{CreateInstanceRequest, LimitsRequest},
        },
    },
    instances::metadata::InstanceMetadata,
    jobs::import_export::{
        ExecutionPermit, ImportExportJobPermit, JobEstimateInput, JobResourceCost,
        SchedulerAcquireError,
    },
    placement::{
        DeploymentMigration, DeploymentMode, EngineRuntime, EngineRuntimeStatus, MigrationFailure,
        MigrationPatch, MigrationStage, runtime as runtime_ops,
        tenant::{self, TenantTarget},
    },
    runtime::docker::DockerContainerStatus,
    shared::{redaction, time::now_rfc3339},
};

pub(super) fn spawn(
    state: AppState,
    source: InstanceMetadata,
    migration: DeploymentMigration,
    creation: OwnedMutexGuard<()>,
    operation: OwnedMutexGuard<()>,
    admission: ImportExportJobPermit,
    mutation: MutationPermit,
) {
    let migration_id = migration.migration_id.clone();
    tokio::spawn(async move {
        let _operation = operation;
        let _admission = admission;
        let _mutation = mutation;
        let result = match (migration.source_mode, migration.target_mode) {
            (DeploymentMode::Dedicated, DeploymentMode::Shared) => {
                let run = run_dedicated_to_shared(&state, source, migration, creation).boxed();
                std::panic::AssertUnwindSafe(run).catch_unwind().await
            }
            (DeploymentMode::Shared, DeploymentMode::Dedicated) => {
                let run = run_shared_to_dedicated(&state, source, migration, creation).boxed();
                std::panic::AssertUnwindSafe(run).catch_unwind().await
            }
            _ => Ok(Err(ApiError::Conflict(
                "deployment migration source and target modes must differ".into(),
            ))),
        };
        let detail = match result {
            Ok(Ok(())) => return,
            Ok(Err(error)) => redaction::redact_connection_url(&error.to_string()),
            Err(_) => "deployment migration worker panicked".to_string(),
        };
        tracing::error!(
            event = "audit deployment_migration_worker_failed",
            %migration_id,
            error = %detail,
        );
        if let Err(error) = recover_failure(&state, &migration_id).await {
            tracing::error!(
                event = "audit deployment_migration_recovery_failed",
                %migration_id,
                error = %redaction::redact_connection_url(&error.to_string()),
                "deployment migration could not reach a verified recovery state"
            );
        }
    });
}

async fn advance<'a>(
    state: &AppState,
    migration: DeploymentMigration,
    stage: MigrationStage,
    patch: MigrationPatch<'a>,
) -> Result<DeploymentMigration, ApiError> {
    state
        .placements
        .migrations()
        .transition(&migration.migration_id, migration.revision, stage, patch)
        .await
        .map_err(migration_error)
}

mod copy;
mod recovery;
mod support;
mod target;
use recovery::recover_failure;
pub(crate) use recovery::{fence_active_routes_on_boot, recover_on_boot};
use support::*;
use target::{run_dedicated_to_shared, run_shared_to_dedicated};
