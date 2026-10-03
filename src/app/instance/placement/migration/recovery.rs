use super::*;

impl DeploymentMigrationRepository {
    pub async fn recover_unfinished(
        &self,
    ) -> Result<MigrationRecoverySummary, DeploymentMigrationError> {
        let mut summary = MigrationRecoverySummary::default();
        for migration in self.list_active().await? {
            let Some(next) = migration.stage.recovery_stage() else {
                summary.already_pending += 1;
                continue;
            };
            let (failure, recovered_count) = match next {
                MigrationStage::Failed => (
                    MigrationFailure::RestartBeforeMutation,
                    &mut summary.failed_before_mutation,
                ),
                MigrationStage::RollingBack => (
                    MigrationFailure::RestartBeforeCutover,
                    &mut summary.rollback_pending,
                ),
                MigrationStage::CleanupPending => (
                    MigrationFailure::RestartAfterCutover,
                    &mut summary.cleanup_pending,
                ),
                _ => {
                    return Err(DeploymentMigrationError::InvalidValue(
                        "recovery_stage",
                        next.as_str().to_string(),
                    ));
                }
            };
            self.transition(
                &migration.migration_id,
                migration.revision,
                next,
                MigrationPatch {
                    failure: Some(failure),
                    ..MigrationPatch::default()
                },
            )
            .await?;
            *recovered_count += 1;
        }
        Ok(summary)
    }
}

pub(super) fn cutover_is_ready(
    current: &DeploymentMigration,
    source_mode: DeploymentMode,
    target_mode: DeploymentMode,
    target: &InstanceMetadata,
) -> bool {
    current.stage == MigrationStage::CutoverPending
        && current.source_mode == source_mode
        && current.target_mode == target_mode
        && current.instance_id == target.instance_id
        && current.protocol == target.protocol
        && current.target_runtime_id.as_deref() == Some(target.runtime_id())
        && current.source_fenced
}
