use super::{PlacementRepository, PlacementRepositoryError};

impl PlacementRepository {
    /// An allowlisted pool must not override a separate credential or import
    /// recovery incident. A missing metadata row also fails closed.
    pub(crate) async fn tenant_recovery_blocked(
        &self,
        instance_id: &str,
    ) -> Result<bool, PlacementRepositoryError> {
        Ok(sqlx::query_scalar::<_, bool>(
            "SELECT COALESCE((SELECT protected_secret_recovery_required
                FROM instance_metadata WHERE instance_id = ?1), 1)
                OR EXISTS(SELECT 1 FROM import_export_jobs WHERE instance_id = ?1
                    AND (status IN ('queued', 'running')
                        OR (action = 'import' AND status = 'failed')))",
        )
        .bind(instance_id)
        .fetch_one(&self.pool)
        .await?)
    }
}
