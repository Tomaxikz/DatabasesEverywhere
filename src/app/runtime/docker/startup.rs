use bollard::models::{ContainerUpdateBody, RestartPolicy, RestartPolicyNameEnum};

use super::{DockerError, DockerRuntime};
use crate::shared::protocol::Protocol;

pub(super) fn no_restarts() -> RestartPolicy {
    RestartPolicy {
        name: Some(RestartPolicyNameEnum::NO),
        maximum_retry_count: Some(0),
    }
}

fn restarts_enabled(policy: Option<&RestartPolicy>) -> bool {
    policy.and_then(|policy| policy.name).is_some_and(|name| {
        !matches!(
            name,
            RestartPolicyNameEnum::NO | RestartPolicyNameEnum::EMPTY
        )
    })
}

impl DockerRuntime {
    pub(crate) fn with_startup_history(mut self, pool: sqlx::SqlitePool) -> Self {
        self.startup_history = Some(pool);
        self
    }

    /// Automatic boot recovery has a durable two-attempt budget. Explicit API
    /// starts and restore/rollback operations remain possible after repair.
    pub(crate) async fn check_autostart(&self, runtime_id: &str) -> Result<(), DockerError> {
        if let Some(pool) = &self.startup_history {
            let attempts: Option<i64> = sqlx::query_scalar(
                "SELECT startup_attempts FROM engine_runtimes WHERE runtime_id = ?",
            )
            .bind(runtime_id)
            .fetch_optional(pool)
            .await?;
            if attempts.is_some_and(|attempts| attempts >= 2) {
                return Err(DockerError::AutostartBlocked(runtime_id.to_string()));
            }
        }
        Ok(())
    }

    /// Persist before contacting the engine: daemon interruption must not give
    /// an unconfirmed startup a fresh budget. A readiness poll is not an attempt.
    pub(super) async fn note_start(
        &self,
        runtime_id: &str,
        automatic: bool,
    ) -> Result<(), DockerError> {
        if let Some(pool) = &self.startup_history {
            let result = sqlx::query("UPDATE engine_runtimes SET startup_attempts = min(startup_attempts + 1, 2) WHERE runtime_id = ? AND (? = 0 OR startup_attempts < 2)")
                .bind(runtime_id)
                .bind(automatic)
                .execute(pool)
                .await?;
            if automatic && result.rows_affected() != 1 {
                return Err(DockerError::AutostartBlocked(runtime_id.into()));
            }
        }
        Ok(())
    }

    pub(super) async fn startup_ready(&self, runtime_id: &str) -> Result<(), DockerError> {
        if let Some(pool) = &self.startup_history {
            sqlx::query("UPDATE engine_runtimes SET startup_attempts = 0 WHERE runtime_id = ? AND startup_attempts <> 0")
                .bind(runtime_id)
                .execute(pool)
                .await?;
        }
        Ok(())
    }

    /// DBEV alone controls boot activation, after mounts, quotas and operator
    /// intent have been checked. Repair old externally configured restart loops
    /// in place; do not recreate containers or touch their data.
    pub(crate) async fn disable_restarts(
        &self,
        protocol: Protocol,
        runtime_id: &str,
    ) -> Result<(), DockerError> {
        let Some(inspection) = self
            .inspect_verified_container(protocol, runtime_id)
            .await?
        else {
            return Ok(());
        };
        let policy = inspection.host_config.and_then(|host| host.restart_policy);
        if !restarts_enabled(policy.as_ref()) {
            return Ok(());
        }
        let id = inspection.id.filter(|id| !id.is_empty()).ok_or_else(|| {
            DockerError::ManagedContainerIdUnavailable {
                container: runtime_id.into(),
            }
        })?;
        self.docker
            .update_container(
                &id,
                ContainerUpdateBody {
                    restart_policy: Some(no_restarts()),
                    ..Default::default()
                },
            )
            .await?;
        let confirmed = self.docker.inspect_container(&id, None).await?;
        let policy = confirmed.host_config.and_then(|host| host.restart_policy);
        if policy.is_none() || restarts_enabled(policy.as_ref()) {
            return Err(DockerError::RestartPolicyNotDisabled(runtime_id.into()));
        }
        tracing::info!(
            event = "audit container_restart_policy_repaired",
            runtime_id,
            "disabled engine-managed restarts; DBEV performs bounded boot activation"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
