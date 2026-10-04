use crate::databases::protocol::Protocol;
use crate::routes::http::response::ApiError;
use crate::routes::http::router::AppState;
use crate::server::paths::InstancePaths;

pub(super) async fn cleanup_created_container(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
) -> Result<(), ApiError> {
    if let Err(error) = state.docker.delete(protocol, instance_id).await {
        if error.is_not_found() {
            tracing::debug!(%instance_id, %protocol, "container already absent during create failure cleanup");
            return Ok(());
        }
        return Err(ApiError::Runtime(format!(
            "failed to clean up container after create failure: {error}"
        )));
    }
    Ok(())
}

pub(super) struct CreateFailureCleanup<'a> {
    pub(super) state: &'a AppState,
    pub(super) protocol: Protocol,
    pub(super) instance_id: String,
}

impl<'a> CreateFailureCleanup<'a> {
    pub(super) fn new(state: &'a AppState, protocol: Protocol, instance_id: String) -> Self {
        Self {
            state,
            protocol,
            instance_id,
        }
    }

    pub(super) async fn run(self, error: &ApiError) {
        self.state.install_progress.stage(
            &self.instance_id,
            "cleanup",
            "cleaning failed installation",
        );

        let cleanup_result = self.cleanup_resources().await;
        if cleanup_result.is_ok() {
            if let Err(cleanup_error) = self.state.manager.delete(&self.instance_id).await {
                tracing::warn!(
                    error = %cleanup_error,
                    instance_id = %self.instance_id,
                    "failed to delete metadata after create failure"
                );
            } else {
                self.state.instances.remove(&self.instance_id).await;
                self.state.soft_disk_limiter.remove(&self.instance_id).await;
            }
        }

        self.state
            .install_progress
            .fail_api_error(&self.instance_id, "instance creation", error);
        match cleanup_result {
            Ok(()) => tracing::info!(
                event = "audit instance_create_failed_cleaned",
                instance_id = %self.instance_id,
                protocol = %self.protocol,
                error = %error,
            ),
            Err(cleanup_error) => tracing::error!(
                event = "audit instance_create_cleanup_incomplete",
                instance_id = %self.instance_id,
                protocol = %self.protocol,
                error = %error,
                cleanup_error = %cleanup_error,
            ),
        }
    }

    pub(super) async fn cleanup_resources(&self) -> Result<(), ApiError> {
        cleanup_created_container(self.state, self.protocol, &self.instance_id).await?;
        let paths = InstancePaths::new(&self.state.config.paths, &self.instance_id)
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        cleanup_created_paths(self.state, &paths).await
    }
}

pub(super) async fn cleanup_created_paths(
    state: &AppState,
    paths: &InstancePaths,
) -> Result<(), ApiError> {
    crate::subsystems::instances::purge_instance_paths(state, &paths.instance_id).await
}
