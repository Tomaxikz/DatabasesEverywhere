use super::{DATABASE_READINESS_TIMEOUT, FAILURE_LOG_SUMMARY_MAX_CHARS};
use crate::databases::protocol::Protocol;
use crate::routes::http::response::ApiError;
use crate::routes::http::router::AppState;
use crate::runtime::docker::{DockerImagePullProgress, DockerInstanceSpec};
use crate::server::paths::InstancePaths;
use crate::subsystems::instances::docker_error;
use crate::utils::logs::summarize_failure_logs;
use crate::utils::redaction;
use std::future::Future;

pub(crate) enum ContainerLaunchError {
    Create(ApiError),
    AfterCreate(ApiError),
}

impl ContainerLaunchError {
    pub(crate) fn into_api_error(self) -> ApiError {
        match self {
            Self::Create(error) | Self::AfterCreate(error) => error,
        }
    }
}

pub(crate) async fn launch_container_from_spec<F, H, Fut>(
    state: &AppState,
    spec: &DockerInstanceSpec,
    protocol: Protocol,
    instance_id: &str,
    pull_progress: &F,
    report_install_progress: bool,
    after_start: H,
) -> Result<(), ContainerLaunchError>
where
    F: Fn(DockerImagePullProgress) + Send + Sync,
    H: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), ApiError>>,
{
    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ContainerLaunchError::Create(ApiError::BadRequest(error.to_string())))?;
    paths
        .clear_socket_dir()
        .await
        .map_err(|error| ContainerLaunchError::Create(ApiError::Runtime(error.to_string())))?;
    if report_install_progress {
        state
            .install_progress
            .stage(instance_id, "create_container", "creating Docker container");
    }
    state
        .docker
        .create_with_progress(spec, pull_progress)
        .await
        .map_err(docker_error)
        .map_err(ContainerLaunchError::Create)?;

    if report_install_progress {
        state
            .install_progress
            .stage(instance_id, "start", "starting container");
    }
    state
        .docker
        .start(protocol, instance_id)
        .await
        .map_err(docker_error)
        .map_err(ContainerLaunchError::AfterCreate)?;

    after_start()
        .await
        .map_err(ContainerLaunchError::AfterCreate)?;

    if report_install_progress {
        state.install_progress.stage(
            instance_id,
            "healthcheck",
            "confirming one-time database startup readiness",
        );
    }
    if let Err(error) = state
        .docker
        .wait_until_ready(protocol, instance_id, DATABASE_READINESS_TIMEOUT)
        .await
    {
        return Err(ContainerLaunchError::AfterCreate(
            docker_error_with_logs(state, protocol, instance_id, error).await,
        ));
    }
    Ok(())
}

pub(crate) async fn docker_error_with_logs(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
    error: crate::runtime::docker::DockerError,
) -> ApiError {
    let logs = match state.docker.logs(protocol, instance_id, None).await {
        Ok(output) => {
            let combined = format!("{}{}", output.stdout, output.stderr);
            summarize_failure_logs(
                &redaction::redact_connection_url(&combined),
                FAILURE_LOG_SUMMARY_MAX_CHARS,
            )
        }
        Err(log_error) => format!("failed to read container logs: {log_error}"),
    };

    ApiError::Runtime(format!("{error}; recent container logs: {logs}"))
}
