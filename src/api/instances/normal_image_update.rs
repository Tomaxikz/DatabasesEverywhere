use super::*;
use futures::FutureExt;

pub(super) async fn run_normal_image_update_supervisor(
    state: AppState,
    operation: tokio::sync::OwnedMutexGuard<()>,
    metadata: InstanceMetadata,
    current_image: String,
    image: String,
    password: Option<String>,
) -> Result<UpdateInstanceImageResponse, ApiError> {
    let instance_id = metadata.instance_id.clone();
    let mutation = state
        .daemon_shutdown
        .try_admit_background_mutation()
        .ok_or_else(|| {
            ApiError::ServiceUnavailable(
                "daemon shutdown has started; image updates are not accepted".to_string(),
            )
        })?;
    let task = spawn_owned_mutation_task(async move {
        let _mutation = mutation;
        let _operation = operation;
        let recovery = metadata.clone();
        match std::panic::AssertUnwindSafe(update_instance_image_normal(
            state.clone(),
            metadata,
            current_image,
            image,
            password,
        ))
        .catch_unwind()
        .await
        {
            Ok(result) => result,
            Err(_) => {
                let durable = state
                    .manager
                    .get_persisted(&recovery.instance_id)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or(recovery);
                let quarantine = quarantine_after_image_update_uncertainty(
                    &state,
                    &durable,
                    "normal image-update worker panicked during a potentially destructive replacement",
                )
                .await;
                Err(ApiError::Runtime(format!(
                    "normal image-update worker stopped unexpectedly; {}",
                    image_update_quarantine_summary(&quarantine)
                )))
            }
        }
    });
    match task.await {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(
                %instance_id,
                worker_cancelled = error.is_cancelled(),
                worker_panicked = error.is_panic(),
                "normal image-update supervisor stopped unexpectedly"
            );
            Err(ApiError::Runtime(
                "normal image-update supervisor stopped unexpectedly; inspect and reconcile the instance before retrying"
                    .to_string(),
            ))
        }
    }
}

pub(super) fn spawn_owned_mutation_task<F, T>(future: F) -> tokio::task::JoinHandle<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(future)
}

pub(super) async fn rollback_normal_image_update_or_quarantine(
    state: &AppState,
    rollback_metadata: &InstanceMetadata,
    rollback_spec: &DockerInstanceSpec,
    original_error: ApiError,
) -> ApiError {
    let original_message = original_error.to_string();
    state.install_progress.stage(
        &rollback_metadata.instance_id,
        "rollback",
        "image replacement failed; restoring the previous container",
    );
    let rollback = tokio::time::timeout(
        IMAGE_UPDATE_ROLLBACK_TIMEOUT,
        restore_normal_image_update(state, rollback_metadata, rollback_spec),
    )
    .await;
    let rollback_error = match rollback {
        Ok(Ok(())) => {
            tracing::warn!(
                event = "audit instance_image_update_rolled_back",
                instance_id = %rollback_metadata.instance_id,
                protocol = %rollback_metadata.protocol,
                error = %original_message,
                "image replacement failed and the previous immutable image was restored"
            );
            return original_error;
        }
        Ok(Err(error)) => error.to_string(),
        Err(_) => format!(
            "rollback exceeded its {} second deadline",
            IMAGE_UPDATE_ROLLBACK_TIMEOUT.as_secs()
        ),
    };

    let quarantine = quarantine_after_image_update_uncertainty(
        state,
        rollback_metadata,
        "normal image update rollback failed",
    )
    .await;
    tracing::error!(
        event = "audit instance_image_update_rollback_failed",
        instance_id = %rollback_metadata.instance_id,
        protocol = %rollback_metadata.protocol,
        error = %original_message,
        rollback_error = %rollback_error,
        quarantine_complete = quarantine.is_ok(),
        "image replacement and rollback both failed; instance was quarantined fail-closed"
    );
    ApiError::Runtime(format!(
        "image update failed ({original_message}) and rollback failed ({rollback_error}); {}",
        image_update_quarantine_summary(&quarantine)
    ))
}

async fn restore_normal_image_update(
    state: &AppState,
    rollback_metadata: &InstanceMetadata,
    rollback_spec: &DockerInstanceSpec,
) -> Result<(), ApiError> {
    delete_image_update_container(
        state,
        rollback_metadata.protocol,
        &rollback_metadata.instance_id,
    )
    .await?;
    let no_progress = |_event| {};
    launch_container_from_spec(
        state,
        rollback_spec,
        rollback_metadata.protocol,
        &rollback_metadata.instance_id,
        &no_progress,
        false,
        || async { Ok(()) },
    )
    .await
    .map_err(|error| error.into_api_error())?;
    state
        .manager
        .upsert(rollback_metadata.clone())
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "previous container was restored but its metadata could not be persisted: {error}"
            ))
        })?;
    state
        .manager
        .delete_compatibility_attestation(&rollback_metadata.instance_id)
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "previous container was restored but its stale compatibility attestation could not be invalidated: {error}"
            ))
        })?;
    invalidate_image_update_caches(state, &rollback_metadata.instance_id).await;
    Ok(())
}

async fn delete_image_update_container(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
) -> Result<(), ApiError> {
    match state.docker.delete(protocol, instance_id).await {
        Ok(_) => Ok(()),
        Err(error) if error.is_not_found() => Ok(()),
        Err(error) => Err(docker_error(error)),
    }
}

pub(super) async fn quarantine_after_image_update_uncertainty(
    state: &AppState,
    metadata: &InstanceMetadata,
    reason: &str,
) -> Result<(), ApiError> {
    let quarantined = quarantined_image_update_metadata(metadata);

    // Remove gateway routes before waiting for Docker or SQLite. A failed
    // durable quarantine must not leave the process routing to an uncertain
    // replacement during this daemon lifetime.
    state.instances.upsert(quarantined.clone()).await;
    invalidate_image_update_caches(state, &quarantined.instance_id).await;

    let (runtime_result, persistence_result) = tokio::join!(
        stop_image_update_target_fail_closed(state, &quarantined),
        state.manager.upsert(quarantined.clone()),
    );
    let persistence_result = persistence_result
        .map_err(|error| format!("failed to persist image-update quarantine: {error}"));
    tracing::error!(
        event = "audit uncertain_image_update_quarantined",
        instance_id = %quarantined.instance_id,
        protocol = %quarantined.protocol,
        %reason,
        runtime_stopped = runtime_result.is_ok(),
        quarantine_persisted = persistence_result.is_ok(),
        "image-update runtime or commit state became uncertain; gateway routes were removed and the instance was quarantined"
    );

    match (runtime_result, persistence_result) {
        (Ok(()), Ok(())) => Ok(()),
        (runtime, persistence) => {
            let mut failures = Vec::new();
            if let Err(error) = runtime {
                failures.push(error);
            }
            if let Err(error) = persistence {
                failures.push(error);
            }
            Err(ApiError::Runtime(failures.join("; ")))
        }
    }
}

async fn stop_image_update_target_fail_closed(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<(), String> {
    match tokio::time::timeout(
        IMAGE_UPDATE_FAIL_CLOSED_STOP_TIMEOUT,
        state.docker.stop(metadata.protocol, &metadata.instance_id),
    )
    .await
    {
        Ok(Ok(_)) => return Ok(()),
        Ok(Err(error)) if error.is_not_running() || error.is_not_found() => return Ok(()),
        Ok(Err(error)) => {
            tracing::warn!(
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                %error,
                "graceful stop failed while quarantining an uncertain image update; forcing shutdown"
            );
        }
        Err(_) => {
            tracing::warn!(
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                "graceful stop timed out while quarantining an uncertain image update; forcing shutdown"
            );
        }
    }

    match tokio::time::timeout(
        IMAGE_UPDATE_FAIL_CLOSED_STOP_TIMEOUT,
        state.docker.kill(metadata.protocol, &metadata.instance_id),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) if error.is_not_running() || error.is_not_found() => Ok(()),
        Ok(Err(error)) => Err(format!(
            "failed to stop or kill uncertain image-update target: {error}"
        )),
        Err(_) => Err("timed out stopping and killing uncertain image-update target".to_string()),
    }
}

async fn invalidate_image_update_caches(state: &AppState, instance_id: &str) {
    state.instance_runtime_cache.remove(instance_id).await;
    state.resource_cache.remove(instance_id).await;
    state.monitoring_cache.invalidate().await;
}

pub(super) fn quarantined_image_update_metadata(metadata: &InstanceMetadata) -> InstanceMetadata {
    let mut quarantined = metadata.clone();
    quarantined.status = InstanceStatus::Quarantined;
    quarantined.desired_state = DesiredInstanceState::Stopped;
    quarantined.updated_at = now_rfc3339();
    quarantined
}

pub(super) fn image_update_quarantine_summary(result: &Result<(), ApiError>) -> String {
    match result {
        Ok(()) => "the instance was stopped and quarantined".to_string(),
        Err(error) => format!(
            "the instance was quarantined in memory, but complete shutdown or persistence failed: {error}"
        ),
    }
}

pub(super) async fn instance_image_update_spec(
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    container_data_path: std::path::PathBuf,
    image: &str,
    password: Option<SecretString>,
    pids_limit: i64,
) -> Result<DockerInstanceSpec, ApiError> {
    let password = match metadata.protocol {
        Protocol::Redis | Protocol::Valkey => {
            password.unwrap_or_else(|| SecretString::from(String::new()))
        }
        _ => password.ok_or_else(|| {
            ApiError::BadRequest(
                "password is required when recreating non-RESP database containers".to_string(),
            )
        })?,
    };

    let mut spec = match metadata.protocol {
        Protocol::Postgres => databases::postgres::docker::instance_spec(
            &metadata.instance_id,
            image,
            &metadata.database.name,
            &metadata.database.username,
            password,
            SecretString::from(metadata.postgres_admin_password.clone().ok_or_else(|| {
                ApiError::BadRequest(
                    "PostgreSQL administrator credential is missing; restart the daemon to migrate this legacy instance before recreation".to_string(),
                )
            })?),
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Redis => databases::redis::docker::instance_spec(
            &metadata.instance_id,
            image,
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Valkey => databases::valkey::docker::instance_spec(
            &metadata.instance_id,
            image,
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mariadb => databases::mariadb::docker::instance_spec(
            &metadata.instance_id,
            image,
            &metadata.database.name,
            &metadata.database.username,
            password,
            SecretString::from(metadata.mariadb_root_password.clone().ok_or_else(|| {
                ApiError::BadRequest(
                    "mariadb internal root password is missing; old instances must be recreated with purge or repaired manually".to_string(),
                )
            })?),
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mysql => databases::mysql::docker::instance_spec(
            &metadata.instance_id,
            image,
            &metadata.database.name,
            SecretString::from(metadata.mysql_root_password.clone().ok_or_else(|| {
                ApiError::BadRequest(
                    "mysql internal root password is missing; old instances must be recreated with purge or repaired manually".to_string(),
                )
            })?),
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mongodb => databases::mongodb::docker::instance_spec(
            &metadata.instance_id,
            image,
            &metadata.database.name,
            databases::mongodb::docker::MongodbAuth {
                username: metadata.database.username.clone(),
                password,
                root_password: SecretString::from(
                    metadata.mongodb_root_password.clone().ok_or_else(|| {
                        ApiError::BadRequest(
                            "mongodb internal root password is missing; old MongoDB instances must be recreated or restored from a manual admin dump before image replacement".to_string(),
                        )
                    })?,
                ),
            },
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Clickhouse => {
            let hosted_config_path =
                databases::clickhouse::docker::write_hosted_config(&paths.runtime_config)
                    .await
                    .map_err(|error| ApiError::Runtime(error.to_string()))?;
            databases::clickhouse::docker::instance_spec(
                &metadata.instance_id,
                image,
                &metadata.database.name,
                &metadata.database.username,
                password,
                container_data_path,
                paths.logs.clone(),
                hosted_config_path,
                paths.sockets.clone(),
                paths.socket_bridge_binary.clone(),
            )
        }
        Protocol::Qdrant => databases::qdrant::docker::instance_spec(
            &metadata.instance_id,
            image,
            password,
            container_data_path,
            paths.logs.clone(),
            paths.sockets.clone(),
            paths.socket_bridge_binary.clone(),
        ),
    };
    spec.cpu_cores = metadata.limits.cpu_cores;
    spec.memory_mib = metadata.limits.memory_mib;
    spec.disk_mib = metadata.limits.disk_mib;
    spec.pids_limit = Some(pids_limit);
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::spawn_owned_mutation_task;

    #[tokio::test]
    async fn dropping_http_waiter_does_not_cancel_owned_image_update_worker() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let waiter = spawn_owned_mutation_task(async move {
            let _ = started_tx.send(());
            let _ = finish_rx.await;
            let _ = done_tx.send(());
        });
        started_rx.await.unwrap();
        drop(waiter);
        finish_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), done_rx)
            .await
            .expect("detached image update worker should finish")
            .unwrap();
    }
}
