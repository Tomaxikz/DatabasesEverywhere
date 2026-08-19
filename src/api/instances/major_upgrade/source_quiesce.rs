use super::*;

pub(super) async fn quiesce_major_upgrade_source(
    state: &AppState,
    metadata: &InstanceMetadata,
    password: &str,
) -> Result<(), ApiError> {
    // Removing the route blocks new sessions. Restarting the source then
    // terminates every already-established gateway session before the dump,
    // so writes cannot race the logical snapshot and disappear at cutover.
    state.instances.fence_routes(&metadata.instance_id).await;
    state
        .docker
        .restart(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)?;
    verify_major_upgrade_source(state, metadata, password).await
}

async fn verify_major_upgrade_source(
    state: &AppState,
    metadata: &InstanceMetadata,
    password: &str,
) -> Result<(), ApiError> {
    state
        .docker
        .wait_until_ready(
            metadata.protocol,
            &metadata.instance_id,
            Duration::from_secs(180),
        )
        .await
        .map_err(docker_error)?;
    if metadata.protocol == Protocol::Postgres {
        harden_postgres_instance_auth(
            state,
            &metadata.instance_id,
            &metadata.database.username,
            password,
            metadata.postgres_admin_password.as_deref().ok_or_else(|| {
                ApiError::Conflict(
                    "the encrypted PostgreSQL administrator credential is missing before major-upgrade export"
                        .to_string(),
                )
            })?,
        )
        .await?;
    }
    if metadata.protocol == Protocol::Mysql {
        harden_mysql_tenant_auth(
            state,
            &metadata.instance_id,
            &metadata.database.username,
            password,
            metadata.mysql_root_password.as_deref().ok_or_else(|| {
                ApiError::Conflict(
                    "the encrypted MySQL maintenance credential is missing before major-upgrade export"
                        .to_string(),
                )
            })?,
        )
        .await?;
    }
    let compatibility = crate::compatibility::probe_instance_compatibility(
        &state.manager,
        &state.docker,
        metadata,
        false,
    )
    .await
    .map_err(|error| {
        ApiError::Runtime(format!(
            "source compatibility verification failed before major-upgrade export: {error}"
        ))
    })?;
    if !compatibility.compatible {
        return Err(ApiError::Conflict(compatibility.diagnostic.unwrap_or_else(
            || "source database version is unsupported".to_string(),
        )));
    }
    Ok(())
}

pub(super) async fn harden_major_upgrade_target(
    state: &AppState,
    metadata: &InstanceMetadata,
    password: &str,
) -> Result<(), ApiError> {
    if metadata.protocol == Protocol::Postgres {
        harden_postgres_instance_auth(
            state,
            &metadata.instance_id,
            &metadata.database.username,
            password,
            metadata.postgres_admin_password.as_deref().ok_or_else(|| {
                ApiError::Conflict(
                    "the encrypted PostgreSQL administrator credential is missing after major-upgrade cutover"
                        .to_string(),
                )
            })?,
        )
        .await?;
    }
    if metadata.protocol == Protocol::Mysql {
        harden_mysql_tenant_auth(
            state,
            &metadata.instance_id,
            &metadata.database.username,
            password,
            metadata.mysql_root_password.as_deref().ok_or_else(|| {
                ApiError::Conflict(
                    "the encrypted MySQL maintenance credential is missing after major-upgrade cutover"
                        .to_string(),
                )
            })?,
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn restore_major_upgrade_source_route(
    state: &AppState,
    metadata: &InstanceMetadata,
    password: &str,
    original_error: ApiError,
) -> ApiError {
    let original_message = original_error.to_string();
    match verify_major_upgrade_source(state, metadata, password).await {
        Ok(()) => {
            state.instances.upsert(metadata.clone()).await;
            state
                .instance_runtime_cache
                .remove(&metadata.instance_id)
                .await;
            state.resource_cache.remove(&metadata.instance_id).await;
            state.monitoring_cache.invalidate().await;
            tracing::warn!(
                event = "audit instance_major_upgrade_pre_cutover_restored",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                error = %original_message,
                "major upgrade failed before cutover; the verified source route was restored without changing its data"
            );
            fail_image_update_api(state, &metadata.instance_id, original_error)
        }
        Err(recovery_error) => {
            let quarantine = quarantine_after_image_update_uncertainty(
                state,
                metadata,
                "major-upgrade source could not be reverified after a pre-cutover failure",
            )
            .await;
            fail_image_update_runtime(
                state,
                &metadata.instance_id,
                format!(
                    "major upgrade failed before cutover ({original_message}), source recovery failed ({recovery_error}); {}",
                    image_update_quarantine_summary(&quarantine)
                ),
            )
        }
    }
}
