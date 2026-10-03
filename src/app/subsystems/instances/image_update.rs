use super::*;

pub async fn update_instance_image(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiJson(request): ApiJson<UpdateInstanceImageRequest>,
) -> ApiResult<UpdateInstanceImageResponse> {
    auth.require_scope(scopes::INSTANCES_WRITE)?;
    let image = validate_image(&request.image)?.to_string();
    let operation = state.instance_locks.lock(&instance_id).await;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    deployment::ensure_no_active_migration(&state, &instance_id).await?;
    if metadata.deployment_mode == crate::server::placement::DeploymentMode::Shared {
        return Err(ApiError::Conflict(
            "shared tenant images are managed by pool placement; migrate the tenant to a compatible pool instead of recreating its runtime"
                .to_string(),
        ));
    }
    if metadata.status == InstanceStatus::Quarantined {
        return Err(ApiError::Conflict(
            "quarantined instances cannot be updated or migrated; inspect the quarantine cause and repair or recover the instance offline"
                .to_string(),
        ));
    }
    if metadata.desired_state == DesiredInstanceState::Stopped {
        return Err(ApiError::Conflict(
            "stopped instances cannot be updated in place; start the instance before updating its image"
                .to_string(),
        ));
    }
    let current_image = state
        .docker
        .container_image(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)
        .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?
        .ok_or_else(|| {
            fail_image_update_api(
                &state,
                &metadata.instance_id,
                ApiError::BadRequest(
                    "current container image could not be inspected; reconcile the instance before updating the image".to_string(),
                ),
            )
        })?;
    update_instance_image_locked(
        state,
        operation,
        metadata,
        current_image,
        image,
        request.major_upgrade,
        request.password,
    )
    .await
    .map(ApiResponse::ok)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn update_instance_image_locked(
    state: AppState,
    operation: tokio::sync::OwnedMutexGuard<()>,
    metadata: InstanceMetadata,
    current_image: String,
    image: String,
    major_upgrade: bool,
    password: Option<String>,
) -> Result<UpdateInstanceImageResponse, ApiError> {
    check_image_allowed(&state, metadata.protocol, &image)?;
    if major_upgrade {
        return run_upgrade_supervisor(
            state.clone(),
            operation,
            metadata,
            current_image,
            image,
            password,
        )
        .await;
    }
    run_image_update(state, operation, metadata, current_image, image, password).await
}
