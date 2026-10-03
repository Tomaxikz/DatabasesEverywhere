use super::*;

pub(super) async fn reject_duplicate_instance(
    state: &AppState,
    request: &CreateInstanceRequest,
) -> Result<(), ApiError> {
    if state.instances.get(&request.instance_id).await.is_some() {
        return Err(ApiError::Conflict(format!(
            "instance_id {} already exists",
            request.instance_id
        )));
    }

    // Instance ids and physical runtime ids share container and filesystem
    // namespaces. A generated shared-pool id must therefore never be treated
    // as an unowned, stale instance id: an explicitly authorized stale purge
    // would otherwise be able to remove a live pool before creation reaches
    // the metadata transaction that rejects the collision.
    if state
        .placements
        .get(&request.instance_id)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?
        .is_some()
    {
        return Err(ApiError::Conflict(format!(
            "instance_id {} is already reserved by a managed database runtime",
            request.instance_id
        )));
    }
    if state
        .placements
        .get_reservation(&request.instance_id)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?
        .is_some()
    {
        return Err(ApiError::Conflict(format!(
            "instance_id {} is already reserved by an unfinished shared tenant operation",
            request.instance_id
        )));
    }

    let instances = state.instances.list().await;
    let route_exists =
        instances.iter().any(
            |metadata| match request.protocol.engine().route_identity() {
                RouteIdentity::UsernameAndDatabase => {
                    metadata.protocol == request.protocol
                        && metadata.database.username == request.username
                        && metadata.database.name == request.database
                }
                RouteIdentity::RouteKey => {
                    let route_key_sha256 = request.protocol.engine().route_key_fingerprint(
                        state.config.websocket_jwt_secret(),
                        &request.password,
                    );
                    metadata.protocol == request.protocol
                        && metadata.route_key_sha256.as_deref() == route_key_sha256.as_deref()
                }
                RouteIdentity::Username => {
                    metadata.protocol == request.protocol
                        && metadata.database.username == request.username
                }
            },
        );

    if route_exists {
        return Err(ApiError::Conflict(format!(
            "{} route already exists for username {} and database {}; choose different credentials or delete the existing database first",
            request.protocol, request.username, request.database
        )));
    }

    Ok(())
}

pub(super) async fn handle_stale_instance_resources(
    state: &AppState,
    request: &CreateInstanceRequest,
) -> Result<(), ApiError> {
    let mut stale_containers = Vec::new();
    for protocol in Protocol::ALL {
        if let Some(container) = state
            .docker
            .verified_managed_container_name(protocol, &request.instance_id)
            .await
            .map_err(docker_error)?
        {
            stale_containers.push((protocol, container));
        }
    }

    let paths = InstancePaths::new(&state.config.paths, &request.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let stale_paths = stale_persistent_paths(&paths)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    if stale_containers.is_empty() && stale_paths.is_empty() {
        return Ok(());
    }

    if !request.purge_stale_resources {
        let resources = stale_containers
            .iter()
            .map(|(_, container)| format!("container {container}"))
            .chain(stale_paths.iter().cloned())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(stale_resources_conflict(request, resources));
    }

    let authorization = DestructiveActionPolicy::authorize(
        "stale resource purge",
        request
            .purge_stale_resources_confirmation
            .as_ref()
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "stale resource purge requires purge_stale_resources_confirmation".to_string(),
                )
            })?,
    )?;

    let stale_container_count = stale_containers.len();
    for (protocol, _) in stale_containers {
        cleanup_created_container(state, protocol, &request.instance_id).await?;
    }
    if !stale_paths.is_empty() {
        cleanup_created_paths(state, &paths).await?;
    }
    tracing::warn!(
        event = "audit stale_instance_resources_purged",
        instance_id = %request.instance_id,
        protocol = %request.protocol,
        stale_container_count,
        stale_path_count = stale_paths.len(),
        reason = authorization.reason(),
        "explicitly purged stale resources before retrying instance creation"
    );
    Ok(())
}

pub(super) fn stale_resources_conflict(
    request: &CreateInstanceRequest,
    resources: String,
) -> ApiError {
    ApiError::Conflict(format!(
        "stale resources already exist for instance_id {} and will not be reused with new credentials: {resources}. Recover the data manually, use a different instance_id, or explicitly retry creation with purge_stale_resources=true to irreversibly remove them",
        request.instance_id
    ))
}

pub(super) async fn stale_persistent_paths(
    paths: &InstancePaths,
) -> Result<Vec<String>, std::io::Error> {
    let mut stale = Vec::new();
    for path in [
        &paths.data,
        &paths.logs,
        &paths.artifacts,
        &paths.exports,
        &paths.imports,
        &paths.backups,
        &paths.runtime_config,
    ] {
        if !path_has_entries(path).await? {
            continue;
        }
        stale.push(path.display().to_string());
    }
    for path in crate::subsystems::instances::retained_instance_volume_paths(&paths.data).await? {
        stale.push(path.display().to_string());
    }
    Ok(stale)
}

pub(super) async fn path_has_entries(path: &std::path::Path) -> Result<bool, std::io::Error> {
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.is_dir() {
        return Ok(true);
    }

    let mut entries = tokio::fs::read_dir(path).await?;
    Ok(entries.next_entry().await?.is_some())
}
