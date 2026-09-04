use super::*;

pub(super) async fn precheck_major_upgrade(
    state: &AppState,
    metadata: &InstanceMetadata,
    current_image: &str,
    requested_image: &str,
) -> Result<MajorUpgradePrecheck, ApiError> {
    state.install_progress.stage(
        &metadata.instance_id,
        "precheck",
        "checking major upgrade compatibility",
    );
    check_major_upgrade(metadata.protocol)?;
    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
        .for_persisted_method(&metadata.limits.disk_enforcement_method)
        .check_upgrade_cutover(&paths.data)
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    let inspection = state
        .docker
        .inspect_instance(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)?;
    if inspection.status != DockerContainerStatus::Running {
        return Err(ApiError::BadRequest(format!(
            "major upgrade requires a running healthy source container; current status is {:?}, health={:?}",
            inspection.status, inspection.health
        )));
    }

    let current_major = image_major_version(current_image).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "{} major upgrade cannot compare current image tag {current_image:?}; use pinned semver-like tags for existing instances",
            metadata.protocol
        ))
    })?;
    let requested_major = image_major_version(requested_image).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "{} major upgrade cannot compare requested image tag {requested_image:?}; use pinned semver-like tags for existing instances",
            metadata.protocol
        ))
    })?;
    validate_upgrade_path(metadata.protocol, current_major, requested_major)?;

    let mut warnings = Vec::new();
    if current_major == requested_major {
        warnings.push(format!(
            "requested image has the same major version as current image ({current_major}); DBE still rebuilt the instance because major_upgrade=true"
        ));
    }
    if metadata.protocol == Protocol::Mongodb {
        precheck_mongodb_upgrade(state, metadata, current_major, requested_major).await?;
    } else {
        warnings.push(format!(
            "{} major upgrade uses logical dump/import; test application compatibility before upgrading production workloads",
            metadata.protocol
        ));
    }

    tracing::info!(
        event = "audit instance_major_upgrade_precheck_passed",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        current_image,
        requested_image,
        current_major,
        requested_major,
    );
    Ok(MajorUpgradePrecheck { warnings })
}

pub(in crate::api::instances) fn validate_upgrade_path(
    protocol: Protocol,
    current_major: u64,
    requested_major: u64,
) -> Result<(), ApiError> {
    if requested_major < current_major {
        return Err(ApiError::BadRequest(format!(
            "{protocol} image downgrade is blocked: current major is {current_major}, requested major is {requested_major}. Restore an older-version backup into a new instance instead."
        )));
    }
    if protocol == Protocol::Mongodb && requested_major > current_major + 1 {
        return Err(ApiError::BadRequest(format!(
            "mongodb major upgrade cannot skip versions: current major is {current_major}, requested major is {requested_major}. Upgrade one major version at a time."
        )));
    }
    Ok(())
}

async fn precheck_mongodb_upgrade(
    state: &AppState,
    metadata: &InstanceMetadata,
    current_major: u64,
    requested_major: u64,
) -> Result<(), ApiError> {
    if metadata.mongodb_root_password.is_none() {
        return Err(ApiError::BadRequest(
            "mongodb internal root password is missing; this instance was created before DBE stored MongoDB maintenance credentials, so automatic major upgrades cannot safely dump protected internal collections. Recreate the instance or restore from a manual admin dump.".to_string(),
        ));
    }
    let fcv = mongodb_fcv_major(state, metadata).await?;
    if requested_major > fcv + 1 {
        return Err(ApiError::BadRequest(format!(
            "mongodb featureCompatibilityVersion blocks this upgrade: FCV major is {fcv}, requested image major is {requested_major}. Upgrade one major version at a time and let FCV advance before the next major upgrade."
        )));
    }
    if fcv > current_major {
        return Err(ApiError::BadRequest(format!(
            "mongodb featureCompatibilityVersion {fcv} is newer than current image major {current_major}; refusing upgrade because the source state is inconsistent"
        )));
    }
    Ok(())
}

async fn mongodb_fcv_major(state: &AppState, metadata: &InstanceMetadata) -> Result<u64, ApiError> {
    let output = state
        .docker
        .exec_shell(
            Protocol::Mongodb,
            &metadata.instance_id,
            r#"mongosh --quiet --host 127.0.0.1 --username "$DBE_MONGO_ROOT_USER" --password "$DBE_MONGO_ROOT_PASSWORD" --authenticationDatabase admin admin --eval 'const f=db.adminCommand({getParameter:1, featureCompatibilityVersion:1}).featureCompatibilityVersion || {}; print(f.version || f.targetVersion || "")'"#,
        )
        .await
        .map_err(|error| {
            ApiError::BadRequest(format!(
                "failed to read mongodb featureCompatibilityVersion with DBE maintenance credentials: {error}"
            ))
        })?;
    parse_major_version(output.stdout.trim()).ok_or_else(|| {
        ApiError::BadRequest(
            "failed to parse mongodb featureCompatibilityVersion from source container".to_string(),
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImageVersionChange {
    SameMajorOrUnknown,
    Major,
}

pub(crate) fn classify_image_update(
    protocol: Protocol,
    current_image: &str,
    requested_image: &str,
) -> Result<ImageVersionChange, ApiError> {
    if current_image == requested_image {
        return Ok(ImageVersionChange::SameMajorOrUnknown);
    }
    let Some(current_major) = image_major_version(current_image) else {
        return Err(ApiError::BadRequest(format!(
            "{} image update cannot compare current image tag {current_image:?}; use pinned semver-like tags for existing instances",
            protocol
        )));
    };
    let Some(requested_major) = image_major_version(requested_image) else {
        return Err(ApiError::BadRequest(format!(
            "{} image update cannot compare requested image tag {requested_image:?}; use pinned semver-like tags for existing instances",
            protocol
        )));
    };
    if current_major == requested_major {
        Ok(ImageVersionChange::SameMajorOrUnknown)
    } else {
        Ok(ImageVersionChange::Major)
    }
}

pub(in crate::api::instances) fn image_major_version(image: &str) -> Option<u64> {
    let image = image.split('@').next().unwrap_or(image);
    let slash_index = image.rfind('/').map(|index| index + 1).unwrap_or(0);
    let tag_index = image[slash_index..].rfind(':')? + slash_index;
    let tag = &image[tag_index + 1..];
    parse_major_version(tag)
}

pub(in crate::api::instances) fn parse_major_version(value: &str) -> Option<u64> {
    let major = value
        .split(|character: char| !character.is_ascii_digit())
        .next()?;
    if major.is_empty() {
        None
    } else {
        major.parse().ok()
    }
}

pub(in crate::api::instances) fn upgrade_required_error(
    protocol: Protocol,
    current_image: &str,
    requested_image: &str,
) -> ApiError {
    ApiError::BadRequest(format!(
        "{protocol} major image upgrade is blocked for normal image updates. Current image is {current_image}, requested image is {requested_image}. Retry with major_upgrade=true to run DBE's export/import migration workflow, or create a fresh instance and import a dump manually."
    ))
}

pub(crate) fn check_major_upgrade(protocol: Protocol) -> Result<(), ApiError> {
    match protocol {
        Protocol::Postgres
        | Protocol::Mariadb
        | Protocol::Mysql
        | Protocol::Mongodb
        | Protocol::Clickhouse => Ok(()),
        Protocol::Redis => Err(ApiError::BadRequest(
            "redis major upgrades are blocked because Redis uses physical archive restore here; create a fresh Redis instance or use a dedicated Redis migration workflow".to_string(),
        )),
        Protocol::Valkey => Err(ApiError::BadRequest(
            "valkey major upgrades are blocked because Valkey uses physical archive restore here; create a fresh Valkey instance or use a dedicated Valkey migration workflow".to_string(),
        )),
        Protocol::Qdrant => Err(ApiError::BadRequest(
            "qdrant major upgrades are blocked because Qdrant snapshot compatibility is version-specific; create a fresh Qdrant instance or use a dedicated Qdrant migration workflow".to_string(),
        )),
    }
}
