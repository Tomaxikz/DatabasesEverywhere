use super::*;

pub(super) fn validate_images(
    images: &crate::config::ImageConfig,
) -> Result<(), ConfigValidationError> {
    for (field, image) in [
        ("images.postgres", images.postgres.as_str()),
        ("images.redis", images.redis.as_str()),
        ("images.valkey", images.valkey.as_str()),
        ("images.mariadb", images.mariadb.as_str()),
        ("images.mysql", images.mysql.as_str()),
        ("images.mongodb", images.mongodb.as_str()),
        ("images.clickhouse", images.clickhouse.as_str()),
        ("images.qdrant", images.qdrant.as_str()),
    ] {
        validate_image_reference(field, image)?;
    }
    for (field, allowed) in [
        (
            "images.allowed.postgres",
            images.allowed.postgres.as_slice(),
        ),
        ("images.allowed.redis", images.allowed.redis.as_slice()),
        ("images.allowed.valkey", images.allowed.valkey.as_slice()),
        ("images.allowed.mariadb", images.allowed.mariadb.as_slice()),
        ("images.allowed.mysql", images.allowed.mysql.as_slice()),
        ("images.allowed.mongodb", images.allowed.mongodb.as_slice()),
        (
            "images.allowed.clickhouse",
            images.allowed.clickhouse.as_slice(),
        ),
        ("images.allowed.qdrant", images.allowed.qdrant.as_slice()),
    ] {
        for image in allowed {
            validate_image_reference(field, image)?;
        }
    }
    Ok(())
}

pub(super) fn validate_image_reference(
    field: &'static str,
    image: &str,
) -> Result<(), ConfigValidationError> {
    let image = image.trim();
    let is_well_formed = !image.is_empty() && !image.chars().any(char::is_whitespace);
    if is_well_formed && is_pinned_image_reference(image) {
        return Ok(());
    }
    Err(ConfigValidationError::InvalidImageReference {
        field,
        image: image.to_string(),
    })
}

pub(super) fn check_mongodb_kernel(image: &str) -> Result<(), ConfigValidationError> {
    let Some(kernel) = linux_kernel_release() else {
        return Ok(());
    };
    if kernel_is_6_19_or_newer(&kernel) && mongodb_image_is_8_or_newer(image) {
        return Err(ConfigValidationError::MongodbKernelIncompatible {
            image: image.to_string(),
            kernel,
        });
    }
    Ok(())
}

pub(super) fn linux_kernel_release() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(super) fn kernel_is_6_19_or_newer(release: &str) -> bool {
    let mut parts = release
        .split(|character: char| !character.is_ascii_digit())
        .filter(|part| !part.is_empty());
    let major = parts
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or_default();
    let minor = parts
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or_default();

    major > 6 || (major == 6 && minor >= 19)
}

pub(super) fn mongodb_image_is_8_or_newer(image: &str) -> bool {
    let image = image.split_once('@').map_or(image, |(name, _)| name);
    let tag = image
        .rsplit_once(':')
        .filter(|(name, _)| !name.contains('/'))
        .map(|(_, tag)| tag)
        .or_else(|| {
            let (name, tag) = image.rsplit_once(':')?;
            if name.rsplit('/').next()?.contains(':') {
                None
            } else {
                Some(tag)
            }
        })
        .unwrap_or("latest");
    tag == "latest"
        || tag
            .split(|character: char| !character.is_ascii_digit())
            .next()
            .and_then(|major| major.parse::<u32>().ok())
            .is_some_and(|major| major >= 8)
}
