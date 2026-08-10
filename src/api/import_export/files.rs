//! Staging, file transfer, compression, and artifact path hardening.

use super::{archive::*, *};

pub(super) async fn logical_staging_root(state: &AppState) -> Result<PathBuf, ApiError> {
    let root = PathBuf::from(state.config.paths.tmp_root()).join("import-export");
    create_private_directory(&root, "logical import/export staging directory").await?;
    Ok(root)
}

pub(super) fn dump_extension(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres => "postgres.sql",
        Protocol::Redis => "redis.tar.gz",
        Protocol::Valkey => "valkey.tar.gz",
        Protocol::Mariadb => "mariadb.sql",
        Protocol::Mysql => "mysql.sql",
        Protocol::Mongodb => "mongodb.archive.gz",
        Protocol::Clickhouse => "clickhouse.sql",
        Protocol::Qdrant => "qdrant.tar.gz",
    }
}

pub(super) async fn copy_file(from: &FsPath, to: &FsPath) -> Result<(), ApiError> {
    if let Some(parent) = to.parent() {
        create_private_directory(parent, "file parent directory").await?;
    }
    let from = from.to_path_buf();
    let to = to.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<(), std::io::Error> {
        let mut input = std::fs::File::open(&from)?;
        write_new_private_file(&to, |mut output| {
            std::io::copy(&mut input, &mut output)?;
            output.flush()
        })
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to join file copy task: {error}")))?
    .map_err(|error| ApiError::Runtime(format!("failed to copy file: {error}")))
}

pub(super) async fn archive_or_copy_export(
    from: &FsPath,
    to: &FsPath,
    format: ExportArchiveFormat,
) -> Result<(), ApiError> {
    match format {
        ExportArchiveFormat::Plain => move_or_copy_file(from, to).await,
        ExportArchiveFormat::Gzip => compress_gzip(from, to).await,
        ExportArchiveFormat::Bzip2 => compress_bzip2(from, to).await,
    }
}

pub(super) async fn move_or_copy_file(from: &FsPath, to: &FsPath) -> Result<(), ApiError> {
    match tokio::fs::rename(from, to).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
            copy_file(from, to).await?;
            tokio::fs::remove_file(from).await.map_err(|error| {
                ApiError::Runtime(format!(
                    "failed to remove export staging file after copying it: {error}"
                ))
            })
        }
        Err(error) => Err(ApiError::Runtime(format!(
            "failed to install export artifact: {error}"
        ))),
    }
}

pub(super) async fn compress_gzip(source: &FsPath, target: &FsPath) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target = target.to_path_buf();
    run_archive_file_operation(
        "compress gzip",
        false,
        move |deadline| -> Result<(), std::io::Error> {
            if let Some(parent) = target.parent() {
                create_private_directory_blocking(parent)?;
            }
            let mut input = std::fs::File::open(source)?;
            write_new_private_file(&target, |output| {
                let mut encoder =
                    flate2::write::GzEncoder::new(output, flate2::Compression::new(3));
                copy_limited_until(&mut input, &mut encoder, u64::MAX, deadline)?;
                encoder.finish()?;
                Ok(())
            })
        },
    )
    .await
}

pub(super) async fn compress_bzip2(source: &FsPath, target: &FsPath) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target = target.to_path_buf();
    run_archive_file_operation(
        "compress bzip2",
        false,
        move |deadline| -> Result<(), std::io::Error> {
            if let Some(parent) = target.parent() {
                create_private_directory_blocking(parent)?;
            }
            let mut input = std::fs::File::open(source)?;
            write_new_private_file(&target, |output| {
                let mut encoder =
                    bzip2::write::BzEncoder::new(output, bzip2::Compression::default());
                copy_limited_until(&mut input, &mut encoder, u64::MAX, deadline)?;
                encoder.finish()?;
                Ok(())
            })
        },
    )
    .await
}

pub(super) async fn run_archive_file_operation(
    failure_label: &'static str,
    io_error_is_bad_request: bool,
    task: impl FnOnce(Instant) -> Result<(), std::io::Error> + Send + 'static,
) -> Result<(), ApiError> {
    let result = tokio::task::spawn_blocking(move || task(archive_operation_deadline()))
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to {failure_label}: {error}")))?;

    match result {
        Ok(()) => Ok(()),
        Err(error) if io_error_is_bad_request => Err(ApiError::BadRequest(format!(
            "failed to {failure_label}: {error}"
        ))),
        Err(error) => Err(ApiError::Runtime(format!(
            "failed to {failure_label}: {error}"
        ))),
    }
}

pub(super) async fn ensure_import_file_size(path: &FsPath) -> Result<u64, ApiError> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        ApiError::Runtime(format!(
            "failed to read import artifact metadata {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ApiError::BadRequest(
            "import artifact must be a real regular file".to_string(),
        ));
    }
    if metadata.len() > MAX_UNARCHIVED_BYTES {
        return Err(ApiError::BadRequest(format!(
            "import artifact is too large: {} bytes exceeds {} bytes",
            metadata.len(),
            MAX_UNARCHIVED_BYTES
        )));
    }
    Ok(metadata.len())
}

pub(super) async fn cleanup_dir(path: &FsPath) {
    cleanup_path(path).await;
}

pub(super) async fn cleanup_path(path: &FsPath) {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => {
            if let Err(error) = tokio::fs::remove_file(path).await {
                tracing::warn!(path = %path.display(), %error, "failed to clean import workspace");
            }
        }
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "failed to clean import workspace");
        }
    }
}

pub(super) async fn create_private_directory(path: &FsPath, label: &str) -> Result<(), ApiError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || create_private_directory_blocking(&path))
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to secure {label}: {error}")))?
        .map_err(|error| ApiError::Runtime(format!("failed to secure {label}: {error}")))
}

pub(super) fn create_private_directory_blocking(path: &FsPath) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a real directory", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(super) fn create_private_file_blocking(path: &FsPath) -> Result<std::fs::File, std::io::Error> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    options.open(path)
}

pub(super) fn write_new_private_file<T>(
    path: &FsPath,
    operation: impl FnOnce(std::fs::File) -> Result<T, std::io::Error>,
) -> Result<T, std::io::Error> {
    let file = create_private_file_blocking(path)?;
    let result = operation(file);
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result
}

pub(super) async fn validate_artifact_path(
    state: &AppState,
    instance_id: &str,
    path: &FsPath,
) -> Result<PathBuf, ApiError> {
    crate::shared::ids::validate_instance_id(instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let artifact_id = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| is_safe_flat_file_name(name))
        .ok_or_else(|| ApiError::BadRequest("invalid artifact_id".to_string()))?;
    if !path.is_absolute() && path.to_str() != Some(artifact_id) {
        return Err(ApiError::BadRequest("invalid artifact_id".to_string()));
    }

    let base_roots = [
        PathBuf::from(state.config.paths.exports_root()),
        PathBuf::from(state.config.paths.imports_root()),
    ];
    let mut instance_roots = Vec::with_capacity(base_roots.len());
    for base_root in base_roots {
        create_private_directory(&base_root, "artifact root").await?;
        let instance_root = base_root.join(instance_id);
        create_private_directory(&instance_root, "instance artifact directory").await?;
        instance_roots.push(
            tokio::fs::canonicalize(&instance_root)
                .await
                .map_err(|error| {
                    ApiError::Runtime(format!("failed to resolve instance artifact root: {error}"))
                })?,
        );
    }

    let artifact_path = if path.is_absolute() {
        let source_metadata = tokio::fs::symlink_metadata(path)
            .await
            .map_err(|error| ApiError::BadRequest(format!("artifact_id is invalid: {error}")))?;
        if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
            return Err(ApiError::BadRequest(
                "artifact_id must name a real regular file".to_string(),
            ));
        }
        let canonical = tokio::fs::canonicalize(path)
            .await
            .map_err(|error| ApiError::BadRequest(format!("artifact_id is invalid: {error}")))?;
        let belongs_to_instance = canonical
            .parent()
            .is_some_and(|parent| instance_roots.iter().any(|root| parent == root));
        if !belongs_to_instance {
            return Err(ApiError::BadRequest(
                "artifact does not belong to the requested instance".to_string(),
            ));
        }
        canonical
    } else {
        let mut resolved = None;
        for root in &instance_roots {
            let candidate = root.join(artifact_id);
            let metadata = match tokio::fs::symlink_metadata(&candidate).await {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(ApiError::Runtime(format!(
                        "failed to inspect import artifact: {error}"
                    )));
                }
            };
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ApiError::BadRequest(
                    "artifact_id must name a real regular file".to_string(),
                ));
            }
            resolved = Some(tokio::fs::canonicalize(candidate).await.map_err(|error| {
                ApiError::Runtime(format!("failed to resolve import artifact: {error}"))
            })?);
            break;
        }
        resolved.ok_or(ApiError::NotFound)?
    };

    if !artifact_has_allowed_extension(&artifact_path) {
        return Err(ApiError::BadRequest(
            "artifact_id extension is not allowed for import".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        tokio::fs::set_permissions(&artifact_path, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|error| {
                ApiError::Runtime(format!("failed to secure import artifact: {error}"))
            })?;
    }
    Ok(artifact_path)
}

pub(super) fn artifact_has_allowed_extension(path: &FsPath) -> bool {
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    [
        ".sql",
        ".archive.gz",
        ".snapshot",
        ".tar.gz",
        ".tgz",
        ".tar",
        ".zip",
        ".gz",
        ".gzip",
        ".bz2",
        ".bzip2",
    ]
    .iter()
    .any(|suffix| filename.ends_with(suffix))
}
