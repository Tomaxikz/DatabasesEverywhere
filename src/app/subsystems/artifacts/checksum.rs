use super::HASH_READ_BUFFER_BYTES;
use crate::routes::http::response::ApiError;
use sha2::Digest;
use sha2::Sha256;
use std::io::Read;
use std::path::Path as FsPath;
use std::path::PathBuf;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub(super) async fn sha256_file(path: PathBuf) -> Result<String, ApiError> {
    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to stat artifact: {error}")))?;
    if let Some(hash) = cached_sha256(&path, &metadata).await? {
        return Ok(hash);
    }

    let hash = tokio::task::spawn_blocking({
        let path = path.clone();
        move || sha256_file_blocking(&path)
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to hash artifact: {error}")))?
    .map_err(|error| ApiError::Runtime(format!("failed to hash artifact: {error}")))?;
    write_checksum_sidecar(&path, &metadata, &hash).await;
    Ok(hash)
}

pub(super) fn sha256_file_blocking(path: &FsPath) -> Result<String, std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut buffer = [0_u8; HASH_READ_BUFFER_BYTES];
    let mut hasher = Sha256::new();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(crate::utils::hex::encode_lower(&hasher.finalize()))
}

pub(super) fn checksum_sidecar_path(path: &FsPath) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    Some(path.with_file_name(format!("{name}.sha256")))
}

pub(super) fn is_checksum_sidecar(path: &FsPath) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".sha256"))
}

pub(super) async fn cached_sha256(
    path: &FsPath,
    metadata: &std::fs::Metadata,
) -> Result<Option<String>, ApiError> {
    let Some(sidecar) = checksum_sidecar_path(path) else {
        return Ok(None);
    };
    let content = match tokio::fs::read_to_string(sidecar).await {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            tracing::debug!(%error, path = %path.display(), "failed to read checksum sidecar");
            return Ok(None);
        }
    };
    let mut hash = None;
    let mut size = None;
    let mut modified_nanos = None;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("sha256 ") {
            hash = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("size ") {
            size = value.trim().parse::<u64>().ok();
        } else if let Some(value) = line.strip_prefix("modified_unix_nanos ") {
            modified_nanos = value.trim().parse::<u128>().ok();
        }
    }
    let Some(hash) = hash.filter(|hash| is_sha256_hex(hash)) else {
        return Ok(None);
    };
    if size == Some(metadata.len())
        && modified_nanos == Some(unix_nanos(metadata.modified().unwrap_or(UNIX_EPOCH)))
    {
        Ok(Some(hash))
    } else {
        Ok(None)
    }
}

pub(super) async fn write_checksum_sidecar(
    path: &FsPath,
    metadata: &std::fs::Metadata,
    hash: &str,
) {
    let Some(sidecar) = checksum_sidecar_path(path) else {
        return;
    };
    let modified = unix_nanos(metadata.modified().unwrap_or(UNIX_EPOCH));
    let content = format!(
        "sha256 {hash}\nsize {}\nmodified_unix_nanos {modified}\n",
        metadata.len()
    );
    let written = tokio::task::spawn_blocking(move || {
        crate::io::files::atomic_write_private(&sidecar, content.as_bytes())
    })
    .await
    .map_err(std::io::Error::other)
    .and_then(|result| result);
    if let Err(error) = written {
        tracing::debug!(%error, path = %path.display(), "failed to write checksum sidecar");
    }
}

pub(super) async fn remove_checksum_sidecar(path: &FsPath) {
    let Some(sidecar) = checksum_sidecar_path(path) else {
        return;
    };
    match tokio::fs::remove_file(sidecar).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::debug!(%error, path = %path.display(), "failed to delete checksum sidecar")
        }
    }
}

pub(super) fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn unix_nanos(time: SystemTime) -> u128 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

pub(super) fn system_time_rfc3339(time: SystemTime) -> String {
    OffsetDateTime::from(time)
        .format(&Rfc3339)
        .expect("Rfc3339 formatting works")
}
