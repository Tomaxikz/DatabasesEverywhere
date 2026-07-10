use std::{
    fs::File,
    io::{ErrorKind, Write},
    path::Path,
    sync::Arc,
};

use axum::extract::State;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::{
    api::{
        api_response::{ApiError, ApiJson, ApiResponse, ApiResult},
        routes::AppState,
        security_policy::ApiRequestContext,
    },
    auth::scopes,
    config::{Config, load::load_config, validate::validate_config},
};

const FORBIDDEN_PATCH_PATHS: &[&[&str]] = &[
    &["token"],
    &["jwt_signing_key"],
    &["token_id"],
    &["uuid"],
    &["paths"],
    &["disk", "fuse_quota_binary"],
    &["disk", "fuse_quota_binary_sha256"],
];

#[derive(Debug, Serialize)]
pub struct ConfigPatchResponse {
    pub applied: bool,
    pub restart_required: bool,
    pub config_path: String,
}

#[derive(Debug, Clone, Default)]
pub struct ConfigPatchCoordinator {
    inner: Arc<Mutex<()>>,
}

impl ConfigPatchCoordinator {
    async fn apply(&self, path: &Path, patch: Value) -> Result<(), ApiError> {
        let _guard = self.inner.lock().await;
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || apply_config_patch(&path, patch))
            .await
            .map_err(|error| ApiError::Runtime(format!("failed to join config writer: {error}")))?
    }
}

pub async fn patch_config(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiJson(patch): ApiJson<Value>,
) -> ApiResult<ConfigPatchResponse> {
    auth.require_scope(scopes::CONFIG_ADMIN)?;
    if !patch.is_object() {
        return Err(ApiError::BadRequest(
            "config patch must be a JSON object".to_string(),
        ));
    }
    reject_forbidden_paths(&patch)?;
    state
        .config_patches
        .apply(&state.config_path, patch)
        .await?;

    tracing::info!(
        event = "audit config_patch_applied",
        config = %state.config_path.display(),
        "config patch written; daemon restart required"
    );

    Ok(ApiResponse::ok(ConfigPatchResponse {
        applied: true,
        restart_required: true,
        config_path: state.config_path.display().to_string(),
    }))
}

fn apply_config_patch(path: &Path, patch: Value) -> Result<(), ApiError> {
    let current = load_config(path)
        .map_err(|error| ApiError::Runtime(format!("failed to load current config: {error}")))?;
    let mut document = serde_json::to_value(current)
        .map_err(|error| ApiError::Runtime(format!("failed to serialize config: {error}")))?;
    merge_json(&mut document, patch);
    let config: Config = serde_json::from_value(document)
        .map_err(|error| ApiError::BadRequest(format!("invalid config patch: {error}")))?;
    validate_config(&config).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let yaml = serde_yaml::to_string(&config)
        .map_err(|error| ApiError::Runtime(format!("failed to encode config: {error}")))?;
    atomic_replace_config(path, yaml.as_bytes())
        .map_err(|error| ApiError::Runtime(format!("failed to write config: {error}")))
}

fn atomic_replace_config(path: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            "config path has no parent directory",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "config path has no file name")
    })?;
    let directory = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let existing = rustix::fs::openat(
        &directory,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let existing_stat = rustix::fs::fstat(&existing).map_err(std::io::Error::from)?;
    if FileType::from_raw_mode(existing_stat.st_mode) != FileType::RegularFile
        || existing_stat.st_nlink != 1
    {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "config {} must be a real, singly-linked regular file",
                path.display()
            ),
        ));
    }
    drop(existing);

    let temporary_name = format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        uuid::Uuid::new_v4()
    );
    let temporary_fd = rustix::fs::openat(
        &directory,
        temporary_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(std::io::Error::from)?;
    let mut temporary = File::from(temporary_fd);

    let result = (|| {
        temporary.write_all(contents)?;
        temporary.flush()?;
        rustix::fs::fchmod(&temporary, Mode::RUSR | Mode::WUSR).map_err(std::io::Error::from)?;
        temporary.sync_all()?;
        drop(temporary);

        rustix::fs::renameat_with(
            &directory,
            temporary_name.as_str(),
            &directory,
            file_name,
            RenameFlags::empty(),
        )
        .map_err(std::io::Error::from)?;
        sync_directory(&directory)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = rustix::fs::unlinkat(&directory, temporary_name.as_str(), AtFlags::empty());
    }
    result
}

fn sync_directory(directory: &impl std::os::fd::AsFd) -> Result<(), std::io::Error> {
    match rustix::fs::fsync(directory) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::INVAL | rustix::io::Errno::OPNOTSUPP) => Ok(()),
        Err(error) => Err(std::io::Error::from(error)),
    }
}

fn merge_json(target: &mut Value, patch: Value) {
    match (target, patch) {
        (Value::Object(target), Value::Object(patch)) => {
            for (key, value) in patch {
                if value.is_null() {
                    target.remove(&key);
                } else {
                    merge_json(target.entry(key).or_insert(Value::Null), value);
                }
            }
        }
        (target, patch) => *target = patch,
    }
}

fn reject_forbidden_paths(patch: &Value) -> Result<(), ApiError> {
    for path in FORBIDDEN_PATCH_PATHS {
        if value_has_path(patch, path) {
            return Err(ApiError::BadRequest(format!(
                "config patch may not modify {}",
                path.join(".")
            )));
        }
    }
    Ok(())
}

fn value_has_path(value: &Value, path: &[&str]) -> bool {
    let mut current = value;
    for segment in path {
        let Some(next) = current.get(*segment) else {
            return false;
        };
        current = next;
    }
    true
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    #[test]
    fn merge_json_replaces_scalars_and_merges_objects() {
        let mut target = serde_json::json!({
            "api": { "host": "127.0.0.1", "port": 8090 },
            "debug": false
        });
        merge_json(
            &mut target,
            serde_json::json!({
                "api": { "port": 9090 },
                "debug": true
            }),
        );

        assert_eq!(target["api"]["host"], "127.0.0.1");
        assert_eq!(target["api"]["port"], 9090);
        assert_eq!(target["debug"], true);
    }

    #[test]
    fn rejects_token_patch() {
        let patch = serde_json::json!({ "token": "new" });

        assert!(reject_forbidden_paths(&patch).is_err());
    }

    #[test]
    fn rejects_jwt_signing_key_patch() {
        let patch = serde_json::json!({ "jwt_signing_key": "new" });

        assert!(reject_forbidden_paths(&patch).is_err());
    }

    #[test]
    fn rejects_fuse_helper_executable_patch() {
        let patch = serde_json::json!({
            "disk": {
                "fuse_quota_binary": "/var/lib/dbev/imports/attacker",
                "fuse_quota_binary_sha256": "a".repeat(64)
            }
        });

        assert!(reject_forbidden_paths(&patch).is_err());
    }

    #[test]
    fn rejects_runtime_path_patch() {
        assert!(
            reject_forbidden_paths(&serde_json::json!({
                "paths": { "data": "/tmp/attacker" }
            }))
            .is_err()
        );
    }

    #[test]
    fn atomically_replaces_config_with_private_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config.yml");
        std::fs::write(&config, "old").unwrap();

        atomic_replace_config(&config, b"new\n").unwrap();

        assert_eq!(std::fs::read_to_string(&config).unwrap(), "new\n");
        let mode = std::fs::metadata(&config).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn refuses_to_replace_symlinked_config() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.yml");
        let config = directory.path().join("config.yml");
        std::fs::write(&target, "secret").unwrap();
        symlink(&target, &config).unwrap();

        assert!(atomic_replace_config(&config, b"replacement").is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "secret");
    }

    #[test]
    fn sequential_patches_merge_against_the_latest_disk_config() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yml");
        std::fs::write(
            &path,
            r#"
remote: https://panel.example.com
uuid: node-uuid
token_id: token-id
token: test-api-token-0123456789abcdef-01
jwt_signing_key: test-jwt-signing-key-0123456789abcdef-02
api:
  host: 127.0.0.1
  port: 8090
paths:
  data: /var/lib/databases-everywhere
  sockets: /run/databases-everywhere
  logs: /var/log/databases-everywhere
  artifacts: /var/lib/databases-everywhere/artifacts
"#,
        )
        .unwrap();

        apply_config_patch(&path, serde_json::json!({"api": {"port": 9090}})).unwrap();
        apply_config_patch(&path, serde_json::json!({"debug": true})).unwrap();

        let config = load_config(&path).unwrap();
        assert_eq!(config.api.port, 9090);
        assert!(config.debug);
    }
}
