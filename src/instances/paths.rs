use std::path::{Path, PathBuf};

use crate::{config::PathConfig, shared::ids::validate_instance_id};

#[derive(Debug, Clone)]
pub struct RuntimePathStatus {
    pub entries: usize,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mode: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct InstancePaths {
    pub instance_id: String,
    pub data: PathBuf,
    pub logs: PathBuf,
    pub sockets: PathBuf,
    pub artifacts: PathBuf,
    /// Portable exports owned by this instance.
    pub exports: PathBuf,
    /// Operator-staged imports owned by this instance.
    pub imports: PathBuf,
    /// Physical backups are created lazily, but remain owned by the instance.
    pub backups: PathBuf,
    /// Daemon-owned configuration that must never be writable by a database container.
    pub runtime_config: PathBuf,
    /// Daemon executable copy used only by TCP-only engines as a local socket bridge.
    pub socket_bridge_binary: PathBuf,
}

impl InstancePaths {
    pub fn new(config: &PathConfig, instance_id: &str) -> Result<Self, InstancePathError> {
        validate_instance_id(instance_id)?;
        let volumes_root_value = config.volumes_root();
        let data_root = root("paths.volumes", &volumes_root_value)?;
        let logs_root = root("paths.logs", &config.logs)?;
        let sockets_root = root("paths.sockets", &config.sockets)?;
        let artifacts_root = root("paths.artifacts", &config.artifacts)?;
        let exports_root = root("paths.exports", &config.exports_root())?;
        let imports_root = root("paths.imports", &config.imports_root())?;
        let backups_root = root("paths.backups", &config.backups_root())?;
        let metadata_root = root("paths.metadata", &config.metadata_root())?;
        let runtime_config_root = metadata_root.join("runtime-configs");

        Ok(Self {
            instance_id: instance_id.to_string(),
            data: child_direct(&data_root, instance_id)?,
            logs: child(&logs_root, instance_id)?,
            sockets: child_direct(&sockets_root, instance_id)?,
            artifacts: child(&artifacts_root, instance_id)?,
            exports: child_direct(&exports_root, instance_id)?,
            imports: child_direct(&imports_root, instance_id)?,
            backups: child_direct(&backups_root, instance_id)?,
            runtime_config: child_direct(&runtime_config_root, instance_id)?,
            socket_bridge_binary: metadata_root
                .join("runtime")
                .join("bin")
                .join(crate::bins::SOCKET_BRIDGE_FILENAME),
        })
    }

    pub async fn create_dirs(&self) -> Result<(), InstancePathError> {
        create_private_dir(&self.data).await?;
        create_private_dir(&self.logs).await?;
        create_private_dir(&self.sockets).await?;
        create_private_dir(&self.artifacts).await?;
        create_private_dir(&self.runtime_config).await?;
        Ok(())
    }

    pub async fn clear_socket_dir(&self) -> Result<(), InstancePathError> {
        let sockets = self.sockets.clone();
        tokio::task::spawn_blocking(move || clear_dir_contents(&sockets))
            .await
            .map_err(|error| InstancePathError::Task(error.to_string()))?
    }

    pub async fn socket_dir_status(&self) -> Result<RuntimePathStatus, InstancePathError> {
        let sockets = self.sockets.clone();
        tokio::task::spawn_blocking(move || dir_status(&sockets))
            .await
            .map_err(|error| InstancePathError::Task(error.to_string()))?
    }

    pub async fn apply_container_owner(&self) -> Result<(), InstancePathError> {
        #[cfg(unix)]
        {
            let Some(owner) = self.desired_container_owner().await? else {
                return Ok(());
            };
            let paths = vec![
                self.data.clone(),
                self.logs.clone(),
                self.sockets.clone(),
                self.artifacts.clone(),
            ];
            tokio::task::spawn_blocking(move || {
                for path in paths {
                    chown_recursive(&path, owner)?;
                }
                Ok(())
            })
            .await
            .map_err(|error| InstancePathError::Task(error.to_string()))?
        }

        #[cfg(not(unix))]
        {
            Ok(())
        }
    }

    #[cfg(unix)]
    pub async fn apply_socket_owner(&self, uid: u32, gid: u32) -> Result<(), InstancePathError> {
        let sockets = self.sockets.clone();
        let owner = ContainerOwner { uid, gid };
        tokio::task::spawn_blocking(move || chown_recursive(&sockets, owner))
            .await
            .map_err(|error| InstancePathError::Task(error.to_string()))?
    }

    #[cfg(not(unix))]
    pub async fn apply_socket_owner(&self, _uid: u32, _gid: u32) -> Result<(), InstancePathError> {
        Ok(())
    }

    #[cfg(unix)]
    async fn desired_container_owner(&self) -> Result<Option<ContainerOwner>, InstancePathError> {
        if let Some(owner) = owner_from_env("DBE_CONTAINER_UID", "DBE_CONTAINER_GID") {
            return Ok(Some(owner));
        }

        let metadata = tokio::fs::metadata(&self.data).await.map_err(|source| {
            InstancePathError::ReadMetadata {
                path: self.data.display().to_string(),
                source,
            }
        })?;

        use std::os::unix::fs::MetadataExt;

        Ok(default_owner_for(metadata.uid(), metadata.gid()))
    }

    pub async fn container_user(&self) -> Result<String, InstancePathError> {
        let metadata = tokio::fs::metadata(&self.data).await.map_err(|source| {
            InstancePathError::ReadMetadata {
                path: self.data.display().to_string(),
                source,
            }
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            Ok(format!("{}:{}", metadata.uid(), metadata.gid()))
        }

        #[cfg(not(unix))]
        {
            let _ = metadata;
            Err(InstancePathError::UnsupportedContainerUser)
        }
    }
}

fn root(field: &'static str, value: &str) -> Result<PathBuf, InstancePathError> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(InstancePathError::RelativeRoot {
            field,
            path: value.to_string(),
        })
    }
}

fn child(root: &Path, instance_id: &str) -> Result<PathBuf, InstancePathError> {
    let path = root.join("instances").join(instance_id);
    if path.starts_with(root) {
        Ok(path)
    } else {
        Err(InstancePathError::EscapesRoot {
            path: path.display().to_string(),
            root: root.display().to_string(),
        })
    }
}

fn child_direct(root: &Path, instance_id: &str) -> Result<PathBuf, InstancePathError> {
    let path = root.join(instance_id);
    if path.starts_with(root) {
        Ok(path)
    } else {
        Err(InstancePathError::EscapesRoot {
            path: path.display().to_string(),
            root: root.display().to_string(),
        })
    }
}

async fn create_private_dir(path: &Path) -> Result<(), InstancePathError> {
    tokio::fs::create_dir_all(path)
        .await
        .map_err(|source| InstancePathError::CreateDir {
            path: path.display().to_string(),
            source,
        })?;
    ensure_real_directory(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|source| InstancePathError::CreateDir {
                path: path.display().to_string(),
                source,
            })?;
    }

    Ok(())
}

fn ensure_real_directory(path: &Path) -> Result<(), InstancePathError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|source| InstancePathError::ReadMetadata {
            path: path.display().to_string(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(InstancePathError::InvalidDirectory {
            path: path.display().to_string(),
        });
    }
    Ok(())
}

fn clear_dir_contents(path: &Path) -> Result<(), InstancePathError> {
    ensure_real_directory(path)?;

    for entry in std::fs::read_dir(path).map_err(|source| InstancePathError::ReadDir {
        path: path.display().to_string(),
        source,
    })? {
        let entry = entry.map_err(|source| InstancePathError::ReadDir {
            path: path.display().to_string(),
            source,
        })?;
        let entry_path = entry.path();
        let metadata = std::fs::symlink_metadata(&entry_path).map_err(|source| {
            InstancePathError::ReadMetadata {
                path: entry_path.display().to_string(),
                source,
            }
        })?;

        if metadata.is_dir() {
            std::fs::remove_dir_all(&entry_path).map_err(|source| {
                InstancePathError::RemovePath {
                    path: entry_path.display().to_string(),
                    source,
                }
            })?;
        } else {
            std::fs::remove_file(&entry_path).map_err(|source| InstancePathError::RemovePath {
                path: entry_path.display().to_string(),
                source,
            })?;
        }
    }

    Ok(())
}

fn dir_status(path: &Path) -> Result<RuntimePathStatus, InstancePathError> {
    ensure_real_directory(path)?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|source| InstancePathError::ReadMetadata {
            path: path.display().to_string(),
            source,
        })?;
    let entries = std::fs::read_dir(path)
        .map_err(|source| InstancePathError::ReadDir {
            path: path.display().to_string(),
            source,
        })?
        .count();

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        Ok(RuntimePathStatus {
            entries,
            uid: Some(metadata.uid()),
            gid: Some(metadata.gid()),
            mode: Some(metadata.permissions().mode() & 0o777),
        })
    }

    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok(RuntimePathStatus {
            entries,
            uid: None,
            gid: None,
            mode: None,
        })
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContainerOwner {
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
const DEFAULT_CONTAINER_UID: u32 = 1000;
#[cfg(unix)]
const DEFAULT_CONTAINER_GID: u32 = 1000;

#[cfg(unix)]
fn owner_from_env(uid_key: &str, gid_key: &str) -> Option<ContainerOwner> {
    let uid = std::env::var(uid_key).ok()?.parse::<u32>().ok()?;
    let gid = std::env::var(gid_key).ok()?.parse::<u32>().ok()?;
    if uid == 0 {
        return None;
    }
    Some(ContainerOwner { uid, gid })
}

#[cfg(unix)]
fn default_owner_for(uid: u32, _gid: u32) -> Option<ContainerOwner> {
    if uid == 0 {
        Some(ContainerOwner {
            uid: DEFAULT_CONTAINER_UID,
            gid: DEFAULT_CONTAINER_GID,
        })
    } else {
        None
    }
}

#[cfg(unix)]
fn chown_recursive(path: &Path, owner: ContainerOwner) -> Result<(), InstancePathError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(InstancePathError::ReadMetadata {
                path: path.display().to_string(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    std::os::unix::fs::chown(path, Some(owner.uid), Some(owner.gid)).map_err(|source| {
        InstancePathError::Chown {
            path: path.display().to_string(),
            source,
        }
    })?;
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path).map_err(|source| InstancePathError::ReadDir {
            path: path.display().to_string(),
            source,
        })? {
            let entry = entry.map_err(|source| InstancePathError::ReadDir {
                path: path.display().to_string(),
                source,
            })?;
            chown_recursive(&entry.path(), owner)?;
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum InstancePathError {
    #[error(transparent)]
    InvalidId(#[from] crate::shared::ids::IdError),
    #[error("{field} must be absolute: {path}")]
    RelativeRoot { field: &'static str, path: String },
    #[error("path {path} escapes root {root}")]
    EscapesRoot { path: String, root: String },
    #[error("path {path} is not a real directory")]
    InvalidDirectory { path: String },
    #[error("failed to create directory {path}: {source}")]
    CreateDir {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read metadata for {path}: {source}")]
    ReadMetadata {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read directory {path}: {source}")]
    ReadDir {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to set container owner on {path}: {source}")]
    Chown {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to remove runtime path {path}: {source}")]
    RemovePath {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("instance path task failed: {0}")]
    Task(String),
    #[error("container user detection is only supported on unix")]
    UnsupportedContainerUser,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsafe_instance_ids() {
        let config = PathConfig::default();

        let error = InstancePaths::new(&config, "../bad").unwrap_err();

        assert!(matches!(error, InstancePathError::InvalidId(_)));
    }

    #[test]
    fn builds_paths_under_configured_roots() {
        let config = PathConfig::default();

        let paths = InstancePaths::new(&config, "inst_abc").unwrap();

        assert!(paths.data.starts_with(&config.data));
        assert!(paths.logs.starts_with(&config.logs));
        assert!(paths.exports.starts_with(config.exports_root()));
        assert!(paths.imports.starts_with(config.imports_root()));
        assert!(paths.backups.starts_with(config.backups_root()));
        assert!(paths.runtime_config.starts_with(config.metadata_root()));
    }

    #[cfg(unix)]
    #[test]
    fn root_owned_paths_default_to_non_root_container_owner() {
        assert_eq!(
            default_owner_for(0, 0),
            Some(ContainerOwner {
                uid: DEFAULT_CONTAINER_UID,
                gid: DEFAULT_CONTAINER_GID
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_root_owned_paths_keep_existing_owner() {
        assert_eq!(default_owner_for(1001, 1001), None);
    }
}
