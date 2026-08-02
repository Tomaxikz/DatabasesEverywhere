use std::path::{Component, Path};

use bollard::{API_DEFAULT_VERSION, ClientVersion, Docker, models::SystemVersion};

use crate::config::{DaemonConfig, DaemonEngine};
use crate::shared::ownership::HostOwner;

const API_TIMEOUT_SECONDS: u64 = 120;
const PODMAN_SYSTEM_SOCKET: &str = "/run/podman/podman.sock";
const PODMAN_COMPAT_API_VERSION: &ClientVersion = &ClientVersion {
    major_version: 1,
    minor_version: 40,
};

#[derive(Debug, Clone)]
pub struct DaemonEngineConnection {
    pub engine: DaemonEngine,
    pub socket_path: Option<String>,
}

impl DaemonEngineConnection {
    pub fn from_config(config: &DaemonConfig) -> Self {
        Self {
            engine: config.engine,
            socket_path: configured_or_default_socket(config),
        }
    }

    pub fn connect(&self) -> Result<Docker, bollard::errors::Error> {
        if let Some(socket_path) = self.socket_path.as_deref() {
            let api_version = match self.engine {
                DaemonEngine::Docker => API_DEFAULT_VERSION,
                DaemonEngine::Podman => PODMAN_COMPAT_API_VERSION,
            };
            return Docker::connect_with_socket(socket_path, API_TIMEOUT_SECONDS, api_version);
        }

        match self.engine {
            DaemonEngine::Docker => Docker::connect_with_local_defaults(),
            DaemonEngine::Podman => Docker::connect_with_socket(
                PODMAN_SYSTEM_SOCKET,
                API_TIMEOUT_SECONDS,
                PODMAN_COMPAT_API_VERSION,
            ),
        }
    }

    pub fn socket_path_for_logs(&self) -> &str {
        self.socket_path.as_deref().unwrap_or("auto")
    }
}

pub fn rootless_podman_uid_from_socket_path(path: &str) -> Option<u32> {
    let components = Path::new(path).components().collect::<Vec<_>>();
    match components.as_slice() {
        [
            Component::RootDir,
            Component::Normal(run),
            Component::Normal(user),
            Component::Normal(uid),
            Component::Normal(podman),
            Component::Normal(socket),
        ] if *run == "run"
            && *user == "user"
            && *podman == "podman"
            && *socket == "podman.sock" =>
        {
            uid.to_str()?.parse::<u32>().ok().filter(|uid| *uid != 0)
        }
        _ => None,
    }
}

pub fn reports_podman(version: &SystemVersion) -> bool {
    let platform = version
        .platform
        .as_ref()
        .map(|platform| platform.name.as_str());
    platform
        .into_iter()
        .chain(
            version
                .components
                .iter()
                .flatten()
                .map(|component| component.name.as_str()),
        )
        .any(|name| name.to_ascii_lowercase().contains("podman"))
}

pub fn podman_socket_owner(path: &str) -> std::io::Result<HostOwner> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{path} must be a real Unix socket, not a symlink"),
        ));
    }
    let owner = HostOwner {
        uid: metadata.uid(),
        gid: metadata.gid(),
    };
    if let Some(expected_uid) = rootless_podman_uid_from_socket_path(path)
        && owner.uid != expected_uid
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "rootless Podman socket {path} is owned by uid {}, expected uid {expected_uid}",
                owner.uid
            ),
        ));
    }
    Ok(owner)
}

fn configured_or_default_socket(config: &DaemonConfig) -> Option<String> {
    if let Some(socket_path) = config.configured_socket_path() {
        return Some(socket_path.to_string());
    }

    match config.engine {
        DaemonEngine::Docker => None,
        DaemonEngine::Podman => discover_podman_socket(),
    }
}

fn discover_podman_socket() -> Option<String> {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let socket = format!("{runtime_dir}/podman/podman.sock");
        if Path::new(&socket).exists() {
            return Some(socket);
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if let Ok(metadata) = std::fs::metadata("/proc/self") {
            let socket = format!("/run/user/{}/podman/podman.sock", metadata.uid());
            if Path::new(&socket).exists() {
                return Some(socket);
            }
        }
    }

    if Path::new(PODMAN_SYSTEM_SOCKET).exists() {
        return Some(PODMAN_SYSTEM_SOCKET.to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use bollard::models::{SystemVersionComponents, SystemVersionPlatform};

    use super::*;

    #[test]
    fn recognizes_only_the_standard_rootless_podman_socket_shape() {
        assert_eq!(
            rootless_podman_uid_from_socket_path("/run/user/1001/podman/podman.sock"),
            Some(1001)
        );
        assert_eq!(
            rootless_podman_uid_from_socket_path("/run/podman/podman.sock"),
            None
        );
        assert_eq!(
            rootless_podman_uid_from_socket_path("/run/user/0/podman/podman.sock"),
            None
        );
        assert_eq!(
            rootless_podman_uid_from_socket_path("/tmp/podman.sock"),
            None
        );
    }

    #[test]
    fn detects_podman_from_version_platform_or_components() {
        let platform = SystemVersion {
            platform: Some(SystemVersionPlatform {
                name: "Podman Engine".to_string(),
            }),
            ..Default::default()
        };
        assert!(reports_podman(&platform));

        let component = SystemVersion {
            components: Some(vec![SystemVersionComponents {
                name: "Podman Engine".to_string(),
                version: "5.6.0".to_string(),
                details: None,
            }]),
            ..Default::default()
        };
        assert!(reports_podman(&component));
        assert!(!reports_podman(&SystemVersion::default()));
    }
}
