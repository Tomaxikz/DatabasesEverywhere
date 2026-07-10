use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use bollard::models::HostConfig;

use crate::{
    config::DaemonConfig,
    runtime::socket_bridge::is_valid_bridge,
    shared::backend::{CONTAINER_SOCKET_DIRECTORY, SOCKET_BRIDGE_CONTAINER_PATH},
};

use super::DockerInstanceSpec;

const FORBIDDEN_MOUNT_PREFIXES: &[&str] = &[
    "/",
    "/etc",
    "/dev",
    "/proc",
    "/root",
    "/sys",
    "/var/run/docker.sock",
    "/run/docker.sock",
];

const ALLOWED_EXTRA_MOUNT_TARGETS: &[&str] =
    &["/etc/clickhouse-server/config.d/dbe-hosted-overrides.xml"];

#[derive(Debug, Clone)]
pub struct DockerSecurityPolicy {
    pub no_new_privileges: bool,
    pub drop_all_capabilities: bool,
    pub pids_limit: i64,
    pub read_only_rootfs: bool,
    pub userns_mode: Option<String>,
    pub seccomp_profile: Option<String>,
    pub apparmor_profile: Option<String>,
    pub security_opts: Vec<String>,
}

impl Default for DockerSecurityPolicy {
    fn default() -> Self {
        Self {
            no_new_privileges: true,
            drop_all_capabilities: true,
            pids_limit: 512,
            read_only_rootfs: false,
            userns_mode: None,
            seccomp_profile: None,
            apparmor_profile: None,
            security_opts: Vec::new(),
        }
    }
}

impl DockerSecurityPolicy {
    pub fn from_config(config: &DaemonConfig) -> Self {
        Self {
            read_only_rootfs: config.container_read_only_rootfs,
            userns_mode: non_empty_string(&config.container_userns_mode),
            seccomp_profile: non_empty_string(&config.container_seccomp_profile),
            apparmor_profile: non_empty_string(&config.container_apparmor_profile),
            security_opts: config
                .container_security_opts
                .iter()
                .filter_map(|value| non_empty_string(value))
                .collect(),
            ..Default::default()
        }
    }

    pub fn apply(&self, host_config: &mut HostConfig) {
        host_config.privileged = Some(false);
        host_config.pids_limit = Some(self.pids_limit);
        host_config.readonly_rootfs = Some(self.read_only_rootfs);
        host_config.userns_mode = self.userns_mode.clone();

        let mut security_opts = self.security_opts.clone();
        if self.no_new_privileges {
            push_security_opt(&mut security_opts, "no-new-privileges".to_string());
        }
        if let Some(seccomp_profile) = &self.seccomp_profile {
            push_security_opt(&mut security_opts, format!("seccomp={seccomp_profile}"));
        }
        if let Some(apparmor_profile) = &self.apparmor_profile {
            push_security_opt(&mut security_opts, format!("apparmor={apparmor_profile}"));
        }
        if !security_opts.is_empty() {
            host_config.security_opt = Some(security_opts);
        }
        if self.drop_all_capabilities {
            host_config.cap_drop = Some(vec!["ALL".to_string()]);
        }
        host_config.devices = Some(Vec::new());
    }

    pub fn validate_spec(&self, spec: &DockerInstanceSpec) -> Result<(), DockerSecurityError> {
        validate_mount_source(&spec.data_path)?;
        validate_mount_target(&spec.data_target)?;
        validate_mount_source(&spec.logs_path)?;
        validate_mount_target(&spec.logs_target)?;
        for mount in &spec.extra_mounts {
            validate_mount_source(&mount.source)?;
            validate_extra_mount_target(&mount.target)?;
        }
        self.validate_socket_bridge_spec(spec)?;
        Ok(())
    }

    fn validate_socket_bridge_spec(
        &self,
        spec: &DockerInstanceSpec,
    ) -> Result<(), DockerSecurityError> {
        if spec.socket_bridges.is_empty() {
            return Ok(());
        }
        if !matches!(
            spec.protocol,
            crate::shared::protocol::Protocol::Clickhouse
                | crate::shared::protocol::Protocol::Qdrant
        ) || spec
            .socket_bridges
            .iter()
            .any(|bridge| !is_valid_bridge(bridge))
        {
            return Err(DockerSecurityError::InvalidSocketBridge);
        }
        let helper = spec
            .extra_mounts
            .iter()
            .any(|mount| mount.target == SOCKET_BRIDGE_CONTAINER_PATH && mount.read_only);
        let sockets = spec
            .extra_mounts
            .iter()
            .any(|mount| mount.target == CONTAINER_SOCKET_DIRECTORY && !mount.read_only);
        if !helper || !sockets {
            return Err(DockerSecurityError::InvalidSocketBridge);
        }
        Ok(())
    }
}

fn validate_mount_source(path: &Path) -> Result<(), DockerSecurityError> {
    if !path.is_absolute() {
        return Err(DockerSecurityError::InvalidMountSource {
            path: path.display().to_string(),
            reason: "source must be absolute".to_string(),
        });
    }
    reject_parent_components(path).map_err(|reason| DockerSecurityError::InvalidMountSource {
        path: path.display().to_string(),
        reason,
    })?;
    let path = canonicalize_existing_prefix(path).map_err(|reason| {
        DockerSecurityError::InvalidMountSource {
            path: path.display().to_string(),
            reason,
        }
    })?;
    reject_forbidden_path(&path)
}

fn validate_mount_target(target: &str) -> Result<(), DockerSecurityError> {
    let target = target.trim();
    if target.is_empty() {
        return Err(DockerSecurityError::InvalidMountTarget {
            target: target.to_string(),
            reason: "target must not be empty".to_string(),
        });
    }
    let path = Path::new(target);
    if !path.is_absolute() {
        return Err(DockerSecurityError::InvalidMountTarget {
            target: target.to_string(),
            reason: "target must be absolute".to_string(),
        });
    }
    reject_parent_components(path).map_err(|reason| DockerSecurityError::InvalidMountTarget {
        target: target.to_string(),
        reason,
    })?;
    let path = normalize_path(path);
    reject_forbidden_path(&path).map_err(|error| match error {
        DockerSecurityError::ForbiddenMount { path } => {
            DockerSecurityError::ForbiddenMountTarget { target: path }
        }
        error => error,
    })
}

fn validate_extra_mount_target(target: &str) -> Result<(), DockerSecurityError> {
    let target = target.trim();
    if ALLOWED_EXTRA_MOUNT_TARGETS.contains(&target) {
        return Ok(());
    }
    validate_mount_target(target)
}

fn reject_forbidden_path(path: &Path) -> Result<(), DockerSecurityError> {
    let path = normalize_path(path);
    for forbidden in FORBIDDEN_MOUNT_PREFIXES {
        let forbidden = Path::new(forbidden);
        let forbidden_root = forbidden == Path::new("/");
        if path == forbidden || (!forbidden_root && path.starts_with(forbidden)) {
            return Err(DockerSecurityError::ForbiddenMount {
                path: path.display().to_string(),
            });
        }
    }
    Ok(())
}

fn canonicalize_existing_prefix(path: &Path) -> Result<PathBuf, String> {
    if let Ok(canonical) = fs::canonicalize(path) {
        return Ok(normalize_path(&canonical));
    }

    for ancestor in path.ancestors().skip(1) {
        if !ancestor.exists() {
            continue;
        }
        let canonical = fs::canonicalize(ancestor)
            .map_err(|error| format!("failed to canonicalize existing ancestor: {error}"))?;
        let suffix = path
            .strip_prefix(ancestor)
            .map_err(|error| format!("failed to validate path suffix: {error}"))?;
        let mut resolved = canonical;
        for component in suffix.components() {
            match component {
                Component::Normal(value) => resolved.push(value),
                Component::CurDir => {}
                _ => return Err("source contains unsupported path components".to_string()),
            }
        }
        return Ok(normalize_path(&resolved));
    }

    Err("source has no canonicalizable ancestor".to_string())
}

fn reject_parent_components(path: &Path) -> Result<(), String> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("path must not contain parent directory components".to_string());
    }
    Ok(())
}

fn normalize_path(path: &Path) -> PathBuf {
    path.components().collect()
}

fn non_empty_string(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn push_security_opt(security_opts: &mut Vec<String>, value: String) {
    if !security_opts.iter().any(|existing| existing == &value) {
        security_opts.push(value);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DockerSecurityError {
    #[error("refusing forbidden host mount: {path}")]
    ForbiddenMount { path: String },
    #[error("refusing forbidden container mount target: {target}")]
    ForbiddenMountTarget { target: String },
    #[error("invalid host mount source {path}: {reason}")]
    InvalidMountSource { path: String, reason: String },
    #[error("invalid container mount target {target}: {reason}")]
    InvalidMountTarget { target: String, reason: String },
    #[error("invalid or incomplete local socket bridge configuration")]
    InvalidSocketBridge,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{runtime::docker::DockerEnv, shared::protocol::Protocol};
    use secrecy::SecretString;

    #[test]
    fn applies_hardening_defaults() {
        let mut host_config = HostConfig::default();

        DockerSecurityPolicy::default().apply(&mut host_config);

        assert_eq!(host_config.privileged, Some(false));
        assert_eq!(
            host_config.security_opt,
            Some(vec!["no-new-privileges".to_string()])
        );
        assert_eq!(host_config.cap_drop, Some(vec!["ALL".to_string()]));
        assert_eq!(host_config.pids_limit, Some(512));
    }

    #[test]
    fn applies_configured_container_security_options() {
        let mut host_config = HostConfig::default();
        let policy = DockerSecurityPolicy {
            read_only_rootfs: true,
            userns_mode: Some("private".to_string()),
            seccomp_profile: Some("/etc/docker/seccomp-dbe.json".to_string()),
            apparmor_profile: Some("docker-default".to_string()),
            security_opts: vec!["label=disable".to_string()],
            ..Default::default()
        };

        policy.apply(&mut host_config);

        assert_eq!(host_config.readonly_rootfs, Some(true));
        assert_eq!(host_config.userns_mode, Some("private".to_string()));
        assert_eq!(
            host_config.security_opt,
            Some(vec![
                "label=disable".to_string(),
                "no-new-privileges".to_string(),
                "seccomp=/etc/docker/seccomp-dbe.json".to_string(),
                "apparmor=docker-default".to_string(),
            ])
        );
    }

    #[test]
    fn rejects_docker_socket_mount() {
        let mut spec = test_spec();
        spec.data_path = PathBuf::from("/var/run/docker.sock");

        let error = DockerSecurityPolicy::default()
            .validate_spec(&spec)
            .unwrap_err();

        assert!(matches!(error, DockerSecurityError::ForbiddenMount { .. }));
    }

    #[test]
    fn rejects_forbidden_extra_mount_source() {
        let mut spec = test_spec();
        spec.extra_mounts.push(super::super::DockerMount {
            source: PathBuf::from("/etc"),
            target: "/mnt/config".to_string(),
            read_only: true,
        });

        let error = DockerSecurityPolicy::default()
            .validate_spec(&spec)
            .unwrap_err();

        assert!(matches!(error, DockerSecurityError::ForbiddenMount { .. }));
    }

    #[test]
    fn rejects_relative_extra_mount_target() {
        let mut spec = test_spec();
        spec.extra_mounts.push(super::super::DockerMount {
            source: PathBuf::from("/tmp"),
            target: "relative".to_string(),
            read_only: true,
        });

        let error = DockerSecurityPolicy::default()
            .validate_spec(&spec)
            .unwrap_err();

        assert!(matches!(
            error,
            DockerSecurityError::InvalidMountTarget { .. }
        ));
    }

    #[test]
    fn rejects_forbidden_extra_mount_target() {
        let mut spec = test_spec();
        spec.extra_mounts.push(super::super::DockerMount {
            source: PathBuf::from("/tmp"),
            target: "/etc/database".to_string(),
            read_only: true,
        });

        let error = DockerSecurityPolicy::default()
            .validate_spec(&spec)
            .unwrap_err();

        assert!(matches!(
            error,
            DockerSecurityError::ForbiddenMountTarget { .. }
        ));
    }

    #[test]
    fn allows_clickhouse_hosted_config_extra_mount_target() {
        let tempdir = tempfile::tempdir().unwrap();
        let source = tempdir.path().join("dbe-hosted-overrides.xml");
        std::fs::write(&source, "<clickhouse/>").unwrap();
        let mut spec = test_spec();
        spec.extra_mounts.push(super::super::DockerMount {
            source,
            target: "/etc/clickhouse-server/config.d/dbe-hosted-overrides.xml".to_string(),
            read_only: true,
        });

        DockerSecurityPolicy::default()
            .validate_spec(&spec)
            .unwrap();
    }

    #[test]
    fn socket_bridge_requires_tcp_only_protocol_and_both_private_mounts() {
        let mut spec = test_spec();
        spec.socket_bridges
            .push(crate::runtime::socket_bridge::SocketBridge {
                socket_path: "/run/dbev/native.sock".to_string(),
                target: crate::runtime::socket_bridge::loopback_target(9000),
            });

        assert!(matches!(
            DockerSecurityPolicy::default().validate_spec(&spec),
            Err(DockerSecurityError::InvalidSocketBridge)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_extra_mount_source_symlink_to_forbidden_path() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().unwrap();
        let link = tempdir.path().join("etc-link");
        symlink("/etc", &link).unwrap();
        let mut spec = test_spec();
        spec.extra_mounts.push(super::super::DockerMount {
            source: link,
            target: "/mnt/config".to_string(),
            read_only: true,
        });

        let error = DockerSecurityPolicy::default()
            .validate_spec(&spec)
            .unwrap_err();

        assert!(matches!(error, DockerSecurityError::ForbiddenMount { .. }));
    }

    fn test_spec() -> DockerInstanceSpec {
        DockerInstanceSpec {
            instance_id: "inst_abc".to_string(),
            protocol: Protocol::Postgres,
            image: "postgres:18.4".to_string(),
            project_id: None,
            user: None,
            working_dir: None,
            entrypoint: None,
            cpu_cores: 1.0,
            memory_mib: 512,
            disk_mib: 10240,
            pids_limit: None,
            data_path: PathBuf::from("/var/lib/databases-everywhere/instances/inst_abc/data"),
            data_target: "/var/lib/postgresql".to_string(),
            logs_path: PathBuf::from("/var/log/databases-everywhere/instances/inst_abc"),
            logs_target: "/logs".to_string(),
            extra_mounts: Vec::new(),
            socket_bridges: Vec::new(),
            env: vec![DockerEnv {
                key: "POSTGRES_PASSWORD".to_string(),
                value: SecretString::from("secret"),
            }],
            command: Vec::new(),
        }
    }
}
