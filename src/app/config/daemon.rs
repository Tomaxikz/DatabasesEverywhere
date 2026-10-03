use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonConfig {
    pub limits: RuntimeLimits,
    /// Ignored legacy setting. Boot recovery discovers failed/quarantined pools.
    #[serde(skip_serializing)]
    pub recover_shared_pools: Vec<String>,
    pub engine: DaemonEngine,
    pub socket_path: String,
    pub container_read_only_rootfs: bool,
    pub container_userns_mode: String,
    pub container_seccomp_profile: String,
    pub container_apparmor_profile: String,
    pub container_security_opts: Vec<String>,
    /// Process-wide shared SQL buffer capacity in MiB; restart required.
    pub sql_buffer_global_mib: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            limits: RuntimeLimits::default(),
            recover_shared_pools: Vec::new(),
            engine: DaemonEngine::Docker,
            socket_path: String::new(),
            container_read_only_rootfs: false,
            container_userns_mode: String::new(),
            container_seccomp_profile: String::new(),
            container_apparmor_profile: String::new(),
            container_security_opts: Vec::new(),
            sql_buffer_global_mib: 1024,
        }
    }
}

impl DaemonConfig {
    pub(crate) fn validate_runtime_limits(&self) -> Result<(), validate::ConfigValidationError> {
        self.limits.validate()?;
        self.sql_buffer_global_bytes()?;
        Ok(())
    }

    pub(crate) fn sql_buffer_global_bytes(&self) -> Result<usize, validate::ConfigValidationError> {
        self.sql_buffer_global_mib
            .checked_mul(1024 * 1024)
            .and_then(|bytes| usize::try_from(bytes).ok())
            .filter(|bytes| *bytes > 0 && *bytes <= tokio::sync::Semaphore::MAX_PERMITS)
            .ok_or(validate::ConfigValidationError::InvalidDaemonLimit {
                field: "sql_buffer_global_mib",
                maximum: (tokio::sync::Semaphore::MAX_PERMITS / (1024 * 1024)) as u64,
            })
    }

    pub fn configured_socket_path(&self) -> Option<&str> {
        let socket_path = self.socket_path.trim();
        if socket_path.is_empty() {
            None
        } else {
            Some(socket_path)
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonEngine {
    #[default]
    Docker,
    Podman,
}

impl DaemonEngine {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}
