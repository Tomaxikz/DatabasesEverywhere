use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Semaphore;

use super::validate::ConfigValidationError;

#[derive(Debug)]
pub(crate) struct SharedBudgets {
    pub gateway_handshakes: Arc<Semaphore>,
    pub backup_materializations: Arc<Semaphore>,
}

/// Node admission controls. Scope is retained by each consumer; restart required.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeLimits {
    pub gateway_connections_per_peer: usize,
    pub gateway_connections_per_listener: usize,
    pub gateway_handshakes: usize,
    pub api_connections: usize,
    pub api_connections_per_peer: usize,
    pub api_requests: usize,
    pub api_heartbeat_requests: usize,
    pub api_websockets: usize,
    pub instance_creations: usize,
    pub upload_inspections: usize,
    pub backup_materializations: usize,
    pub recovery_volume_entries: usize,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            gateway_connections_per_peer: 64,
            gateway_connections_per_listener: 1024,
            gateway_handshakes: 256,
            api_connections: 2048,
            api_connections_per_peer: 256,
            api_requests: 1024,
            api_heartbeat_requests: 16,
            api_websockets: 1024,
            instance_creations: 64,
            upload_inspections: 2,
            backup_materializations: 8,
            recovery_volume_entries: 4096,
        }
    }
}

impl RuntimeLimits {
    /// Called after validation by RuntimeConfig, once per daemon run.
    pub(crate) fn shared_budgets(&self) -> SharedBudgets {
        SharedBudgets {
            gateway_handshakes: Arc::new(Semaphore::new(self.gateway_handshakes)),
            backup_materializations: Arc::new(Semaphore::new(self.backup_materializations)),
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigValidationError> {
        let maximum = tokio::sync::Semaphore::MAX_PERMITS.min(u32::MAX as usize) as u64;
        for (field, value) in [
            (
                "limits.gateway_connections_per_peer",
                self.gateway_connections_per_peer,
            ),
            (
                "limits.gateway_connections_per_listener",
                self.gateway_connections_per_listener,
            ),
            ("limits.gateway_handshakes", self.gateway_handshakes),
            ("limits.api_connections", self.api_connections),
            (
                "limits.api_connections_per_peer",
                self.api_connections_per_peer,
            ),
            ("limits.api_requests", self.api_requests),
            ("limits.api_heartbeat_requests", self.api_heartbeat_requests),
            ("limits.api_websockets", self.api_websockets),
            ("limits.instance_creations", self.instance_creations),
            ("limits.upload_inspections", self.upload_inspections),
            (
                "limits.backup_materializations",
                self.backup_materializations,
            ),
            (
                "limits.recovery_volume_entries",
                self.recovery_volume_entries,
            ),
        ] {
            if value == 0 || value as u64 > maximum {
                return Err(ConfigValidationError::InvalidDaemonLimit { field, maximum });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_preserve_existing_capacity() {
        let expected = serde_json::json!({
            "gateway_connections_per_peer": 64, "gateway_connections_per_listener": 1024,
            "gateway_handshakes": 256, "api_connections": 2048, "api_connections_per_peer": 256,
            "api_requests": 1024, "api_heartbeat_requests": 16, "api_websockets": 1024,
            "instance_creations": 64, "upload_inspections": 2, "backup_materializations": 8,
            "recovery_volume_entries": 4096
        });
        assert_eq!(
            serde_json::to_value(RuntimeLimits::default()).unwrap(),
            expected
        );
    }

    #[test]
    fn every_limit_rejects_zero_and_overflow() {
        let defaults = serde_json::to_value(RuntimeLimits::default()).unwrap();
        for name in defaults.as_object().unwrap().keys() {
            for value in [0, u32::MAX as u64 + 1] {
                let mut invalid = defaults.clone();
                invalid[name] = value.into();
                let limits: RuntimeLimits = serde_json::from_value(invalid).unwrap();
                let mut settings = super::super::Config::default();
                settings.daemon.limits = limits;
                let error = super::super::RuntimeConfig::new(settings).unwrap_err();
                assert!(error.to_string().contains(name));
            }
        }
    }

    #[test]
    fn partial_yaml_preserves_defaults_and_builds_shared_budgets() {
        let config: super::super::Config = yaml_serde::from_str(
            "daemon:\n  limits:\n    gateway_handshakes: 2\n    backup_materializations: 3\n",
        )
        .unwrap();
        assert_eq!(config.daemon.sql_buffer_global_mib, 1024);
        assert_eq!(config.daemon.limits.api_connections, 2048);
        let runtime = std::sync::Arc::new(super::super::RuntimeConfig::new(config).unwrap());
        let other = std::sync::Arc::clone(&runtime);
        let handshakes = runtime
            .budgets
            .gateway_handshakes
            .try_acquire_many(2)
            .unwrap();
        assert!(other.budgets.gateway_handshakes.try_acquire().is_err());
        let backups = runtime
            .budgets
            .backup_materializations
            .try_acquire_many(3)
            .unwrap();
        assert!(other.budgets.backup_materializations.try_acquire().is_err());
        drop((handshakes, backups));
        assert_eq!(other.budgets.gateway_handshakes.available_permits(), 2);
        assert_eq!(other.budgets.backup_materializations.available_permits(), 3);
    }
}
