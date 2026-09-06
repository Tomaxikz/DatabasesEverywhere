use serde::{Deserialize, Serialize};

use crate::shared::limits::InstanceLimits;

#[derive(Debug, Clone)]
pub(crate) struct PoolSpec {
    pub owner: PoolOwner,
    pub protocol: crate::shared::protocol::Protocol,
    pub image: String,
    pub limits: PoolLimits,
}

/// The panel namespace comes from the authenticated daemon token, never JSON.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolOwner {
    pub panel_id: String,
    pub server_id: String,
}

impl PoolOwner {
    pub fn check(&self) -> Result<(), String> {
        for (name, value) in [("panel_id", &self.panel_id), ("server_id", &self.server_id)] {
            if value.is_empty()
                || value.len() > 128
                || !value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
            {
                return Err(format!(
                    "{name} must be 1-128 ASCII letters, digits, hyphens, dots or underscores"
                ));
            }
        }
        Ok(())
    }
}

/// Fixed physical engine capacity, charged once, not once per database.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolLimits {
    pub cpu_cores: f64,
    pub memory_mib: u64,
    pub disk_mib: u64,
    pub max_tenants: u32,
}

impl PoolLimits {
    pub fn limits(&self) -> InstanceLimits {
        InstanceLimits {
            cpu_cores: self.cpu_cores,
            memory_mib: self.memory_mib,
            disk_mib: self.disk_mib,
            disk_enforced: false,
            disk_enforcement_method: "pending".into(),
        }
    }

    pub fn check(&self) -> Result<(), String> {
        crate::shared::limits::validate_runtime_limits(self.cpu_cores, self.memory_mib)
            .map_err(|error| error.to_string())?;
        if self.disk_mib == 0
            || self.disk_mib > u64::MAX / (1024 * 1024)
            || !(1..=1024).contains(&self.max_tenants)
        {
            return Err("pool disk_mib must be positive and max_tenants must be 1-1024".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_keys_and_capacity_are_bounded() {
        for key in [
            "",
            " server",
            "server/name",
            "server\nname",
            "é",
            &"x".repeat(129),
        ] {
            assert!(
                PoolOwner {
                    panel_id: "panel".into(),
                    server_id: key.into()
                }
                .check()
                .is_err()
            );
        }
        assert!(
            PoolOwner {
                panel_id: "panel-1".into(),
                server_id: "server_2.uuid".into()
            }
            .check()
            .is_ok()
        );
        let valid = PoolLimits {
            cpu_cores: 2.0,
            memory_mib: 2048,
            disk_mib: 16384,
            max_tenants: 32,
        };
        assert!(valid.check().is_ok());
        for cpu in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(
                PoolLimits {
                    cpu_cores: cpu,
                    ..valid.clone()
                }
                .check()
                .is_err()
            );
        }
        assert!(
            PoolLimits {
                disk_mib: u64::MAX,
                ..valid.clone()
            }
            .check()
            .is_err()
        );
        assert!(
            PoolLimits {
                max_tenants: 0,
                ..valid.clone()
            }
            .check()
            .is_err()
        );
        assert!(
            PoolLimits {
                max_tenants: 1025,
                ..valid
            }
            .check()
            .is_err()
        );
    }
}
