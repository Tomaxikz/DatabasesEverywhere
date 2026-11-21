use std::{io, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::RuntimeConfig;

// Shared SQL inspection must buffer a complete command. Bound the combined
// allocations, not just individual packets or the number of connections.
const TENANT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct QueryBudget {
    tenant: Arc<Semaphore>,
    global: Arc<Semaphore>,
}

#[cfg(test)]
impl Default for QueryBudget {
    fn default() -> Self {
        Self::new(&RuntimeConfig::default())
    }
}

pub(crate) struct QueryReservation {
    _tenant: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

impl QueryBudget {
    pub(crate) fn new(config: &RuntimeConfig) -> Self {
        Self {
            tenant: Arc::new(Semaphore::new(TENANT_BYTES)),
            global: Arc::clone(&config.sql_buffer_budget),
        }
    }

    pub(crate) fn reserve(&self, bytes: usize) -> io::Result<QueryReservation> {
        let full = || {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "shared SQL buffer capacity reached",
            )
        };
        let bytes = u32::try_from(bytes).map_err(|_| full())?;
        let tenant = Arc::clone(&self.tenant)
            .try_acquire_many_owned(bytes)
            .map_err(|_| full())?;
        let global = Arc::clone(&self.global)
            .try_acquire_many_owned(bytes)
            .map_err(|_| full())?;
        Ok(QueryReservation {
            _tenant: tenant,
            _global: global,
        })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context as _;

    use super::*;

    #[test]
    fn reservations_are_shared_and_released() -> anyhow::Result<()> {
        let budget = QueryBudget {
            tenant: Arc::new(Semaphore::new(8)),
            global: Arc::new(Semaphore::new(16)),
        };
        let other_connection = budget.clone();
        let reserved = budget.reserve(6)?;
        assert!(other_connection.reserve(3).is_err());
        drop(reserved);
        assert!(other_connection.reserve(8).is_ok());
        assert_eq!(budget.tenant.available_permits(), 8);
        assert_eq!(budget.global.available_permits(), 16);

        Ok(())
    }

    #[test]
    fn global_rejection_releases_tenant_reservation() -> anyhow::Result<()> {
        let budget = QueryBudget {
            tenant: Arc::new(Semaphore::new(8)),
            global: Arc::new(Semaphore::new(4)),
        };
        assert_eq!(
            budget
                .reserve(6)
                .err()
                .context("err should provide a value")?
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(budget.tenant.available_permits(), 8);
        assert_eq!(budget.global.available_permits(), 4);

        Ok(())
    }

    #[test]
    fn tenants_share_the_configured_global_capacity() -> anyhow::Result<()> {
        let settings = crate::config::Config {
            daemon: crate::config::DaemonConfig {
                sql_buffer_global_mib: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let config = RuntimeConfig::new(settings)?;
        let first = QueryBudget::new(&config);
        let second = QueryBudget::new(&config);
        let reservation = first.reserve(1024 * 1024)?;
        assert_eq!(
            second
                .reserve(1)
                .err()
                .context("err should provide a value")?
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(second.tenant.available_permits(), TENANT_BYTES);
        drop(reservation);
        assert!(second.reserve(1024 * 1024).is_ok());

        Ok(())
    }

    #[test]
    fn independent_runtime_configs_do_not_share_capacity() -> anyhow::Result<()> {
        let settings = crate::config::Config {
            daemon: crate::config::DaemonConfig {
                sql_buffer_global_mib: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let first = QueryBudget::new(&RuntimeConfig::new(settings.clone())?);
        let second = QueryBudget::new(&RuntimeConfig::new(settings)?);
        let _first = first.reserve(1024 * 1024)?;
        assert!(second.reserve(1024 * 1024).is_ok());

        Ok(())
    }
}
