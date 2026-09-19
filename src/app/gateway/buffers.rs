use std::{
    io,
    sync::{Arc, OnceLock},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, SemaphorePermit};

// Shared SQL inspection must buffer a complete command. Bound the combined
// allocations, not just individual packets or the number of connections.
const TENANT_BYTES: usize = 32 * 1024 * 1024;
static GLOBAL_BYTES: OnceLock<Semaphore> = OnceLock::new();

/// Called once at daemon startup, before any connection can reserve capacity.
pub(crate) fn initialize_global_budget(bytes: usize) -> io::Result<()> {
    initialize_budget(&GLOBAL_BYTES, bytes)
}

fn initialize_budget(global: &OnceLock<Semaphore>, bytes: usize) -> io::Result<()> {
    if bytes == 0 || bytes > Semaphore::MAX_PERMITS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid global SQL buffer capacity",
        ));
    }

    global.set(Semaphore::new(bytes)).map_err(|_| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "global SQL buffer budget already initialized",
        )
    })
}

#[derive(Debug, Clone)]
pub(crate) struct QueryBudget(Arc<Semaphore>);

impl Default for QueryBudget {
    fn default() -> Self {
        // Unit tests create gateways without running the daemon startup path.
        #[cfg(test)]
        initialize_test_budget();
        Self(Arc::new(Semaphore::new(TENANT_BYTES)))
    }
}

pub(crate) struct QueryReservation {
    _tenant: OwnedSemaphorePermit,
    _global: SemaphorePermit<'static>,
}

impl QueryBudget {
    pub(crate) fn reserve(&self, bytes: usize) -> io::Result<QueryReservation> {
        let semaphore = GLOBAL_BYTES
            .get()
            .ok_or_else(|| io::Error::other("global SQL buffer budget is not initialized"))?;

        let full = || {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "shared SQL buffer capacity reached",
            )
        };
        let bytes = u32::try_from(bytes).map_err(|_| full())?;
        let tenant = self
            .0
            .clone()
            .try_acquire_many_owned(bytes)
            .map_err(|_| full())?;
        let global = semaphore.try_acquire_many(bytes).map_err(|_| full())?;
        Ok(QueryReservation {
            _tenant: tenant,
            _global: global,
        })
    }
}

#[cfg(test)]
fn initialize_test_budget() {
    GLOBAL_BYTES.get_or_init(|| {
        Semaphore::new(
            crate::config::DaemonConfig::default()
                .sql_buffer_global_bytes()
                .unwrap(),
        )
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_are_shared_and_released() {
        initialize_test_budget();
        let budget = QueryBudget(Arc::new(Semaphore::new(8)));
        let other_connection = budget.clone();
        let reserved = budget.reserve(6).unwrap();
        assert!(other_connection.reserve(3).is_err());
        drop(reserved);
        assert!(other_connection.reserve(8).is_ok());
        assert_eq!(budget.0.available_permits(), 8);
    }

    #[test]
    fn global_rejection_releases_tenant_reservation() {
        initialize_test_budget();
        // Reserve permits only; this test never allocates a query buffer.
        let bytes = 1024 * 1024 * 1024 + 1;
        let budget = QueryBudget(Arc::new(Semaphore::new(bytes)));
        assert_eq!(
            budget.reserve(bytes).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(budget.0.available_permits(), bytes);
    }

    #[test]
    fn global_initialization_uses_configured_capacity_and_refuses_reinitialization() {
        let global = OnceLock::new();
        let config: crate::config::DaemonConfig =
            yaml_serde::from_str("sql_buffer_global_mib: 2").unwrap();
        let capacity = config.sql_buffer_global_bytes().unwrap();
        initialize_budget(&global, capacity).unwrap();
        let semaphore = global.get().unwrap();
        let reservation = semaphore.try_acquire_many(capacity as u32).unwrap();
        assert!(semaphore.try_acquire().is_err());
        assert_eq!(
            initialize_budget(&global, capacity * 2).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        drop(reservation);
        assert_eq!(semaphore.available_permits(), 2 * 1024 * 1024);
    }

    #[test]
    fn invalid_capacity_does_not_initialize_the_budget() {
        let global = OnceLock::new();
        for capacity in [0, Semaphore::MAX_PERMITS + 1] {
            assert_eq!(
                initialize_budget(&global, capacity).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert!(global.get().is_none());
        }
    }
}
