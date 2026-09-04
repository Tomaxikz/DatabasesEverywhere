use std::{io, sync::Arc};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, SemaphorePermit};

// Shared SQL inspection must buffer a complete command. Bound the combined
// allocations, not just individual packets or the number of connections.
const TENANT_BYTES: usize = 32 * 1024 * 1024;
static GLOBAL_BYTES: Semaphore = Semaphore::const_new(256 * 1024 * 1024);

#[derive(Debug, Clone)]
pub(crate) struct QueryBudget(Arc<Semaphore>);

impl Default for QueryBudget {
    fn default() -> Self {
        Self(Arc::new(Semaphore::new(TENANT_BYTES)))
    }
}

pub(crate) struct QueryReservation {
    _tenant: OwnedSemaphorePermit,
    _global: SemaphorePermit<'static>,
}

impl QueryBudget {
    pub(crate) fn reserve(&self, bytes: usize) -> io::Result<QueryReservation> {
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
        let global = GLOBAL_BYTES.try_acquire_many(bytes).map_err(|_| full())?;
        Ok(QueryReservation {
            _tenant: tenant,
            _global: global,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_are_shared_and_released() {
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
        // Reserve permits only; this test never allocates a query buffer.
        let budget = QueryBudget(Arc::new(Semaphore::new(300 * 1024 * 1024)));
        assert!(budget.reserve(300 * 1024 * 1024).is_err());
        assert_eq!(budget.0.available_permits(), 300 * 1024 * 1024);
    }
}
