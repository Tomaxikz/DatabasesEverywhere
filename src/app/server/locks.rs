use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};

use tokio::sync::{Mutex, OwnedMutexGuard};

#[derive(Debug, Clone, Default)]
pub struct InstanceLocks {
    locks: Arc<Mutex<HashMap<String, Weak<Mutex<()>>>>>,
    creation: Arc<Mutex<()>>,
}

impl InstanceLocks {
    pub async fn lock(&self, instance_id: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().await;
            locks.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = locks.get(instance_id).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(Mutex::new(()));
                locks.insert(instance_id.to_string(), Arc::downgrade(&lock));
                lock
            }
        };
        lock.lock_owned().await
    }

    /// Serializes create-time route checks and reservations across instance IDs.
    pub async fn lock_creation(&self) -> OwnedMutexGuard<()> {
        Arc::clone(&self.creation).lock_owned().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn same_instance_operations_are_serialized() {
        let locks = InstanceLocks::default();
        let first = locks.lock("inst_one").await;
        let contender = tokio::spawn({
            let locks = locks.clone();
            async move { locks.lock("inst_one").await }
        });
        tokio::task::yield_now().await;
        assert!(!contender.is_finished());

        drop(first);
        contender.await.unwrap();
    }

    #[tokio::test]
    async fn different_instances_can_run_concurrently() {
        let locks = InstanceLocks::default();
        let _first = locks.lock("inst_one").await;

        tokio::time::timeout(std::time::Duration::from_secs(1), locks.lock("inst_two"))
            .await
            .unwrap();
    }
}
