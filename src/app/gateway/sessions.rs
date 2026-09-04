use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::Context,
    time::Duration,
};

use futures::task::AtomicWaker;
use tokio::sync::Notify;

#[derive(Debug, Default)]
struct SessionState {
    authenticated: AtomicBool,
    cancelled: AtomicBool,
    waker: AtomicWaker,
}

impl SessionState {
    fn poll_cancelled(&self, context: &Context<'_>) -> bool {
        if self.cancelled.load(Ordering::Acquire) {
            return true;
        }
        self.waker.register(context.waker());
        self.cancelled.load(Ordering::Acquire)
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.waker.wake();
    }
}

#[derive(Debug, Default)]
struct TenantEntry {
    sessions: HashMap<u64, Weak<SessionState>>,
    drained: Arc<Notify>,
    buffers: super::buffers::QueryBudget,
}

#[derive(Debug, Default)]
struct RegistryState {
    tenants: HashMap<String, TenantEntry>,
}

/// Tracks live gateway sessions by logical tenant rather than physical engine.
///
/// Shared-instance lifecycle operations use this registry to close only the
/// selected tenant's sockets. A pool container is never stopped merely to
/// disconnect one tenant.
#[derive(Debug, Clone, Default)]
pub struct TenantSessions {
    state: Arc<Mutex<RegistryState>>,
    next_id: Arc<AtomicU64>,
}

impl TenantSessions {
    #[cfg(test)]
    pub(crate) fn open(&self, instance_id: &str) -> TenantSession {
        self.try_open(instance_id, None)
            .expect("an unlimited tenant session cannot be rejected")
    }

    pub(crate) fn try_open(
        &self,
        instance_id: &str,
        limit: Option<usize>,
    ) -> Result<TenantSession, TenantSessionLimit> {
        self.insert(instance_id, limit, true)
    }

    pub(crate) fn open_pending(&self, instance_id: &str) -> TenantSession {
        self.insert(instance_id, None, false)
            .expect("pending sessions have no tenant quota")
    }

    fn insert(
        &self,
        instance_id: &str,
        limit: Option<usize>,
        authenticated: bool,
    ) -> Result<TenantSession, TenantSessionLimit> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let session = Arc::new(SessionState::default());
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.tenants.entry(instance_id.to_string()).or_default();
        entry
            .sessions
            .retain(|_, session| session.strong_count() > 0);
        if limit.is_some_and(|limit| authenticated_count(entry) >= limit) {
            return Err(TenantSessionLimit {
                instance_id: instance_id.to_string(),
                limit: limit.unwrap_or_default(),
            });
        }
        entry.sessions.insert(id, Arc::downgrade(&session));
        session
            .authenticated
            .store(authenticated, Ordering::Release);
        Ok(TenantSession {
            instance_id: instance_id.to_string(),
            id,
            session,
            registry: Arc::downgrade(&self.state),
            buffers: entry.buffers.clone(),
        })
    }

    /// Cancels every live gateway socket for one tenant. New sessions are not
    /// affected; callers must fence the tenant route before invoking this.
    pub fn cancel(&self, instance_id: &str) -> usize {
        let sessions = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            let Some(entry) = state.tenants.get_mut(instance_id) else {
                return 0;
            };
            entry
                .sessions
                .retain(|_, session| session.strong_count() > 0);
            entry
                .sessions
                .values()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>()
        };
        for session in &sessions {
            session.cancel();
        }
        sessions.len()
    }

    pub fn active(&self, instance_id: &str) -> usize {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let Some(entry) = state.tenants.get_mut(instance_id) else {
            return 0;
        };
        entry
            .sessions
            .retain(|_, session| session.strong_count() > 0);
        entry.sessions.len()
    }

    pub async fn cancel_and_wait(&self, instance_id: &str, timeout: Duration) -> bool {
        self.cancel(instance_id);
        let drained = {
            let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state
                .tenants
                .get(instance_id)
                .map(|entry| Arc::clone(&entry.drained))
        };
        let Some(drained) = drained else {
            return true;
        };
        tokio::time::timeout(timeout, async {
            loop {
                let notified = drained.notified();
                if self.active(instance_id) == 0 {
                    return;
                }
                notified.await;
            }
        })
        .await
        .is_ok()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("tenant {instance_id} has reached its {limit}-connection gateway limit")]
pub(crate) struct TenantSessionLimit {
    instance_id: String,
    limit: usize,
}

#[derive(Debug)]
pub(crate) struct TenantSession {
    instance_id: String,
    id: u64,
    session: Arc<SessionState>,
    registry: Weak<Mutex<RegistryState>>,
    buffers: super::buffers::QueryBudget,
}

fn authenticated_count(entry: &TenantEntry) -> usize {
    entry
        .sessions
        .values()
        .filter_map(Weak::upgrade)
        .filter(|session| session.authenticated.load(Ordering::Acquire))
        .count()
}

impl TenantSession {
    pub(crate) fn query_budget(&self) -> super::buffers::QueryBudget {
        self.buffers.clone()
    }

    pub(crate) fn authenticate(&self, limit: Option<usize>) -> std::io::Result<()> {
        let aborted = || {
            std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "tenant session is no longer active",
            )
        };
        let registry = self.registry.upgrade().ok_or_else(aborted)?;
        let state = registry.lock().unwrap_or_else(|error| error.into_inner());
        let entry = state.tenants.get(&self.instance_id).ok_or_else(aborted)?;
        if self.session.cancelled.load(Ordering::Acquire) {
            return Err(aborted());
        }
        if self.session.authenticated.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Some(limit) = limit.filter(|limit| authenticated_count(entry) >= *limit) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                TenantSessionLimit {
                    instance_id: self.instance_id.clone(),
                    limit,
                },
            ));
        }
        self.session.authenticated.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) fn poll_cancelled(&self, context: &Context<'_>) -> bool {
        self.session.poll_cancelled(context)
    }
}

impl Drop for TenantSession {
    fn drop(&mut self) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        let mut state = registry.lock().unwrap_or_else(|error| error.into_inner());
        let Some(entry) = state.tenants.get_mut(&self.instance_id) else {
            return;
        };
        entry.sessions.remove(&self.id);
        entry.drained.notify_waiters();
        if entry.sessions.is_empty() {
            state.tenants.remove(&self.instance_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::task::{RawWaker, RawWakerVTable, Waker};

    use super::*;

    fn no_op_waker() -> Waker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        unsafe fn no_op(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        // SAFETY: every vtable function accepts the same null data pointer and
        // performs no dereference.
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    #[tokio::test]
    async fn cancelling_one_tenant_leaves_other_sessions_live() {
        let registry = TenantSessions::default();
        let tenant_a = registry.open("tenant-a");
        let tenant_b = registry.open("tenant-b");
        let waker = no_op_waker();
        let context = Context::from_waker(&waker);

        assert_eq!(registry.cancel("tenant-a"), 1);
        assert!(tenant_a.poll_cancelled(&context));
        assert!(!tenant_b.poll_cancelled(&context));
        assert_eq!(registry.active("tenant-b"), 1);
    }

    #[tokio::test]
    async fn cancel_wait_observes_session_drop() {
        let registry = TenantSessions::default();
        let session = registry.open("tenant");
        let waiting = tokio::spawn({
            let registry = registry.clone();
            async move {
                registry
                    .cancel_and_wait("tenant", Duration::from_secs(1))
                    .await
            }
        });
        tokio::task::yield_now().await;
        drop(session);
        assert!(waiting.await.unwrap());
    }

    #[test]
    fn connection_limit_is_atomic_and_tenant_scoped() {
        let registry = TenantSessions::default();
        let first = registry.try_open("tenant-a", Some(1)).unwrap();

        assert!(registry.try_open("tenant-a", Some(1)).is_err());
        assert!(registry.try_open("tenant-b", Some(1)).is_ok());
        drop(first);
        assert!(registry.try_open("tenant-a", Some(1)).is_ok());
    }

    #[tokio::test]
    async fn pending_sessions_do_not_spend_quota_but_remain_cancellable() {
        let registry = TenantSessions::default();
        let pending = registry.open_pending("tenant");
        let active = registry.try_open("tenant", Some(1)).unwrap();
        assert!(pending.authenticate(Some(1)).is_err());
        drop(active);
        pending.authenticate(Some(1)).unwrap();
        assert!(registry.try_open("tenant", Some(1)).is_err());
        drop(pending);

        let pending = registry.open_pending("tenant");
        assert!(
            !registry
                .cancel_and_wait("tenant", Duration::from_millis(1))
                .await
        );
        assert!(pending.authenticate(Some(1)).is_err());
        drop(pending);
        assert!(
            registry
                .cancel_and_wait("tenant", Duration::from_millis(1))
                .await
        );
    }

    #[test]
    fn sessions_share_only_their_own_tenant_buffer_budget() {
        let registry = TenantSessions::default();
        let first = registry.open("tenant-a");
        let second = registry.open("tenant-a");
        let other = registry.open("tenant-b");
        let reserved = first.query_budget().reserve(32 * 1024 * 1024).unwrap();
        assert!(second.query_budget().reserve(1).is_err());
        assert!(other.query_budget().reserve(1).is_ok());
        drop(reserved);
        assert!(second.query_budget().reserve(1).is_ok());
    }
}
