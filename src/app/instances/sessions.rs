use std::time::Duration;

use crate::{gateway::sessions::TenantSessions, instances::state::InstanceStore};

/// Removes the tenant from every route index before closing its already-open
/// gateway sockets. The ordering prevents a reconnect from racing the fence.
pub(crate) async fn fence(
    store: &InstanceStore,
    sessions: &TenantSessions,
    instance_id: &str,
) -> bool {
    let fenced = store.fence_routes(instance_id).await;
    if fenced {
        sessions.cancel(instance_id);
    }
    fenced
}

pub(crate) async fn fence_and_wait(
    store: &InstanceStore,
    sessions: &TenantSessions,
    instance_id: &str,
    timeout: Duration,
) -> bool {
    if !store.fence_routes(instance_id).await {
        return false;
    }
    sessions.cancel_and_wait(instance_id, timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_tenant_is_not_reported_as_fenced() {
        let store = InstanceStore::default();
        let sessions = TenantSessions::default();
        assert!(!fence(&store, &sessions, "missing").await);
        assert_eq!(sessions.active("missing"), 0);
    }
}
