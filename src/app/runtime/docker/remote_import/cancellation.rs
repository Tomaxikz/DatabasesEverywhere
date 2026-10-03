use super::*;

#[derive(Default)]
pub(super) struct HelperCancellation {
    cancelled: AtomicBool,
    notified: Notify,
}

impl HelperCancellation {
    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notified.notify_waiters();
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub(super) async fn cancelled(&self) {
        loop {
            let notified = self.notified.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

pub(super) struct CancelHelperOnDrop {
    cancellation: Arc<HelperCancellation>,
    armed: bool,
}

impl CancelHelperOnDrop {
    pub(super) fn new(cancellation: Arc<HelperCancellation>) -> Self {
        Self {
            cancellation,
            armed: true,
        }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelHelperOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.cancel();
        }
    }
}

pub(super) struct RemoteImportHelperCleanupGuard {
    docker: Docker,
    name: String,
    armed: bool,
}

impl RemoteImportHelperCleanupGuard {
    pub(super) fn new(docker: Docker, name: String) -> Self {
        Self {
            docker,
            name,
            armed: true,
        }
    }

    pub(super) async fn cleanup(&mut self) -> Result<(), DockerError> {
        let result = remove_import_helper(&self.docker, &self.name).await;
        if result.is_ok() {
            self.armed = false;
        }
        result
    }
}

impl Drop for RemoteImportHelperCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let docker = self.docker.clone();
        let name = self.name.clone();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::error!(
                helper = %name,
                "remote import helper cleanup could not be scheduled; startup reconciliation will retry it"
            );
            return;
        };
        runtime.spawn(async move {
            if let Err(error) = remove_import_helper(&docker, &name).await {
                tracing::error!(
                    helper = %name,
                    error = %error,
                    "remote import helper cleanup failed; startup reconciliation will retry it"
                );
            }
        });
    }
}
