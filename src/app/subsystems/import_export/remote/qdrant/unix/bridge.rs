use super::*;

pub(super) struct QdrantBridge {
    pub(super) cleanup: Option<QdrantBridgeCleanup>,
}

pub(super) struct QdrantBridgeCleanup {
    pub(super) state: AppState,
    pub(super) instance_id: String,
}

pub(crate) async fn cleanup_stale_bridge(
    state: &AppState,
    instance_id: &str,
) -> Result<(), ApiError> {
    tokio::time::timeout(
        CLEANUP_TIMEOUT,
        state
            .docker
            .exec_shell(Protocol::Qdrant, instance_id, &qdrant_bridge_stop_script()),
    )
    .await
    .map_err(|_| {
        ApiError::Runtime("timed out cleaning up a stale managed qdrant HTTP bridge".to_string())
    })?
    .map_err(|error| {
        ApiError::Runtime(format!(
            "failed to clean up a stale managed qdrant HTTP bridge: {error}"
        ))
    })?;
    Ok(())
}

impl QdrantBridge {
    pub(super) async fn start(
        state: &AppState,
        instance_id: &str,
        paths: &InstancePaths,
    ) -> Result<Self, ApiError> {
        // Arm cleanup before the start command is sent. Docker exec can be cancelled after the
        // command has started but before its response arrives, so arming afterward can leak a
        // live bridge and its socket/state artifacts.
        let bridge = Self {
            cleanup: Some(QdrantBridgeCleanup {
                state: state.clone(),
                instance_id: instance_id.to_string(),
            }),
        };
        let start = qdrant_bridge_start_script();
        if let Err(error) = state
            .docker
            .exec_shell(Protocol::Qdrant, instance_id, &start)
            .await
        {
            let error = ApiError::Runtime(format!(
                "failed to start managed qdrant HTTP bridge: {error}"
            ));
            bridge.stop().await;
            return Err(error);
        }
        let host_socket = paths.sockets.join(HOST_BRIDGE_SOCKET_NAME);
        let deadline = tokio::time::Instant::now() + BRIDGE_READY_TIMEOUT;
        loop {
            if tokio::fs::symlink_metadata(&host_socket)
                .await
                .is_ok_and(|metadata| metadata.file_type().is_socket())
            {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                bridge.stop().await;
                return Err(ApiError::Runtime(
                    "managed qdrant HTTP bridge did not become ready".to_string(),
                ));
            }
            tokio::time::sleep(BRIDGE_READY_POLL_INTERVAL).await;
        }
        Ok(bridge)
    }

    pub(super) fn disarm(mut self) {
        self.cleanup.take();
    }

    pub(super) async fn stop(mut self) {
        let Some(cleanup) = self.cleanup.take() else {
            return;
        };
        let instance_id = cleanup.instance_id.clone();

        // Spawn before awaiting so cancellation of the caller cannot cancel cleanup. Taking
        // the payload first disarms Drop and guarantees that cleanup is scheduled once.
        if let Err(error) = tokio::spawn(cleanup.run()).await {
            tracing::warn!(
                instance_id = %instance_id,
                %error,
                "temporary qdrant HTTP bridge cleanup task failed"
            );
        }
    }
}

impl Drop for QdrantBridge {
    fn drop(&mut self) {
        let Some(cleanup) = self.cleanup.take() else {
            return;
        };
        let instance_id = cleanup.instance_id.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let _cleanup_task = handle.spawn(cleanup.run());
            }
            Err(error) => {
                tracing::warn!(
                    instance_id = %instance_id,
                    %error,
                    "could not schedule temporary qdrant HTTP bridge cleanup"
                );
            }
        }
    }
}

impl QdrantBridgeCleanup {
    pub(super) async fn run(self) {
        if let Err(error) = cleanup_stale_bridge(&self.state, &self.instance_id).await {
            tracing::warn!(
                instance_id = self.instance_id,
                %error,
                "failed to stop temporary qdrant HTTP bridge"
            );
        }
    }
}
