use crate::{api::http::state::AppState, disk::DiskLimiter, instances::paths::InstancePaths};

/// Cleanup runs synchronously before routes and background jobs are published.
pub(super) async fn cleanup(state: &AppState) {
    if let Err(error) = cleanup_inner(state).await {
        tracing::warn!(event = "audit fuse_cleanup_deferred", %error,
            "FUSE inventory could not be verified; retained remaining helpers and mounts");
    }
}

async fn cleanup_inner(state: &AppState) -> anyhow::Result<()> {
    let limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
    let mut protected = Vec::new();
    // Even stopped/quarantined owners retain their mounts for a later recovery.
    for metadata in state.instances.list().await {
        let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)?;
        protected.push(limiter.legacy_fuse_container_path(&paths.data)?);
    }
    for runtime in state.placements.list().await? {
        let paths = InstancePaths::new(&state.config.paths, &runtime.runtime_id)?;
        protected.push(limiter.legacy_fuse_container_path(&paths.data)?);
    }
    let summary = crate::disk::cleanup_unused_helpers(
        std::path::Path::new(&state.config.paths.fuse_root()),
        &protected,
        &state.docker,
    )
    .await?;
    tracing::info!(
        event = "fuse_helper_reconciliation",
        checked = summary.checked,
        retained = summary.retained,
        removed = summary.removed,
        deferred = summary.deferred,
        "reconciled FUSE helpers; retained mounts may serve running, stopped, or quarantined databases across daemon restarts"
    );
    Ok(())
}
