use crate::{
    compatibility::{
        COMPATIBILITY_PROBE_REVISION, compatibility_profile, database_version_script,
        normalize_database_version,
    },
    config::Config,
    disk::DiskLimiter,
    instances::paths::InstancePaths,
    placement::{EngineRuntime, PlacementRepository, RuntimeCompatibility},
    runtime::docker::DockerRuntime,
};

const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeProbe {
    pub version: String,
    pub compatibility: RuntimeCompatibility,
}

/// Attests one physical shared engine. The identity is checked on both sides
/// of the command so a concurrent reconstruction cannot attach a result to a
/// different container or image.
pub(crate) async fn probe_compatibility(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
) -> Result<RuntimeProbe, String> {
    let before = docker
        .verified_compatibility_identity(runtime.protocol, &runtime.runtime_id)
        .await
        .map_err(|error| format!("runtime identity inspection failed: {error}"))?
        .ok_or_else(|| "shared runtime disappeared before probing".to_string())?;
    let output = docker
        .exec_shell_with_timeout(
            runtime.protocol,
            &runtime.runtime_id,
            database_version_script(runtime.protocol),
            PROBE_TIMEOUT,
        )
        .await
        .map_err(|error| format!("database version probe failed: {error}"))?;
    let version = normalize_database_version(runtime.protocol, &output.stdout)
        .ok_or_else(|| "database version could not be parsed".to_string())?;
    compatibility_profile(runtime.protocol, &version).map_err(|error| error.to_string())?;
    let after = docker
        .verified_compatibility_identity(runtime.protocol, &runtime.runtime_id)
        .await
        .map_err(|error| format!("runtime identity inspection failed: {error}"))?
        .ok_or_else(|| "shared runtime disappeared after probing".to_string())?;
    if before != after {
        return Err("shared runtime changed during its compatibility probe".to_string());
    }
    Ok(RuntimeProbe {
        version,
        compatibility: RuntimeCompatibility {
            container_id: after.id,
            image_id: after.image_id,
            probe_revision: COMPATIBILITY_PROBE_REVISION,
        },
    })
}

/// Applies aggregate CPU/memory reservations and the derived root disk charge
/// to one physical shared engine. Tenant handlers must never call Docker limit
/// APIs with a tenant id.
pub(crate) async fn apply_limits(
    docker: &DockerRuntime,
    config: &Config,
    placements: &PlacementRepository,
    runtime: &EngineRuntime,
) -> Result<(), String> {
    docker
        .update_limits(
            runtime.protocol,
            &runtime.runtime_id,
            runtime.limits.cpu_cores,
            runtime.limits.memory_mib,
        )
        .await
        .map_err(|error| format!("runtime CPU/memory update failed: {error}"))?;

    apply_root_disk_limit(config, placements, runtime).await?;
    Ok(())
}

/// Applies only the part of the shared engine's disk budget still charged to
/// its root project. Hard tenant child projects carry their own limits and
/// must not be counted a second time at the root.
pub(crate) async fn apply_root_disk_limit(
    config: &Config,
    placements: &PlacementRepository,
    runtime: &EngineRuntime,
) -> Result<u64, String> {
    let root_disk_mib = placements
        .root_charged_disk_mib(&runtime.runtime_id)
        .await
        .map_err(|error| format!("runtime root disk capacity lookup failed: {error}"))?;
    let paths = InstancePaths::new(&config.paths, &runtime.runtime_id)
        .map_err(|error| format!("runtime paths are invalid: {error}"))?;
    DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root())
        .for_persisted_protocol(runtime.protocol, &runtime.limits.disk_enforcement_method)
        .update_shared_pool_limit(&runtime.runtime_id, &paths.data, root_disk_mib)
        .await
        .map_err(|error| format!("runtime disk update failed: {error}"))?;
    Ok(root_disk_mib)
}
