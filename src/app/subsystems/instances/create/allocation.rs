use super::*;

pub(crate) async fn enforce_node_allocation_policy(
    state: &AppState,
    requested: &crate::utils::limits::InstanceLimits,
    previous: Option<&crate::utils::limits::InstanceLimits>,
) -> Result<(), ApiError> {
    let previous_cpu_cores = previous.map(|limits| limits.cpu_cores).unwrap_or_default();
    let previous_memory_bytes = previous
        .map(|limits| mib_to_bytes(limits.memory_mib))
        .unwrap_or_default();
    let previous_disk_bytes = previous
        .map(|limits| mib_to_bytes(limits.disk_mib))
        .unwrap_or_default();
    let requested_memory_bytes = mib_to_bytes(requested.memory_mib);
    let requested_disk_bytes = mib_to_bytes(requested.disk_mib);
    let allocation = &state.config.allocation;
    let check_cpu =
        allocation.prevent_cpu_overallocation && requested.cpu_cores > previous_cpu_cores;
    let check_memory =
        allocation.prevent_memory_overallocation && requested_memory_bytes > previous_memory_bytes;
    let check_disk =
        allocation.prevent_disk_overallocation && requested_disk_bytes > previous_disk_bytes;

    // Decreases are always safe, and disabled guards must not retain hidden
    // host-probe failure modes or overhead.
    if !check_cpu && !check_memory && !check_disk {
        return Ok(());
    }

    let runtimes = state.placements.list().await.map_err(|error| {
        ApiError::Runtime(format!("failed to load runtime allocation: {error}"))
    })?;
    let allocated = crate::server::placement::policy::sum_runtime_limits(
        runtimes.iter().map(|runtime| &runtime.limits),
    );
    let volumes_root = state.config.paths.volumes_root();
    let (host_cpu_cores, host_memory, host_disk) = tokio::join!(
        sample_host_if(check_cpu, read_host_cpu_cores()),
        sample_host_if(check_memory, read_host_memory()),
        sample_host_if(check_disk, read_host_disk(&volumes_root)),
    );

    let host_cpu_cores = host_cpu_cores.map_err(|error| host_sample_error("CPU", error))?;
    if let Some(host_cores) = host_cpu_cores {
        enforce_cpu_allocation(
            allocated.cpu_cores,
            previous_cpu_cores,
            requested.cpu_cores,
            host_cores,
        )?;
    }
    let host_memory = host_memory.map_err(|error| host_sample_error("memory", error))?;
    if let Some(host) = host_memory {
        enforce_resource_allocation(
            "memory",
            mib_to_bytes(allocated.memory_mib),
            previous_memory_bytes,
            requested_memory_bytes,
            allocation.memory_allocation_cap_bytes(host.total_bytes),
            host.available_bytes,
            allocation.reserved_memory_bytes(),
        )?;
    }
    let host_disk = host_disk.map_err(|error| host_sample_error("disk", error))?;
    if let Some(host) = host_disk {
        enforce_resource_allocation(
            "disk",
            mib_to_bytes(allocated.disk_mib),
            previous_disk_bytes,
            requested_disk_bytes,
            allocation.disk_allocation_cap_bytes(host.total_bytes),
            host.available_bytes,
            allocation.reserved_disk_bytes(),
        )?;
    }

    Ok(())
}

pub(super) async fn sample_host_if<T>(
    enabled: bool,
    sample: impl Future<Output = Result<T, std::io::Error>>,
) -> Result<Option<T>, std::io::Error> {
    if !enabled {
        return Ok(None);
    }
    sample.await.map(Some)
}

pub(super) fn host_sample_error(resource: &str, error: std::io::Error) -> ApiError {
    ApiError::Runtime(format!(
        "failed to sample host {resource} for allocation admission: {error}"
    ))
}

pub(super) fn enforce_cpu_allocation(
    allocated_cores: f64,
    previous_cores: f64,
    requested_cores: f64,
    host_cores: u64,
) -> Result<(), ApiError> {
    if requested_cores <= previous_cores {
        return Ok(());
    }
    let projected_cores = (allocated_cores - previous_cores).max(0.0) + requested_cores;
    if projected_cores > host_cores as f64 {
        return Err(ApiError::ServiceUnavailable(format!(
            "node CPU allocation capacity exhausted: projected allocation {projected_cores:.2} cores exceeds the detected {host_cores}-core capacity"
        )));
    }
    Ok(())
}

pub(super) fn enforce_resource_allocation(
    resource: &str,
    allocated_bytes: u64,
    previous_bytes: u64,
    requested_bytes: u64,
    allocation_limit_bytes: u64,
    available_bytes: u64,
    reserved_bytes: u64,
) -> Result<(), ApiError> {
    let additional_bytes = requested_bytes.saturating_sub(previous_bytes);
    if additional_bytes == 0 {
        return Ok(());
    }

    let projected_bytes = allocated_bytes
        .saturating_sub(previous_bytes)
        .saturating_add(requested_bytes);
    if projected_bytes > allocation_limit_bytes {
        return Err(allocation_unavailable(
            resource,
            projected_bytes,
            allocation_limit_bytes,
        ));
    }
    if additional_bytes.saturating_add(reserved_bytes) > available_bytes {
        return Err(capacity_unavailable(
            resource,
            additional_bytes,
            available_bytes,
            reserved_bytes,
        ));
    }

    Ok(())
}

pub(super) fn allocation_unavailable(
    resource: &str,
    projected_bytes: u64,
    limit_bytes: u64,
) -> ApiError {
    ApiError::ServiceUnavailable(format!(
        "node {resource} allocation capacity exhausted: projected allocation {} MiB exceeds the {} MiB limit",
        bytes_to_mib_ceil(projected_bytes),
        bytes_to_mib_ceil(limit_bytes),
    ))
}

pub(super) fn capacity_unavailable(
    resource: &str,
    additional_bytes: u64,
    available_bytes: u64,
    reserved_bytes: u64,
) -> ApiError {
    ApiError::ServiceUnavailable(format!(
        "node {resource} safety reserve would be breached: allocation increase requires {} MiB, {} MiB is available, and {} MiB must remain reserved",
        bytes_to_mib_ceil(additional_bytes),
        bytes_to_mib_ceil(available_bytes),
        bytes_to_mib_ceil(reserved_bytes),
    ))
}
