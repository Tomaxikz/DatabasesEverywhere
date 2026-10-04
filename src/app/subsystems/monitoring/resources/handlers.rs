use super::RESOURCE_FANOUT_LIMIT;
use super::reports::{
    CpuReport, DiskReport, MemoryReport, NetworkReport, ResourceReport, ResourceScope, ResourceView,
};
use super::reports::{NodeCpuSummary, NodeDiskSummary, NodeMemorySummary, NodeResourceSummary};
use super::sampler::{read_host_disk, read_host_memory};
use super::{pools, sampler, shared_disk};
use crate::auth::scopes;
use crate::databases::protocol::Protocol;
use crate::routes::http::policy::ApiRequestContext;
use crate::routes::http::response::{ApiError, ApiPath, ApiResponse, ApiResult};
use crate::routes::http::router::AppState;
use crate::server::disk::soft::{SoftDiskSnapshot, SoftDiskTarget};
use crate::server::metadata::InstanceMetadata;
use crate::server::paths::InstancePaths;
use crate::server::placement::DeploymentMode;
use crate::utils::limits::mib_to_bytes;
use axum::extract::State;
use futures::{StreamExt, TryStreamExt};

pub async fn list_resources(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<Vec<ResourceReport>> {
    auth.require_scope(scopes::RESOURCES_ADMIN)?;
    let reports = futures::stream::iter(state.instances.list().await)
        .map(|metadata| {
            let state = state.clone();
            async move { resource_report(&state, &metadata, ResourceView::Admin).await }
        })
        .buffer_unordered(RESOURCE_FANOUT_LIMIT)
        .try_collect()
        .await?;
    Ok(ApiResponse::ok(reports))
}

pub async fn node_resource_summary(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<NodeResourceSummary> {
    auth.require_scope(scopes::RESOURCES_ADMIN)?;
    let instances = state.instances.list().await;
    let runtimes = state.placements.list().await.map_err(|error| {
        ApiError::Runtime(format!("failed to load runtime allocation: {error}"))
    })?;
    let allocations = sampler::summarize_allocations(&instances, &runtimes);
    let resource_reports = futures::stream::iter(instances.iter().cloned())
        .map(|metadata| {
            let state = state.clone();
            async move {
                (
                    metadata.deployment_mode,
                    resource_report(&state, &metadata, ResourceView::Tenant).await,
                )
            }
        })
        .buffer_unordered(RESOURCE_FANOUT_LIMIT)
        .collect::<Vec<_>>();
    let shared_runtime_usage = sampler::sample_shared_runtime_usage(&state, &runtimes, &instances);
    let volumes_root = state.config.paths.volumes_root();
    let (host_cpu, host_memory, host_disk, resource_reports, shared_runtime_usage) = tokio::join!(
        state.resource_cache.host_cpu_usage(),
        read_host_memory(),
        read_host_disk(&volumes_root),
        resource_reports,
        shared_runtime_usage,
    );
    let host_cpu = host_cpu
        .map_err(|error| ApiError::Runtime(format!("failed to sample host CPU: {error}")))?;
    let host_memory = host_memory
        .map_err(|error| ApiError::Runtime(format!("failed to sample host memory: {error}")))?;
    let host_disk = host_disk
        .map_err(|error| ApiError::Runtime(format!("failed to sample host disk: {error}")))?;
    let managed = sampler::aggregate_managed_usage(&resource_reports, &shared_runtime_usage);

    Ok(ApiResponse::ok(NodeResourceSummary {
        node_uuid: state.config.uuid.clone(),
        sampled_at: crate::utils::time::now_rfc3339(),
        cpu: NodeCpuSummary {
            total_cores: host_cpu.cores,
            allocated_cores: allocations.allocated_cpu_cores,
            host_usage_percent: host_cpu.usage_percent,
            managed_usage_cores: managed.cpu_usage_cores,
        },
        memory: NodeMemorySummary {
            total_bytes: host_memory.total_bytes,
            allocation_limit_bytes: state
                .config
                .allocation
                .memory_allocation_cap_bytes(host_memory.total_bytes),
            reserved_bytes: state.config.allocation.reserved_memory_bytes(),
            allocated_bytes: allocations.allocated_memory_bytes,
            host_used_bytes: host_memory.used_bytes,
            managed_used_bytes: managed.memory_used_bytes,
            available_bytes: host_memory.available_bytes,
        },
        disk: NodeDiskSummary {
            total_bytes: host_disk.total_bytes,
            allocation_limit_bytes: state
                .config
                .allocation
                .disk_allocation_cap_bytes(host_disk.total_bytes),
            reserved_bytes: state.config.allocation.reserved_disk_bytes(),
            allocated_bytes: allocations.allocated_disk_bytes,
            host_used_bytes: host_disk.used_bytes,
            managed_used_bytes: managed.disk_used_bytes,
            available_bytes: host_disk.available_bytes,
        },
        instances: allocations.instances,
    }))
}

pub async fn instance_resources(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<ResourceReport> {
    auth.require_scope(scopes::RESOURCES_READ)?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    Ok(ApiResponse::ok(
        resource_report(&state, &metadata, ResourceView::Tenant).await?,
    ))
}

pub(crate) async fn resource_report(
    state: &AppState,
    metadata: &InstanceMetadata,
    view: ResourceView,
) -> Result<ResourceReport, ApiError> {
    let runtime_id = metadata.runtime_id();
    let shared = metadata.deployment_mode == DeploymentMode::Shared;
    let pool_capacity = if view == ResourceView::Admin {
        pools::load_pool_capacity(state, metadata).await?
    } else {
        None
    };
    let stats = state.resource_cache.runtime_stats(runtime_id).await;
    let (network_rx_bytes, network_tx_bytes) = state
        .resource_cache
        .network_usage(&metadata.instance_id)
        .await;
    let soft_enforcement = metadata.limits.disk_enforcement_method == "soft_scanner";
    let shared_soft_guard =
        shared_disk::uses_soft_guard(metadata.deployment_mode, metadata.limits.disk_enforced);
    let legacy_qdrant_safety_monitor = metadata.protocol == Protocol::Qdrant
        && metadata.limits.disk_enforcement_method == "fuse_quota";
    let scanner_active = !shared && (soft_enforcement || legacy_qdrant_safety_monitor);
    let (scanner, disk_used) = if shared {
        // Telemetry must not make a stopped/unmeasurable tenant unlistable.
        // Enforcement and admission still use the strict measurement paths.
        let used = shared_disk::usage(state, metadata).await.ok();
        (None, used)
    } else {
        dedicated_disk_usage(state, metadata, scanner_active).await?
    };
    let usage = pools::runtime_report_usage(
        metadata.deployment_mode,
        runtime_id,
        metadata.limits.memory_mib,
        stats.as_ref(),
        pool_capacity,
        view,
    )?;
    let report = ResourceReport {
        instance_id: metadata.instance_id.clone(),
        runtime_id: runtime_id.to_string(),
        deployment_mode: metadata.deployment_mode,
        scope: if shared {
            ResourceScope::SharedTenant
        } else {
            ResourceScope::DedicatedInstance
        },
        protocol: metadata.protocol.to_string(),
        status: metadata.status.as_str().to_string(),
        cpu: CpuReport {
            configured_cores: metadata.limits.cpu_cores,
            usage_percent: usage.cpu_usage_percent,
        },
        memory: MemoryReport {
            configured_mib: metadata.limits.memory_mib,
            usage_bytes: usage.memory_usage_bytes,
            limit_bytes: usage.memory_limit_bytes,
        },
        disk: DiskReport {
            configured_mib: metadata.limits.disk_mib,
            limit_bytes: mib_to_bytes(metadata.limits.disk_mib),
            used_bytes: disk_used,
            enforced: metadata.limits.disk_enforced,
            enforcement_method: metadata.limits.disk_enforcement_method.clone(),
            enforcement_strength: disk_enforcement_strength(
                metadata.limits.disk_enforced,
                shared_soft_guard || soft_enforcement,
            ),
            scanner_logical_bytes: scanner.as_ref().map(|sample| sample.usage.logical_bytes),
            scanner_physical_bytes: scanner.as_ref().map(|sample| sample.usage.physical_bytes),
            scanner_growth_bytes_per_second: scanner
                .as_ref()
                .map(|sample| sample.growth_bytes_per_second),
            scanner_peak_growth_bytes_per_second: scanner
                .as_ref()
                .map(|sample| sample.peak_growth_bytes_per_second),
            scanner_predicted_seconds_to_limit: scanner
                .as_ref()
                .and_then(|sample| sample.predicted_seconds_to_limit),
            scanner_stop_threshold_bytes: scanner
                .as_ref()
                .map(|sample| sample.stop_threshold_bytes),
            scanner_recovery_threshold_bytes: scanner
                .as_ref()
                .map(|sample| sample.recovery_threshold_bytes),
            scanner_restart_blocked: (scanner_active || shared_soft_guard).then(|| {
                metadata.disk_limit_blocked || scanner.as_ref().is_some_and(|sample| sample.blocked)
            }),
            scanner_sample_age_seconds: scanner
                .as_ref()
                .map(|sample| sample.sampled_at.elapsed().as_secs()),
        },
        network: NetworkReport {
            // Database containers have no network namespace attachment. Their
            // traffic crosses DBE's authenticated host gateways and Unix
            // sockets, so Docker's optional `networks` stats are not the source
            // of truth. These counters are updated directly by the gateway.
            rx_bytes: Some(network_rx_bytes),
            tx_bytes: Some(network_tx_bytes),
        },
        pool: usage.pool,
    };

    Ok(report)
}

pub(super) async fn dedicated_disk_usage(
    state: &AppState,
    metadata: &InstanceMetadata,
    scanner_active: bool,
) -> Result<(Option<SoftDiskSnapshot>, Option<u64>), ApiError> {
    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let scanner_target = SoftDiskTarget {
        instance_id: metadata.instance_id.clone(),
        created_at: metadata.created_at.clone(),
        protocol: metadata.protocol,
        data_path: paths.data.clone(),
        limit_bytes: mib_to_bytes(metadata.limits.disk_mib),
        durable_blocked: metadata.disk_limit_blocked,
    };
    let scanner = if scanner_active {
        state.soft_disk_limiter.snapshot(&scanner_target).await
    } else {
        None
    };
    let used = shared_disk::reported_disk_used_bytes(scanner.as_ref(), || async {
        state
            .resource_cache
            .disk_usage(&state.config, &metadata.instance_id, paths.data)
            .await
            .map(|sample| sample.used_bytes)
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to measure disk usage: {error}")))?;
    Ok((scanner, Some(used)))
}

pub(super) const fn disk_enforcement_strength(hard: bool, soft: bool) -> &'static str {
    if hard {
        "hard"
    } else if soft {
        "soft"
    } else {
        "none"
    }
}
