use std::collections::HashMap;

use axum::extract::State;
use serde::Serialize;
use tokio::time::Instant;

use super::{
    ApiError, ApiRequestContext, ApiResponse, ApiResult, AppState, CachedRuntimeStats,
    DISK_REFRESH_INTERVAL, InstanceMetadata, InstanceStatus, PoolUsageReport, Protocol,
    RUNTIME_STATS_STALE_AFTER, ResourceView, mib_to_bytes, resource_report,
    sampler::{
        RuntimeStatsSnapshot, SharedDiskUsage, SharedDiskUsageSource, sample_shared_runtime_usage,
    },
};
use crate::{
    api::http::{diagnostics::PublicDiagnostic, response::ApiPath},
    auth::scopes,
    placement::{DeploymentMode, EngineRuntime, EngineRuntimeStatus},
    shared::limits::InstanceLimits,
};

#[derive(Debug, Serialize)]
pub(crate) struct SharedPoolReport {
    pub owner: Option<crate::placement::PoolOwner>,
    pub runtime_id: String,
    pub protocol: Protocol,
    pub status: EngineRuntimeStatus,
    pub desired_state: &'static str,
    pub image: String,
    pub pending_image: Option<String>,
    pub database_version: Option<String>,
    pub tenant_count: u32,
    pub max_tenants: u32,
    pub cpu: PoolCpu,
    pub memory: PoolMemory,
    pub disk: PoolDisk,
}

#[derive(Debug, Serialize)]
pub(crate) struct PoolCpu {
    pub limit_cores: f64,
    pub usage_percent: Option<f64>,
    pub sample: PoolMetricSample,
}

#[derive(Debug, Serialize)]
pub(crate) struct PoolMemory {
    pub limit_bytes: u64,
    pub usage_bytes: Option<u64>,
    pub sample: PoolMetricSample,
}

#[derive(Debug, Serialize)]
pub(crate) struct PoolDisk {
    pub limit_bytes: u64,
    pub reserved_bytes: u64,
    pub usage_bytes: Option<u64>,
    pub enforced: bool,
    pub enforcement_method: String,
    pub sample: PoolMetricSample,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PoolMetricSource {
    ContainerCpu,
    ContainerMemoryWorkingSet,
    FilesystemQuota,
    FuseQuota,
    ResourceDiskSampler,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PoolMetricState {
    Fresh,
    Warming,
    Stale,
    Stopped,
    Failed,
}

#[derive(Debug, Serialize)]
pub(crate) struct PoolMetricSample {
    pub source: PoolMetricSource,
    pub state: PoolMetricState,
    pub sampled_at_unix: Option<i64>,
    pub sample_age_seconds: Option<u64>,
    pub fresh: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<PublicDiagnostic>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SharedPoolTenant {
    pub instance_id: String,
    pub database: String,
    pub username: String,
    pub status: InstanceStatus,
    pub limits: InstanceLimits,
    pub resources: super::ResourceReport,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PoolCapacity {
    pub(super) cpu_limit_cores: f64,
    pub(super) memory_limit_bytes: u64,
}

pub(super) struct RuntimeReportUsage {
    pub(super) cpu_usage_percent: Option<f64>,
    pub(super) memory_usage_bytes: Option<u64>,
    pub(super) memory_limit_bytes: Option<u64>,
    pub(super) pool: Option<super::PoolUsageReport>,
}

pub(super) fn runtime_report_usage(
    deployment_mode: DeploymentMode,
    runtime_id: &str,
    memory_mib: u64,
    stats: Option<&CachedRuntimeStats>,
    pool_capacity: Option<PoolCapacity>,
    view: ResourceView,
) -> Result<RuntimeReportUsage, ApiError> {
    let cpu_usage_percent = stats.and_then(|stats| stats.cpu_usage_percent);
    let memory_usage_bytes = stats.and_then(|stats| stats.memory_usage_bytes);
    if deployment_mode == DeploymentMode::Shared {
        // CPU time and working-set memory are cgroup measurements. They cannot
        // be attributed honestly to one tenant within a shared engine.
        let pool = if view == ResourceView::Admin {
            let capacity = pool_capacity.ok_or_else(|| {
                ApiError::Runtime("shared runtime capacity is temporarily unavailable".to_string())
            })?;
            Some(PoolUsageReport {
                runtime_id: runtime_id.to_string(),
                cpu_limit_cores: capacity.cpu_limit_cores,
                cpu_usage_percent,
                memory_limit_bytes: capacity.memory_limit_bytes,
                memory_usage_bytes,
            })
        } else {
            None
        };
        Ok(RuntimeReportUsage {
            cpu_usage_percent: None,
            memory_usage_bytes: None,
            memory_limit_bytes: None,
            pool,
        })
    } else {
        Ok(RuntimeReportUsage {
            cpu_usage_percent,
            memory_usage_bytes,
            memory_limit_bytes: Some(mib_to_bytes(memory_mib)),
            pool: None,
        })
    }
}

pub(super) async fn load_pool_capacity(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<Option<PoolCapacity>, ApiError> {
    if metadata.deployment_mode == DeploymentMode::Dedicated {
        return Ok(None);
    }
    let runtime = state
        .placements
        .get(metadata.runtime_id())
        .await
        .map_err(|_| {
            ApiError::Runtime("shared runtime capacity is temporarily unavailable".to_string())
        })?
        .ok_or_else(|| {
            ApiError::Runtime("shared runtime capacity is temporarily unavailable".to_string())
        })?;
    if runtime.deployment_mode != DeploymentMode::Shared || runtime.protocol != metadata.protocol {
        return Err(ApiError::Runtime(
            "shared runtime capacity is temporarily unavailable".to_string(),
        ));
    }
    Ok(Some(PoolCapacity {
        cpu_limit_cores: runtime.limits.cpu_cores,
        memory_limit_bytes: mib_to_bytes(runtime.limits.memory_mib),
    }))
}

pub(crate) async fn list_shared_pools(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<Vec<SharedPoolReport>> {
    auth.require_scope(scopes::POOLS_READ)?;
    let runtimes = shared_runtimes(&state).await?;
    let reports = pool_reports(&state, &runtimes).await?;
    Ok(ApiResponse::ok(reports))
}

pub(crate) async fn get_shared_pool(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(runtime_id): ApiPath<String>,
) -> ApiResult<SharedPoolReport> {
    auth.require_scope(scopes::POOLS_READ)?;
    let runtime = state
        .placements
        .get(&runtime_id)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to load shared pool: {error}")))?
        .filter(|runtime| runtime.deployment_mode == DeploymentMode::Shared)
        .ok_or(ApiError::NotFound)?;
    let mut reports = pool_reports(&state, std::slice::from_ref(&runtime)).await?;
    reports
        .pop()
        .ok_or_else(|| {
            ApiError::Runtime("shared pool metrics are temporarily unavailable".to_string())
        })
        .map(ApiResponse::ok)
}

pub(crate) async fn list_pool_tenants(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(runtime_id): ApiPath<String>,
) -> ApiResult<Vec<SharedPoolTenant>> {
    auth.require_scope(scopes::POOLS_READ)?;
    let runtime = state
        .placements
        .get(&runtime_id)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to load shared pool: {error}")))?
        .filter(|runtime| runtime.deployment_mode == DeploymentMode::Shared)
        .ok_or(ApiError::NotFound)?;
    let tenant_ids = state
        .placements
        .tenants(&runtime.runtime_id)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to load pool tenants: {error}")))?;
    let mut tenants = Vec::with_capacity(tenant_ids.len());
    for instance_id in tenant_ids {
        let metadata = state.instances.get(&instance_id).await.ok_or_else(|| {
            ApiError::Runtime(format!(
                "shared pool {} references missing tenant {instance_id}",
                runtime.runtime_id
            ))
        })?;
        if metadata.deployment_mode != DeploymentMode::Shared
            || metadata.runtime_id() != runtime.runtime_id
            || metadata.protocol != runtime.protocol
            || metadata.owner != runtime.owner
        {
            return Err(ApiError::Runtime(format!(
                "shared pool {} has inconsistent tenant metadata",
                runtime.runtime_id
            )));
        }
        let resources = resource_report(&state, &metadata, ResourceView::Tenant).await?;
        tenants.push(SharedPoolTenant {
            instance_id: metadata.instance_id,
            database: metadata.database.name,
            username: metadata.database.username,
            status: metadata.status,
            limits: metadata.limits,
            resources,
        });
    }
    Ok(ApiResponse::ok(tenants))
}

async fn shared_runtimes(state: &AppState) -> Result<Vec<EngineRuntime>, ApiError> {
    state
        .placements
        .list()
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to load shared pools: {error}")))
        .map(|runtimes| {
            runtimes
                .into_iter()
                .filter(|runtime| runtime.deployment_mode == DeploymentMode::Shared)
                .collect()
        })
}

pub(crate) async fn pool_reports(
    state: &AppState,
    runtimes: &[EngineRuntime],
) -> Result<Vec<SharedPoolReport>, ApiError> {
    let instances = state.instances.list().await;
    let usage = sample_shared_runtime_usage(state, runtimes, &instances)
        .await
        .into_iter()
        .map(|usage| (usage.runtime_id.clone(), usage))
        .collect::<HashMap<_, _>>();
    let clock = ReportClock::now();
    let mut reports = Vec::with_capacity(runtimes.len());
    for runtime in runtimes {
        let usage = usage.get(&runtime.runtime_id);
        let stats = usage.map(|usage| &usage.runtime_stats);
        let (cpu_usage_percent, cpu_sample) = runtime_metric(
            runtime.status,
            stats,
            PoolMetricSource::ContainerCpu,
            |sample| sample.cpu_usage_percent,
            clock,
        );
        let (memory_usage_bytes, memory_sample) = runtime_metric(
            runtime.status,
            stats,
            PoolMetricSource::ContainerMemoryWorkingSet,
            |sample| sample.memory_usage_bytes,
            clock,
        );
        let (disk_usage_bytes, disk_sample) = disk_metric(
            &runtime.runtime_id,
            disk_source(runtime),
            usage.map(|usage| &usage.disk_usage),
            clock,
        );
        reports.push(SharedPoolReport {
            owner: runtime.owner.clone(),
            runtime_id: runtime.runtime_id.clone(),
            protocol: runtime.protocol,
            status: runtime.status,
            desired_state: runtime.desired_state.as_str(),
            image: runtime.image.clone(),
            pending_image: runtime.pending_image.clone(),
            database_version: runtime.database_version.clone(),
            tenant_count: runtime.reserved.tenants,
            max_tenants: runtime.max_tenants,
            cpu: PoolCpu {
                limit_cores: runtime.limits.cpu_cores,
                usage_percent: cpu_usage_percent,
                sample: cpu_sample,
            },
            memory: PoolMemory {
                limit_bytes: mib_to_bytes(runtime.limits.memory_mib),
                usage_bytes: memory_usage_bytes,
                sample: memory_sample,
            },
            disk: PoolDisk {
                limit_bytes: mib_to_bytes(runtime.limits.disk_mib),
                reserved_bytes: mib_to_bytes(runtime.reserved.disk_mib),
                usage_bytes: disk_usage_bytes,
                enforced: runtime.limits.disk_enforced,
                enforcement_method: runtime.limits.disk_enforcement_method.clone(),
                sample: disk_sample,
            },
        });
    }
    reports.sort_unstable_by(|left, right| left.runtime_id.cmp(&right.runtime_id));
    Ok(reports)
}

#[derive(Debug, Clone, Copy)]
struct ReportClock {
    instant: Instant,
    unix: i64,
}

impl ReportClock {
    fn now() -> Self {
        Self {
            instant: Instant::now(),
            unix: crate::shared::time::now_unix(),
        }
    }

    fn sample_time(self, sampled_at: Instant) -> (i64, u64) {
        let age = self.instant.saturating_duration_since(sampled_at).as_secs();
        (
            self.unix.saturating_sub(age.min(i64::MAX as u64) as i64),
            age,
        )
    }
}

fn runtime_metric<T: Copy>(
    status: EngineRuntimeStatus,
    stats: Option<&RuntimeStatsSnapshot>,
    source: PoolMetricSource,
    value: impl Fn(&super::CachedRuntimeStats) -> Option<T>,
    clock: ReportClock,
) -> (Option<T>, PoolMetricSample) {
    if !matches!(
        status,
        EngineRuntimeStatus::Booting | EngineRuntimeStatus::Running
    ) {
        let failed = status == EngineRuntimeStatus::Failed;
        return (
            None,
            metric_sample(
                source,
                if failed {
                    PoolMetricState::Failed
                } else {
                    PoolMetricState::Stopped
                },
                None,
                Some(PublicDiagnostic::public(
                    if failed {
                        "runtime_failed"
                    } else {
                        "runtime_stopped"
                    },
                    if failed {
                        "the shared pool runtime is failed"
                    } else {
                        "the shared pool runtime is not running"
                    },
                )),
            ),
        );
    }

    let Some(stats) = stats else {
        return (
            None,
            metric_sample(
                source,
                PoolMetricState::Failed,
                None,
                Some(PublicDiagnostic::public(
                    "sampler_report_missing",
                    "the shared pool sampler did not return this runtime",
                )),
            ),
        );
    };
    let Some(sample) = stats.sample() else {
        let warming = status == EngineRuntimeStatus::Booting || stats.worker_active();
        return (
            None,
            metric_sample(
                source,
                if warming {
                    PoolMetricState::Warming
                } else {
                    PoolMetricState::Failed
                },
                None,
                Some(PublicDiagnostic::public(
                    if warming {
                        "sampler_warming"
                    } else {
                        "sampler_unavailable"
                    },
                    if warming {
                        "the shared pool sampler is waiting for its first value"
                    } else {
                        "the shared pool sampler is temporarily unavailable"
                    },
                )),
            ),
        );
    };

    let (sampled_at_unix, sample_age_seconds) = clock.sample_time(sample.sampled_at);
    if clock.instant.saturating_duration_since(sample.sampled_at) >= RUNTIME_STATS_STALE_AFTER {
        return (
            None,
            metric_sample(
                source,
                PoolMetricState::Stale,
                Some((sampled_at_unix, sample_age_seconds)),
                Some(PublicDiagnostic::public(
                    "stale_sample",
                    "the latest shared pool runtime sample is stale",
                )),
            ),
        );
    }
    let Some(value) = value(sample) else {
        return (
            None,
            metric_sample(
                source,
                PoolMetricState::Failed,
                Some((sampled_at_unix, sample_age_seconds)),
                Some(PublicDiagnostic::public(
                    "metric_unavailable",
                    "the container runtime omitted this metric",
                )),
            ),
        );
    };
    (
        Some(value),
        metric_sample(
            source,
            PoolMetricState::Fresh,
            Some((sampled_at_unix, sample_age_seconds)),
            None,
        ),
    )
}

fn disk_metric(
    runtime_id: &str,
    fallback_source: PoolMetricSource,
    disk: Option<&Result<SharedDiskUsage, String>>,
    clock: ReportClock,
) -> (Option<u64>, PoolMetricSample) {
    let Some(disk) = disk else {
        return (
            None,
            metric_sample(
                fallback_source,
                PoolMetricState::Failed,
                None,
                Some(PublicDiagnostic::public(
                    "sampler_report_missing",
                    "the shared pool sampler did not return this runtime",
                )),
            ),
        );
    };
    let sample = match disk {
        Ok(sample) => sample,
        Err(error) => {
            let warming = error.contains("still in progress");
            tracing::debug!(
                %runtime_id,
                %error,
                "shared pool disk sample unavailable"
            );
            return (
                None,
                metric_sample(
                    fallback_source,
                    if warming {
                        PoolMetricState::Warming
                    } else {
                        PoolMetricState::Failed
                    },
                    None,
                    Some(PublicDiagnostic::public(
                        if warming {
                            "disk_scan_warming"
                        } else {
                            "disk_sample_failed"
                        },
                        if warming {
                            "the shared pool disk scan is still in progress"
                        } else {
                            "shared pool disk usage is temporarily unavailable"
                        },
                    )),
                ),
            );
        }
    };
    let (sampled_at_unix, sample_age_seconds) = clock.sample_time(sample.sampled_at);
    if clock.instant.saturating_duration_since(sample.sampled_at) >= DISK_REFRESH_INTERVAL {
        return (
            None,
            metric_sample(
                sample.source.into(),
                PoolMetricState::Stale,
                Some((sampled_at_unix, sample_age_seconds)),
                Some(PublicDiagnostic::public(
                    "stale_sample",
                    "the latest shared pool disk sample is stale",
                )),
            ),
        );
    }
    (
        Some(sample.bytes),
        metric_sample(
            sample.source.into(),
            PoolMetricState::Fresh,
            Some((sampled_at_unix, sample_age_seconds)),
            None,
        ),
    )
}

fn metric_sample(
    source: PoolMetricSource,
    state: PoolMetricState,
    time: Option<(i64, u64)>,
    diagnostic: Option<PublicDiagnostic>,
) -> PoolMetricSample {
    PoolMetricSample {
        source,
        state,
        sampled_at_unix: time.map(|time| time.0),
        sample_age_seconds: time.map(|time| time.1),
        fresh: state == PoolMetricState::Fresh,
        diagnostic,
    }
}

fn disk_source(runtime: &EngineRuntime) -> PoolMetricSource {
    if !runtime.limits.disk_enforced {
        PoolMetricSource::ResourceDiskSampler
    } else if runtime.limits.disk_enforcement_method == "fuse_quota" {
        PoolMetricSource::FuseQuota
    } else {
        PoolMetricSource::FilesystemQuota
    }
}

impl From<SharedDiskUsageSource> for PoolMetricSource {
    fn from(source: SharedDiskUsageSource) -> Self {
        match source {
            SharedDiskUsageSource::FilesystemQuota => Self::FilesystemQuota,
            SharedDiskUsageSource::FuseQuota => Self::FuseQuota,
            SharedDiskUsageSource::ResourceDiskSampler => Self::ResourceDiskSampler,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::api::monitoring::resources::CachedRuntimeStats;

    fn clock() -> ReportClock {
        ReportClock {
            instant: Instant::now(),
            unix: 1_000,
        }
    }

    #[test]
    fn runtime_metric_distinguishes_fresh_stale_warming_and_stopped() {
        let clock = clock();
        let fresh = RuntimeStatsSnapshot {
            sample: Some(CachedRuntimeStats {
                cpu_usage_percent: Some(125.0),
                memory_usage_bytes: Some(512),
                sampled_at: clock.instant - Duration::from_secs(1),
            }),
            worker_active: true,
        };
        let (usage, sample) = runtime_metric(
            EngineRuntimeStatus::Running,
            Some(&fresh),
            PoolMetricSource::ContainerCpu,
            |sample| sample.cpu_usage_percent,
            clock,
        );
        assert_eq!(usage, Some(125.0));
        assert_eq!(sample.state, PoolMetricState::Fresh);
        assert_eq!(sample.sampled_at_unix, Some(999));
        assert_eq!(sample.sample_age_seconds, Some(1));
        assert!(sample.fresh);
        assert!(sample.diagnostic.is_none());

        let stale = RuntimeStatsSnapshot {
            sample: Some(CachedRuntimeStats {
                cpu_usage_percent: Some(125.0),
                memory_usage_bytes: Some(512),
                sampled_at: clock.instant - RUNTIME_STATS_STALE_AFTER,
            }),
            worker_active: true,
        };
        let (usage, sample) = runtime_metric(
            EngineRuntimeStatus::Running,
            Some(&stale),
            PoolMetricSource::ContainerCpu,
            |sample| sample.cpu_usage_percent,
            clock,
        );
        assert_eq!(usage, None);
        assert_eq!(sample.state, PoolMetricState::Stale);
        assert!(!sample.fresh);
        assert_eq!(sample.diagnostic.unwrap().code, "stale_sample");

        let warming = RuntimeStatsSnapshot {
            sample: None,
            worker_active: true,
        };
        let (_, sample) = runtime_metric::<f64>(
            EngineRuntimeStatus::Booting,
            Some(&warming),
            PoolMetricSource::ContainerCpu,
            |sample| sample.cpu_usage_percent,
            clock,
        );
        assert_eq!(sample.state, PoolMetricState::Warming);

        let (_, sample) = runtime_metric(
            EngineRuntimeStatus::Stopped,
            Some(&fresh),
            PoolMetricSource::ContainerMemoryWorkingSet,
            |sample| sample.memory_usage_bytes,
            clock,
        );
        assert_eq!(sample.state, PoolMetricState::Stopped);
    }

    #[test]
    fn missing_or_failed_samples_have_bounded_public_diagnostics() {
        let clock = clock();
        let missing = RuntimeStatsSnapshot::default();
        let (_, sample) = runtime_metric::<u64>(
            EngineRuntimeStatus::Running,
            Some(&missing),
            PoolMetricSource::ContainerMemoryWorkingSet,
            |sample| sample.memory_usage_bytes,
            clock,
        );
        assert_eq!(sample.state, PoolMetricState::Failed);
        assert_eq!(sample.diagnostic.unwrap().code, "sampler_unavailable");

        let error = Err("secret=/var/lib/private password=hunter2".to_string());
        let (_, sample) = disk_metric(
            "pool-a",
            PoolMetricSource::ResourceDiskSampler,
            Some(&error),
            clock,
        );
        let encoded = serde_json::to_string(&sample).unwrap();
        assert_eq!(sample.state, PoolMetricState::Failed);
        assert!(encoded.contains("disk_sample_failed"));
        assert!(!encoded.contains("hunter2"));
        assert!(!encoded.contains("/var/lib/private"));

        let warming = Err("disk usage scan is still in progress".to_string());
        let (_, sample) = disk_metric(
            "pool-a",
            PoolMetricSource::ResourceDiskSampler,
            Some(&warming),
            clock,
        );
        assert_eq!(sample.state, PoolMetricState::Warming);
    }

    #[test]
    fn disk_sample_reports_source_timestamp_and_freshness() {
        let clock = clock();
        let fresh = Ok(SharedDiskUsage {
            bytes: 42,
            sampled_at: clock.instant - Duration::from_secs(1),
            source: SharedDiskUsageSource::FilesystemQuota,
        });
        let (usage, sample) = disk_metric(
            "pool-a",
            PoolMetricSource::FilesystemQuota,
            Some(&fresh),
            clock,
        );
        assert_eq!(usage, Some(42));
        assert_eq!(sample.source, PoolMetricSource::FilesystemQuota);
        assert_eq!(sample.state, PoolMetricState::Fresh);
        assert_eq!(sample.sampled_at_unix, Some(999));

        let stale = Ok(SharedDiskUsage {
            bytes: 42,
            sampled_at: clock.instant - DISK_REFRESH_INTERVAL,
            source: SharedDiskUsageSource::ResourceDiskSampler,
        });
        let (usage, sample) = disk_metric(
            "pool-a",
            PoolMetricSource::ResourceDiskSampler,
            Some(&stale),
            clock,
        );
        assert_eq!(usage, None);
        assert_eq!(sample.state, PoolMetricState::Stale);
        assert!(!sample.fresh);
    }
}
