use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use futures::{StreamExt, stream};
use tokio::time::{Instant, MissedTickBehavior};

use super::{OperationCounts, counter::EngineObservation};
use crate::{
    api::http::router::AppState,
    instances::metadata::InstanceMetadata,
    placement::{DeploymentMode, EngineRuntime, EngineRuntimeStatus, tenant},
    runtime::docker::ManagedContainerIdentity,
    shared::protocol::Protocol,
};

mod queries;
use queries::parse_clickhouse_window;
pub(crate) use queries::{
    clickhouse_collect_sql, keep_tenant_rows, mariadb_collect_sql, mariadb_prepare_sql,
    mysql_collect_sql, mysql_prepare_sql, parse_mariadb_ready, parse_mariadb_rows,
    parse_mysql_capabilities, parse_mysql_rows,
};

const SAMPLE_INTERVAL: Duration = Duration::from_secs(15);
const MAX_CONCURRENT_POOLS: usize = 4;
const FAILURE_LOG_INTERVAL: u32 = 20;
const MAX_FAILURE_BACKOFF: Duration = Duration::from_secs(15 * 60);

/// Starts best-effort engine-native accounting for shared tenants.
///
/// This intentionally does not report PostgreSQL or MongoDB CPU/RSS: those
/// engines have no defensible database-user attribution for those resources.
/// Pool failures only make the optional measurements unavailable; they never
/// restart, fence, or quarantine a shared runtime.
pub fn start_engine_activity_sampler(state: AppState) {
    let mut shutdown = state.gateway_supervisor.subscribe_shutdown();
    tokio::spawn(async move {
        let mut sampler = EngineSampler::default();
        let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!("shared tenant engine activity sampler stopped");
                        break;
                    }
                }
                _ = ticker.tick() => sampler.sample(&state).await,
            }
        }
    });
}

#[derive(Default)]
struct EngineSampler {
    pools: HashMap<String, PoolState>,
    repository_failures: u32,
}

impl EngineSampler {
    async fn sample(&mut self, state: &AppState) {
        let instances = state.instances.list().await;
        let runtimes = match state.placements.list().await {
            Ok(runtimes) => {
                if self.repository_failures > 0 {
                    tracing::info!(
                        "shared tenant engine activity resumed after placement storage recovered"
                    );
                    self.repository_failures = 0;
                }
                runtimes
            }
            Err(_) => {
                mark_instances_unavailable(state, &instances).await;
                for pool in self.pools.values_mut() {
                    pool.invalidate_window();
                }
                self.repository_failures = self.repository_failures.saturating_add(1);
                if should_log_failure(self.repository_failures) {
                    tracing::warn!(
                        failures = self.repository_failures,
                        "shared tenant engine activity could not read pool placement"
                    );
                }
                return;
            }
        };

        let tenants = tenants_by_runtime(&instances);
        let active = runtimes
            .into_iter()
            .filter(collects_engine_activity)
            .collect::<Vec<_>>();
        let active_protocols = active
            .iter()
            .map(|runtime| (runtime.runtime_id.clone(), runtime.protocol))
            .collect::<HashMap<_, _>>();
        mark_inactive_instances(state, &instances, &active_protocols).await;
        let active_ids = active_protocols.keys().cloned().collect::<HashSet<_>>();
        self.pools
            .retain(|runtime_id, _| active_ids.contains(runtime_id));

        let mut jobs = Vec::with_capacity(active.len());
        for runtime in active {
            let runtime_id = runtime.runtime_id.clone();
            let candidates = tenants.get(&runtime_id).cloned().unwrap_or_default();
            let (unique, ambiguous) = split_unique_tenants(candidates, runtime.protocol);
            mark_unavailable(state, &ambiguous).await;
            let pool = self
                .pools
                .remove(&runtime_id)
                .filter(|pool| pool.protocol == runtime.protocol)
                .unwrap_or_else(|| PoolState::new(runtime.protocol));
            jobs.push((runtime, unique, pool));
        }

        let mut results = stream::iter(jobs.into_iter().map(|(runtime, tenants, pool)| {
            let state = state.clone();
            async move { sample_pool(&state, runtime, tenants, pool).await }
        }))
        .buffer_unordered(MAX_CONCURRENT_POOLS);
        while let Some((runtime_id, pool)) = results.next().await {
            self.pools.insert(runtime_id, pool);
        }
    }
}

fn collects_engine_activity(runtime: &EngineRuntime) -> bool {
    runtime.deployment_mode == DeploymentMode::Shared
        && runtime.status == EngineRuntimeStatus::Running
        && engine_protocol(runtime.protocol)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TenantIdentity {
    instance_id: String,
    created_at: String,
    username: String,
    protocol: Protocol,
}

fn tenants_by_runtime(instances: &[InstanceMetadata]) -> HashMap<String, Vec<TenantIdentity>> {
    let mut grouped = HashMap::<String, Vec<TenantIdentity>>::new();
    for instance in instances {
        if instance.deployment_mode != DeploymentMode::Shared || !engine_protocol(instance.protocol)
        {
            continue;
        }
        grouped
            .entry(instance.runtime_id().to_string())
            .or_default()
            .push(TenantIdentity {
                instance_id: instance.instance_id.clone(),
                created_at: instance.created_at.clone(),
                username: instance.database.username.clone(),
                protocol: instance.protocol,
            });
    }
    grouped
}

/// A duplicate username is ambiguous at the engine accounting boundary. The
/// placement repository prevents it, but excluding a corrupt duplicate is
/// safer than assigning the same physical counters to two tenants.
fn split_unique_tenants(
    tenants: Vec<TenantIdentity>,
    protocol: Protocol,
) -> (Vec<TenantIdentity>, Vec<TenantIdentity>) {
    let tenants = tenants
        .into_iter()
        .filter(|tenant| tenant.protocol == protocol)
        .collect::<Vec<_>>();
    let mut counts = HashMap::<String, usize>::new();
    for tenant in &tenants {
        *counts.entry(tenant.username.clone()).or_default() += 1;
    }
    tenants
        .into_iter()
        .partition(|tenant| counts.get(tenant.username.as_str()) == Some(&1))
}

async fn mark_instances_unavailable(state: &AppState, instances: &[InstanceMetadata]) {
    let tenants = instances
        .iter()
        .filter(|instance| engine_protocol(instance.protocol))
        .map(tenant_identity)
        .collect::<Vec<_>>();
    mark_unavailable(state, &tenants).await;
}

async fn mark_inactive_instances(
    state: &AppState,
    instances: &[InstanceMetadata],
    active: &HashMap<String, Protocol>,
) {
    let inactive = instances
        .iter()
        .filter(|instance| {
            engine_protocol(instance.protocol)
                && (instance.deployment_mode != DeploymentMode::Shared
                    || active.get(instance.runtime_id()).copied() != Some(instance.protocol))
        })
        .map(tenant_identity)
        .collect::<Vec<_>>();
    mark_unavailable(state, &inactive).await;
}

fn engine_protocol(protocol: Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Mysql | Protocol::Mariadb | Protocol::Clickhouse
    )
}

fn tenant_identity(instance: &InstanceMetadata) -> TenantIdentity {
    TenantIdentity {
        instance_id: instance.instance_id.clone(),
        created_at: instance.created_at.clone(),
        username: instance.database.username.clone(),
        protocol: instance.protocol,
    }
}

async fn mark_unavailable(state: &AppState, tenants: &[TenantIdentity]) {
    for tenant in tenants {
        state
            .resource_cache
            .activity_counter(&tenant.instance_id, &tenant.created_at)
            .await
            .set_engine_availability(
                false,
                false,
                (tenant.protocol == Protocol::Clickhouse).then_some(false),
            );
    }
}

async fn sample_pool(
    state: &AppState,
    runtime: EngineRuntime,
    tenants: Vec<TenantIdentity>,
    mut pool: PoolState,
) -> (String, PoolState) {
    let runtime_id = runtime.runtime_id.clone();
    pool.sync_tenants(&tenants);
    if tenants.is_empty() {
        pool.record_success();
        return (runtime_id, pool);
    }

    let before = match state
        .docker
        .verified_container_identity(runtime.protocol, &runtime_id)
        .await
    {
        Ok(Some(identity)) => identity,
        Ok(None) => {
            pool.clear_generation();
            mark_unavailable(state, &tenants).await;
            pool.record_failure(&runtime);
            return (runtime_id, pool);
        }
        Err(_) => {
            mark_unavailable(state, &tenants).await;
            pool.record_failure(&runtime);
            return (runtime_id, pool);
        }
    };
    if pool.bind_generation(before.clone()) {
        mark_unavailable(state, &tenants).await;
    }
    if pool.backing_off(Instant::now()) {
        mark_unavailable(state, &tenants).await;
        return (runtime_id, pool);
    }

    let result = if !pool.prepared {
        prepare_pool(state, &runtime, &mut pool).await.map(|_| None)
    } else {
        collect_pool(state, &runtime, &pool).await.map(Some)
    };

    let after = match state
        .docker
        .verified_container_identity(runtime.protocol, &runtime_id)
        .await
    {
        Ok(Some(identity)) => identity,
        Ok(None) => {
            pool.clear_generation();
            mark_unavailable(state, &tenants).await;
            pool.record_failure(&runtime);
            return (runtime_id, pool);
        }
        Err(_) => {
            mark_unavailable(state, &tenants).await;
            pool.record_failure(&runtime);
            return (runtime_id, pool);
        }
    };
    if after != before {
        pool.bind_generation(after);
        mark_unavailable(state, &tenants).await;
        return (runtime_id, pool);
    }

    match result {
        Ok(Some(mut sample)) => {
            pool.record_success();
            keep_tenant_rows(
                &mut sample.rows,
                tenants.iter().map(|tenant| tenant.username.as_str()),
            );
            pool.capabilities = sample.capabilities;
            apply_sample(state, &tenants, &mut pool, &sample).await;
            if let Some(checkpoint) = sample.next_clickhouse_checkpoint {
                pool.clickhouse_checkpoint = Some(checkpoint);
            }
        }
        // Preparation alone does not prove collection recovered. Preserve the
        // failure streak until a complete, generation-stable sample succeeds.
        Ok(None) => {}
        Err(error) => {
            if matches!(error, CollectError::NotReady) {
                // The verified process explicitly reported that its in-memory
                // accounting switch was disabled. Re-enable it after backoff.
                pool.prepared = false;
            }
            mark_unavailable(state, &tenants).await;
            pool.record_failure(&runtime);
        }
    }
    (runtime_id, pool)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Capabilities {
    pub(crate) cpu: bool,
    pub(crate) memory: bool,
    pub(crate) operations: bool,
}

#[derive(Debug)]
struct PoolState {
    protocol: Protocol,
    generation: Option<ManagedContainerIdentity>,
    prepared: bool,
    capabilities: Capabilities,
    baselines: HashMap<String, TenantBaseline>,
    clickhouse_checkpoint: Option<u64>,
    failures: u32,
    retry_at: Option<Instant>,
}

impl PoolState {
    fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            generation: None,
            prepared: protocol == Protocol::Clickhouse,
            capabilities: Capabilities::default(),
            baselines: HashMap::new(),
            clickhouse_checkpoint: None,
            failures: 0,
            retry_at: None,
        }
    }

    fn bind_generation(&mut self, generation: ManagedContainerIdentity) -> bool {
        if self.generation.as_ref() == Some(&generation) {
            return false;
        }
        self.generation = Some(generation);
        self.reset_generation_state();
        true
    }

    fn clear_generation(&mut self) {
        if self.generation.take().is_some() {
            self.reset_generation_state();
        }
    }

    fn reset_generation_state(&mut self) {
        self.prepared = self.protocol == Protocol::Clickhouse;
        self.capabilities = Capabilities::default();
        self.baselines.clear();
        self.clickhouse_checkpoint = None;
        self.failures = 0;
        self.retry_at = None;
    }

    fn sync_tenants(&mut self, tenants: &[TenantIdentity]) {
        self.baselines.retain(|instance_id, baseline| {
            tenants.iter().any(|tenant| {
                tenant.instance_id == *instance_id
                    && tenant.created_at == baseline.instance_generation
            })
        });
    }

    fn backing_off(&self, now: Instant) -> bool {
        self.retry_at.is_some_and(|retry_at| retry_at > now)
    }

    fn record_success(&mut self) {
        if self.failures > 0 {
            tracing::info!(
                protocol = %self.protocol,
                "shared tenant engine activity recovered"
            );
        }
        self.failures = 0;
        self.retry_at = None;
    }

    fn record_failure(&mut self, runtime: &EngineRuntime) {
        self.invalidate_window();
        self.failures = self.failures.saturating_add(1);
        self.retry_at = Some(Instant::now() + failure_backoff(self.failures));
        if should_log_failure(self.failures) {
            tracing::warn!(
                runtime_id = %runtime.runtime_id,
                protocol = %runtime.protocol,
                failures = self.failures,
                "shared tenant engine activity is unavailable; optional CPU and query-memory fields remain unknown"
            );
        }
    }

    fn invalidate_window(&mut self) {
        self.baselines.clear();
        if self.protocol == Protocol::Clickhouse {
            self.clickhouse_checkpoint = None;
        }
    }
}

fn failure_backoff(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(16);
    SAMPLE_INTERVAL
        .checked_mul(1_u32 << shift)
        .unwrap_or(MAX_FAILURE_BACKOFF)
        .min(MAX_FAILURE_BACKOFF)
}

fn should_log_failure(failures: u32) -> bool {
    failures == 1 || failures.is_multiple_of(FAILURE_LOG_INTERVAL)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CollectError {
    #[error("engine telemetry command unavailable")]
    Unavailable,
    #[error("engine telemetry output was invalid")]
    InvalidOutput,
    #[error("engine telemetry accounting was disabled")]
    NotReady,
}

async fn prepare_pool(
    state: &AppState,
    runtime: &EngineRuntime,
    pool: &mut PoolState,
) -> Result<(), CollectError> {
    let sql = match runtime.protocol {
        Protocol::Mysql => mysql_prepare_sql(),
        Protocol::Mariadb => mariadb_prepare_sql(),
        Protocol::Clickhouse => {
            pool.prepared = true;
            return Ok(());
        }
        _ => return Err(CollectError::Unavailable),
    };
    let output = tenant::telemetry_sql(&state.docker, runtime, sql)
        .await
        .map_err(|_| CollectError::Unavailable)?;
    pool.capabilities = match runtime.protocol {
        Protocol::Mysql => parse_mysql_capabilities(&output.stdout)?,
        Protocol::Mariadb => parse_mariadb_ready(&output.stdout)?,
        _ => return Err(CollectError::Unavailable),
    };
    pool.prepared = true;
    Ok(())
}

async fn collect_pool(
    state: &AppState,
    runtime: &EngineRuntime,
    pool: &PoolState,
) -> Result<EngineSample, CollectError> {
    let capabilities = pool.capabilities;
    let (rows, capabilities, mode, next_clickhouse_checkpoint) = match runtime.protocol {
        Protocol::Mysql if capabilities.cpu || capabilities.memory => {
            let output =
                tenant::telemetry_sql(&state.docker, runtime, mysql_collect_sql(capabilities))
                    .await
                    .map_err(|_| CollectError::Unavailable)?;
            (
                parse_mysql_rows(&output.stdout, capabilities)?,
                capabilities,
                SampleMode::Cumulative,
                None,
            )
        }
        Protocol::Mysql => (HashMap::new(), capabilities, SampleMode::Cumulative, None),
        Protocol::Mariadb => {
            let output = tenant::telemetry_sql(&state.docker, runtime, mariadb_collect_sql())
                .await
                .map_err(|_| CollectError::Unavailable)?;
            (
                parse_mariadb_rows(&output.stdout)?,
                capabilities,
                SampleMode::Cumulative,
                None,
            )
        }
        Protocol::Clickhouse => {
            let output = tenant::clickhouse_telemetry_window(
                &state.docker,
                runtime,
                pool.clickhouse_checkpoint,
                clickhouse_collect_sql(),
            )
            .await
            .map_err(|_| CollectError::Unavailable)?;
            let (checkpoint, rows) = parse_clickhouse_window(&output.stdout)?;
            if pool
                .clickhouse_checkpoint
                .is_some_and(|previous| checkpoint < previous)
            {
                return Err(CollectError::InvalidOutput);
            }
            (
                rows,
                Capabilities {
                    cpu: true,
                    memory: true,
                    operations: true,
                },
                SampleMode::Interval,
                Some(checkpoint),
            )
        }
        _ => return Err(CollectError::Unavailable),
    };
    Ok(EngineSample {
        capabilities,
        rows,
        mode,
        next_clickhouse_checkpoint,
    })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EngineTotals {
    cpu_time_micros: u64,
    peak_query_memory_bytes: u64,
    operations: OperationCounts,
}

#[derive(Debug)]
struct EngineSample {
    capabilities: Capabilities,
    rows: HashMap<String, EngineTotals>,
    mode: SampleMode,
    next_clickhouse_checkpoint: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SampleMode {
    Cumulative,
    Interval,
}

async fn apply_sample(
    state: &AppState,
    tenants: &[TenantIdentity],
    pool: &mut PoolState,
    sample: &EngineSample,
) {
    for tenant in tenants {
        let totals = sample
            .rows
            .get(&tenant.username)
            .copied()
            .unwrap_or_default();
        let (cpu, memory, operations, discontinuity) = observation_for(
            sample.mode,
            sample.capabilities,
            totals,
            pool.baselines
                .entry(tenant.instance_id.clone())
                .or_insert_with(|| TenantBaseline::new(&tenant.username, &tenant.created_at)),
            &tenant.username,
            &tenant.created_at,
        );

        let counter = state
            .resource_cache
            .activity_counter(&tenant.instance_id, &tenant.created_at)
            .await;
        counter.observe_engine_sample(EngineObservation {
            cpu_time_micros: cpu,
            peak_query_memory_bytes: memory,
            operations,
            cpu_available: sample.capabilities.cpu,
            memory_available: sample.capabilities.memory,
            operations_available: (tenant.protocol == Protocol::Clickhouse)
                .then_some(sample.capabilities.operations),
            discontinuity,
        });
    }
}

fn observation_for(
    mode: SampleMode,
    capabilities: Capabilities,
    totals: EngineTotals,
    baseline: &mut TenantBaseline,
    username: &str,
    instance_generation: &str,
) -> (Option<u64>, Option<u64>, Option<OperationCounts>, bool) {
    if baseline.username != username || baseline.instance_generation != instance_generation {
        *baseline = TenantBaseline::new(username, instance_generation);
    }
    match mode {
        SampleMode::Cumulative => {
            let (cpu, cpu_reset) = if capabilities.cpu {
                let (value, reset) = baseline.cpu.delta(totals.cpu_time_micros);
                (Some(value), reset)
            } else {
                (None, false)
            };
            let (memory, memory_reset) = if capabilities.memory {
                baseline.memory.observe_peak(totals.peak_query_memory_bytes)
            } else {
                (None, false)
            };
            (cpu, memory, None, cpu_reset || memory_reset)
        }
        SampleMode::Interval => {
            let ready = baseline.admit_interval();
            (
                capabilities
                    .cpu
                    .then_some(if ready { totals.cpu_time_micros } else { 0 }),
                capabilities.memory.then_some(if ready {
                    totals.peak_query_memory_bytes
                } else {
                    0
                }),
                capabilities.operations.then_some(if ready {
                    totals.operations
                } else {
                    OperationCounts::default()
                }),
                false,
            )
        }
    }
}

#[derive(Debug)]
struct TenantBaseline {
    username: String,
    instance_generation: String,
    cpu: CounterBaseline,
    memory: PeakBaseline,
    /// Query-log rows identify a username, not a DBEV instance generation.
    /// Skip the first interval for a newly seen generation so retained rows
    /// from a deleted tenant with the same username cannot be reassigned.
    interval_ready: bool,
}

impl TenantBaseline {
    fn new(username: &str, instance_generation: &str) -> Self {
        Self {
            username: username.to_string(),
            instance_generation: instance_generation.to_string(),
            cpu: CounterBaseline::default(),
            memory: PeakBaseline::default(),
            interval_ready: false,
        }
    }

    fn admit_interval(&mut self) -> bool {
        let was_ready = self.interval_ready;
        self.interval_ready = true;
        was_ready
    }
}

#[derive(Debug, Default)]
struct CounterBaseline(Option<u64>);

impl CounterBaseline {
    /// A first observation and a counter reset establish a fresh baseline.
    /// Neither can safely be charged as new work to this daemon epoch.
    fn delta(&mut self, current: u64) -> (u64, bool) {
        let reset = self.0.is_some_and(|previous| current < previous);
        let delta = self
            .0
            .and_then(|previous| current.checked_sub(previous))
            .unwrap_or_default();
        self.0 = Some(current);
        (delta, reset)
    }
}

#[derive(Debug, Default)]
struct PeakBaseline(Option<u64>);

impl PeakBaseline {
    fn observe_peak(&mut self, current: u64) -> (Option<u64>, bool) {
        let reset = self.0.is_some_and(|previous| current < previous);
        let observation = match self.0 {
            // MySQL exposes a cumulative engine high-water mark. Its first
            // value can predate this daemon process, so establish a baseline
            // without attributing that historical value to the tenant's live
            // series. A reset likewise starts a new baseline.
            None => None,
            Some(previous) if current > previous => Some(current),
            Some(previous) if current < previous => None,
            Some(_) => None,
        };
        self.0 = Some(current);
        (observation, reset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cumulative_baselines_never_charge_startup_or_resets() {
        let mut cpu = CounterBaseline::default();
        assert_eq!(cpu.delta(100), (0, false));
        assert_eq!(cpu.delta(145), (45, false));
        assert_eq!(cpu.delta(4), (0, true));
        assert_eq!(cpu.delta(11), (7, false));
    }

    #[test]
    fn clickhouse_skips_a_new_generation_then_applies_interval_deltas() {
        let capabilities = Capabilities {
            cpu: true,
            memory: true,
            operations: true,
        };
        let totals = EngineTotals {
            cpu_time_micros: 25,
            peak_query_memory_bytes: 4096,
            operations: OperationCounts {
                read: 2,
                write: 1,
                ddl: 0,
                other: 1,
            },
        };
        let mut baseline = TenantBaseline::new("tenant_a", "generation-a");
        let first = observation_for(
            SampleMode::Interval,
            capabilities,
            totals,
            &mut baseline,
            "tenant_a",
            "generation-a",
        );
        let second = observation_for(
            SampleMode::Interval,
            capabilities,
            totals,
            &mut baseline,
            "tenant_a",
            "generation-a",
        );
        assert_eq!(
            first,
            (Some(0), Some(0), Some(OperationCounts::default()), false)
        );
        assert_eq!(
            second,
            (Some(25), Some(4096), Some(totals.operations), false)
        );
    }

    #[test]
    fn recreated_instance_never_inherits_its_old_engine_baseline() {
        let capabilities = Capabilities {
            cpu: true,
            memory: false,
            operations: false,
        };
        let mut baseline = TenantBaseline::new("same_user", "generation-a");
        assert_eq!(
            observation_for(
                SampleMode::Cumulative,
                capabilities,
                EngineTotals {
                    cpu_time_micros: 100,
                    ..EngineTotals::default()
                },
                &mut baseline,
                "same_user",
                "generation-a",
            )
            .0,
            Some(0)
        );
        assert_eq!(
            observation_for(
                SampleMode::Cumulative,
                capabilities,
                EngineTotals {
                    cpu_time_micros: 160,
                    ..EngineTotals::default()
                },
                &mut baseline,
                "same_user",
                "generation-a",
            )
            .0,
            Some(60)
        );
        assert_eq!(
            observation_for(
                SampleMode::Cumulative,
                capabilities,
                EngineTotals {
                    cpu_time_micros: 200,
                    ..EngineTotals::default()
                },
                &mut baseline,
                "same_user",
                "generation-b",
            )
            .0,
            Some(0)
        );
    }

    #[test]
    fn pool_generation_change_clears_all_runtime_bound_state() {
        let first = ManagedContainerIdentity {
            id: "container-a".to_string(),
            started_at: "2026-09-01T00:00:00Z".to_string(),
        };
        let second = ManagedContainerIdentity {
            id: "container-a".to_string(),
            started_at: "2026-09-01T00:01:00Z".to_string(),
        };
        let mut pool = PoolState::new(Protocol::Mysql);
        assert!(pool.bind_generation(first.clone()));
        pool.prepared = true;
        pool.capabilities.cpu = true;
        pool.baselines.insert(
            "tenant".to_string(),
            TenantBaseline::new("user", "generation"),
        );
        pool.clickhouse_checkpoint = Some(42);
        pool.failures = 3;
        pool.retry_at = Some(Instant::now() + Duration::from_secs(60));

        assert!(!pool.bind_generation(first));
        assert!(pool.prepared);
        assert!(pool.bind_generation(second));
        assert!(!pool.prepared);
        assert_eq!(pool.capabilities, Capabilities::default());
        assert!(pool.baselines.is_empty());
        assert_eq!(pool.clickhouse_checkpoint, None);
        assert_eq!(pool.failures, 0);
        assert_eq!(pool.retry_at, None);
    }

    #[test]
    fn collector_outage_rebaselines_without_charging_the_outage() {
        let capabilities = Capabilities {
            cpu: true,
            memory: false,
            operations: false,
        };
        let mut pool = PoolState::new(Protocol::Mysql);
        let observe = |pool: &mut PoolState, cpu_time_micros| {
            observation_for(
                SampleMode::Cumulative,
                capabilities,
                EngineTotals {
                    cpu_time_micros,
                    ..EngineTotals::default()
                },
                pool.baselines
                    .entry("tenant-a".to_string())
                    .or_insert_with(|| TenantBaseline::new("user-a", "generation-a")),
                "user-a",
                "generation-a",
            )
            .0
        };

        assert_eq!(observe(&mut pool, 100), Some(0));
        assert_eq!(observe(&mut pool, 160), Some(60));
        pool.invalidate_window();
        assert_eq!(observe(&mut pool, 500), Some(0));
        assert_eq!(observe(&mut pool, 520), Some(20));
    }

    #[test]
    fn clickhouse_recreation_keeps_the_pool_window_but_drops_its_baseline() {
        let mut pool = PoolState::new(Protocol::Clickhouse);
        pool.clickhouse_checkpoint = Some(42);
        pool.baselines.insert(
            "same-id".to_string(),
            TenantBaseline::new("same-user", "generation-a"),
        );
        let mut recreated = test_tenant("same-id", "same-user");
        recreated.protocol = Protocol::Clickhouse;
        recreated.created_at = "generation-b".to_string();

        pool.sync_tenants(&[recreated]);
        assert_eq!(pool.clickhouse_checkpoint, Some(42));
        assert!(pool.baselines.is_empty());
    }

    #[test]
    fn clickhouse_tenant_churn_does_not_hide_an_existing_tenants_interval() {
        let capabilities = Capabilities {
            cpu: true,
            memory: true,
            operations: true,
        };
        let totals = EngineTotals {
            cpu_time_micros: 25,
            peak_query_memory_bytes: 4096,
            operations: OperationCounts {
                read: 2,
                write: 1,
                ddl: 0,
                other: 1,
            },
        };
        let mut pool = PoolState::new(Protocol::Clickhouse);
        pool.clickhouse_checkpoint = Some(42);
        let mut existing = TenantBaseline::new("user-a", "generation-a");
        assert!(!existing.admit_interval());
        pool.baselines.insert("tenant-a".to_string(), existing);

        let mut tenant_a = test_tenant("tenant-a", "user-a");
        tenant_a.protocol = Protocol::Clickhouse;
        tenant_a.created_at = "generation-a".to_string();
        let mut tenant_b = test_tenant("tenant-b", "user-b");
        tenant_b.protocol = Protocol::Clickhouse;
        tenant_b.created_at = "generation-b".to_string();
        pool.sync_tenants(&[tenant_a.clone(), tenant_b.clone()]);

        assert_eq!(pool.clickhouse_checkpoint, Some(42));
        let a = observation_for(
            SampleMode::Interval,
            capabilities,
            totals,
            pool.baselines.get_mut("tenant-a").unwrap(),
            &tenant_a.username,
            &tenant_a.created_at,
        );
        let b = observation_for(
            SampleMode::Interval,
            capabilities,
            totals,
            pool.baselines
                .entry("tenant-b".to_string())
                .or_insert_with(|| TenantBaseline::new(&tenant_b.username, &tenant_b.created_at)),
            &tenant_b.username,
            &tenant_b.created_at,
        );

        assert_eq!(a, (Some(25), Some(4096), Some(totals.operations), false));
        assert_eq!(
            b,
            (Some(0), Some(0), Some(OperationCounts::default()), false)
        );
    }

    #[test]
    fn collector_backoff_is_exponential_and_capped() {
        assert_eq!(failure_backoff(1), Duration::from_secs(15));
        assert_eq!(failure_backoff(2), Duration::from_secs(30));
        assert_eq!(failure_backoff(5), Duration::from_secs(240));
        assert_eq!(failure_backoff(7), Duration::from_secs(900));
        assert_eq!(failure_backoff(u32::MAX), Duration::from_secs(900));
    }

    #[test]
    fn peak_baseline_only_reports_new_or_reset_observations() {
        let mut peak = PeakBaseline::default();
        assert_eq!(peak.observe_peak(128), (None, false));
        assert_eq!(peak.observe_peak(128), (None, false));
        assert_eq!(peak.observe_peak(256), (Some(256), false));
        assert_eq!(peak.observe_peak(32), (None, true));
        assert_eq!(peak.observe_peak(64), (Some(64), false));
    }

    #[test]
    fn ambiguous_engine_username_is_not_attributed() {
        let tenants = vec![
            test_tenant("one", "duplicate"),
            test_tenant("two", "duplicate"),
            test_tenant("three", "unique"),
        ];
        let (unique, ambiguous) = split_unique_tenants(tenants, Protocol::Mysql);
        assert_eq!(unique, vec![test_tenant("three", "unique")]);
        assert_eq!(ambiguous.len(), 2);
    }

    #[test]
    fn postgres_and_mongodb_have_no_engine_cpu_collector() {
        for protocol in [Protocol::Postgres, Protocol::Mongodb] {
            let mut runtime = test_runtime(protocol);
            runtime.status = EngineRuntimeStatus::Running;
            assert!(!collects_engine_activity(&runtime));
        }
    }

    fn test_tenant(instance_id: &str, username: &str) -> TenantIdentity {
        TenantIdentity {
            instance_id: instance_id.to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            username: username.to_string(),
            protocol: Protocol::Mysql,
        }
    }

    fn test_runtime(protocol: Protocol) -> EngineRuntime {
        let mut runtime = crate::placement::test_support::runtime("pool_test", protocol, "test");
        runtime.status = EngineRuntimeStatus::Stopped;
        runtime.backend = crate::shared::backend::BackendEndpoint::UnixSocket {
            socket_path: "/tmp/test.sock".to_string(),
        };
        runtime.runtime.container_name = "pool_test".to_string();
        runtime.limits.disk_mib = 1024;
        runtime.limits.disk_enforcement_method = "test".to_string();
        runtime.compatibility_key = "test".to_string();
        runtime.max_tenants = 8;
        runtime.admin_secret = Some("test".to_string());
        runtime
    }
}
