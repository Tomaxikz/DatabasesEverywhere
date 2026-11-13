use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::{
    auth::scopes,
    databases::protocol::Protocol,
    routes::http::{
        policy::ApiRequestContext,
        response::{ApiError, ApiPath, ApiQuery, ApiResponse, ApiResult},
        router::AppState,
    },
    server::monitoring::{ActivityBucket, ActivityCurrent},
    server::placement::DeploymentMode,
    storage::activity::MAX_HISTORY_ROWS,
    utils::time::now_unix,
};

const DEFAULT_HISTORY_ROWS: u16 = 240;

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TenantActivity {
    #[serde(flatten)]
    #[schema(inline)]
    pub current: ActivityCurrent,
    #[schema(inline)]
    pub sources: ActivitySources,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ActivitySources {
    #[schema(schema_with = crate::routes::openapi::literals::connections_source)]
    pub connections: &'static str,
    #[schema(schema_with = crate::routes::openapi::literals::network_source)]
    pub network: &'static str,
    #[schema(schema_with = crate::routes::openapi::literals::operations_source)]
    pub operations: &'static str,
    #[schema(schema_with = crate::routes::openapi::literals::engine_query_source)]
    pub cpu_time: &'static str,
    #[schema(schema_with = crate::routes::openapi::literals::engine_query_source)]
    pub peak_query_memory: &'static str,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ActivityHistory {
    pub instance_id: String,
    #[schema(schema_with = crate::routes::openapi::literals::bucket_seconds)]
    pub bucket_seconds: i64,
    #[schema(schema_with = crate::routes::openapi::literals::max_buckets)]
    pub max_buckets: u16,
    #[schema(max_items = 1440)]
    pub buckets: Vec<ActivityBucket>,
}

#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
#[serde(default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct HistoryQuery {
    pub before: Option<i64>,
    #[param(minimum = 1, maximum = 1440, default = 240)]
    pub limit: Option<u16>,
}

#[utoipa::path(
    get,
    path = "/api/instances/{instance_id}/activity",
    tag = "monitoring",
    summary = "Get current tenant-attributed gateway and query activity.",
    description = "Returns cumulative gateway counters plus explicitly source-labelled engine observations. For gateway sources, accepted means forwarded by DBEV rather than successfully executed, and rejected includes only DBEV pre-backend rejections. It never returns SQL text, bind values, client addresses, errors, or whole-pool CPU/RAM as tenant usage.",
    extensions(("x-required-scope" = json!(scopes::RESOURCES_READ))),
    params(("instance_id" = String, Path)),
    responses((status = 200, description = "Current tenant activity.", body = TenantActivity))
)]
pub async fn current(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<TenantActivity> {
    auth.require_scope(scopes::RESOURCES_READ)?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    Ok(ApiResponse::ok(tenant_activity(&state, &metadata).await))
}

#[utoipa::path(
    get,
    path = "/api/instances/{instance_id}/activity/history",
    tag = "monitoring",
    summary = "Get rolling tenant activity history.",
    description = "Returns at most 1440 aggregate buckets in chronological order on a target 60-second cadence. If sampling is delayed, one bucket covers the complete elapsed interval and duration_seconds is authoritative. before is an exclusive Unix timestamp for backwards pagination. DBEV persists only aggregate counters in SQLite and never exposes SQL text, bind values, client addresses, or engine errors through this API. Shared ClickHouse pools temporarily retain a protected, size-bounded system.query_log so the daemon can derive aggregates. It has a two-hour asynchronous TTL target and a finite per-tenant query quota; tenant roles cannot read it or alter the required logging settings.",
    extensions(("x-required-scope" = json!(scopes::RESOURCES_READ))),
    params(("instance_id" = String, Path), HistoryQuery),
    responses((status = 200, description = "Rolling activity history.", body = ActivityHistory))
)]
pub async fn history(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<HistoryQuery>,
) -> ApiResult<ActivityHistory> {
    auth.require_scope(scopes::RESOURCES_READ)?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let limit = history_limit(query.limit)?;
    let buckets = state
        .resource_cache
        .activity_history(&instance_id, &metadata.created_at, query.before, limit)
        .await
        .map_err(ApiError::runtime_context("failed to load activity history"))?;
    Ok(ApiResponse::ok(ActivityHistory {
        instance_id,
        bucket_seconds: crate::server::monitoring::BUCKET_SECONDS,
        max_buckets: MAX_HISTORY_ROWS,
        buckets,
    }))
}

fn history_limit(limit: Option<u16>) -> Result<u16, ApiError> {
    let limit = limit.unwrap_or(DEFAULT_HISTORY_ROWS);
    if !(1..=MAX_HISTORY_ROWS).contains(&limit) {
        return Err(ApiError::BadRequest(format!(
            "limit must be between 1 and {MAX_HISTORY_ROWS}"
        )));
    }
    Ok(limit)
}

pub(crate) async fn tenant_activity(
    state: &AppState,
    metadata: &crate::server::metadata::InstanceMetadata,
) -> TenantActivity {
    let current = state
        .resource_cache
        .current_activity(&metadata.instance_id, &metadata.created_at, now_unix())
        .await;
    TenantActivity {
        sources: sources(metadata.protocol, metadata.deployment_mode, &current),
        current,
    }
}

fn sources(
    protocol: Protocol,
    deployment_mode: DeploymentMode,
    current: &ActivityCurrent,
) -> ActivitySources {
    let shared_clickhouse_measured = protocol.engine().telemetry_reports_operations()
        && deployment_mode == DeploymentMode::Shared
        && current.operations_measured;
    let (connections, operations) = if gateway_ops_available(protocol) {
        ("gateway_authenticated_exact", "gateway_protocol_observed")
    } else if shared_clickhouse_measured {
        ("unavailable", "engine_query_log_observed")
    } else {
        ("unavailable", "unavailable")
    };
    ActivitySources {
        connections,
        network: "gateway_route_exact",
        operations,
        cpu_time: engine_query_source(current.cpu_time_micros.is_some()),
        peak_query_memory: engine_query_source(current.peak_query_memory_bytes.is_some()),
    }
}

const fn engine_query_source(observed: bool) -> &'static str {
    if observed {
        "engine_query_observed"
    } else {
        "unavailable"
    }
}

pub(crate) fn gateway_ops_available(protocol: Protocol) -> bool {
    protocol.engine().gateway_counts_operations()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::monitoring::OperationCounts;
    use axum::{extract::FromRequestParts, http::Request};

    fn current(cpu: Option<u64>, memory: Option<u64>) -> ActivityCurrent {
        ActivityCurrent {
            instance_id: "tenant-a".to_string(),
            stats_epoch: "epoch-a".to_string(),
            sampled_at_unix: 1,
            accepted: OperationCounts::default(),
            operations_measured: false,
            rejected: OperationCounts::default(),
            active_connections: 0,
            opened_connections: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            cpu_time_micros: cpu,
            peak_query_memory_bytes: memory,
        }
    }

    #[test]
    fn sources_do_not_claim_unmeasured_tenant_cpu_or_memory() {
        let postgres_sources = sources(
            Protocol::Postgres,
            DeploymentMode::Shared,
            &current(None, None),
        );
        assert_eq!(postgres_sources.connections, "gateway_authenticated_exact");
        assert_eq!(postgres_sources.cpu_time, "unavailable");
        assert_eq!(postgres_sources.peak_query_memory, "unavailable");

        let mut clickhouse = current(Some(0), Some(0));
        clickhouse.operations_measured = true;
        let clickhouse_sources = sources(Protocol::Clickhouse, DeploymentMode::Shared, &clickhouse);
        assert_eq!(clickhouse_sources.connections, "unavailable");
        assert_eq!(clickhouse_sources.operations, "engine_query_log_observed");
        assert_eq!(clickhouse_sources.cpu_time, "engine_query_observed");
        assert_eq!(
            clickhouse_sources.peak_query_memory,
            "engine_query_observed"
        );

        let dedicated = sources(Protocol::Clickhouse, DeploymentMode::Dedicated, &clickhouse);
        assert_eq!(dedicated.operations, "unavailable");
    }

    #[tokio::test]
    async fn history_query_rejects_unknown_and_overflowing_values() {
        for uri in [
            "/activity/history?unknown=1",
            "/activity/history?limit=70000",
        ] {
            let request = Request::builder().uri(uri).body(()).unwrap();
            let (mut parts, _) = request.into_parts();
            let error = ApiQuery::<HistoryQuery>::from_request_parts(&mut parts, &())
                .await
                .unwrap_err();
            assert_eq!(error.status(), axum::http::StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn history_limit_matches_the_published_bounds() {
        assert!(history_limit(Some(0)).is_err());
        assert_eq!(history_limit(None).unwrap(), DEFAULT_HISTORY_ROWS);
        assert_eq!(
            history_limit(Some(MAX_HISTORY_ROWS)).unwrap(),
            MAX_HISTORY_ROWS
        );
    }
}
