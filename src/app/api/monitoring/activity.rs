use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::{
    api::http::{
        policy::ApiRequestContext,
        response::{ApiError, ApiPath, ApiQuery, ApiResponse, ApiResult},
        router::AppState,
    },
    auth::scopes,
    monitoring::{ActivityBucket, ActivityCurrent},
    placement::DeploymentMode,
    shared::{protocol::Protocol, time::now_unix},
    storage::activity::MAX_HISTORY_ROWS,
};

const DEFAULT_HISTORY_ROWS: u16 = 240;

#[derive(Debug, Serialize)]
pub struct TenantActivity {
    #[serde(flatten)]
    pub current: ActivityCurrent,
    pub sources: ActivitySources,
}

#[derive(Debug, Serialize)]
pub struct ActivitySources {
    pub connections: &'static str,
    pub network: &'static str,
    pub operations: &'static str,
    pub cpu_time: &'static str,
    pub peak_query_memory: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ActivityHistory {
    pub instance_id: String,
    pub bucket_seconds: i64,
    pub max_buckets: u16,
    pub buckets: Vec<ActivityBucket>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistoryQuery {
    pub before: Option<i64>,
    pub limit: Option<u16>,
}

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
        .map_err(|error| ApiError::Runtime(format!("failed to load activity history: {error}")))?;
    Ok(ApiResponse::ok(ActivityHistory {
        instance_id,
        bucket_seconds: crate::monitoring::BUCKET_SECONDS,
        max_buckets: MAX_HISTORY_ROWS,
        buckets,
    }))
}

fn history_limit(limit: Option<u16>) -> Result<u16, ApiError> {
    let limit = limit.unwrap_or(DEFAULT_HISTORY_ROWS);
    (1..=MAX_HISTORY_ROWS)
        .contains(&limit)
        .then_some(limit)
        .ok_or_else(|| {
            ApiError::BadRequest(format!("limit must be between 1 and {MAX_HISTORY_ROWS}"))
        })
}

pub(crate) async fn tenant_activity(
    state: &AppState,
    metadata: &crate::instances::metadata::InstanceMetadata,
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
    let (connections, operations) = if gateway_ops_available(protocol) {
        ("gateway_authenticated_exact", "gateway_protocol_observed")
    } else if protocol == Protocol::Clickhouse
        && deployment_mode == DeploymentMode::Shared
        && current.operations_measured
    {
        ("unavailable", "engine_query_log_observed")
    } else {
        ("unavailable", "unavailable")
    };
    ActivitySources {
        connections,
        network: "gateway_route_exact",
        operations,
        cpu_time: if current.cpu_time_micros.is_some() {
            "engine_query_observed"
        } else {
            "unavailable"
        },
        peak_query_memory: if current.peak_query_memory_bytes.is_some() {
            "engine_query_observed"
        } else {
            "unavailable"
        },
    }
}

pub(crate) const fn gateway_ops_available(protocol: Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Postgres | Protocol::Mysql | Protocol::Mariadb | Protocol::Mongodb
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitoring::OperationCounts;
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

    #[test]
    fn gateway_operation_sources_match_instrumented_protocols() {
        for protocol in [
            Protocol::Postgres,
            Protocol::Mysql,
            Protocol::Mariadb,
            Protocol::Mongodb,
        ] {
            assert!(gateway_ops_available(protocol), "{protocol}");
        }
        for protocol in [
            Protocol::Clickhouse,
            Protocol::Redis,
            Protocol::Valkey,
            Protocol::Qdrant,
        ] {
            assert!(!gateway_ops_available(protocol), "{protocol}");
        }
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
