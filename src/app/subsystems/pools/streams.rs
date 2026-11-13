use crate::{
    auth::{
        jwt::{Claims, PoolGrant},
        scopes,
    },
    routes::http::{
        policy::{ApiRequestContext, WebSocketRequestContext},
        response::{ApiError, ApiPath, ApiQuery, ApiResponse, ApiResult},
        router::AppState,
    },
    server::placement::EngineRuntime,
    subsystems::{
        instances::LogsQuery,
        monitoring::{
            resources::{SharedPoolReport, pool_reports},
            websocket::{
                self,
                log_stream::{LogTarget, stream_logs},
                wire::ProgressCursor,
            },
        },
    },
};
use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::Response,
};
use serde::Serialize;
use tokio::time::{Duration, Instant, MissedTickBehavior, interval, sleep_until};

const MAX_POOL_STATS_MESSAGE_BYTES: usize = 16 * 1024;

fn grant_for(claims: &Claims, pool: &EngineRuntime) -> Result<PoolGrant, ApiError> {
    if claims.all_instances || !claims.instances.is_empty() {
        return Err(ApiError::Unauthorized);
    }
    claims
        .pools
        .iter()
        .find(|grant| grant.matches(pool))
        .cloned()
        .ok_or(ApiError::Unauthorized)
}

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PoolLogs {
    runtime_id: String,
    stdout: String,
    stderr: String,
}

#[utoipa::path(
    get,
    path = "/api/pools/{runtime_id}/logs",
    tag = "pools",
    summary = "Read recent redacted pool logs.",
    description = "Read recent redacted pool logs.",
    extensions(("x-required-scope" = json!(scopes::POOLS_LOGS))),
    params(("runtime_id" = String, Path), LogsQuery),
    responses((status = 200, description = "Operation result.", body = PoolLogs))
)]
pub(crate) async fn logs(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(id): ApiPath<String>,
    ApiQuery(query): ApiQuery<LogsQuery>,
) -> ApiResult<PoolLogs> {
    auth.require_scope(scopes::POOLS_LOGS)?;
    let pool = super::load(&state, &id).await?;
    let logs = state
        .docker
        .logs(pool.protocol, &id, query.tail)
        .await
        .map_err(ApiError::runtime)?;
    Ok(ApiResponse::ok(PoolLogs {
        runtime_id: id,
        stdout: crate::utils::redaction::redact_connection_url(&logs.stdout),
        stderr: crate::utils::redaction::redact_connection_url(&logs.stderr),
    }))
}

#[utoipa::path(
    get,
    path = "/ws/pools/{runtime_id}/logs",
    tag = "pools",
    summary = "Stream whole-pool logs.",
    description = "Requires an owner-and-generation-bound pools:logs JWT, not logs:read. Pool-wide logs can contain data from every child database. Same reset/append/end protocol as dedicated logs, with runtime_id instead of instance_id. Reconnect with a fresh one-use JWT. No query-token authentication.",
    extensions(
        ("x-required-scope" = json!(scopes::POOLS_LOGS)),
        ("x-websocket" = json!(true)),
        ("x-websocket-message" = json!({"$ref": "#/components/schemas/PoolLogEvent"}))
    ),
    params(("runtime_id" = String, Path), websocket::LogsQuery),
    responses((status = 101, description = "WebSocket upgrade."))
)]
pub(crate) async fn log_socket(
    State(state): State<AppState>,
    auth: WebSocketRequestContext,
    ApiPath(id): ApiPath<String>,
    ApiQuery(query): ApiQuery<websocket::LogsQuery>,
    socket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let claims = auth.require_scope(scopes::POOLS_LOGS, None)?;
    let pool = super::load(&state, &id).await?;
    let grant = grant_for(&claims, &pool)?;
    let permit = websocket::admit_websocket(&state, &claims).await?;
    Ok(websocket::upgrade_websocket(socket)
        .protocols(["dbe.jwt", "bearer"])
        .on_upgrade(move |socket| {
            stream_logs(
                socket,
                state,
                LogTarget::Pool {
                    grant,
                    protocol: pool.protocol,
                },
                query.tail,
                claims.exp,
                permit,
            )
        }))
}

#[utoipa::path(
    get,
    path = "/ws/pools/{runtime_id}/monitoring",
    tag = "pools",
    summary = "Stream whole-pool metrics.",
    description = "Requires an owner-and-generation-bound pools:monitor JWT minted with pools plus server_id. No instance token grants this access. Sends one unbatched pool_stats snapshot per second; progress is change-only. Merge reset/removals/updates and reconnect with a fresh one-use JWT after a sequence gap. Values are already percentage points/bytes; keep null and sample freshness.",
    extensions(
        ("x-required-scope" = json!(scopes::POOLS_MONITOR)),
        ("x-websocket" = json!(true)),
        ("x-websocket-message" = json!({"$ref": "#/components/schemas/PoolStats"}))
    ),
    params(("runtime_id" = String, Path)),
    responses((status = 101, description = "WebSocket upgrade."))
)]
pub(crate) async fn monitoring(
    State(state): State<AppState>,
    auth: WebSocketRequestContext,
    ApiPath(id): ApiPath<String>,
    socket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let claims = auth.require_scope(scopes::POOLS_MONITOR, None)?;
    let pool = super::load(&state, &id).await?;
    let grant = grant_for(&claims, &pool)?;
    let permit = websocket::admit_websocket(&state, &claims).await?;
    Ok(websocket::upgrade_websocket(socket)
        .protocols(["dbe.jwt", "bearer"])
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            monitor(socket, state, grant, claims.exp).await;
        }))
}

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PoolStats<'a> {
    #[schema(schema_with = crate::routes::openapi::literals::pool_stats)]
    r#type: &'static str,
    #[schema(minimum = 1)]
    sequence: u64,
    sampled_at_unix: i64,
    pool: SharedPoolReport,
    progress_reset: bool,
    install_progress: Vec<&'a crate::subsystems::instances::progress::InstallProgress>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    install_progress_removed: Vec<String>,
}

async fn monitor(mut socket: WebSocket, state: AppState, grant: PoolGrant, exp: i64) {
    let _monitor = state.resource_cache.register_monitor();
    let mut shutdown = state.daemon_shutdown.subscribe();
    let deadline = websocket::jwt_expiration_deadline(exp);
    let expiration = sleep_until(deadline);
    tokio::pin!(expiration);
    let mut timer = interval(Duration::from_secs(1));
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut sequence = 0_u64;
    let mut cursor = ProgressCursor::default();
    loop {
        tokio::select! {
            _ = websocket::wait_for_daemon_shutdown(&mut shutdown) => {
                websocket::close_shutdown_socket(&mut socket).await;
                break;
            }
            _ = &mut expiration => {
                websocket::close_expired_socket(&mut socket).await;
                break;
            }
            incoming = socket.recv() => {
                if matches!(incoming, None | Some(Err(_)) | Some(Ok(Message::Close(_)))) {
                    break;
                }
            }
            _ = timer.tick() => {
                let keep_streaming = send_pool_stats(
                    &mut socket,
                    &state,
                    &grant,
                    &mut cursor,
                    &mut sequence,
                    deadline,
                )
                .await;
                if !keep_streaming {
                    break;
                }
            }
        }
    }
}

async fn send_pool_stats(
    socket: &mut WebSocket,
    state: &AppState,
    grant: &PoolGrant,
    cursor: &mut ProgressCursor,
    sequence: &mut u64,
    deadline: Instant,
) -> bool {
    let Ok(Ok(pool)) =
        websocket::complete_before(deadline, super::load(state, &grant.runtime_id)).await
    else {
        return false;
    };
    if !grant.matches(&pool) {
        websocket::close_replaced_socket(socket).await;
        return false;
    }
    let Ok(Ok(mut reports)) =
        websocket::complete_before(deadline, pool_reports(state, std::slice::from_ref(&pool)))
            .await
    else {
        return false;
    };
    let Some(report) = reports.pop() else {
        return false;
    };
    let progress = state.install_progress.get(&pool.runtime_id);
    let updates = cursor.select(&progress.iter().collect::<Vec<_>>());
    *sequence += 1;
    let event = PoolStats {
        r#type: "pool_stats",
        sequence: *sequence,
        sampled_at_unix: crate::utils::time::now_unix(),
        pool: report,
        progress_reset: updates.reset,
        install_progress: updates.updates,
        install_progress_removed: updates.removed,
    };
    let Ok(Ok(current)) =
        websocket::complete_before(deadline, super::load(state, &grant.runtime_id)).await
    else {
        return false;
    };
    if !grant.matches(&current) {
        return false;
    }
    let fits_message_limit =
        serde_json::to_vec(&event).is_ok_and(|body| body.len() <= MAX_POOL_STATS_MESSAGE_BYTES);
    if !fits_message_limit {
        return false;
    }
    websocket::send_json_before(socket, &event, deadline)
        .await
        .is_ok()
}

#[utoipa::path(
    get,
    path = "/api/pools/{runtime_id}/backups",
    tag = "pools",
    summary = "List backups of the pool's databases.",
    description = "Lists existing per-database backups for this pool. Requires pools:read and backups:read. These remain independent backups, not a simultaneous whole-engine snapshot.",
    extensions(("x-required-scope" = json!(scopes::POOLS_READ))),
    params(("runtime_id" = String, Path)),
    responses((status = 200, description = "Operation result.", body = Vec<crate::subsystems::backups::BackupInfo>))
)]
pub(crate) async fn backups(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Vec<crate::subsystems::backups::BackupInfo>> {
    auth.require_scope(scopes::POOLS_READ)?;
    auth.require_scope(scopes::BACKUPS_READ)?;
    let pool = super::load(&state, &id).await?;
    let tenants = super::tenants(&state, &pool).await?;
    let mut records = Vec::new();
    for instance in tenants {
        records.extend(
            crate::subsystems::backups::list_instance_backups(
                State(state.clone()),
                auth.clone(),
                ApiPath(instance.instance_id),
            )
            .await?
            .into_body(),
        );
    }
    Ok(ApiResponse::ok(records))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pool_grants_are_bound_to_owner_and_generation() {
        let pool = crate::server::placement::test_support::runtime(
            "pool-one",
            crate::databases::protocol::Protocol::Mysql,
            "mysql:8.4",
        );
        let mut grant = PoolGrant {
            runtime_id: pool.runtime_id.clone(),
            created_at: pool.created_at.clone(),
            owner: pool.owner.clone().unwrap(),
        };
        assert!(grant.matches(&pool));
        grant.owner.server_id = "other-server".into();
        assert!(!grant.matches(&pool));
        grant.owner = pool.owner.clone().unwrap();
        grant.created_at = "different-generation".into();
        assert!(!grant.matches(&pool));
    }
}
