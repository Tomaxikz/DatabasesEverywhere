use crate::{
    api::{
        http::{
            policy::{ApiRequestContext, WebSocketRequestContext},
            response::{ApiError, ApiPath, ApiQuery, ApiResponse, ApiResult},
            router::AppState,
        },
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
    auth::{
        jwt::{Claims, PoolGrant},
        scopes,
    },
    placement::EngineRuntime,
};
use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::Response,
};
use serde::Serialize;
use tokio::time::{Duration, MissedTickBehavior, interval, sleep_until};

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

pub(crate) async fn logs(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(id): ApiPath<String>,
    ApiQuery(query): ApiQuery<LogsQuery>,
) -> ApiResult<serde_json::Value> {
    auth.require_scope(scopes::POOLS_LOGS)?;
    let pool = super::load(&state, &id).await?;
    let logs = state
        .docker
        .logs(pool.protocol, &id, query.tail)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    Ok(ApiResponse::ok(serde_json::json!({"runtime_id":id,
        "stdout":crate::shared::redaction::redact_connection_url(&logs.stdout),
        "stderr":crate::shared::redaction::redact_connection_url(&logs.stderr)})))
}

pub(crate) async fn log_socket(
    State(state): State<AppState>,
    auth: WebSocketRequestContext,
    ApiPath(id): ApiPath<String>,
    ApiQuery(query): ApiQuery<LogsQuery>,
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

#[derive(Serialize)]
struct PoolStats<'a> {
    r#type: &'static str,
    sequence: u64,
    sampled_at_unix: i64,
    pool: SharedPoolReport,
    progress_reset: bool,
    install_progress: Vec<&'a crate::api::instances::progress::InstallProgress>,
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
            _ = websocket::wait_for_daemon_shutdown(&mut shutdown) => { websocket::close_shutdown_socket(&mut socket).await; break; }
            _ = &mut expiration => { websocket::close_expired_socket(&mut socket).await; break; }
            incoming = socket.recv() => {
                if matches!(incoming, None | Some(Err(_)) | Some(Ok(Message::Close(_)))) { break; }
            }
            _ = timer.tick() => {
                let Ok(Ok(pool)) = websocket::complete_before(deadline, super::load(&state, &grant.runtime_id)).await else { break; };
                if !grant.matches(&pool) { websocket::close_replaced_socket(&mut socket).await; break; }
                let Ok(Ok(mut reports)) = websocket::complete_before(deadline, pool_reports(&state, std::slice::from_ref(&pool))).await else { break; };
                let Some(report) = reports.pop() else { break; };
                let progress = state.install_progress.get(&pool.runtime_id);
                let updates = cursor.select(&progress.iter().collect::<Vec<_>>());
                sequence += 1;
                let event = PoolStats { r#type:"pool_stats", sequence, sampled_at_unix:crate::shared::time::now_unix(), pool:report, progress_reset:updates.reset, install_progress:updates.updates, install_progress_removed:updates.removed };
                let Ok(Ok(current)) = websocket::complete_before(deadline, super::load(&state, &grant.runtime_id)).await else { break; };
                if !grant.matches(&current) { break; }
                if serde_json::to_vec(&event).map_or(true, |body| body.len() > 16 * 1024) { break; }
                if websocket::send_json_before(&mut socket, &event, deadline).await.is_err() { break; }
            }
        }
    }
}

pub(crate) async fn backups(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Vec<crate::api::backups::BackupInfo>> {
    auth.require_scope(scopes::POOLS_READ)?;
    auth.require_scope(scopes::BACKUPS_READ)?;
    let pool = super::load(&state, &id).await?;
    let tenants = super::tenants(&state, &pool).await?;
    let mut records = Vec::new();
    for instance in tenants {
        records.extend(
            crate::api::backups::list_instance_backups(
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
        let pool = crate::placement::test_support::runtime(
            "pool-one",
            crate::shared::protocol::Protocol::Mysql,
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
