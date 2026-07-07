use axum::{
    Json,
    extract::State,
    http::{HeaderMap, Uri},
};
use serde::Serialize;
use std::net::SocketAddr;

use crate::api::{
    handlers::{ApiError, ApiResult, authorize_scope},
    routes::AppState,
};
use crate::auth::scopes;

#[derive(Debug, Serialize)]
pub struct SystemResponse {
    pub service: &'static str,
    pub version: &'static str,
    pub runtime: &'static str,
    pub uuid: String,
    pub token_id: String,
    pub remote: String,
    pub api_host: String,
    pub api_port: u16,
    pub api_bind: String,
    pub api_ssl_enabled: bool,
    pub daemon_engine: &'static str,
    pub daemon_socket: String,
    pub daemon_network: String,
    pub daemon_internal_network: bool,
    pub daemon_disk_limits_enforced: bool,
    pub daemon_disk_enforcement_method: &'static str,
    pub disk_mode: &'static str,
    pub postgres_enabled: bool,
    pub redis_enabled: bool,
    pub mariadb_enabled: bool,
    pub mongodb_enabled: bool,
    pub clickhouse_enabled: bool,
    pub clickhouse_http_enabled: bool,
    pub clickhouse_http_bind: String,
    pub clickhouse_http_port: u16,
    pub qdrant_enabled: bool,
}

pub async fn system(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<SystemResponse> {
    authorize_scope(&state, &headers, &uri, scopes::SYSTEM_READ)?;
    Ok(Json(SystemResponse {
        service: "databases-everywhere",
        version: env!("CARGO_PKG_VERSION"),
        runtime: state.config.daemon.engine.as_str(),
        uuid: state.config.uuid.clone(),
        token_id: state.config.token_id.clone(),
        remote: state.config.remote.clone(),
        api_host: state.config.api.host.clone(),
        api_port: state.config.api.port,
        api_bind: state.config.api.bind_addr(),
        api_ssl_enabled: state.config.api.ssl.enabled,
        daemon_engine: state.config.daemon.engine.as_str(),
        daemon_socket: state.docker.socket_path().to_string(),
        daemon_network: state.config.daemon.network.clone(),
        daemon_internal_network: state.config.daemon.internal_network,
        daemon_disk_limits_enforced: state.config.disk.mode.enforced(),
        daemon_disk_enforcement_method: state.config.disk.mode.method(),
        disk_mode: state.config.disk.mode.method(),
        postgres_enabled: state.config.postgres.enabled,
        redis_enabled: state.config.redis.enabled,
        mariadb_enabled: state.config.mariadb.enabled,
        mongodb_enabled: state.config.mongodb.enabled,
        clickhouse_enabled: state.config.clickhouse.enabled,
        clickhouse_http_enabled: state.config.clickhouse.enabled,
        clickhouse_http_bind: state.config.clickhouse.http_bind.clone(),
        clickhouse_http_port: clickhouse_http_port(&state.config.clickhouse.http_bind),
        qdrant_enabled: state.config.qdrant.enabled,
    }))
}

fn clickhouse_http_port(bind: &str) -> u16 {
    bind.parse::<SocketAddr>()
        .map(|addr| addr.port())
        .unwrap_or_default()
}

#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    pub status: &'static str,
}

pub async fn heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<HeartbeatResponse>, ApiError> {
    authorize_scope(&state, &headers, &uri, scopes::SYSTEM_READ)?;
    Ok(Json(HeartbeatResponse { status: "ok" }))
}
