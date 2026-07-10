use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;
use std::net::SocketAddr;

use crate::api::{
    api_response::{ApiResponse, ApiResult},
    routes::AppState,
    security_policy::ApiRequestContext,
};
use crate::auth::scopes;

// API compatibility is versioned independently from the daemon binary release.
pub const API_VERSION: &str = "0.2.0";

#[derive(Debug, Serialize)]
pub struct SystemResponse {
    pub service: &'static str,
    pub version: &'static str,
    pub api_version: &'static str,
    pub uuid: String,
    pub token_id: String,
    pub remote: String,
    pub api_host: String,
    pub api_port: u16,
    pub api_bind: String,
    pub api_ssl_enabled: bool,
    pub daemon_engine: &'static str,
    pub daemon_socket: String,
    pub database_container_network_mode: &'static str,
    pub database_backend_transport: &'static str,
    pub daemon_disk_limits_enforced: bool,
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
    auth: ApiRequestContext,
) -> ApiResult<SystemResponse> {
    auth.require_scope(scopes::SYSTEM_READ)?;
    Ok(ApiResponse::ok(SystemResponse {
        service: "databases-everywhere",
        version: env!("CARGO_PKG_VERSION"),
        api_version: API_VERSION,
        uuid: state.config.uuid.clone(),
        token_id: state.config.token_id.clone(),
        remote: state.config.remote.clone(),
        api_host: state.config.api.host.clone(),
        api_port: state.config.api.port,
        api_bind: state.config.api.bind_addr(),
        api_ssl_enabled: state.config.api.ssl.enabled,
        daemon_engine: state.config.daemon.engine.as_str(),
        daemon_socket: state.docker.socket_path().to_string(),
        database_container_network_mode: "none",
        database_backend_transport: "unix_socket",
        daemon_disk_limits_enforced: state.config.disk.mode.enforced(),
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
    pub gateways: crate::gateway::supervisor::GatewayReadinessSnapshot,
}

pub async fn heartbeat(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<HeartbeatResponse> {
    auth.require_scope(scopes::SYSTEM_READ)?;
    let gateways = state.gateway_supervisor.snapshot();
    let ready = state.gateway_supervisor.is_ready();
    let response = HeartbeatResponse {
        status: if ready { "ok" } else { "not_ready" },
        gateways,
    };
    Ok(if ready {
        ApiResponse::ok(response)
    } else {
        ApiResponse::with_status(StatusCode::SERVICE_UNAVAILABLE, response)
    })
}
