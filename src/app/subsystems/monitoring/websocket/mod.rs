pub(crate) mod log_stream;
pub(crate) mod wire;
use log_stream::stream_logs;

use axum::{
    extract::{State, ws::WebSocketUpgrade},
    response::Response,
};
use serde::Deserialize;
use tokio::time::Duration;

use crate::{
    auth::{jwt::Claims, scopes},
    routes::http::{
        limits::{WebSocketAdmissionError, WebSocketConnectionPermit},
        policy::WebSocketRequestContext,
        response::{ApiError, ApiPath, ApiQuery},
        router::AppState,
    },
    subsystems::{
        instances::progress::InstallProgress,
        monitoring::{activity::TenantActivity, resources::ResourceReport},
    },
};

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct LogsQuery {
    #[param(minimum = 1, maximum = 2000, default = 100)]
    pub tail: Option<usize>,
}

#[derive(Debug, Deserialize, Default, Clone, utoipa::IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ImportExportQuery {
    pub job_id: Option<String>,
}

const WEBSOCKET_MAX_MESSAGE_BYTES: usize = 16 * 1024;
const WEBSOCKET_MAX_FRAME_BYTES: usize = 16 * 1024;
const WEBSOCKET_READ_BUFFER_BYTES: usize = 4 * 1024;
const WEBSOCKET_WRITE_BUFFER_BYTES: usize = 16 * 1024;
const WEBSOCKET_MAX_WRITE_BUFFER_BYTES: usize = 256 * 1024;
const MONITORING_BATCH_TARGET_BYTES: usize = 12 * 1024;
const MONITORING_SNAPSHOT_TTL: Duration = Duration::from_millis(400);
const MONITORING_TICK_INTERVAL: Duration = Duration::from_secs(1);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const CLOSE_FRAME_TIMEOUT: Duration = Duration::from_secs(1);
const SEND_TIMEOUT: Duration = Duration::from_secs(5);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(15);
const BATCH_ENVELOPE_BYTES: usize = 256;

mod authorization;
pub(crate) mod import_export;
pub(crate) mod monitoring;
mod socket;
pub(crate) use authorization::BindableGenerations;
use authorization::resolve_instance_authorization;
use import_export::stream_import_export;

pub use monitoring::{MonitoringSnapshotCache, monitoring};
pub(crate) use socket::{
    close_expired_socket, close_replaced_socket, close_shutdown_socket, complete_before,
    jwt_expiration_deadline, send_json_before, wait_for_daemon_shutdown,
};

pub(crate) fn upgrade_websocket(websocket: WebSocketUpgrade) -> WebSocketUpgrade {
    websocket
        .read_buffer_size(WEBSOCKET_READ_BUFFER_BYTES)
        .max_message_size(WEBSOCKET_MAX_MESSAGE_BYTES)
        .max_frame_size(WEBSOCKET_MAX_FRAME_BYTES)
        .write_buffer_size(WEBSOCKET_WRITE_BUFFER_BYTES)
        .max_write_buffer_size(WEBSOCKET_MAX_WRITE_BUFFER_BYTES)
}

#[utoipa::path(
    get,
    path = "/ws/instances/{instance_id}/logs",
    tag = "monitoring",
    summary = "WebSocket stream of container logs for one instance.",
    description = "Requires logs:read on a generation-bound WebSocket JWT. Dedicated instances only; shared logs return 409. API 0.16 sends type=logs with event=reset and sequence=0, then event=append with stream=stdout|stderr and data containing new text only. One Docker follow request delivers the requested tail followed by live output. Append to a bounded client buffer; never replace it for append events. event=end terminates the stream, optionally with a public error. Sequence numbers are per connection. Reconnect clears local sequence state and receives a new reset/tail, not guaranteed lossless history. Complete records are redacted across runtime chunks, then split into UTF-8-safe messages below 16 KiB. An incomplete final secret value is omitted. Records exceeding the 128-KiB redaction budget end the stream with log_record_limit; do not retry that error in a tight loop. Heartbeats use Ping/Pong every 30 seconds and never resend log text. Expiry, shutdown and generation fencing remain enforced.",
    extensions(
        ("x-required-scope" = json!(scopes::LOGS_READ)),
        ("x-websocket" = json!(true)),
        ("x-websocket-message" = json!({"$ref": "#/components/schemas/LogEvent"}))
    ),
    params(("instance_id" = String, Path), LogsQuery),
    responses(
        (status = 101, description = "WebSocket upgrade."),
        (status = 409, description = "Shared-engine logs are pool-wide and cannot be exposed through a tenant-scoped WebSocket."),
    )
)]
pub async fn logs(
    State(state): State<AppState>,
    auth: WebSocketRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<LogsQuery>,
    websocket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let claims = auth.require_scope(scopes::LOGS_READ, Some(&instance_id))?;
    let metadata = state.instances.get(&instance_id).await;
    let progress = state.install_progress.get(&instance_id);
    if metadata.is_none()
        && progress
            .as_ref()
            .and_then(|p| p.creation_generation())
            .is_none()
    {
        return Err(ApiError::NotFound);
    }
    let authorization = resolve_instance_authorization(&state, &claims).await?;
    let target = match metadata {
        Some(metadata) if authorization.allows(&instance_id, &metadata.created_at) => {
            crate::subsystems::instances::check_logs_available(&metadata)?;
            log_stream::LogTarget::Instance {
                instance_id: metadata.instance_id,
                created_at: metadata.created_at,
                protocol: metadata.protocol,
            }
        }
        _ => creating_log_target(&instance_id, progress, &authorization)?,
    };
    let connection = admit_websocket(&state, &claims).await?;
    Ok(upgrade_websocket(websocket)
        .protocols(["dbe.jwt", "bearer"])
        .on_upgrade(move |socket| {
            stream_logs(socket, state, target, query.tail, claims.exp, connection)
        }))
}

fn creating_log_target(
    instance_id: &str,
    progress: Option<InstallProgress>,
    authorization: &authorization::InstanceAuthorization,
) -> Result<log_stream::LogTarget, ApiError> {
    let progress = progress.ok_or(ApiError::Unauthorized)?;
    let generation = progress
        .creation_generation()
        .filter(|generation| authorization.allows(instance_id, generation))
        .ok_or(ApiError::Unauthorized)?;
    if !progress.creates_dedicated_container() {
        return Err(crate::subsystems::instances::shared_logs_unavailable());
    }
    let protocol = progress
        .protocol
        .parse()
        .map_err(|_| ApiError::Runtime("creation progress names an unknown engine".to_string()))?;
    Ok(log_stream::LogTarget::Creating {
        instance_id: instance_id.to_string(),
        generation,
        protocol,
    })
}

#[utoipa::path(
    get,
    path = "/ws/instances/{instance_id}/import-export",
    tag = "import-export",
    summary = "WebSocket stream of import/export jobs for one instance.",
    description = "Requires a short-lived WebSocket JWT with import-export:read and access to the instance in the path. Messages and frames are limited to 16 KiB.",
    extensions(
        ("x-required-scope" = json!(scopes::IMPORT_EXPORT_READ)),
        ("x-websocket" = json!(true)),
        ("x-websocket-message" = json!({"oneOf": [
            {"$ref": "#/components/schemas/ImportExportSnapshot"},
            {"$ref": "#/components/schemas/ImportExportJobEvent"},
            {"$ref": "#/components/schemas/ImportExportLaggedEvent"}
        ]}))
    ),
    params(("instance_id" = String, Path), ImportExportQuery),
    responses((status = 101, description = "WebSocket upgrade."))
)]
pub async fn import_export(
    State(state): State<AppState>,
    auth: WebSocketRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<ImportExportQuery>,
    websocket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let claims = auth.require_scope(scopes::IMPORT_EXPORT_READ, Some(&instance_id))?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let authorization = resolve_instance_authorization(&state, &claims).await?;
    if !authorization.allows(&instance_id, &metadata.created_at) {
        return Err(ApiError::Unauthorized);
    }
    let instance_generation = metadata.created_at;
    let connection = admit_websocket(&state, &claims).await?;
    Ok(upgrade_websocket(websocket)
        .protocols(["dbe.jwt", "bearer"])
        .on_upgrade(move |socket| {
            stream_import_export(
                socket,
                state,
                instance_id,
                instance_generation,
                query,
                claims,
                connection,
            )
        }))
}

pub(crate) async fn admit_websocket(
    state: &AppState,
    claims: &Claims,
) -> Result<WebSocketConnectionPermit, ApiError> {
    if state.daemon_shutdown.is_triggered() {
        return Err(ApiError::ServiceUnavailable(
            "daemon shutdown is in progress".to_string(),
        ));
    }
    match state
        .api_rate_limiter
        .admit_websocket(&claims.jti, claims.exp)
        .await
    {
        Ok(connection) => Ok(connection),
        Err(WebSocketAdmissionError::Replay | WebSocketAdmissionError::Expired) => {
            tracing::warn!(subject = %claims.sub, "audit websocket_token_rejected");
            Err(ApiError::Unauthorized)
        }
        Err(
            WebSocketAdmissionError::TokenCapacity | WebSocketAdmissionError::ConnectionCapacity,
        ) => {
            tracing::warn!(subject = %claims.sub, "audit websocket_capacity_reached");
            Err(ApiError::RateLimited)
        }
    }
}

#[cfg(test)]
mod tests;
