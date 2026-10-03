pub(crate) mod log_stream;
pub(crate) mod wire;
use log_stream::stream_logs;

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{
        State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code},
    },
    response::Response,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast};
use tokio::time::{
    Duration, Instant, MissedTickBehavior, interval, interval_at, sleep_until, timeout_at,
};

use crate::{
    auth::{
        jwt::{self, Claims},
        scopes,
    },
    routes::http::{
        diagnostics::PublicDiagnostic,
        limits::{WebSocketAdmissionError, WebSocketConnectionPermit},
        policy::WebSocketRequestContext,
        response::{ApiError, ApiPath, ApiQuery},
        router::AppState,
    },
    server::jobs::import_export::{ImportExportAction, ImportExportJob, ImportExportStatus},
    server::metadata::InstanceMetadata,
    subsystems::{
        artifacts::{DownloadUrlResponse, artifact_download_url},
        import_export::{ImportExportJobResponse, public_job_response},
        instances::progress::InstallProgress,
        monitoring::{
            activity::{TenantActivity, tenant_activity},
            resources::{ResourceReport, ResourceScope, ResourceView, resource_report},
        },
    },
    utils::time::now_unix,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogsQuery {
    pub tail: Option<usize>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
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
mod import_export;
mod monitoring;
mod socket;
use authorization::*;
use import_export::*;
pub use monitoring::*;
pub(crate) use socket::*;

pub(crate) fn upgrade_websocket(websocket: WebSocketUpgrade) -> WebSocketUpgrade {
    websocket
        // Incoming traffic is mostly small controls/pings. Larger permitted
        // frames are still assembled, with unchanged frame/message limits.
        .read_buffer_size(WEBSOCKET_READ_BUFFER_BYTES)
        .max_message_size(WEBSOCKET_MAX_MESSAGE_BYTES)
        .max_frame_size(WEBSOCKET_MAX_FRAME_BYTES)
        .write_buffer_size(WEBSOCKET_WRITE_BUFFER_BYTES)
        .max_write_buffer_size(WEBSOCKET_MAX_WRITE_BUFFER_BYTES)
}

pub async fn logs(
    State(state): State<AppState>,
    auth: WebSocketRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<LogsQuery>,
    websocket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let claims = auth.require_scope(scopes::LOGS_READ, Some(&instance_id))?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let authorization = resolve_instance_authorization(&state, &claims).await?;
    if !authorization.allows(&instance_id, &metadata.created_at) {
        return Err(ApiError::Unauthorized);
    }
    crate::subsystems::instances::check_logs_available(&metadata)?;
    let connection = admit_websocket(&state, &claims).await?;
    Ok(upgrade_websocket(websocket)
        .protocols(["dbe.jwt", "bearer"])
        .on_upgrade(move |socket| {
            stream_logs(
                socket,
                state,
                log_stream::LogTarget::Instance {
                    instance_id: metadata.instance_id,
                    created_at: metadata.created_at,
                    protocol: metadata.protocol,
                },
                query.tail,
                claims.exp,
                connection,
            )
        }))
}

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
