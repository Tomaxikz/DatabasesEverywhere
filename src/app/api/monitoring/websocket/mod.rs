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
    api::{
        artifacts::{DownloadUrlResponse, artifact_download_url},
        http::{
            diagnostics::PublicDiagnostic,
            limits::{WebSocketAdmissionError, WebSocketConnectionPermit},
            policy::WebSocketRequestContext,
            response::{ApiError, ApiPath, ApiQuery},
            router::AppState,
        },
        import_export::{ImportExportJobResponse, public_job_response},
        instances::progress::InstallProgress,
        monitoring::{
            activity::{TenantActivity, tenant_activity},
            resources::{ResourceReport, ResourceScope, ResourceView, resource_report},
        },
    },
    auth::{
        jwt::{self, Claims},
        scopes,
    },
    instances::metadata::InstanceMetadata,
    jobs::import_export::{ImportExportAction, ImportExportJob, ImportExportStatus},
    shared::{redaction, time::now_unix},
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
const WEBSOCKET_WRITE_BUFFER_BYTES: usize = 32 * 1024;
const WEBSOCKET_MAX_WRITE_BUFFER_BYTES: usize = 256 * 1024;
const MONITORING_BATCH_TARGET_BYTES: usize = 12 * 1024;
const MONITORING_SNAPSHOT_TTL: Duration = Duration::from_millis(400);

fn upgrade_websocket(websocket: WebSocketUpgrade) -> WebSocketUpgrade {
    websocket
        .max_message_size(WEBSOCKET_MAX_MESSAGE_BYTES)
        .max_frame_size(WEBSOCKET_MAX_FRAME_BYTES)
        .write_buffer_size(WEBSOCKET_WRITE_BUFFER_BYTES)
        .max_write_buffer_size(WEBSOCKET_MAX_WRITE_BUFFER_BYTES)
}

pub async fn monitoring(
    State(state): State<AppState>,
    auth: WebSocketRequestContext,
    websocket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let claims = auth.require_scope(scopes::MONITOR_READ, None)?;
    let authorization = resolve_instance_authorization(&state, &claims).await?;
    let expires_at = claims.exp;
    let connection = admit_websocket(&state, &claims).await?;
    Ok(upgrade_websocket(websocket)
        .protocols(["dbe.jwt", "bearer"])
        .on_upgrade(move |socket| {
            stream_monitoring(socket, state, authorization, expires_at, connection)
        }))
}

async fn stream_monitoring(
    mut socket: WebSocket,
    state: AppState,
    authorization: InstanceAuthorization,
    jwt_exp: i64,
    _connection: WebSocketConnectionPermit,
) {
    let _monitor = state.resource_cache.register_monitor();
    let mut shutdown = state.daemon_shutdown.subscribe();
    let mut ticker = interval(Duration::from_secs(1));
    // Monitoring snapshots are current state, not an event backlog. If a send
    // is delayed, skip missed ticks instead of emitting catch-up bursts.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let expiration_deadline = jwt_expiration_deadline(jwt_exp);
    let expiration = sleep_until(expiration_deadline);
    tokio::pin!(expiration);
    let mut sequence = 0_u64;
    loop {
        tokio::select! {
            _ = wait_for_daemon_shutdown(&mut shutdown) => {
                close_shutdown_socket(&mut socket).await;
                break;
            }
            _ = &mut expiration => {
                close_expired_socket(&mut socket).await;
                break;
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => {}
                }
            }
            _ = ticker.tick() => {
                let Ok(message) = complete_before(
                    expiration_deadline,
                    state.monitoring_cache.snapshot(&state, &authorization),
                )
                .await
                else {
                    close_expired_socket(&mut socket).await;
                    break;
                };
                sequence = sequence.saturating_add(1);
                let batches = match message
                    .filtered(&authorization)
                    .batches(sequence, now_unix())
                {
                    Ok(batches) => batches,
                    Err(error) => {
                        tracing::warn!(%error, "failed to serialize monitoring batch");
                        break;
                    }
                };
                let mut failed = false;
                for batch in batches {
                    if send_monitoring_batch(&mut socket, &batch, expiration_deadline)
                        .await
                        .is_err()
                    {
                        failed = true;
                        break;
                    }
                }
                if failed {
                    break;
                }
            }
        }
    }
}

const MONITORING_FANOUT_LIMIT: usize = 16;

#[derive(Debug, Clone, Default)]
pub struct MonitoringSnapshotCache {
    inner: Arc<Mutex<Option<CachedMonitoringSnapshot>>>,
    refresh_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Clone)]
struct CachedMonitoringSnapshot {
    snapshot: Arc<MonitoringSnapshotData>,
    sampled_at: Instant,
}

impl MonitoringSnapshotCache {
    pub(crate) async fn invalidate(&self) {
        *self.inner.lock().await = None;
    }

    async fn snapshot(
        &self,
        state: &AppState,
        authorization: &InstanceAuthorization,
    ) -> Arc<MonitoringSnapshotData> {
        if matches!(authorization, InstanceAuthorization::Selected(_)) {
            return Arc::new(monitoring_snapshot(state, authorization).await);
        }
        if let Some(snapshot) = self.fresh().await {
            return snapshot;
        }
        let _refresh = self.refresh_lock.lock().await;
        if let Some(snapshot) = self.fresh().await {
            return snapshot;
        }
        let snapshot = Arc::new(monitoring_snapshot(state, authorization).await);
        *self.inner.lock().await = Some(CachedMonitoringSnapshot {
            snapshot: Arc::clone(&snapshot),
            sampled_at: Instant::now(),
        });
        snapshot
    }

    async fn fresh(&self) -> Option<Arc<MonitoringSnapshotData>> {
        self.inner
            .lock()
            .await
            .as_ref()
            .filter(|cached| cached.sampled_at.elapsed() < MONITORING_SNAPSHOT_TTL)
            .map(|cached| Arc::clone(&cached.snapshot))
    }
}

async fn monitoring_snapshot(
    state: &AppState,
    authorization: &InstanceAuthorization,
) -> MonitoringSnapshotData {
    use futures::StreamExt;

    let metadata = authorization.metadata(&state.instances).await;
    let mut instances = futures::stream::iter(metadata)
        .map(|metadata| {
            let state = state.clone();
            async move { monitoring_instance(&state, metadata).await }
        })
        .buffer_unordered(MONITORING_FANOUT_LIMIT)
        .collect::<Vec<_>>()
        .await;
    if matches!(authorization, InstanceAuthorization::Selected(_)) {
        let mut current = Vec::with_capacity(instances.len());
        for instance in instances {
            if state
                .instances
                .get(&instance.instance_id)
                .await
                .is_some_and(|metadata| {
                    authorization.allows(&metadata.instance_id, &metadata.created_at)
                        && metadata.created_at == instance.instance_generation
                })
            {
                current.push(instance);
            }
        }
        instances = current;
    }
    instances.sort_unstable_by(|left: &MonitoringInstance, right| {
        left.instance_id.cmp(&right.instance_id)
    });

    let mut install_progress = match authorization {
        InstanceAuthorization::All => state.install_progress.list(),
        InstanceAuthorization::Selected(_) => instances
            .iter()
            .filter_map(|instance| state.install_progress.get(&instance.instance_id))
            .collect(),
    };
    install_progress.sort_unstable_by(|left, right| left.instance_id.cmp(&right.instance_id));

    MonitoringSnapshotData {
        instances,
        install_progress,
    }
}

async fn monitoring_instance(state: &AppState, metadata: InstanceMetadata) -> MonitoringInstance {
    let instance_generation = metadata.created_at.clone();
    let activity = tenant_activity(state, &metadata).await;
    match resource_report(state, &metadata, ResourceView::Tenant).await {
        Ok(resources) => MonitoringInstance {
            instance_id: metadata.instance_id,
            instance_generation,
            runtime_id: resources.runtime_id.clone(),
            deployment_mode: metadata.deployment_mode,
            resource_scope: resources.scope,
            protocol: metadata.protocol.to_string(),
            status: metadata.status.as_str().to_string(),
            runtime: metadata.runtime.kind.as_str(),
            activity,
            resources: Some(resources),
            resource_error: None,
        },
        Err(_error) => {
            let shared = metadata.deployment_mode == crate::placement::DeploymentMode::Shared;
            MonitoringInstance {
                runtime_id: metadata.runtime_id().to_string(),
                deployment_mode: metadata.deployment_mode,
                resource_scope: if shared {
                    ResourceScope::SharedTenant
                } else {
                    ResourceScope::DedicatedInstance
                },
                instance_id: metadata.instance_id,
                instance_generation,
                protocol: metadata.protocol.to_string(),
                status: metadata.status.as_str().to_string(),
                runtime: metadata.runtime.kind.as_str(),
                activity,
                resources: None,
                resource_error: Some(PublicDiagnostic::public(
                    "resource_unavailable",
                    "resource metrics are temporarily unavailable",
                )),
            }
        }
    }
}

#[derive(Debug)]
struct MonitoringSnapshotData {
    instances: Vec<MonitoringInstance>,
    install_progress: Vec<InstallProgress>,
}

impl MonitoringSnapshotData {
    fn filtered<'a>(
        &'a self,
        authorization: &'a InstanceAuthorization,
    ) -> AuthorizedMonitoring<'a> {
        let current_generations = self
            .instances
            .iter()
            .map(|instance| {
                (
                    instance.instance_id.as_str(),
                    instance.instance_generation.as_str(),
                )
            })
            .collect::<HashMap<_, _>>();
        AuthorizedMonitoring {
            instances: self
                .instances
                .iter()
                .filter(|instance| {
                    authorization.allows(&instance.instance_id, &instance.instance_generation)
                })
                .collect(),
            install_progress: self
                .install_progress
                .iter()
                .filter(|progress| {
                    authorization.allows_progress(
                        &progress.instance_id,
                        current_generations
                            .get(progress.instance_id.as_str())
                            .copied(),
                    )
                })
                .collect(),
        }
    }
}

struct AuthorizedMonitoring<'a> {
    instances: Vec<&'a MonitoringInstance>,
    install_progress: Vec<&'a InstallProgress>,
}

impl<'a> AuthorizedMonitoring<'a> {
    fn batches(
        self,
        sequence: u64,
        sampled_at_unix: i64,
    ) -> Result<Vec<MonitoringBatch<'a>>, serde_json::Error> {
        let instance_batches = chunk_serialized(self.instances)?;
        let progress_batches = chunk_serialized(self.install_progress)?;
        let batch_count = (instance_batches.len() + progress_batches.len()).max(1) as u32;
        let mut batches = Vec::with_capacity(batch_count as usize);

        for instances in instance_batches {
            batches.push(MonitoringBatch {
                r#type: "stats",
                sequence,
                sampled_at_unix,
                batch_index: batches.len() as u32,
                batch_count,
                instances,
                install_progress: Vec::new(),
            });
        }
        for install_progress in progress_batches {
            batches.push(MonitoringBatch {
                r#type: "stats",
                sequence,
                sampled_at_unix,
                batch_index: batches.len() as u32,
                batch_count,
                instances: Vec::new(),
                install_progress,
            });
        }
        if batches.is_empty() {
            batches.push(MonitoringBatch {
                r#type: "stats",
                sequence,
                sampled_at_unix,
                batch_index: 0,
                batch_count: 1,
                instances: Vec::new(),
                install_progress: Vec::new(),
            });
        }
        Ok(batches)
    }
}

fn chunk_serialized<T: Serialize>(items: Vec<&T>) -> Result<Vec<Vec<&T>>, serde_json::Error> {
    let mut chunks = Vec::new();
    let mut chunk = Vec::new();
    let mut bytes = 256_usize;
    for item in items {
        let item_bytes = serde_json::to_vec(item)?.len().saturating_add(1);
        if !chunk.is_empty() && bytes.saturating_add(item_bytes) > MONITORING_BATCH_TARGET_BYTES {
            chunks.push(std::mem::take(&mut chunk));
            bytes = 256;
        }
        bytes = bytes.saturating_add(item_bytes);
        chunk.push(item);
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }
    Ok(chunks)
}

#[derive(Debug)]
enum InstanceAuthorization {
    All,
    Selected(HashMap<String, String>),
}

impl InstanceAuthorization {
    fn selected(claims: &Claims, generations: Vec<(String, String)>) -> Result<Self, ApiError> {
        let Some(expected_digest) = claims.instance_generation_digest.as_deref() else {
            return Err(ApiError::Unauthorized);
        };
        if generations.len() != claims.instances.len()
            || jwt::instance_generation_digest(&generations) != expected_digest
        {
            return Err(ApiError::Unauthorized);
        }
        Ok(Self::Selected(generations.into_iter().collect()))
    }

    fn allows(&self, instance_id: &str, instance_generation: &str) -> bool {
        match self {
            Self::All => true,
            Self::Selected(instances) => instances
                .get(instance_id)
                .is_some_and(|allowed| allowed == instance_generation),
        }
    }

    fn allows_progress(&self, instance_id: &str, instance_generation: Option<&str>) -> bool {
        match self {
            Self::All => true,
            Self::Selected(_) => {
                instance_generation.is_some_and(|generation| self.allows(instance_id, generation))
            }
        }
    }

    async fn metadata(
        &self,
        instances: &crate::instances::state::InstanceStore,
    ) -> Vec<InstanceMetadata> {
        match self {
            Self::All => instances.list().await,
            Self::Selected(selected) => {
                let mut metadata = Vec::with_capacity(selected.len());
                for (instance_id, generation) in selected {
                    if let Some(instance) = instances
                        .get(instance_id)
                        .await
                        .filter(|instance| instance.created_at == *generation)
                    {
                        metadata.push(instance);
                    }
                }
                metadata
            }
        }
    }
}

async fn resolve_instance_authorization(
    state: &AppState,
    claims: &Claims,
) -> Result<InstanceAuthorization, ApiError> {
    if claims.all_instances {
        return if claims.instances.is_empty() && claims.instance_generation_digest.is_none() {
            Ok(InstanceAuthorization::All)
        } else {
            Err(ApiError::Unauthorized)
        };
    }

    let mut seen = HashSet::with_capacity(claims.instances.len());
    let mut generations = Vec::with_capacity(claims.instances.len());
    for instance_id in &claims.instances {
        if !seen.insert(instance_id) {
            return Err(ApiError::Unauthorized);
        }
        let metadata = state
            .instances
            .get(instance_id)
            .await
            .ok_or(ApiError::Unauthorized)?;
        generations.push((instance_id.clone(), metadata.created_at));
    }
    InstanceAuthorization::selected(claims, generations)
}

#[derive(Debug, Serialize)]
struct MonitoringBatch<'a> {
    r#type: &'static str,
    sequence: u64,
    sampled_at_unix: i64,
    batch_index: u32,
    batch_count: u32,
    instances: Vec<&'a MonitoringInstance>,
    install_progress: Vec<&'a InstallProgress>,
}

#[derive(Debug, Serialize)]
struct MonitoringInstance {
    instance_id: String,
    #[serde(skip)]
    instance_generation: String,
    runtime_id: String,
    deployment_mode: crate::placement::DeploymentMode,
    resource_scope: ResourceScope,
    protocol: String,
    status: String,
    runtime: &'static str,
    activity: TenantActivity,
    resources: Option<ResourceReport>,
    resource_error: Option<PublicDiagnostic>,
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
    crate::api::instances::check_logs_available(&metadata)?;
    let connection = admit_websocket(&state, &claims).await?;
    Ok(upgrade_websocket(websocket)
        .protocols(["dbe.jwt", "bearer"])
        .on_upgrade(move |socket| {
            stream_logs(socket, state, metadata, query.tail, claims.exp, connection)
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

async fn admit_websocket(
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

async fn stream_logs(
    mut socket: WebSocket,
    state: AppState,
    metadata: InstanceMetadata,
    tail: Option<usize>,
    jwt_exp: i64,
    _connection: WebSocketConnectionPermit,
) {
    let mut shutdown = state.daemon_shutdown.subscribe();
    let expiration_deadline = jwt_expiration_deadline(jwt_exp);
    if !instance_generation_is_current(&state, &metadata.instance_id, &metadata.created_at).await {
        close_replaced_socket(&mut socket).await;
        return;
    }
    let follow_logs = state
        .docker
        .follow_logs(metadata.protocol, &metadata.instance_id, tail);
    let logs_result = tokio::select! {
        _ = wait_for_daemon_shutdown(&mut shutdown) => {
            close_shutdown_socket(&mut socket).await;
            return;
        }
        result = follow_logs => result,
    };
    let mut logs = match logs_result {
        Ok(logs) => logs,
        Err(error) => {
            let message = LogSnapshot {
                r#type: "logs",
                instance_id: metadata.instance_id,
                sequence: 1,
                stdout: None,
                stderr: None,
                error: Some(PublicDiagnostic::internal("container log stream", error)),
            };
            let _ = send_json_before(&mut socket, &message, expiration_deadline).await;
            return;
        }
    };
    let mut heartbeat = interval(Duration::from_secs(30));
    let mut sequence = 0_u64;
    let mut stdout_buffer = String::new();
    let mut stderr_buffer = String::new();
    let expiration = sleep_until(expiration_deadline);
    tokio::pin!(expiration);
    loop {
        let message = tokio::select! {
            _ = wait_for_daemon_shutdown(&mut shutdown) => {
                close_shutdown_socket(&mut socket).await;
                break;
            }
            _ = &mut expiration => {
                close_expired_socket(&mut socket).await;
                break;
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => continue,
                }
            }
            output = logs.recv() => {
                sequence += 1;
                match output {
                    Some(Ok(output)) => {
                        append_log_buffer(&mut stdout_buffer, &output.stdout);
                        append_log_buffer(&mut stderr_buffer, &output.stderr);
                        LogSnapshot {
                            r#type: "logs",
                            instance_id: metadata.instance_id.clone(),
                            sequence,
                            stdout: non_empty_redacted(&stdout_buffer),
                            stderr: non_empty_redacted(&stderr_buffer),
                            error: None,
                        }
                    }
                    Some(Err(error)) => LogSnapshot {
                        r#type: "logs",
                        instance_id: metadata.instance_id.clone(),
                        sequence,
                        stdout: None,
                        stderr: None,
                        error: Some(PublicDiagnostic::internal("container log stream", error)),
                    },
                    None => LogSnapshot {
                        r#type: "logs",
                        instance_id: metadata.instance_id.clone(),
                        sequence,
                        stdout: None,
                        stderr: None,
                        error: Some(PublicDiagnostic::public(
                            "stream_ended",
                            "container log stream ended",
                        )),
                    },
                }
            }
            _ = heartbeat.tick() => {
                sequence += 1;
                LogSnapshot {
                    r#type: "logs",
                    instance_id: metadata.instance_id.clone(),
                    sequence,
                    stdout: non_empty_redacted(&stdout_buffer),
                    stderr: non_empty_redacted(&stderr_buffer),
                    error: None,
                }
            }
        };

        if !instance_generation_is_current(&state, &metadata.instance_id, &metadata.created_at)
            .await
        {
            close_replaced_socket(&mut socket).await;
            break;
        }
        if send_json_before(&mut socket, &message, expiration_deadline)
            .await
            .is_err()
        {
            break;
        }
    }
}

const LOG_STREAM_BUFFER_LIMIT: usize = 128 * 1024;

fn append_log_buffer(buffer: &mut String, chunk: &str) {
    if chunk.is_empty() {
        return;
    }
    buffer.push_str(chunk);
    if buffer.len() <= LOG_STREAM_BUFFER_LIMIT {
        return;
    }
    let mut start = buffer.len().saturating_sub(LOG_STREAM_BUFFER_LIMIT);
    while start < buffer.len() && !buffer.is_char_boundary(start) {
        start += 1;
    }
    buffer.replace_range(..start, "");
}

fn non_empty_redacted(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| redaction::redact_connection_url(value))
}

async fn stream_import_export(
    mut socket: WebSocket,
    state: AppState,
    instance_id: String,
    instance_generation: String,
    query: ImportExportQuery,
    claims: Arc<Claims>,
    _connection: WebSocketConnectionPermit,
) {
    if !instance_generation_is_current(&state, &instance_id, &instance_generation).await {
        close_replaced_socket(&mut socket).await;
        return;
    }
    let mut events = state.import_export_jobs.subscribe();
    let mut shutdown = state.daemon_shutdown.subscribe();
    let expiration_deadline = jwt_expiration_deadline(claims.exp);
    let snapshot = complete_before(
        expiration_deadline,
        import_export_snapshot(&state, &instance_id, &query, &claims),
    );
    let snapshot = tokio::select! {
        _ = wait_for_daemon_shutdown(&mut shutdown) => {
            close_shutdown_socket(&mut socket).await;
            return;
        }
        snapshot = snapshot => snapshot,
    };
    let Ok(snapshot) = snapshot else {
        close_expired_socket(&mut socket).await;
        return;
    };
    if !instance_generation_is_current(&state, &instance_id, &instance_generation).await {
        close_replaced_socket(&mut socket).await;
        return;
    }
    if send_json_before(&mut socket, &snapshot, expiration_deadline)
        .await
        .is_err()
    {
        return;
    }

    let heartbeat_period = Duration::from_secs(30);
    let mut heartbeat = interval_at(Instant::now() + heartbeat_period, heartbeat_period);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let expiration = sleep_until(expiration_deadline);
    tokio::pin!(expiration);
    let mut awaiting_pong = false;
    loop {
        tokio::select! {
            _ = wait_for_daemon_shutdown(&mut shutdown) => {
                close_shutdown_socket(&mut socket).await;
                break;
            }
            _ = &mut expiration => {
                close_expired_socket(&mut socket).await;
                break;
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Pong(_))) => awaiting_pong = false,
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => {}
                }
            }
            _ = heartbeat.tick() => {
                if !instance_generation_is_current(&state, &instance_id, &instance_generation).await {
                    close_replaced_socket(&mut socket).await;
                    break;
                }
                if awaiting_pong {
                    close_unresponsive_socket(&mut socket).await;
                    break;
                }
                if send_message_before(
                    &mut socket,
                    Message::Ping(b"dbe-heartbeat".as_slice().into()),
                    expiration_deadline,
                )
                .await
                .is_err()
                {
                    break;
                }
                awaiting_pong = true;
            }
            event = events.recv() => {
                match event {
                    Ok(job) => {
                        if !instance_generation_is_current(&state, &instance_id, &instance_generation).await {
                            close_replaced_socket(&mut socket).await;
                            break;
                        }
                        if !job_matches_access(&job, &instance_id, &query, &claims) {
                            continue;
                        }
                        let Ok(job) = complete_before(
                            expiration_deadline,
                            public_job_update(&state, job, &claims),
                        )
                        .await
                        else {
                            close_expired_socket(&mut socket).await;
                            break;
                        };
                        let event = ImportExportJobEvent {
                            r#type: "import_export_job",
                            job,
                        };
                        if send_json_before(&mut socket, &event, expiration_deadline)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        if !instance_generation_is_current(&state, &instance_id, &instance_generation).await {
                            close_replaced_socket(&mut socket).await;
                            break;
                        }
                        let event = ImportExportLaggedEvent {
                            r#type: "import_export_lagged",
                            skipped,
                        };
                        if send_json_before(&mut socket, &event, expiration_deadline)
                            .await
                            .is_err()
                        {
                            break;
                        }
                        let Ok(snapshot) = complete_before(
                            expiration_deadline,
                            import_export_snapshot(
                                &state,
                                &instance_id,
                                &query,
                                &claims,
                            ),
                        )
                        .await
                        else {
                            close_expired_socket(&mut socket).await;
                            break;
                        };
                        if send_json_before(&mut socket, &snapshot, expiration_deadline)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

async fn import_export_snapshot(
    state: &AppState,
    instance_id: &str,
    query: &ImportExportQuery,
    claims: &Claims,
) -> ImportExportSnapshot {
    let jobs = snapshot_jobs(state, instance_id, query).await;
    let mut response = Vec::with_capacity(jobs.len());
    for job in jobs {
        if job_matches_access(&job, instance_id, query, claims) {
            response.push(public_job_update(state, job, claims).await);
        }
    }
    ImportExportSnapshot {
        r#type: "import_export_snapshot",
        jobs: response,
    }
}

async fn snapshot_jobs(
    state: &AppState,
    instance_id: &str,
    query: &ImportExportQuery,
) -> Vec<ImportExportJob> {
    if let Some(job_id) = query.job_id.as_deref() {
        return match state.import_export_jobs.get(job_id).await {
            Ok(Some(job)) => vec![job],
            Ok(None) => Vec::new(),
            Err(error) => {
                tracing::warn!(%error, %job_id, "failed to build import/export websocket snapshot");
                Vec::new()
            }
        };
    }

    list_snapshot_jobs(state, Some(instance_id)).await
}

async fn list_snapshot_jobs(state: &AppState, instance_id: Option<&str>) -> Vec<ImportExportJob> {
    match state.import_export_jobs.list(instance_id, None, 100).await {
        Ok(jobs) => jobs,
        Err(error) => {
            tracing::warn!(%error, ?instance_id, "failed to build import/export websocket snapshot");
            Vec::new()
        }
    }
}

fn job_matches_access(
    job: &ImportExportJob,
    instance_id: &str,
    query: &ImportExportQuery,
    claims: &Claims,
) -> bool {
    claims.allows_instance(&job.instance_id)
        && job.instance_id == instance_id
        && query
            .job_id
            .as_deref()
            .is_none_or(|job_id| job.job_id == job_id)
}

// Repeat the instance check at the ticket boundary so a future caller cannot
// turn an unauthorized job into a signed artifact credential.
async fn public_job_update(
    state: &AppState,
    job: ImportExportJob,
    claims: &Claims,
) -> ImportExportJobUpdate {
    let download = download_ticket_for_job(state, &job, claims).await;
    ImportExportJobUpdate {
        job: public_job_response(job).await,
        download,
    }
}

async fn download_ticket_for_job(
    state: &AppState,
    job: &ImportExportJob,
    claims: &Claims,
) -> Option<DownloadUrlResponse> {
    if !claims.allows_instance(&job.instance_id)
        || job.action != ImportExportAction::Export
        || job.status != ImportExportStatus::Succeeded
    {
        return None;
    }
    let artifact_name = job
        .artifact_path
        .as_deref()
        .and_then(|path| std::path::Path::new(path).file_name())
        .and_then(|name| name.to_str())?;
    match artifact_download_url(state, artifact_name, &job.instance_id, Some(120), true).await {
        Ok(ticket) => Some(ticket),
        Err(error) => {
            tracing::warn!(
                %error,
                job_id = %job.job_id,
                instance_id = %job.instance_id,
                artifact = %artifact_name,
                "failed to issue import/export websocket download ticket"
            );
            None
        }
    }
}

fn jwt_expiration_deadline(exp: i64) -> Instant {
    let now_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let expires_since_epoch = Duration::from_secs(u64::try_from(exp).unwrap_or_default());
    Instant::now() + expires_since_epoch.saturating_sub(now_since_epoch)
}

async fn instance_generation_is_current(
    state: &AppState,
    instance_id: &str,
    instance_generation: &str,
) -> bool {
    state
        .instances
        .get(instance_id)
        .await
        .is_some_and(|metadata| metadata.created_at == instance_generation)
}

async fn close_expired_socket(socket: &mut WebSocket) {
    close_socket(socket, "JWT expired").await;
}

async fn close_unresponsive_socket(socket: &mut WebSocket) {
    close_socket(socket, "heartbeat timeout").await;
}

async fn close_replaced_socket(socket: &mut WebSocket) {
    close_socket(socket, "instance identity changed").await;
}

async fn close_shutdown_socket(socket: &mut WebSocket) {
    close_socket_with_code(socket, close_code::RESTART, "server restarting").await;
}

async fn close_socket(socket: &mut WebSocket, reason: &'static str) {
    close_socket_with_code(socket, close_code::POLICY, reason).await;
}

async fn close_socket_with_code(socket: &mut WebSocket, code: u16, reason: &'static str) {
    let close_deadline = Instant::now() + Duration::from_secs(1);
    let _ = send_message_before(
        socket,
        Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })),
        close_deadline,
    )
    .await;
}

async fn wait_for_daemon_shutdown(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

async fn send_json_before<T: Serialize>(
    socket: &mut WebSocket,
    value: &T,
    deadline: Instant,
) -> Result<(), ()> {
    let payload = serde_json::to_string(value).map_err(|error| {
        tracing::warn!(%error, "failed to serialize websocket payload");
    })?;
    send_message_before(socket, Message::Text(payload.into()), deadline).await
}

async fn send_monitoring_batch(
    socket: &mut WebSocket,
    batch: &MonitoringBatch<'_>,
    deadline: Instant,
) -> Result<(), ()> {
    let payload = serde_json::to_string(batch).map_err(|error| {
        tracing::warn!(%error, "failed to serialize monitoring batch");
    })?;
    if payload.len() > WEBSOCKET_MAX_MESSAGE_BYTES {
        tracing::warn!(
            sequence = batch.sequence,
            batch_index = batch.batch_index,
            payload_bytes = payload.len(),
            max_bytes = WEBSOCKET_MAX_MESSAGE_BYTES,
            "monitoring item exceeded the bounded websocket batch size"
        );
        return Err(());
    }
    send_message_before(socket, Message::Text(payload.into()), deadline).await
}

async fn send_message_before(
    socket: &mut WebSocket,
    message: Message,
    deadline: Instant,
) -> Result<(), ()> {
    let now = Instant::now();
    if now >= deadline {
        return Err(());
    }
    let send_deadline = deadline.min(now + Duration::from_secs(5));
    timeout_at(send_deadline, socket.send(message))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

async fn complete_before<F>(deadline: Instant, future: F) -> Result<F::Output, ()>
where
    F: Future,
{
    let now = Instant::now();
    if now >= deadline {
        return Err(());
    }
    let operation_deadline = deadline.min(now + Duration::from_secs(15));
    timeout_at(operation_deadline, future).await.map_err(|_| ())
}

#[derive(Debug, Serialize)]
struct ImportExportSnapshot {
    r#type: &'static str,
    jobs: Vec<ImportExportJobUpdate>,
}

#[derive(Debug, Serialize)]
struct ImportExportJobEvent {
    r#type: &'static str,
    job: ImportExportJobUpdate,
}

#[derive(Debug, Serialize)]
struct ImportExportJobUpdate {
    #[serde(flatten)]
    job: ImportExportJobResponse,
    download: Option<DownloadUrlResponse>,
}

#[derive(Debug, Serialize)]
struct ImportExportLaggedEvent {
    r#type: &'static str,
    skipped: u64,
}

#[derive(Debug, Serialize)]
struct LogSnapshot {
    r#type: &'static str,
    instance_id: String,
    sequence: u64,
    stdout: Option<String>,
    stderr: Option<String>,
    error: Option<PublicDiagnostic>,
}

#[cfg(test)]
mod tests;
