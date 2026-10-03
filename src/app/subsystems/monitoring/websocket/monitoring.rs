use super::*;

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

pub(super) async fn stream_monitoring(
    mut socket: WebSocket,
    state: AppState,
    authorization: InstanceAuthorization,
    jwt_exp: i64,
    _connection: WebSocketConnectionPermit,
) {
    let _monitor = state.resource_cache.register_monitor();
    let mut shutdown = state.daemon_shutdown.subscribe();
    let mut ticker = interval(MONITORING_TICK_INTERVAL);
    // Monitoring snapshots are current state, not an event backlog. If a send
    // is delayed, skip missed ticks instead of emitting catch-up bursts.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let expiration_deadline = jwt_expiration_deadline(jwt_exp);
    let expiration = sleep_until(expiration_deadline);
    tokio::pin!(expiration);
    let mut sequence = 0_u64;
    let mut progress_cursor = wire::ProgressCursor::default();
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
                    .batches(sequence, now_unix(), &mut progress_cursor)
                {
                    Ok(batches) => batches,
                    Err(error) => {
                        tracing::warn!(%error, "failed to serialize monitoring batch");
                        break;
                    }
                };
                if send_monitoring_batches(&mut socket, &batches, expiration_deadline)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

pub(super) const MONITORING_FANOUT_LIMIT: usize = 16;

#[derive(Debug, Clone, Default)]
pub struct MonitoringSnapshotCache {
    pub(super) inner: Arc<Mutex<Option<CachedMonitoringSnapshot>>>,
    pub(super) refresh_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Clone)]
pub(super) struct CachedMonitoringSnapshot {
    pub(super) snapshot: Arc<MonitoringSnapshotData>,
    pub(super) sampled_at: Instant,
}

impl MonitoringSnapshotCache {
    pub(crate) async fn invalidate(&self) {
        *self.inner.lock().await = None;
    }

    pub(super) async fn snapshot(
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

    pub(super) async fn fresh(&self) -> Option<Arc<MonitoringSnapshotData>> {
        self.inner
            .lock()
            .await
            .as_ref()
            .filter(|cached| cached.sampled_at.elapsed() < MONITORING_SNAPSHOT_TTL)
            .map(|cached| Arc::clone(&cached.snapshot))
    }
}

pub(super) async fn monitoring_snapshot(
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

pub(super) async fn monitoring_instance(
    state: &AppState,
    metadata: InstanceMetadata,
) -> MonitoringInstance {
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
            let shared =
                metadata.deployment_mode == crate::instance::placement::DeploymentMode::Shared;
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
pub(super) struct MonitoringSnapshotData {
    pub(super) instances: Vec<MonitoringInstance>,
    pub(super) install_progress: Vec<InstallProgress>,
}

impl MonitoringSnapshotData {
    pub(super) fn filtered<'a>(
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

pub(super) struct AuthorizedMonitoring<'a> {
    pub(super) instances: Vec<&'a MonitoringInstance>,
    pub(super) install_progress: Vec<&'a InstallProgress>,
}

impl<'a> AuthorizedMonitoring<'a> {
    pub(super) fn batches(
        self,
        sequence: u64,
        sampled_at_unix: i64,
        cursor: &mut wire::ProgressCursor,
    ) -> Result<Vec<MonitoringBatch<'a>>, serde_json::Error> {
        let instance_batches = chunk_serialized(self.instances)?;
        let progress = cursor.select(&self.install_progress);
        let progress_batches = chunk_serialized(progress.updates)?;
        let removed_batches = chunk_serialized(progress.removed.iter().collect())?
            .into_iter()
            .map(|batch| batch.into_iter().cloned().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let batch_count =
            (instance_batches.len() + progress_batches.len() + removed_batches.len()).max(1) as u32;
        let progress_reset = progress.reset;
        let new_batch =
            |batch_index: usize,
             instances: Vec<&'a MonitoringInstance>,
             install_progress: Vec<&'a InstallProgress>,
             install_progress_removed: Vec<String>| MonitoringBatch {
                r#type: "stats",
                progress_reset,
                install_progress_removed,
                sequence,
                sampled_at_unix,
                batch_index: batch_index as u32,
                batch_count,
                instances,
                install_progress,
            };
        let mut batches = Vec::with_capacity(batch_count as usize);

        for instances in instance_batches {
            batches.push(new_batch(batches.len(), instances, Vec::new(), Vec::new()));
        }
        for install_progress in progress_batches {
            batches.push(new_batch(
                batches.len(),
                Vec::new(),
                install_progress,
                Vec::new(),
            ));
        }
        for removed in removed_batches {
            batches.push(new_batch(batches.len(), Vec::new(), Vec::new(), removed));
        }
        if batches.is_empty() {
            batches.push(new_batch(0, Vec::new(), Vec::new(), Vec::new()));
        }
        Ok(batches)
    }
}

pub(super) fn chunk_serialized<T: Serialize>(
    items: Vec<&T>,
) -> Result<Vec<Vec<&T>>, serde_json::Error> {
    let mut chunks = Vec::new();
    let mut chunk = Vec::new();
    let mut bytes = BATCH_ENVELOPE_BYTES;
    for item in items {
        let item_bytes = serde_json::to_vec(item)?.len().saturating_add(1);
        if !chunk.is_empty() && bytes.saturating_add(item_bytes) > MONITORING_BATCH_TARGET_BYTES {
            chunks.push(std::mem::take(&mut chunk));
            bytes = BATCH_ENVELOPE_BYTES;
        }
        bytes = bytes.saturating_add(item_bytes);
        chunk.push(item);
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }
    Ok(chunks)
}

#[derive(Debug, Serialize)]
pub(super) struct MonitoringBatch<'a> {
    pub(super) progress_reset: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) install_progress_removed: Vec<String>,
    r#type: &'static str,
    pub(super) sequence: u64,
    pub(super) sampled_at_unix: i64,
    pub(super) batch_index: u32,
    pub(super) batch_count: u32,
    pub(super) instances: Vec<&'a MonitoringInstance>,
    pub(super) install_progress: Vec<&'a InstallProgress>,
}

#[derive(Debug, Serialize)]
pub(super) struct MonitoringInstance {
    pub(super) instance_id: String,
    #[serde(skip)]
    pub(super) instance_generation: String,
    pub(super) runtime_id: String,
    pub(super) deployment_mode: crate::instance::placement::DeploymentMode,
    pub(super) resource_scope: ResourceScope,
    pub(super) protocol: String,
    pub(super) status: String,
    pub(super) runtime: &'static str,
    #[serde(serialize_with = "wire::activity")]
    pub(super) activity: TenantActivity,
    #[serde(serialize_with = "wire::resources")]
    pub(super) resources: Option<ResourceReport>,
    pub(super) resource_error: Option<PublicDiagnostic>,
}

pub(super) async fn send_monitoring_batches(
    socket: &mut WebSocket,
    batches: &[MonitoringBatch<'_>],
    deadline: Instant,
) -> Result<(), ()> {
    for batch in batches {
        send_monitoring_batch(socket, batch, deadline).await?;
    }
    Ok(())
}

pub(super) async fn send_monitoring_batch(
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
