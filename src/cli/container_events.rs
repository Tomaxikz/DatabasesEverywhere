use super::*;

pub(super) async fn monitor_managed_container_events(state: AppState) {
    let mut shutdown = state.daemon_shutdown.subscribe();
    let mut reconnect_delay = CONTAINER_EVENT_RECONNECT_INITIAL_DELAY;
    let mut first_subscription = true;

    loop {
        if *shutdown.borrow() {
            return;
        }

        let docker = state.docker.clone();
        let mut events = docker.managed_container_events();
        if first_subscription {
            tracing::info!(
                engine = %docker.engine_name(),
                "subscribed to managed container lifecycle events"
            );
            first_subscription = false;
        } else {
            tracing::debug!(
                engine = %docker.engine_name(),
                "resubscribed to managed container lifecycle events"
            );
        }

        let stream_error = loop {
            let next = tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                    continue;
                }
                next = events.next() => next,
            };
            match next {
                Some(Ok(event)) => {
                    reconnect_delay = CONTAINER_EVENT_RECONNECT_INITIAL_DELAY;
                    if let Err(error) = reconcile_managed_container_event(&state, event).await {
                        tracing::error!(
                            %error,
                            "failed to reconcile a managed container lifecycle event"
                        );
                    }
                }
                Some(Err(error)) => break Some(error.to_string()),
                None => break None,
            }
        };

        match stream_error {
            Some(error) => tracing::warn!(
                %error,
                reconnect_delay_seconds = reconnect_delay.as_secs(),
                "managed container event stream failed; reconciling a runtime snapshot before reconnecting"
            ),
            None => tracing::warn!(
                reconnect_delay_seconds = reconnect_delay.as_secs(),
                "managed container event stream ended; reconciling a runtime snapshot before reconnecting"
            ),
        }
        reconcile_managed_container_snapshot(&state).await;

        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            _ = tokio::time::sleep(reconnect_delay) => {}
        }
        reconnect_delay = reconnect_delay
            .saturating_mul(2)
            .min(CONTAINER_EVENT_RECONNECT_MAX_DELAY);
    }
}

pub(super) async fn reconcile_managed_container_event(
    state: &AppState,
    event: ManagedContainerEvent,
) -> anyhow::Result<()> {
    let instance_id = event.instance_id.clone();
    reconcile_managed_container_state(state, &instance_id, Some(event)).await
}

pub(super) async fn reconcile_managed_container_snapshot(state: &AppState) {
    let instances = state.instances.list().await;
    let outcomes = futures::stream::iter(instances)
        .map(|metadata| async move {
            reconcile_managed_container_state(state, &metadata.instance_id, None).await
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    for outcome in outcomes {
        if let Err(error) = outcome {
            tracing::error!(
                %error,
                "failed to reconcile managed container runtime snapshot"
            );
        }
    }
}

pub(super) async fn reconcile_managed_container_state(
    state: &AppState,
    instance_id: &str,
    event: Option<ManagedContainerEvent>,
) -> anyhow::Result<()> {
    let _operation = state.instance_locks.lock(instance_id).await;
    let Some(metadata) = state.instances.get(instance_id).await else {
        return Ok(());
    };

    if let Some(event) = event.as_ref()
        && metadata.protocol != event.protocol
    {
        tracing::error!(
            event = "audit managed_container_event_label_mismatch",
            instance_id,
            stored_protocol = %metadata.protocol,
            event_protocol = %event.protocol,
            "ignored a managed container event whose ownership labels disagree with durable metadata"
        );
        return Ok(());
    }

    if metadata.status == InstanceStatus::Deleting {
        return Ok(());
    }

    if metadata.status == InstanceStatus::Quarantined {
        let should_stop = event
            .as_ref()
            .is_none_or(|event| event.action.activates_container());
        if should_stop {
            match state
                .docker
                .inspect_instance(metadata.protocol, &metadata.instance_id)
                .await
            {
                Ok(inspection)
                    if matches!(
                        inspection.status,
                        DockerContainerStatus::Running | DockerContainerStatus::Starting
                    ) =>
                {
                    state
                        .docker
                        .stop(metadata.protocol, &metadata.instance_id)
                        .await?;
                    tracing::warn!(
                        event = "audit quarantined_instance_event_stopped",
                        instance_id = %metadata.instance_id,
                        protocol = %metadata.protocol,
                        "stopped an externally activated quarantined instance"
                    );
                }
                Ok(_) => {}
                Err(error) if error.is_not_found() => {}
                Err(error) => return Err(error.into()),
            }
        }
        state
            .instance_runtime_cache
            .remove(&metadata.instance_id)
            .await;
        state.resource_cache.remove(&metadata.instance_id).await;
        return Ok(());
    }

    let previous_status = metadata.status;
    let activation_readiness_error = if event.as_ref().is_some_and(|event| {
        event.action.activates_container() && previous_status != InstanceStatus::Running
    }) {
        state
            .docker
            .wait_until_ready(
                metadata.protocol,
                &metadata.instance_id,
                Duration::from_secs(120),
            )
            .await
            .err()
    } else {
        None
    };
    if activation_readiness_error.is_some()
        && let Err(error) = state
            .docker
            .stop(metadata.protocol, &metadata.instance_id)
            .await
        && !error.is_not_running()
        && !error.is_not_found()
    {
        tracing::error!(
            event = "audit event_readiness_cleanup_failed",
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            %error,
            "an externally activated database failed startup readiness and could not be stopped"
        );
    }

    let mut reconciled = reconcile::reconcile_one(metadata, &state.docker).await;
    let unexpected_failure = event.as_ref().is_some_and(|event| {
        event.action.indicates_unexpected_failure()
            && matches!(
                previous_status,
                InstanceStatus::Booting | InstanceStatus::Running | InstanceStatus::Failed
            )
    });
    let preserve_failure = previous_status == InstanceStatus::Failed
        && event
            .as_ref()
            .is_some_and(|event| event.action.deactivates_container());
    if activation_readiness_error.is_some() || unexpected_failure || preserve_failure {
        reconciled.status = InstanceStatus::Failed;
        reconciled.updated_at = now_rfc3339();
    }
    let current_status = reconciled.status;
    state.manager.upsert(reconciled.clone()).await?;
    state
        .instance_runtime_cache
        .remove(&reconciled.instance_id)
        .await;
    state.resource_cache.remove(&reconciled.instance_id).await;

    if let Some(event) = event {
        if let Some(readiness_error) = activation_readiness_error {
            tracing::error!(
                event = "audit managed_container_startup_readiness_failed",
                instance_id = %reconciled.instance_id,
                protocol = %reconciled.protocol,
                action = event.action.as_str(),
                previous_status = previous_status.as_str(),
                current_status = current_status.as_str(),
                error = %readiness_error,
                "managed database container activation did not become ready and was stopped"
            );
        } else if unexpected_failure {
            tracing::error!(
                event = "audit managed_container_runtime_failure",
                instance_id = %reconciled.instance_id,
                protocol = %reconciled.protocol,
                action = event.action.as_str(),
                previous_status = previous_status.as_str(),
                current_status = current_status.as_str(),
                "managed database container stopped unexpectedly; inspect its container logs and resource limits"
            );
        } else {
            tracing::info!(
                instance_id = %reconciled.instance_id,
                protocol = %reconciled.protocol,
                action = event.action.as_str(),
                previous_status = previous_status.as_str(),
                current_status = current_status.as_str(),
                "managed container lifecycle event reconciled"
            );
        }
    }
    Ok(())
}
