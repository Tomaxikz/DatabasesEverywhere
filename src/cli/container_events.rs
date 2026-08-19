use super::*;
use futures::FutureExt;
use std::collections::HashSet;

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

        let mut reconciliations = tokio::task::JoinSet::new();
        let mut active_instances = HashSet::new();
        let mut pending_events = HashMap::new();
        let stream_error = loop {
            if reconciliations.len() >= MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY {
                if let Err(error) = complete_event_reconciliation(
                    &state,
                    &mut reconciliations,
                    &mut active_instances,
                    &mut pending_events,
                )
                .await
                {
                    break Some(error);
                }
                continue;
            }
            let next = tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        drain_event_reconciliations(
                            &state,
                            &mut reconciliations,
                            &mut active_instances,
                            &mut pending_events,
                        ).await;
                        return;
                    }
                    continue;
                }
                completed = reconciliations.join_next(), if !reconciliations.is_empty() => {
                    if let Some(result) = completed
                        && let Err(error) = finish_event_reconciliation(
                            &state,
                            &mut reconciliations,
                            &mut active_instances,
                            &mut pending_events,
                            result,
                        )
                    {
                        break Some(error);
                    }
                    continue;
                }
                next = events.next() => next,
            };
            match next {
                Some(Ok(event)) => {
                    reconnect_delay = CONTAINER_EVENT_RECONNECT_INITIAL_DELAY;
                    schedule_event_reconciliation(
                        &state,
                        &mut reconciliations,
                        &mut active_instances,
                        &mut pending_events,
                        event,
                    );
                }
                Some(Err(error)) => break Some(error.to_string()),
                None => break None,
            }
        };
        drain_event_reconciliations(
            &state,
            &mut reconciliations,
            &mut active_instances,
            &mut pending_events,
        )
        .await;

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

fn schedule_event_reconciliation(
    state: &AppState,
    reconciliations: &mut tokio::task::JoinSet<String>,
    active_instances: &mut HashSet<String>,
    pending_events: &mut HashMap<String, ManagedContainerEvent>,
    event: ManagedContainerEvent,
) {
    let instance_id = event.instance_id.clone();
    if !active_instances.insert(instance_id.clone()) {
        // Every reconciliation inspects the current Docker state. Retaining
        // only the newest queued event for one busy instance preserves the
        // final transition without allowing an event storm to grow memory.
        pending_events.insert(instance_id, event);
        return;
    }
    spawn_event_reconciliation(state, reconciliations, event);
}

fn spawn_event_reconciliation(
    state: &AppState,
    reconciliations: &mut tokio::task::JoinSet<String>,
    event: ManagedContainerEvent,
) {
    let event_state = state.clone();
    let instance_id = event.instance_id.clone();
    reconciliations.spawn(async move {
        match std::panic::AssertUnwindSafe(reconcile_managed_container_event(&event_state, event))
            .catch_unwind()
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::error!(
                %error,
                "failed to reconcile a managed container lifecycle event"
            ),
            Err(_) => tracing::error!(
                instance_id,
                "managed container event reconciliation task panicked"
            ),
        }
        instance_id
    });
}

async fn complete_event_reconciliation(
    state: &AppState,
    reconciliations: &mut tokio::task::JoinSet<String>,
    active_instances: &mut HashSet<String>,
    pending_events: &mut HashMap<String, ManagedContainerEvent>,
) -> Result<(), String> {
    let Some(result) = reconciliations.join_next().await else {
        return Ok(());
    };
    finish_event_reconciliation(
        state,
        reconciliations,
        active_instances,
        pending_events,
        result,
    )
}

fn finish_event_reconciliation(
    state: &AppState,
    reconciliations: &mut tokio::task::JoinSet<String>,
    active_instances: &mut HashSet<String>,
    pending_events: &mut HashMap<String, ManagedContainerEvent>,
    result: Result<String, tokio::task::JoinError>,
) -> Result<(), String> {
    let instance_id = result.map_err(|error| {
        tracing::error!(
            %error,
            "managed container event reconciliation task stopped unexpectedly"
        );
        error.to_string()
    })?;
    if let Some(event) = pending_events.remove(&instance_id) {
        spawn_event_reconciliation(state, reconciliations, event);
    } else {
        active_instances.remove(&instance_id);
    }
    Ok(())
}

async fn drain_event_reconciliations(
    state: &AppState,
    reconciliations: &mut tokio::task::JoinSet<String>,
    active_instances: &mut HashSet<String>,
    pending_events: &mut HashMap<String, ManagedContainerEvent>,
) {
    while !reconciliations.is_empty() {
        if complete_event_reconciliation(state, reconciliations, active_instances, pending_events)
            .await
            .is_err()
        {
            reconciliations.abort_all();
            while reconciliations.join_next().await.is_some() {}
            break;
        }
    }
    active_instances.clear();
    pending_events.clear();
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
    let Some(_mutation) = state.daemon_shutdown.try_admit_background_mutation() else {
        return Ok(());
    };
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

    if metadata.desired_state == crate::instances::metadata::DesiredInstanceState::Stopped {
        let previous_status = metadata.status;
        let reconciled = reconcile::reconcile_one(metadata, &state.docker).await;
        let current_status = reconciled.status;
        state.manager.upsert(reconciled.clone()).await?;
        state
            .instance_runtime_cache
            .remove(&reconciled.instance_id)
            .await;
        state.resource_cache.remove(&reconciled.instance_id).await;
        if let Some(event) = event {
            tracing::info!(
                instance_id = %reconciled.instance_id,
                protocol = %reconciled.protocol,
                action = event.action.as_str(),
                previous_status = previous_status.as_str(),
                current_status = current_status.as_str(),
                "enforced durable stopped state after a managed container lifecycle event"
            );
        }
        return Ok(());
    }

    if let Some(event) = event.as_ref()
        && event.container_id.is_some()
    {
        let current_container_id = state
            .docker
            .verified_managed_container_id(metadata.protocol, &metadata.instance_id)
            .await?;
        if event_targets_superseded_container(event, current_container_id.as_deref()) {
            tracing::debug!(
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                action = event.action.as_str(),
                event_container_id = event.container_id.as_deref().unwrap_or("unknown"),
                current_container_id = current_container_id.as_deref().unwrap_or("unknown"),
                "ignored a delayed lifecycle event emitted by a replaced managed container"
            );
            return Ok(());
        }
    }

    let previous_status = metadata.status;
    let activation_observed = if let Some(event) = event.as_ref() {
        event.action.activates_container()
    } else if previous_status == InstanceStatus::Running {
        false
    } else {
        match state
            .docker
            .inspect_instance(metadata.protocol, &metadata.instance_id)
            .await
        {
            Ok(inspection) => matches!(
                inspection.status,
                DockerContainerStatus::Running | DockerContainerStatus::Starting
            ),
            Err(error) if error.is_not_found() => false,
            Err(error) => return Err(error.into()),
        }
    };
    let mut activation_error = if activation_observed {
        state.instances.fence_routes(&metadata.instance_id).await;
        state
            .docker
            .enforce_cpu_burst_policy(metadata.protocol, &metadata.instance_id)
            .await;
        match state
            .docker
            .wait_until_ready(
                metadata.protocol,
                &metadata.instance_id,
                Duration::from_secs(120),
            )
            .await
        {
            Ok(_) => match harden_activated_instance_auth(state, &metadata).await {
                Ok(()) => compatibility_after_activation(state, &metadata).await.err(),
                Err(error) => Some(error),
            },
            Err(error) => Some(error.to_string()),
        }
    } else {
        None
    };
    if activation_error.is_none() && !activation_observed {
        match state
            .docker
            .inspect_instance(metadata.protocol, &metadata.instance_id)
            .await
        {
            Ok(inspection) if inspection.status == DockerContainerStatus::Running => {
                activation_error = compatibility_after_activation(state, &metadata).await.err();
            }
            Ok(_) => {}
            Err(error) if error.is_not_found() => {}
            Err(error) => activation_error = Some(error.to_string()),
        }
    }
    if activation_error.is_some()
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
    if activation_error.is_some() || unexpected_failure || preserve_failure {
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
        if let Some(readiness_error) = activation_error {
            tracing::error!(
                event = "audit managed_container_startup_readiness_failed",
                instance_id = %reconciled.instance_id,
                protocol = %reconciled.protocol,
                action = event.action.as_str(),
                previous_status = previous_status.as_str(),
                current_status = current_status.as_str(),
                error = %readiness_error,
                "managed database container activation failed readiness or authentication hardening and was stopped"
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

async fn compatibility_after_activation(
    state: &AppState,
    metadata: &crate::instances::metadata::InstanceMetadata,
) -> Result<(), String> {
    let outcome = crate::compatibility::probe_instance_compatibility(
        &state.manager,
        &state.docker,
        metadata,
        false,
    )
    .await
    .map_err(|error| error.to_string())?;
    if outcome.compatible {
        Ok(())
    } else {
        Err(outcome
            .diagnostic
            .unwrap_or_else(|| "database engine version is unsupported".to_string()))
    }
}

async fn harden_activated_instance_auth(
    state: &AppState,
    metadata: &crate::instances::metadata::InstanceMetadata,
) -> Result<(), String> {
    match metadata.protocol {
        Protocol::Postgres => {
            let password = metadata.tenant_password.as_deref().ok_or_else(|| {
                "the encrypted PostgreSQL tenant credential is missing".to_string()
            })?;
            let admin_password = metadata.postgres_admin_password.as_deref().ok_or_else(|| {
                "the encrypted PostgreSQL administrator credential is missing".to_string()
            })?;
            crate::api::instance_create::harden_postgres_instance_auth(
                state,
                &metadata.instance_id,
                &metadata.database.username,
                password,
                admin_password,
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
        }
        Protocol::Mysql => {
            let password = metadata
                .tenant_password
                .as_deref()
                .ok_or_else(|| "the encrypted MySQL tenant credential is missing".to_string())?;
            let root_password = metadata.mysql_root_password.as_deref().ok_or_else(|| {
                "the encrypted MySQL maintenance credential is missing".to_string()
            })?;
            crate::api::instance_create::harden_mysql_tenant_auth(
                state,
                &metadata.instance_id,
                &metadata.database.username,
                password,
                root_password,
            )
            .await
            .map_err(|error| error.to_string())
        }
        _ => Ok(()),
    }
}

fn event_targets_superseded_container(
    event: &ManagedContainerEvent,
    current_container_id: Option<&str>,
) -> bool {
    event
        .container_id
        .as_deref()
        .zip(current_container_id)
        .is_some_and(|(event_id, current_id)| !container_ids_match(event_id, current_id))
}

fn container_ids_match(left: &str, right: &str) -> bool {
    let left = left.trim().strip_prefix("sha256:").unwrap_or(left.trim());
    let right = right.trim().strip_prefix("sha256:").unwrap_or(right.trim());
    left == right
        || (left.len().min(right.len()) >= 12
            && (left.starts_with(right) || right.starts_with(left)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::docker::ManagedContainerAction;

    fn event(
        protocol: Protocol,
        action: ManagedContainerAction,
        container_id: Option<&str>,
    ) -> ManagedContainerEvent {
        ManagedContainerEvent {
            container_id: container_id.map(str::to_string),
            instance_id: "inst_password_rotation".to_string(),
            protocol,
            action,
        }
    }

    #[test]
    fn password_recreation_teardown_events_targeting_the_old_container_are_superseded() {
        for protocol in [
            Protocol::Redis,
            Protocol::Valkey,
            Protocol::Clickhouse,
            Protocol::Qdrant,
        ] {
            for action in [
                ManagedContainerAction::Exited {
                    exit_code: Some(137),
                },
                ManagedContainerAction::Destroyed,
            ] {
                let event = event(protocol, action, Some("old-container-id"));
                assert!(event_targets_superseded_container(
                    &event,
                    Some("new-container-id")
                ));
            }
        }
    }

    #[test]
    fn a_failure_from_the_current_container_is_not_suppressed() {
        let event = event(
            Protocol::Redis,
            ManagedContainerAction::Exited {
                exit_code: Some(137),
            },
            Some("0123456789abcdef"),
        );

        assert!(!event_targets_superseded_container(
            &event,
            Some("0123456789abcdef")
        ));
        assert!(!event_targets_superseded_container(
            &event,
            Some("0123456789abcdef0123456789abcdef")
        ));
    }

    #[test]
    fn missing_identity_is_not_suppressed_but_stale_activation_is() {
        let unidentified = event(Protocol::Qdrant, ManagedContainerAction::Destroyed, None);
        let activation = event(
            Protocol::Qdrant,
            ManagedContainerAction::Started,
            Some("old-container-id"),
        );

        assert!(!event_targets_superseded_container(
            &unidentified,
            Some("new-container-id")
        ));
        assert!(event_targets_superseded_container(
            &activation,
            Some("new-container-id")
        ));
        assert!(!event_targets_superseded_container(
            &activation,
            Some("old-container-id")
        ));
    }
}
