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
        && event.action.deactivates_container()
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
                "ignored a delayed teardown event emitted by a replaced managed container"
            );
            return Ok(());
        }
    }

    let previous_status = metadata.status;
    let activation_observed = if previous_status == InstanceStatus::Running {
        false
    } else if let Some(event) = event.as_ref() {
        event.action.activates_container()
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
    let activation_error = if activation_observed {
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
            Ok(_) => harden_activated_instance_auth(state, &metadata).await.err(),
            Err(error) => Some(error.to_string()),
        }
    } else {
        None
    };
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
    event.action.deactivates_container()
        && event
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
    fn missing_identity_and_activation_events_keep_normal_reconciliation() {
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
        assert!(!event_targets_superseded_container(
            &activation,
            Some("new-container-id")
        ));
    }
}
