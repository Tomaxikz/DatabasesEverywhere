use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use secrecy::{ExposeSecret, SecretString};
use tokio::task::JoinError;

use super::{
    ApiError, PreviousCredential, ResetInstancePasswordResponse,
    rotation::{
        activate_resp_acl, apply_db_credential, capture_mysql_tenant_auth,
        capture_postgres_verifier, protected_value_matches, reset_password_in_place,
        restore_resp_acl, verify_tenant_credential,
    },
};
use crate::{
    api::{
        http::{
            response::{ApiResponse, ApiResult},
            router::AppState,
        },
        instances::create::launch_container_from_spec,
    },
    instances::{
        locks::InstanceLocks,
        metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus},
        paths::InstancePaths,
    },
    runtime::docker::DockerInstanceSpec,
    shared::protocol::Protocol,
};

pub(super) struct InPlaceResetContext<'a> {
    pub(super) state: &'a AppState,
    pub(super) metadata: &'a InstanceMetadata,
    pub(super) paths: &'a InstancePaths,
    pub(super) credential_data_path: &'a std::path::Path,
    pub(super) new_password: &'a SecretString,
    pub(super) previous: &'a PreviousCredential,
}

pub(super) enum PasswordMetadataCommitResolution {
    Committed,
    Previous,
    Uncertain {
        reason: String,
        persisted: Option<Box<InstanceMetadata>>,
    },
}

pub(super) async fn run_password_worker<T, W, R, RF>(
    locks: &InstanceLocks,
    instance_id: &str,
    worker: W,
    recovery: R,
) -> T
where
    T: Send + 'static,
    W: Future<Output = T> + Send + 'static,
    R: FnOnce(JoinError) -> RF + Send,
    RF: Future<Output = T> + Send,
{
    let _operation = locks.lock(instance_id).await;
    match tokio::spawn(worker).await {
        Ok(result) => result,
        Err(error) => recovery(error).await,
    }
}

pub(super) enum PasswordWorkerPanicRecoveryPlan {
    QuarantineDurable(Box<InstanceMetadata>),
    StopWithoutPersistence {
        protocol: Option<Protocol>,
        reason: String,
    },
}

pub(super) fn plan_panic_recovery(
    persisted: Result<Option<InstanceMetadata>, String>,
    stale_store: Option<&InstanceMetadata>,
) -> PasswordWorkerPanicRecoveryPlan {
    match persisted {
        Ok(Some(metadata)) => {
            PasswordWorkerPanicRecoveryPlan::QuarantineDurable(Box::new(metadata))
        }
        Ok(None) => PasswordWorkerPanicRecoveryPlan::StopWithoutPersistence {
            protocol: stale_store.map(|metadata| metadata.protocol),
            reason: "the durable instance metadata row is missing".to_string(),
        },
        Err(reason) => PasswordWorkerPanicRecoveryPlan::StopWithoutPersistence {
            protocol: stale_store.map(|metadata| metadata.protocol),
            reason: format!("the durable instance metadata could not be read: {reason}"),
        },
    }
}

pub(super) async fn recover_password_panic(state: &AppState, instance_id: &str) -> String {
    // This durable read runs while the supervisor still owns the instance
    // operation lock. A successful credential commit may have happened just
    // before the worker panicked, while the in-memory store is still stale.
    let persisted = state
        .manager
        .get_persisted(instance_id)
        .await
        .map_err(|error| error.to_string());
    let stale_store = state.instances.get(instance_id).await;
    match plan_panic_recovery(persisted, stale_store.as_ref()) {
        PasswordWorkerPanicRecoveryPlan::QuarantineDurable(metadata) => {
            let result = quarantine_instance(state, &metadata).await;
            password_quarantine_summary(&result)
        }
        PasswordWorkerPanicRecoveryPlan::StopWithoutPersistence { protocol, reason } => {
            let stop_summary = stop_stale_runtime(state, instance_id, protocol).await;
            format!("{reason}; {stop_summary}")
        }
    }
}

async fn stop_stale_runtime(
    state: &AppState,
    instance_id: &str,
    protocol: Option<Protocol>,
) -> String {
    super::super::route_fence::fence(state, instance_id).await;
    state.instances.remove(instance_id).await;

    let protocols = protocol
        .map(|protocol| vec![protocol])
        .unwrap_or_else(|| Protocol::ALL.to_vec());
    let mut failures = Vec::new();
    for protocol in protocols {
        match state.docker.stop(protocol, instance_id).await {
            Ok(_) => {}
            Err(error) if error.is_not_found() || error.is_not_running() => {}
            Err(error) => failures.push(format!("{protocol}: {error}")),
        }
    }

    state.instance_runtime_cache.remove(instance_id).await;
    state.resource_cache.invalidate_runtime(instance_id).await;
    state.monitoring_cache.invalidate().await;

    if failures.is_empty() {
        "the in-memory route was removed and the managed runtime was stopped without rewriting durable credentials"
            .to_string()
    } else {
        format!(
            "the in-memory route was removed without rewriting durable credentials, but runtime shutdown was incomplete: {}",
            failures.join("; ")
        )
    }
}

async fn quarantine_instance(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<(), ApiError> {
    // Persist fail-closed intent before touching the runtime. Boot must never
    // route an instance whose active credential is uncertain.
    let quarantined = quarantined_metadata(metadata);
    super::super::route_fence::fence(state, &metadata.instance_id).await;
    state.instances.upsert(quarantined.clone()).await;
    let persistence_error = state.manager.upsert(quarantined).await.err().map(|error| {
        tracing::error!(
            instance_id = %metadata.instance_id,
            error = %error,
            "failed to persist quarantine after password reset rollback failure; runtime stop will still be attempted"
        );
        format!("failed to persist password-reset quarantine: {error}")
    });
    let runtime_error = match state
        .docker
        .stop(metadata.protocol, &metadata.instance_id)
        .await
    {
        Ok(_) => None,
        Err(error) if error.is_not_found() || error.is_not_running() => None,
        Err(error) => {
            tracing::error!(
                instance_id = %metadata.instance_id,
                %error,
                "failed to stop instance while quarantining an uncertain password rotation"
            );
            Some(format!(
                "failed to stop password-reset quarantine target: {error}"
            ))
        }
    };
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state
        .resource_cache
        .invalidate_runtime(&metadata.instance_id)
        .await;
    state.monitoring_cache.invalidate().await;

    let failures = [persistence_error, runtime_error]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(ApiError::Runtime(failures.join("; ")))
    }
}

fn password_quarantine_summary(result: &Result<(), ApiError>) -> String {
    match result {
        Ok(()) => "the instance was stopped and quarantined".to_string(),
        Err(error) => format!(
            "gateway routes were removed, but complete shutdown or durable quarantine failed: {error}"
        ),
    }
}

pub(super) fn quarantined_metadata(metadata: &InstanceMetadata) -> InstanceMetadata {
    let mut quarantined = metadata.clone();
    quarantined.status = InstanceStatus::Quarantined;
    quarantined.desired_state = DesiredInstanceState::Stopped;
    quarantined.updated_at = crate::shared::time::now_rfc3339();
    quarantined
}

pub(super) async fn resolve_password_metadata_commit(
    state: &AppState,
    previous: &InstanceMetadata,
    intended: &InstanceMetadata,
) -> PasswordMetadataCommitResolution {
    match state.manager.get_persisted(&intended.instance_id).await {
        Ok(Some(persisted)) => classify_password_commit(persisted, previous, intended),
        Ok(None) => PasswordMetadataCommitResolution::Uncertain {
            reason: "the durable instance metadata row is missing".to_string(),
            persisted: None,
        },
        Err(error) => PasswordMetadataCommitResolution::Uncertain {
            reason: format!("the durable metadata read failed: {error}"),
            persisted: None,
        },
    }
}

pub(super) fn classify_password_commit(
    persisted: InstanceMetadata,
    previous: &InstanceMetadata,
    intended: &InstanceMetadata,
) -> PasswordMetadataCommitResolution {
    match super::super::major_upgrade::classify_upgrade_commit(&persisted, previous, intended) {
        super::super::major_upgrade::MajorUpgradeCommitResolution::Committed => {
            PasswordMetadataCommitResolution::Committed
        }
        super::super::major_upgrade::MajorUpgradeCommitResolution::NotCommitted => {
            PasswordMetadataCommitResolution::Previous
        }
        super::super::major_upgrade::MajorUpgradeCommitResolution::Uncertain(reason) => {
            PasswordMetadataCommitResolution::Uncertain {
                reason,
                persisted: Some(Box::new(persisted)),
            }
        }
    }
}

pub(super) async fn fail_uncertain_password_commit(
    state: &AppState,
    intended: &InstanceMetadata,
    persisted: Option<&InstanceMetadata>,
    commit_error: &str,
    reason: &str,
) -> ApiResult<ResetInstancePasswordResponse> {
    let quarantine_basis = persisted.unwrap_or(intended);
    let quarantine = quarantine_instance(state, quarantine_basis).await;
    let quarantine_summary = password_quarantine_summary(&quarantine);
    tracing::error!(
        event = "audit instance_password_reset_commit_uncertain",
        instance_id = %intended.instance_id,
        protocol = %intended.protocol,
        error = %commit_error,
        %reason,
        "password reset runtime completed but durable metadata could not be classified; instance was quarantined without attempting a credential rollback"
    );
    Err(ApiError::Runtime(format!(
        "password reset runtime completed, but metadata persistence failed ({commit_error}) and durable commit state is uncertain ({reason}); {quarantine_summary}"
    )))
}

pub(super) async fn reset_live_password(
    state: &AppState,
    mut metadata: InstanceMetadata,
    paths: &InstancePaths,
    credential_data_path: &std::path::Path,
    new_password: &SecretString,
    previous: &PreviousCredential,
) -> ApiResult<ResetInstancePasswordResponse> {
    let previous_metadata = metadata.clone();
    let new_verifier =
        matches!(metadata.protocol, Protocol::Mariadb | Protocol::Mysql).then(|| {
            crate::protocols::mariadb::native_password_sha1_stage2_hex(new_password.expose_secret())
        });
    let credential_changed = Arc::new(AtomicBool::new(false));
    super::super::route_fence::fence(state, &metadata.instance_id).await;
    {
        let context = InPlaceResetContext {
            state,
            metadata: &previous_metadata,
            paths,
            credential_data_path,
            new_password,
            previous,
        };
        if let Err(error) = reset_password_in_place(
            &context,
            new_verifier.as_deref(),
            Arc::clone(&credential_changed),
        )
        .await
        {
            return rollback_in_place_or_fail(
                &context,
                credential_changed.load(Ordering::Acquire),
                error,
            )
            .await;
        }
    }

    let qdrant_route_secret = state.config.websocket_jwt_secret();
    apply_new_route_auth(&mut metadata, new_password, previous, qdrant_route_secret);
    metadata.status = InstanceStatus::Running;
    metadata.updated_at = crate::shared::time::now_rfc3339();
    if let Err(error) = state
        .manager
        .upsert_recovered_secrets(metadata.clone())
        .await
    {
        let commit_error = error.to_string();
        match resolve_password_metadata_commit(state, &previous_metadata, &metadata).await {
            PasswordMetadataCommitResolution::Committed => {
                state.instances.upsert(metadata.clone()).await;
                tracing::warn!(
                    event = "audit instance_password_reset_commit_ack_lost",
                    instance_id = %metadata.instance_id,
                    protocol = %metadata.protocol,
                    error = %commit_error,
                    "password reset metadata was durably committed despite a failed commit acknowledgement"
                );
            }
            PasswordMetadataCommitResolution::Previous => {
                let context = InPlaceResetContext {
                    state,
                    metadata: &previous_metadata,
                    paths,
                    credential_data_path,
                    new_password,
                    previous,
                };
                return rollback_in_place_or_fail(
                    &context,
                    credential_changed.load(Ordering::Acquire),
                    ApiError::Runtime(format!(
                        "failed to persist rotated instance authentication: {commit_error}"
                    )),
                )
                .await;
            }
            PasswordMetadataCommitResolution::Uncertain { reason, persisted } => {
                return fail_uncertain_password_commit(
                    state,
                    &metadata,
                    persisted.as_deref(),
                    &commit_error,
                    &reason,
                )
                .await;
            }
        }
    }

    invalidate_password_caches(state, &metadata).await;
    tracing::info!(
        event = "audit instance_password_reset",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        restarted = false,
        "instance password reset completed in place"
    );
    Ok(ApiResponse::ok(ResetInstancePasswordResponse {
        instance: metadata,
        restarted: false,
    }))
}

async fn rollback_in_place_or_fail(
    context: &InPlaceResetContext<'_>,
    credential_changed: bool,
    original_error: ApiError,
) -> ApiResult<ResetInstancePasswordResponse> {
    let original_message = original_error.to_string();
    let rollback = rollback_in_place_password_reset(context, credential_changed).await;
    match rollback {
        Ok(()) => {
            context
                .state
                .instances
                .upsert(context.metadata.clone())
                .await;
            invalidate_password_caches(context.state, context.metadata).await;
            tracing::warn!(
                event = "audit instance_password_reset_rolled_back",
                instance_id = %context.metadata.instance_id,
                protocol = %context.metadata.protocol,
                error = %original_message,
                "in-place password reset failed and the previous credential was restored"
            );
            Err(original_error)
        }
        Err(rollback_error) => {
            let rollback_message = rollback_error.to_string();
            let quarantine = quarantine_instance(context.state, context.metadata).await;
            let quarantine_summary = password_quarantine_summary(&quarantine);
            tracing::error!(
                event = "audit instance_password_reset_rollback_failed",
                instance_id = %context.metadata.instance_id,
                protocol = %context.metadata.protocol,
                error = %original_message,
                rollback_error = %rollback_message,
                "in-place password reset and rollback both failed"
            );
            Err(ApiError::Runtime(format!(
                "password reset failed ({original_message}) and rollback failed ({rollback_message}); {quarantine_summary}"
            )))
        }
    }
}

async fn rollback_in_place_password_reset(
    context: &InPlaceResetContext<'_>,
    credential_changed: bool,
) -> Result<(), ApiError> {
    if matches!(
        context.metadata.protocol,
        Protocol::Redis | Protocol::Valkey
    ) {
        let acl = context.previous.acl.as_deref().ok_or_else(|| {
            ApiError::Runtime("previous RESP ACL was not captured for rollback".to_string())
        })?;
        restore_resp_acl(context.metadata.protocol, context.credential_data_path, acl).await?;
        context
            .paths
            .restore_data_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        let previous_password = context.previous.environment.as_ref().ok_or_else(|| {
            ApiError::Runtime("previous RESP credential was not captured for rollback".to_string())
        })?;
        let (first_password, fallback_password) = if credential_changed {
            (context.new_password, previous_password)
        } else {
            (previous_password, context.new_password)
        };
        if activate_resp_acl(context.state, context.metadata, first_password)
            .await
            .is_err()
        {
            // A timed-out ACL LOAD may have completed just before the runtime
            // recovered the exec by restarting the container. Try the other
            // known credential so rollback remains deterministic in either
            // state.
            activate_resp_acl(context.state, context.metadata, fallback_password).await?;
        }
        return Ok(());
    }

    // The mutation flag is set immediately before a live database command is
    // dispatched. If it is still clear, preparation or administrator
    // verification failed and the tenant credential was never touched.
    if !credential_changed {
        return Ok(());
    }

    // PostgreSQL and MySQL can restore the exact captured verifier rather than
    // deriving a new salted verifier from plaintext. This also handles legacy
    // instances whose tenant plaintext was never persisted.
    let rollback_password = match context.metadata.protocol {
        Protocol::Postgres | Protocol::Mysql => None,
        _ => context.previous.environment.as_ref(),
    };
    apply_db_credential(
        context.state,
        context.metadata,
        context.previous,
        rollback_password,
        context.previous.native_password_verifier.as_deref(),
        None,
    )
    .await?;
    verify_rollback_credential(context).await
}

pub(super) async fn verify_rollback_credential(
    context: &InPlaceResetContext<'_>,
) -> Result<(), ApiError> {
    match context.metadata.protocol {
        Protocol::Postgres => {
            let actual =
                capture_postgres_verifier(context.state, context.metadata, context.previous)
                    .await?;
            let expected = context
                .previous
                .native_password_verifier
                .as_deref()
                .ok_or_else(|| {
                    ApiError::Runtime(
                        "previous PostgreSQL password verifier is missing".to_string(),
                    )
                })?;
            if !protected_value_matches(expected, &actual) {
                return Err(ApiError::Runtime(
                    "PostgreSQL credential rollback could not be verified".to_string(),
                ));
            }
        }
        Protocol::Mysql => {
            let (plugin, authentication_string) =
                capture_mysql_tenant_auth(context.state, context.metadata, context.previous)
                    .await?;
            let expected_plugin =
                context
                    .previous
                    .mysql_auth_plugin
                    .as_deref()
                    .ok_or_else(|| {
                        ApiError::Runtime(
                            "previous MySQL authentication plugin is missing".to_string(),
                        )
                    })?;
            let expected_auth =
                context
                    .previous
                    .mysql_auth_string_b64
                    .as_ref()
                    .ok_or_else(|| {
                        ApiError::Runtime(
                            "previous MySQL authentication string is missing".to_string(),
                        )
                    })?;
            if plugin != expected_plugin
                || !protected_value_matches(
                    expected_auth.expose_secret(),
                    authentication_string.expose_secret(),
                )
            {
                return Err(ApiError::Runtime(
                    "MySQL credential rollback could not be verified".to_string(),
                ));
            }
        }
        Protocol::Mariadb | Protocol::Mongodb => {}
        Protocol::Redis | Protocol::Valkey | Protocol::Clickhouse | Protocol::Qdrant => {
            return Err(ApiError::Runtime(format!(
                "{} cannot verify a live database password rollback",
                context.metadata.protocol
            )));
        }
    }
    if let Some(previous_password) = context.previous.environment.as_ref() {
        verify_tenant_credential(context.state, context.metadata, previous_password).await?;
    }
    Ok(())
}

pub(super) async fn rollback_or_fail(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    credential_data_path: &std::path::Path,
    old_spec: &DockerInstanceSpec,
    previous: &PreviousCredential,
    original_error: ApiError,
) -> ApiResult<ResetInstancePasswordResponse> {
    let original_message = original_error.to_string();
    match rollback_password_reset(
        state,
        metadata,
        paths,
        credential_data_path,
        old_spec,
        previous,
    )
    .await
    {
        Ok(()) => {
            state.instances.upsert(metadata.clone()).await;
            invalidate_password_caches(state, metadata).await;
            tracing::warn!(
                event = "audit instance_password_reset_rolled_back",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                error = %original_message,
                "instance password reset failed and the previous credential was restored"
            );
            Err(original_error)
        }
        Err(rollback_error) => {
            let rollback_message = rollback_error.to_string();
            let quarantine = quarantine_instance(state, metadata).await;
            let quarantine_summary = password_quarantine_summary(&quarantine);
            tracing::error!(
                event = "audit instance_password_reset_rollback_failed",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                error = %original_message,
                rollback_error = %rollback_message,
                "instance password reset and rollback both failed"
            );
            Err(ApiError::Runtime(format!(
                "password reset failed ({original_message}) and rollback failed ({rollback_message}); {quarantine_summary}"
            )))
        }
    }
}

async fn rollback_password_reset(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    credential_data_path: &std::path::Path,
    old_spec: &DockerInstanceSpec,
    previous: &PreviousCredential,
) -> Result<(), ApiError> {
    delete_managed_container(state, metadata.protocol, &metadata.instance_id).await?;
    if matches!(metadata.protocol, Protocol::Redis | Protocol::Valkey) {
        let acl = previous.acl.as_deref().ok_or_else(|| {
            ApiError::Runtime("previous RESP ACL was not captured for rollback".to_string())
        })?;
        restore_resp_acl(metadata.protocol, credential_data_path, acl).await?;
        paths
            .restore_data_owner()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
    }

    let no_progress = |_event| {};
    // The old spec (and restored RESP ACL above) is the rollback. Its normal
    // launch readiness probe authenticates with the old credential, so a
    // rollback cannot be reported as successful while authentication is stale.
    launch_container_from_spec(
        state,
        old_spec,
        metadata.protocol,
        &metadata.instance_id,
        &no_progress,
        false,
        || async { Ok(()) },
    )
    .await
    .map_err(|error| error.into_api_error())?;
    Ok(())
}

pub(super) async fn delete_managed_container(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
) -> Result<(), ApiError> {
    match state.docker.delete(protocol, instance_id).await {
        Ok(_) => Ok(()),
        Err(error) if error.is_not_found() => Ok(()),
        Err(error) => Err(super::super::docker_error(error)),
    }
}

pub(super) fn apply_new_route_auth(
    metadata: &mut InstanceMetadata,
    password: &SecretString,
    previous: &PreviousCredential,
    qdrant_route_secret: &[u8],
) {
    metadata.tenant_password = Some(password.expose_secret().to_string());
    match metadata.protocol {
        Protocol::Mariadb => {
            metadata.mariadb_root_password = previous
                .maintenance
                .as_ref()
                .map(|value| value.expose_secret().to_string());
            metadata.mariadb_native_password_sha1_stage2 =
                Some(crate::protocols::mariadb::native_password_sha1_stage2_hex(
                    password.expose_secret(),
                ));
        }
        Protocol::Mysql => {
            metadata.mysql_root_password = previous
                .maintenance
                .as_ref()
                .map(|value| value.expose_secret().to_string());
            metadata.mysql_native_password_sha1_stage2 =
                Some(crate::protocols::mariadb::native_password_sha1_stage2_hex(
                    password.expose_secret(),
                ));
        }
        Protocol::Qdrant => {
            metadata.route_key_sha256 = Some(crate::protocols::qdrant::route_key_fingerprint(
                qdrant_route_secret,
                password.expose_secret(),
            ));
        }
        Protocol::Postgres => {
            metadata.postgres_admin_password = previous
                .maintenance
                .as_ref()
                .map(|value| value.expose_secret().to_string());
        }
        Protocol::Mongodb => {
            metadata.mongodb_root_password = previous
                .maintenance
                .as_ref()
                .map(|value| value.expose_secret().to_string());
        }
        Protocol::Redis | Protocol::Valkey | Protocol::Clickhouse => {}
    }
}

pub(super) async fn invalidate_password_caches(state: &AppState, metadata: &InstanceMetadata) {
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state
        .resource_cache
        .invalidate_runtime(&metadata.instance_id)
        .await;
    state.monitoring_cache.invalidate().await;
}
