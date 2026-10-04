use super::super::ResetInstancePasswordResponse;
use super::lifecycle::{completion_report, mark_quarantined, route_was_open, target};
use super::maintenance::{clear_caches, drain_tenant_sessions};
use super::runtime::{load_running_runtime, reload_after_runtime_lock, shared_runtime_id};
use crate::routes::http::response::{ApiError, ApiResponse, ApiResult};
use crate::routes::http::router::AppState;
use crate::server::metadata::InstanceMetadata;
use crate::server::placement::{EngineRuntime, tenant};
use crate::utils::time::now_rfc3339;
use secrecy::ExposeSecret;
use secrecy::SecretString;

pub(in super::super) async fn reset_password(
    state: &AppState,
    mut metadata: InstanceMetadata,
    new_password: SecretString,
) -> ApiResult<ResetInstancePasswordResponse> {
    let runtime_id = shared_runtime_id(&metadata)?.to_string();
    let _runtime_operation = state.instance_locks.lock(&runtime_id).await;
    metadata = reload_after_runtime_lock(state, &metadata).await?;
    let route_fenced = state.instances.routes_fenced(&metadata.instance_id).await;
    if !route_was_open(&metadata, route_fenced) {
        return Err(ApiError::Conflict(
            "password reset requires a running, unfenced shared tenant".to_string(),
        ));
    }
    let previous_password = metadata.tenant_password.clone().ok_or_else(|| {
        ApiError::Conflict(
            "the encrypted tenant credential is missing; shared password rotation cannot be rolled back"
                .to_string(),
        )
    })?;
    let previous = metadata.clone();
    let runtime = load_running_runtime(state, &metadata).await?;
    drain_tenant_sessions(state, &metadata.instance_id).await?;
    let password = new_password.expose_secret();
    let target = target(&metadata);
    let rotated = match tenant::rotate_password(&state.docker, &runtime, target, password).await {
        Ok(()) => tenant::verify_password(&state.docker, &runtime, target, password).await,
        Err(error) => Err(error),
    };
    if let Err(error) = rotated {
        return rollback_password(
            state,
            &runtime,
            &previous,
            &previous_password,
            error.to_string(),
        )
        .await;
    }

    metadata.tenant_password = Some(password.to_string());
    metadata
        .protocol
        .engine()
        .store_tenant_native_verifier(&mut metadata, password);
    metadata.updated_at = now_rfc3339();
    if let Err(error) = state
        .manager
        .upsert_recovered_secrets(metadata.clone())
        .await
    {
        match state.manager.get_persisted(&metadata.instance_id).await {
            Ok(Some(persisted)) if persisted.tenant_password.as_deref() == Some(password) => {
                state.instances.upsert(metadata.clone()).await;
                tracing::warn!(
                    event = "audit shared_tenant_password_commit_ack_lost",
                    instance_id = %metadata.instance_id,
                    runtime_id = %runtime.runtime_id,
                    %error,
                );
            }
            Ok(Some(persisted))
                if persisted.tenant_password.as_deref() == Some(previous_password.as_str()) =>
            {
                return rollback_password(
                    state,
                    &runtime,
                    &previous,
                    &previous_password,
                    format!("failed to persist rotated credential: {error}"),
                )
                .await;
            }
            Ok(Some(mut persisted)) => {
                mark_quarantined(&mut persisted);
                let quarantine = state
                    .manager
                    .quarantine(
                        persisted,
                        crate::storage::quarantine::QuarantineKind::CredentialIntegrity,
                    )
                    .await;
                return Err(ApiError::Runtime(format!(
                    "shared password rotation completed, but durable credential state is ambiguous after {error}; tenant remained fenced and quarantine persistence: {}",
                    completion_report(quarantine)
                )));
            }
            Ok(None) | Err(_) => {
                return Err(ApiError::Runtime(format!(
                    "shared password rotation completed, but its durable commit could not be verified after {error}; tenant remains fenced for operator recovery"
                )));
            }
        }
    }
    clear_caches(state, &metadata).await;
    tracing::info!(
        event = "audit shared_tenant_password_reset",
        instance_id = %metadata.instance_id,
        runtime_id = %runtime.runtime_id,
        protocol = %metadata.protocol,
    );
    Ok(ApiResponse::ok(ResetInstancePasswordResponse {
        instance: metadata,
        restarted: false,
    }))
}

pub(super) async fn rollback_password(
    state: &AppState,
    runtime: &EngineRuntime,
    previous: &InstanceMetadata,
    previous_password: &str,
    original_error: String,
) -> ApiResult<ResetInstancePasswordResponse> {
    let target = target(previous);
    let rollback = tenant::rotate_password(&state.docker, runtime, target, previous_password).await;
    let verified = match rollback {
        Ok(()) => tenant::verify_password(&state.docker, runtime, target, previous_password).await,
        Err(error) => Err(error),
    };
    if let Err(rollback_error) = verified {
        let mut quarantined = previous.clone();
        mark_quarantined(&mut quarantined);
        let persist = state
            .manager
            .quarantine(
                quarantined,
                crate::storage::quarantine::QuarantineKind::CredentialIntegrity,
            )
            .await;
        return Err(ApiError::Runtime(format!(
            "shared password reset failed ({original_error}) and rollback failed ({rollback_error}); tenant was fenced and quarantine persistence: {}",
            completion_report(persist)
        )));
    }
    state.instances.upsert(previous.clone()).await;
    Err(ApiError::Runtime(format!(
        "shared password reset failed and the previous credential was restored: {original_error}"
    )))
}
