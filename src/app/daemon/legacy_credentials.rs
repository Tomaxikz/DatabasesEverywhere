use secrecy::{ExposeSecret, SecretString};

use crate::{
    server::metadata::InstanceMetadata, server::placement::DeploymentMode, state::AppState,
    utils::time::now_rfc3339,
};

/// Recover only absent tenant secrets, before storage migration or image repair.
/// The owned container and persisted verifier must agree; never guess/reset keys.
pub(super) async fn recover(state: &AppState) -> anyhow::Result<()> {
    for mut metadata in state.instances.list().await {
        if !needs_credential_recovery(&metadata) {
            continue;
        }
        let _operation = state.instance_locks.lock(&metadata.instance_id).await;
        let candidate = match container_credential_candidate(state, &metadata).await {
            Ok(Some(candidate)) => candidate,
            Ok(None) => continue,
            Err(_) => {
                // Neither Docker error bodies nor candidate values belong in logs.
                tracing::warn!(event = "audit legacy_credential_recovery_deferred", instance_id = %metadata.instance_id,
                    "could not verify a unique credential from the owned container; saved state was not changed");
                continue;
            }
        };
        let secret = candidate.expose_secret();
        if !matches_saved_verifier(&metadata, secret, state.config.websocket_jwt_secret()) {
            tracing::warn!(event = "audit legacy_credential_recovery_deferred", instance_id = %metadata.instance_id,
                "container credential does not match a saved verifier; password repair is required");
            continue;
        }
        metadata.tenant_password = Some(secret.to_owned());
        if let Some(fingerprint) = metadata
            .protocol
            .engine()
            .tenant_route_fingerprint(state.config.websocket_jwt_secret(), secret)
        {
            metadata.route_key_sha256 = Some(fingerprint);
        }
        metadata.updated_at = now_rfc3339();
        let id = metadata.instance_id.clone();
        // Repository encryption persists the recovered secret; APIs omit it.
        state.manager.upsert(metadata).await?;
        tracing::info!(
            event = "audit legacy_tenant_credential_recovered",
            instance_id = id,
            "recovered and encrypted the existing tenant credential after verifier validation; password unchanged"
        );
    }
    Ok(())
}

fn needs_credential_recovery(metadata: &InstanceMetadata) -> bool {
    let has_tenant_password = metadata
        .tenant_password
        .as_ref()
        .is_some_and(|secret| !secret.is_empty());
    metadata.deployment_mode == DeploymentMode::Dedicated
        && !metadata
            .protocol
            .engine()
            .legacy_recovery_env_keys()
            .is_empty()
        && !has_tenant_password
}

async fn container_credential_candidate(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> anyhow::Result<Option<SecretString>> {
    let engine = metadata.protocol.engine();
    let keys = engine.legacy_recovery_env_keys();
    if keys.is_empty() {
        return Ok(None);
    }
    if let Some(user_key) = engine.legacy_recovery_username_env_key() {
        let user = state
            .docker
            .legacy_environment_secret(metadata.protocol, &metadata.instance_id, user_key)
            .await?;
        anyhow::ensure!(
            user.as_ref()
                .is_some_and(|user| user.expose_secret() == metadata.database.username),
            "legacy username does not match metadata"
        );
    }
    let mut candidate: Option<SecretString> = None;
    for key in keys {
        if let Some(value) = state
            .docker
            .legacy_environment_secret(metadata.protocol, &metadata.instance_id, key)
            .await?
        {
            anyhow::ensure!(!value.expose_secret().is_empty(), "empty legacy credential");
            anyhow::ensure!(
                candidate
                    .as_ref()
                    .is_none_or(|previous| previous.expose_secret() == value.expose_secret()),
                "conflicting legacy credentials"
            );
            candidate = Some(value);
        }
    }
    Ok(candidate)
}

fn matches_saved_verifier(metadata: &InstanceMetadata, secret: &str, daemon_secret: &[u8]) -> bool {
    if secret.is_empty() {
        return false;
    }
    metadata
        .protocol
        .engine()
        .matches_legacy_verifier(metadata, secret, daemon_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::databases::protocol::Protocol;
    use sha2::{Digest, Sha256};

    #[test]
    fn qdrant_recovery_requires_matching_legacy_or_keyed_fingerprint() {
        let mut metadata = crate::server::test_support::metadata("legacy", Protocol::Qdrant);
        assert!(!matches_saved_verifier(&metadata, "secret", b"daemon"));
        for fingerprint in [
            crate::utils::hex::encode_lower(&Sha256::digest(b"secret")),
            crate::gateway::protocols::qdrant::route_key_fingerprint(b"daemon", "secret"),
        ] {
            metadata.route_key_sha256 = Some(fingerprint);
            assert!(matches_saved_verifier(&metadata, "secret", b"daemon"));
            assert!(!matches_saved_verifier(&metadata, "wrong", b"daemon"));
            assert!(!matches_saved_verifier(&metadata, "", b"daemon"));
        }
    }

    #[test]
    fn mariadb_recovery_requires_saved_tenant_verifier() {
        let mut metadata = crate::server::test_support::metadata("legacy", Protocol::Mariadb);
        metadata.mariadb_native_password_sha1_stage2 = None;
        assert!(!matches_saved_verifier(&metadata, "secret", b"daemon"));
        metadata.mariadb_native_password_sha1_stage2 =
            Some(crate::gateway::protocols::mariadb::native_password_sha1_stage2_hex("secret"));
        assert!(matches_saved_verifier(&metadata, "secret", b"daemon"));
        assert!(!matches_saved_verifier(&metadata, "wrong", b"daemon"));
    }
}
