use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use crate::{
    api::http::state::AppState,
    instances::metadata::InstanceMetadata,
    placement::DeploymentMode,
    shared::{protocol::Protocol, time::now_rfc3339},
};

/// Recover only absent tenant secrets, before storage migration or image repair.
/// The owned container and persisted verifier must agree; never guess/reset keys.
pub(super) async fn recover(state: &AppState) -> anyhow::Result<()> {
    for mut metadata in state.instances.list().await {
        if metadata.deployment_mode != DeploymentMode::Dedicated
            || !matches!(metadata.protocol, Protocol::Qdrant | Protocol::Mariadb)
            || metadata
                .tenant_password
                .as_ref()
                .is_some_and(|secret| !secret.is_empty())
        {
            continue;
        }
        let _operation = state.instance_locks.lock(&metadata.instance_id).await;
        let candidate = match candidate(state, &metadata).await {
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
        if metadata.protocol == Protocol::Qdrant {
            metadata.route_key_sha256 = Some(crate::protocols::qdrant::route_key_fingerprint(
                state.config.websocket_jwt_secret(),
                secret,
            ));
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

async fn candidate(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> anyhow::Result<Option<SecretString>> {
    let keys: &[&str] = match metadata.protocol {
        Protocol::Qdrant => &["QDRANT__SERVICE__API_KEY"],
        Protocol::Mariadb => &["DBE_MARIADB_PASSWORD", "MARIADB_PASSWORD"],
        _ => return Ok(None),
    };
    if metadata.protocol == Protocol::Mariadb {
        let user = state
            .docker
            .legacy_environment_secret(metadata.protocol, &metadata.instance_id, "MARIADB_USER")
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
    match metadata.protocol {
        Protocol::Qdrant => {
            let Some(saved) = &metadata.route_key_sha256 else {
                return false;
            };
            let current = crate::protocols::qdrant::route_key_fingerprint(daemon_secret, secret);
            let legacy = crate::shared::hex::encode_lower(&Sha256::digest(secret.as_bytes()));
            saved == &current || saved == &legacy
        }
        Protocol::Mariadb => metadata
            .mariadb_native_password_sha1_stage2
            .as_ref()
            .is_some_and(|saved| {
                saved.eq_ignore_ascii_case(
                    &crate::protocols::mariadb::native_password_sha1_stage2_hex(secret),
                )
            }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qdrant_recovery_requires_matching_legacy_or_keyed_fingerprint() {
        let mut metadata = crate::instances::test_support::metadata("legacy", Protocol::Qdrant);
        assert!(!matches_saved_verifier(&metadata, "secret", b"daemon"));
        for fingerprint in [
            crate::shared::hex::encode_lower(&Sha256::digest(b"secret")),
            crate::protocols::qdrant::route_key_fingerprint(b"daemon", "secret"),
        ] {
            metadata.route_key_sha256 = Some(fingerprint);
            assert!(matches_saved_verifier(&metadata, "secret", b"daemon"));
            assert!(!matches_saved_verifier(&metadata, "wrong", b"daemon"));
            assert!(!matches_saved_verifier(&metadata, "", b"daemon"));
        }
    }

    #[test]
    fn mariadb_recovery_requires_saved_tenant_verifier() {
        let mut metadata = crate::instances::test_support::metadata("legacy", Protocol::Mariadb);
        metadata.mariadb_native_password_sha1_stage2 = None;
        assert!(!matches_saved_verifier(&metadata, "secret", b"daemon"));
        metadata.mariadb_native_password_sha1_stage2 = Some(
            crate::protocols::mariadb::native_password_sha1_stage2_hex("secret"),
        );
        assert!(matches_saved_verifier(&metadata, "secret", b"daemon"));
        assert!(!matches_saved_verifier(&metadata, "wrong", b"daemon"));
    }
}
