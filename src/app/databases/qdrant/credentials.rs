use sha2::{Digest, Sha256};

use crate::{
    databases::engine::{CredentialRollback, EngineCredentials, RecoverySecret, RotatedSecrets},
    gateway::protocols::qdrant::route_key_fingerprint,
    instance::metadata::InstanceMetadata,
};

use super::engine::Qdrant;

impl EngineCredentials for Qdrant {
    fn credential_rollback(&self) -> CredentialRollback {
        CredentialRollback::RecreateContainer
    }

    fn tenant_password_env_keys(&self) -> &'static [&'static str] {
        &["QDRANT__SERVICE__API_KEY"]
    }

    // Qdrant reads the new API key from its immutable container
    // configuration. Its startup readiness probe confirms the authenticated
    // gRPC listener is accepting connections before metadata is committed.
    fn tenant_auth_probe(&self, _username: &str, _database: &str) -> Option<String> {
        None
    }

    fn required_recovery_secrets<'a>(
        &self,
        metadata: &'a InstanceMetadata,
    ) -> Vec<RecoverySecret<'a>> {
        vec![RecoverySecret {
            field: "route_key_sha256",
            value: metadata.route_key_sha256.as_deref(),
            hex_len: Some(64),
        }]
    }

    fn legacy_recovery_env_keys(&self) -> &'static [&'static str] {
        &["QDRANT__SERVICE__API_KEY"]
    }

    fn matches_legacy_verifier(
        &self,
        metadata: &InstanceMetadata,
        secret: &str,
        daemon_secret: &[u8],
    ) -> bool {
        let Some(saved) = &metadata.route_key_sha256 else {
            return false;
        };
        let current = route_key_fingerprint(daemon_secret, secret);
        let legacy = crate::utils::hex::encode_lower(&Sha256::digest(secret.as_bytes()));
        saved == &current || saved == &legacy
    }

    fn tenant_route_fingerprint(&self, daemon_secret: &[u8], secret: &str) -> Option<String> {
        Some(route_key_fingerprint(daemon_secret, secret))
    }

    fn store_rotated_secrets(&self, metadata: &mut InstanceMetadata, rotated: &RotatedSecrets<'_>) {
        metadata.route_key_sha256 = Some(route_key_fingerprint(
            rotated.qdrant_route_secret,
            rotated.plaintext,
        ));
    }
}
