use serde::Serialize;
use sqlx::{Row, SqliteConnection, SqlitePool};

/// Recovery classification is advice, never permission to clear quarantine.
/// Known codes are assigned at the decision point, not inferred from messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuarantineKind {
    Unknown,
    OwnershipMismatch,
    IsolationMismatch,
    StorageBoundary,
    RuntimePathUnsafe,
    CredentialIntegrity,
    SecurityAttestation,
    ProvisioningIncomplete,
    ImageChangeIncomplete,
    ImportRestoreIncomplete,
    MetadataUncertain,
    ShutdownUnconfirmed,
    RecoveryFailed,
}

impl QuarantineKind {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::OwnershipMismatch => "ownership_mismatch",
            Self::IsolationMismatch => "isolation_mismatch",
            Self::StorageBoundary => "storage_boundary",
            Self::RuntimePathUnsafe => "runtime_path_unsafe",
            Self::CredentialIntegrity => "credential_integrity",
            Self::SecurityAttestation => "security_attestation",
            Self::ProvisioningIncomplete => "provisioning_incomplete",
            Self::ImageChangeIncomplete => "image_change_incomplete",
            Self::ImportRestoreIncomplete => "import_restore_incomplete",
            Self::MetadataUncertain => "metadata_uncertain",
            Self::ShutdownUnconfirmed => "shutdown_unconfirmed",
            Self::RecoveryFailed => "recovery_failed",
        }
    }

    pub(crate) fn recovery_class(self) -> &'static str {
        match self {
            Self::ShutdownUnconfirmed => "validated_retry",
            Self::IsolationMismatch
            | Self::StorageBoundary
            | Self::RuntimePathUnsafe
            | Self::CredentialIntegrity
            | Self::SecurityAttestation
            | Self::ProvisioningIncomplete
            | Self::ImageChangeIncomplete
            | Self::ImportRestoreIncomplete => "repair_required",
            Self::Unknown
            | Self::OwnershipMismatch
            | Self::MetadataUncertain
            | Self::RecoveryFailed => "manual_review",
        }
    }
}

/// Called within the same write transaction as the quarantined metadata. Inserting
/// first lets the SQL status trigger supply Unknown only for unclassified writers.
pub(crate) async fn record(
    connection: &mut SqliteConnection,
    entity_kind: &'static str,
    id: &str,
    generation: &str,
    kind: QuarantineKind,
    source: &'static str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO quarantine_events(entity_kind,entity_id,generation,code,recovery_class,source)
        VALUES (?1,?2,?3,?4,?5,?6)
        ON CONFLICT(entity_kind,entity_id,generation,code) WHERE closed_at IS NULL
        DO UPDATE SET last_seen=strftime('%Y-%m-%dT%H:%M:%fZ','now'),
            occurrences=MIN(quarantine_events.occurrences + 1, 2147483647)",
    )
    .bind(entity_kind)
    .bind(id)
    .bind(generation)
    .bind(kind.code())
    .bind(kind.recovery_class())
    .bind(source)
    .execute(connection)
    .await?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub(crate) struct QuarantineEvent {
    pub event_id: i64,
    pub entity_kind: String,
    pub entity_id: String,
    pub generation: String,
    pub code: String,
    pub recovery_class: String,
    pub guidance: &'static str,
    pub source: String,
    pub first_seen: String,
    pub last_seen: String,
    pub occurrences: i64,
    pub closed_at: Option<String>,
    pub final_status: Option<String>,
}

pub(crate) async fn list(
    pool: &SqlitePool,
    id: Option<&str>,
    history: bool,
    before: Option<i64>,
    limit: u32,
) -> Result<Vec<QuarantineEvent>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT * FROM quarantine_events
        WHERE (?1 IS NULL OR entity_id = ?1) AND (?2 OR closed_at IS NULL)
          AND (?3 IS NULL OR event_id < ?3)
        ORDER BY event_id DESC LIMIT ?4",
    )
    .bind(id)
    .bind(history)
    .bind(before)
    .bind(limit.clamp(1, 1000))
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let code: String = row.try_get("code")?;
            let recovery_class: String = row.try_get("recovery_class")?;
            Ok(QuarantineEvent {
                event_id: row.try_get("event_id")?,
                entity_kind: row.try_get("entity_kind")?,
                entity_id: row.try_get("entity_id")?,
                generation: row.try_get("generation")?,
                guidance: guidance(&code),
                code,
                recovery_class,
                source: row.try_get("source")?,
                first_seen: row.try_get("first_seen")?,
                last_seen: row.try_get("last_seen")?,
                occurrences: row.try_get("occurrences")?,
                closed_at: row.try_get("closed_at")?,
                final_status: row.try_get("final_status")?,
            })
        })
        .collect()
}

fn guidance(code: &str) -> &'static str {
    match code {
        "shutdown_unconfirmed" => {
            "Restore container-engine control and confirm shutdown; validated boot recovery may then succeed."
        }
        "credential_integrity" => {
            "Repair the protected credential or restore the correct key; verify it against the engine before recovery."
        }
        "ownership_mismatch" => {
            "Verify node, pool and tenant ownership; do not adopt an untrusted container or guess ownership."
        }
        "isolation_mismatch" | "security_attestation" => {
            "Repair network or tenant isolation and pass the security checks before recovery."
        }
        "storage_boundary" | "runtime_path_unsafe" => {
            "Repair the expected mounts, ownership and quota boundary; preserve existing database files."
        }
        "import_restore_incomplete" => {
            "Inspect retained rollback state and complete or roll back the interrupted import/restore; do not discard recovery manifests."
        }
        "image_change_incomplete" => {
            "Complete or roll back the recorded image change before recovery."
        }
        "provisioning_incomplete" => {
            "Verify the partially provisioned engine and tenant state before completing setup or explicitly cleaning up."
        }
        "metadata_uncertain" => {
            "Compare durable metadata, reservations and physical state; resolve conflicting or incomplete commits first."
        }
        "recovery_failed" => {
            "A previous recovery failed; inspect its logs and all active causes if boot recovery continues to refuse it."
        }
        _ => {
            "The original cause is unknown. Boot recovery still requires full validation; investigate logs and physical state if those checks refuse recovery."
        }
    }
}

#[cfg(test)]
mod tests;
