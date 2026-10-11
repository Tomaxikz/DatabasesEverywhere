//! Versioned backup manifest bodies.
//!
//! Schema 1 records only inventory facts (identity, layout, size, checksum).
//! Schema 2 adds the restore contract: artifact format, capture method, scope,
//! restore recipe, consistency level, capture interval, recovery coordinates,
//! engine and tool versions, exclusions, checksums and validation results.
//!
//! Readers never invent guarantees for schema 1 records: their consistency is
//! reported as unrecorded and they restore only through the legacy recipes
//! matching their layout. Unknown schema versions are rejected explicitly
//! rather than reinterpreted.

use std::collections::BTreeMap;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use super::{BackupLayout, BackupStoreError, is_sha256};

pub const LEGACY_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const MANIFEST_SCHEMA_VERSION: u32 = 2;

/// Built-in recipe restoring a gzip tar of the complete instance data
/// directory into a stopped dedicated runtime.
pub const DATA_DIRECTORY_RECIPE: &str = "data_directory_archive";
/// Built-in recipe replaying a shared tenant logical dump.
pub const LOGICAL_DUMP_RECIPE: &str = "logical_dump";
pub const BUILT_IN_RECIPE_VERSION: u32 = 1;

const MAX_TEXT_BYTES: usize = 512;
const MAX_MAP_ENTRIES: usize = 32;
const MAX_LIST_ENTRIES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    /// gzip tar whose root is the instance data directory.
    DataDirectoryArchive,
    /// Engine logical dump produced by the shared tenant export path.
    LogicalDump,
    /// gzip tar of a strategy capture laid out like a data directory archive,
    /// restorable only through the recorded strategy recipe.
    OnlineCapture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupMethod {
    /// Files copied while the database process was stopped.
    OfflineCopy,
    /// Tenant-scoped logical dump of a shared runtime.
    SharedLogicalDump,
    /// Engine-native capture of a running database.
    OnlineStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupScope {
    DedicatedRuntime,
    SharedTenant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyLevel {
    /// Data files of a cleanly stopped process.
    StoppedCopy,
    /// One transactional snapshot of the captured scope.
    TransactionalSnapshot,
    /// Physical files plus the log required to recover to one consistent
    /// point (`recovery` records the coordinates).
    PhysicalRecoveryPoint,
    /// Objects exported individually without one common transactional point.
    PerObject,
}

impl ConsistencyLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StoppedCopy => "stopped_copy",
            Self::TransactionalSnapshot => "transactional_snapshot",
            Self::PhysicalRecoveryPoint => "physical_recovery_point",
            Self::PerObject => "per_object",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRecipeRef {
    pub id: String,
    pub version: u32,
}

impl RestoreRecipeRef {
    pub fn new(id: &str, version: u32) -> Self {
        Self {
            id: id.to_string(),
            version,
        }
    }

    /// Compact form used by tag projections, e.g. `logical_dump@1`.
    pub fn tag_value(&self) -> String {
        format!("{}@{}", self.id, self.version)
    }
}

/// Engine-specific recovery coordinates, e.g. `start_lsn`, `end_lsn`,
/// `timeline`, `system_identifier`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecoveryCoordinates(pub BTreeMap<String, String>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureInterval {
    pub started_at_unix: i64,
    pub finished_at_unix: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Immutable image id or digest of the runtime that produced the data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileChecksum {
    /// Path relative to the archive data root, or a sidecar name.
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationRecord {
    pub check: String,
    pub passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Schema 2 restore contract. Present exactly when `schema_version == 2`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestDetails {
    pub format: ArtifactFormat,
    pub method: BackupMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    pub scope: BackupScope,
    pub restore_recipe: RestoreRecipeRef,
    pub consistency: ConsistencyLevel,
    pub capture: CaptureInterval,
    #[serde(default)]
    pub recovery: RecoveryCoordinates,
    #[serde(default)]
    pub engine: EngineRecord,
    #[serde(default)]
    pub tool_versions: BTreeMap<String, String>,
    /// Relative location of the captured tree inside the data directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_target: Option<String>,
    #[serde(default)]
    pub exclusions: Vec<String>,
    #[serde(default)]
    pub checksums: Vec<FileChecksum>,
    #[serde(default)]
    pub validation: Vec<ValidationRecord>,
    /// Bytes restore extraction charges for the archive (entry sizes plus
    /// the per-entry allowance). Recorded for online captures, which are
    /// rejected before publication when it exceeds what restore accepts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expanded_bytes: Option<u64>,
}

/// How a stored backup must be restored, independent of current placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreFormat<'a> {
    /// Complete data directory archive (schema 1 physical or schema 2
    /// offline copy).
    DataDirectoryArchive { legacy: bool },
    /// Shared tenant logical dump (schema 1 logical or schema 2).
    LogicalDump { legacy: bool },
    /// Online strategy capture; only the named recipe may restore it.
    StrategyCapture {
        strategy: &'a str,
        recipe: &'a RestoreRecipeRef,
        restore_target: &'a str,
    },
}

impl ManifestDetails {
    /// Contract for the built-in stopped-copy and shared logical formats.
    /// `consistency` must describe what the producing tool actually guarantees.
    pub fn built_in(
        layout: BackupLayout,
        consistency: ConsistencyLevel,
        capture: CaptureInterval,
        engine: EngineRecord,
    ) -> Self {
        let (format, method, scope, recipe) = match layout {
            BackupLayout::Physical => (
                ArtifactFormat::DataDirectoryArchive,
                BackupMethod::OfflineCopy,
                BackupScope::DedicatedRuntime,
                DATA_DIRECTORY_RECIPE,
            ),
            BackupLayout::Logical => (
                ArtifactFormat::LogicalDump,
                BackupMethod::SharedLogicalDump,
                BackupScope::SharedTenant,
                LOGICAL_DUMP_RECIPE,
            ),
        };
        Self {
            format,
            method,
            strategy: None,
            scope,
            restore_recipe: RestoreRecipeRef::new(recipe, BUILT_IN_RECIPE_VERSION),
            consistency,
            capture,
            recovery: RecoveryCoordinates::default(),
            engine,
            tool_versions: BTreeMap::new(),
            restore_target: None,
            exclusions: Vec::new(),
            checksums: Vec::new(),
            validation: Vec::new(),
            expanded_bytes: None,
        }
    }

    /// Whether this build restores the built-in recipe version the manifest
    /// names. Validation accepts any positive version so newer built-in
    /// recipes are reported as unsupported rather than as corruption.
    pub fn built_in_recipe_supported(&self) -> bool {
        self.restore_recipe.version == BUILT_IN_RECIPE_VERSION
    }

    pub(crate) fn validate(&self, layout: BackupLayout) -> Result<(), BackupStoreError> {
        let corrupt = |reason: &str| {
            Err(BackupStoreError::Corrupt(format!(
                "backup manifest restore contract is invalid: {reason}"
            )))
        };
        let expected = match self.format {
            ArtifactFormat::DataDirectoryArchive => (
                BackupLayout::Physical,
                BackupMethod::OfflineCopy,
                BackupScope::DedicatedRuntime,
                Some(DATA_DIRECTORY_RECIPE),
            ),
            ArtifactFormat::LogicalDump => (
                BackupLayout::Logical,
                BackupMethod::SharedLogicalDump,
                BackupScope::SharedTenant,
                Some(LOGICAL_DUMP_RECIPE),
            ),
            ArtifactFormat::OnlineCapture => (
                BackupLayout::Physical,
                BackupMethod::OnlineStrategy,
                BackupScope::DedicatedRuntime,
                None,
            ),
        };
        if layout != expected.0 || self.method != expected.1 || self.scope != expected.2 {
            return corrupt("format, layout, method and scope disagree");
        }
        match (
            expected.3,
            self.strategy.as_deref(),
            self.restore_target.as_deref(),
        ) {
            (Some(recipe), None, None) => {
                if self.restore_recipe.id != recipe {
                    return corrupt("built-in format names a foreign recipe");
                }
            }
            (None, Some(strategy), Some(target)) => {
                if !is_identifier(strategy) || !is_safe_relative(target) {
                    return corrupt("strategy id or restore target is unsafe");
                }
            }
            _ => return corrupt("strategy fields do not match the artifact format"),
        }
        if !is_identifier(&self.restore_recipe.id) || self.restore_recipe.version == 0 {
            return corrupt("restore recipe is malformed");
        }
        if self.capture.finished_at_unix < self.capture.started_at_unix {
            return corrupt("capture interval ends before it starts");
        }
        if self.validation.iter().any(|check| !check.passed) {
            return corrupt("a published backup carries a failed validation");
        }
        let map_ok = |map: &BTreeMap<String, String>| {
            map.len() <= MAX_MAP_ENTRIES
                && map
                    .iter()
                    .all(|(key, value)| is_identifier(key) && is_bounded_text(value))
        };
        let engine_ok = [
            &self.engine.version,
            &self.engine.image,
            &self.engine.image_digest,
        ]
        .into_iter()
        .flatten()
        .all(|value| is_bounded_text(value));
        let lists_ok = self.exclusions.len() <= MAX_LIST_ENTRIES
            && self.exclusions.iter().all(|value| is_bounded_text(value))
            && self.checksums.len() <= MAX_LIST_ENTRIES
            && self
                .checksums
                .iter()
                .all(|file| is_bounded_text(&file.path) && is_sha256(&file.sha256))
            && self.validation.len() <= MAX_LIST_ENTRIES
            && self.validation.iter().all(|check| {
                is_identifier(&check.check) && check.detail.as_deref().is_none_or(is_bounded_text)
            });
        if !map_ok(&self.recovery.0) || !map_ok(&self.tool_versions) || !engine_ok || !lists_ok {
            return corrupt("descriptive fields exceed their bounds");
        }
        Ok(())
    }

    pub(crate) fn restore_format(&self) -> RestoreFormat<'_> {
        match (
            self.format,
            self.strategy.as_deref(),
            self.restore_target.as_deref(),
        ) {
            (ArtifactFormat::DataDirectoryArchive, _, _) => {
                RestoreFormat::DataDirectoryArchive { legacy: false }
            }
            (ArtifactFormat::LogicalDump, _, _) => RestoreFormat::LogicalDump { legacy: false },
            (ArtifactFormat::OnlineCapture, Some(strategy), Some(restore_target)) => {
                RestoreFormat::StrategyCapture {
                    strategy,
                    recipe: &self.restore_recipe,
                    restore_target,
                }
            }
            // `validate` rejects this combination before a manifest is used.
            (ArtifactFormat::OnlineCapture, _, _) => {
                unreachable!("validated online captures name a strategy and target")
            }
        }
    }
}

/// Stable identifiers: lowercase ASCII, digits, `_`, `.`, `-`.
pub(crate) fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

fn is_bounded_text(value: &str) -> bool {
    value.len() <= MAX_TEXT_BYTES && !value.chars().any(char::is_control)
}

pub(crate) fn is_safe_relative(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && is_bounded_text(value)
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offline_details() -> ManifestDetails {
        ManifestDetails::built_in(
            BackupLayout::Physical,
            ConsistencyLevel::StoppedCopy,
            CaptureInterval {
                started_at_unix: 10,
                finished_at_unix: 20,
            },
            EngineRecord::default(),
        )
    }

    fn online_details() -> ManifestDetails {
        ManifestDetails {
            format: ArtifactFormat::OnlineCapture,
            method: BackupMethod::OnlineStrategy,
            strategy: Some("postgres.pg_basebackup".to_string()),
            restore_recipe: RestoreRecipeRef::new("postgres.pg_basebackup", 1),
            consistency: ConsistencyLevel::PhysicalRecoveryPoint,
            restore_target: Some("pgdata".to_string()),
            validation: vec![ValidationRecord {
                check: "pg_verifybackup".to_string(),
                passed: true,
                detail: None,
            }],
            ..offline_details()
        }
    }

    #[test]
    fn built_in_and_strategy_contracts_validate() {
        offline_details().validate(BackupLayout::Physical).unwrap();
        ManifestDetails::built_in(
            BackupLayout::Logical,
            ConsistencyLevel::PerObject,
            offline_details().capture,
            EngineRecord::default(),
        )
        .validate(BackupLayout::Logical)
        .unwrap();
        online_details().validate(BackupLayout::Physical).unwrap();
        assert!(matches!(
            online_details().restore_format(),
            RestoreFormat::StrategyCapture {
                strategy: "postgres.pg_basebackup",
                restore_target: "pgdata",
                ..
            }
        ));
    }

    #[test]
    fn inconsistent_contracts_are_rejected() {
        assert!(offline_details().validate(BackupLayout::Logical).is_err());
        let mut foreign = offline_details();
        foreign.restore_recipe = RestoreRecipeRef::new("postgres.pg_basebackup", 1);
        assert!(foreign.validate(BackupLayout::Physical).is_err());
        let mut unsafe_target = online_details();
        unsafe_target.restore_target = Some("../outside".to_string());
        assert!(unsafe_target.validate(BackupLayout::Physical).is_err());
        let mut missing_strategy = online_details();
        missing_strategy.strategy = None;
        assert!(missing_strategy.validate(BackupLayout::Physical).is_err());
        let mut failed = online_details();
        failed.validation[0].passed = false;
        assert!(failed.validate(BackupLayout::Physical).is_err());
    }

    #[test]
    fn unknown_fields_and_formats_do_not_parse() {
        let mut value = serde_json::to_value(online_details()).unwrap();
        value["format"] = serde_json::json!("filesystem_snapshot");
        assert!(serde_json::from_value::<ManifestDetails>(value).is_err());
        let mut value = serde_json::to_value(online_details()).unwrap();
        value["future_field"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ManifestDetails>(value).is_err());
    }
}
