//! Versioned backup manifest bodies. Schema 1 holds inventory facts; schema 2 adds the restore contract. Readers never invent guarantees for schema 1 and reject unknown versions.

use std::collections::BTreeMap;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use super::{BackupLayout, BackupStoreError, is_sha256};

pub const LEGACY_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const MANIFEST_SCHEMA_VERSION: u32 = 2;

pub const DATA_DIRECTORY_RECIPE: &str = "data_directory_archive";
pub const LOGICAL_DUMP_RECIPE: &str = "logical_dump";
pub const BUILT_IN_RECIPE_VERSION: u32 = 1;

const MAX_TEXT_BYTES: usize = 512;
const MAX_MAP_ENTRIES: usize = 32;
const MAX_LIST_ENTRIES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    DataDirectoryArchive,
    LogicalDump,
    OnlineCapture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupMethod {
    OfflineCopy,
    SharedLogicalDump,
    OnlineStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupScope {
    DedicatedRuntime,
    SharedTenant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyLevel {
    StoppedCopy,
    TransactionalSnapshot,
    PhysicalRecoveryPoint,
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

    pub fn tag_value(&self) -> String {
        format!("{}@{}", self.id, self.version)
    }
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileChecksum {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_target: Option<String>,
    #[serde(default)]
    pub exclusions: Vec<String>,
    #[serde(default)]
    pub checksums: Vec<FileChecksum>,
    #[serde(default)]
    pub validation: Vec<ValidationRecord>,
    /// Bytes restore extraction charges; online captures exceeding restore's limit are rejected before publication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expanded_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreFormat<'a> {
    DataDirectoryArchive {
        legacy: bool,
    },
    LogicalDump {
        legacy: bool,
    },
    StrategyCapture {
        strategy: &'a str,
        recipe: &'a RestoreRecipeRef,
        restore_target: &'a str,
    },
}

impl ManifestDetails {
    /// `consistency` must reflect what the producing tool actually guarantees.
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

    /// Validation accepts any positive version so newer recipes read as unsupported, not corrupt.
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
