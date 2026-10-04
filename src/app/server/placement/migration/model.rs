use serde::Serialize;

use super::MigrationStage;
use crate::{databases::protocol::Protocol, server::placement::DeploymentMode};

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentMigration {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pool_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_limits: Option<crate::utils::limits::InstanceLimits>,
    pub migration_id: String,
    pub instance_id: String,
    pub protocol: Protocol,
    pub source_mode: DeploymentMode,
    pub target_mode: DeploymentMode,
    pub source_runtime_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_runtime_id: Option<String>,
    pub stage: MigrationStage,
    pub revision: u64,
    pub source_fenced: bool,
    pub cutover_committed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationFailure {
    PreflightFailed,
    PreCutoverFailure,
    StructuralValidationTimedOut,
    PostCutoverFailure,
    RolledBackBeforeCutover,
    TargetVerificationFailed,
    RestartBeforeMutation,
    RestartBeforeCutover,
    RestartAfterCutover,
}

impl MigrationFailure {
    pub const ALL: [Self; 9] = [
        Self::PreflightFailed,
        Self::PreCutoverFailure,
        Self::StructuralValidationTimedOut,
        Self::PostCutoverFailure,
        Self::RolledBackBeforeCutover,
        Self::TargetVerificationFailed,
        Self::RestartBeforeMutation,
        Self::RestartBeforeCutover,
        Self::RestartAfterCutover,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            Self::PreflightFailed => "preflight_failed",
            Self::PreCutoverFailure => "pre_cutover_failure",
            Self::StructuralValidationTimedOut => "structural_validation_timed_out",
            Self::PostCutoverFailure => "post_cutover_failure",
            Self::RolledBackBeforeCutover => "rolled_back_before_cutover",
            Self::TargetVerificationFailed => "target_verification_failed",
            Self::RestartBeforeMutation => "daemon_restarted_before_mutation",
            Self::RestartBeforeCutover => "daemon_restarted_before_cutover",
            Self::RestartAfterCutover => "daemon_restarted_after_cutover",
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::PreflightFailed => {
                "migration preflight failed before creating or fencing any runtime"
            }
            Self::PreCutoverFailure => {
                "migration failed before cutover; provisional target rollback is pending"
            }
            Self::StructuralValidationTimedOut => {
                "deployment structural validation timed out before cutover; migration was not cut over"
            }
            Self::PostCutoverFailure => {
                "migration target is authoritative; target verification and source cleanup remain pending"
            }
            Self::RolledBackBeforeCutover => {
                "provisional target was removed and the verified source route was restored"
            }
            Self::TargetVerificationFailed => {
                "committed target could not be verified; source retained for manual recovery"
            }
            Self::RestartBeforeMutation => {
                "daemon restarted during migration preflight; no source mutation occurred; retry the migration"
            }
            Self::RestartBeforeCutover => {
                "daemon restarted before placement cutover; source remains authoritative and rollback must finish before retry"
            }
            Self::RestartAfterCutover => {
                "daemon restarted after placement cutover; target remains authoritative and source cleanup must finish"
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MigrationPatch<'a> {
    pub target_runtime_id: Option<&'a str>,
    pub source_fenced: Option<bool>,
    pub failure: Option<MigrationFailure>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MigrationRecoverySummary {
    pub failed_before_mutation: usize,
    pub rollback_pending: usize,
    pub cleanup_pending: usize,
    pub already_pending: usize,
}
