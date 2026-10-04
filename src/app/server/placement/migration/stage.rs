use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationStage {
    Requested,
    Preflight,
    TargetPreparing,
    TargetPrepared,
    SourceFencing,
    SourceFenced,
    Exporting,
    Exported,
    Importing,
    Imported,
    Validating,
    CutoverPending,
    CutoverCommitted,
    VerifyingCutover,
    CleaningSource,
    RollingBack,
    CleanupPending,
    ManualIntervention,
    Completed,
    Failed,
    Cancelled,
}

impl MigrationStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Preflight => "preflight",
            Self::TargetPreparing => "target_preparing",
            Self::TargetPrepared => "target_prepared",
            Self::SourceFencing => "source_fencing",
            Self::SourceFenced => "source_fenced",
            Self::Exporting => "exporting",
            Self::Exported => "exported",
            Self::Importing => "importing",
            Self::Imported => "imported",
            Self::Validating => "validating",
            Self::CutoverPending => "cutover_pending",
            Self::CutoverCommitted => "cutover_committed",
            Self::VerifyingCutover => "verifying_cutover",
            Self::CleaningSource => "cleaning_source",
            Self::RollingBack => "rolling_back",
            Self::CleanupPending => "cleanup_pending",
            Self::ManualIntervention => "manual_intervention",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    pub const fn crossed_cutover(self) -> bool {
        matches!(
            self,
            Self::CutoverCommitted
                | Self::VerifyingCutover
                | Self::CleaningSource
                | Self::CleanupPending
                | Self::Completed
        )
    }

    pub const fn recovery_stage(self) -> Option<Self> {
        match self {
            Self::Requested | Self::Preflight => Some(Self::Failed),
            Self::TargetPreparing
            | Self::TargetPrepared
            | Self::SourceFencing
            | Self::SourceFenced
            | Self::Exporting
            | Self::Exported
            | Self::Importing
            | Self::Imported
            | Self::Validating
            | Self::CutoverPending => Some(Self::RollingBack),
            Self::CutoverCommitted | Self::VerifyingCutover | Self::CleaningSource => {
                Some(Self::CleanupPending)
            }
            Self::RollingBack | Self::CleanupPending | Self::ManualIntervention => None,
            Self::Completed | Self::Failed | Self::Cancelled => None,
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "requested" => Self::Requested,
            "preflight" => Self::Preflight,
            "target_preparing" => Self::TargetPreparing,
            "target_prepared" => Self::TargetPrepared,
            "source_fencing" => Self::SourceFencing,
            "source_fenced" => Self::SourceFenced,
            "exporting" => Self::Exporting,
            "exported" => Self::Exported,
            "importing" => Self::Importing,
            "imported" => Self::Imported,
            "validating" => Self::Validating,
            "cutover_pending" => Self::CutoverPending,
            "cutover_committed" => Self::CutoverCommitted,
            "verifying_cutover" => Self::VerifyingCutover,
            "cleaning_source" => Self::CleaningSource,
            "rolling_back" => Self::RollingBack,
            "cleanup_pending" => Self::CleanupPending,
            "manual_intervention" => Self::ManualIntervention,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            _ => return None,
        })
    }

    pub(super) const fn allows(self, next: Self) -> bool {
        use MigrationStage as S;
        match self {
            S::Requested => matches!(next, S::Preflight | S::Failed | S::Cancelled),
            S::Preflight => matches!(next, S::TargetPreparing | S::Failed | S::Cancelled),
            S::TargetPreparing => matches!(next, S::TargetPrepared | S::RollingBack),
            S::TargetPrepared => matches!(next, S::SourceFencing | S::RollingBack),
            S::SourceFencing => matches!(next, S::SourceFenced | S::RollingBack),
            S::SourceFenced => matches!(next, S::Exporting | S::RollingBack),
            S::Exporting => matches!(next, S::Exported | S::RollingBack),
            S::Exported => matches!(next, S::Importing | S::RollingBack),
            S::Importing => matches!(next, S::Imported | S::RollingBack),
            S::Imported => matches!(next, S::Validating | S::RollingBack),
            S::Validating => matches!(next, S::CutoverPending | S::RollingBack),
            S::CutoverPending => matches!(next, S::CutoverCommitted | S::RollingBack),
            S::CutoverCommitted => matches!(next, S::VerifyingCutover | S::CleanupPending),
            S::VerifyingCutover => matches!(next, S::CleaningSource | S::CleanupPending),
            S::CleaningSource => matches!(next, S::Completed | S::CleanupPending),
            S::RollingBack => matches!(next, S::Failed | S::ManualIntervention),
            S::CleanupPending => matches!(next, S::CleaningSource | S::ManualIntervention),
            S::ManualIntervention => matches!(next, S::RollingBack | S::CleanupPending),
            S::Completed | S::Failed | S::Cancelled => false,
        }
    }
}
