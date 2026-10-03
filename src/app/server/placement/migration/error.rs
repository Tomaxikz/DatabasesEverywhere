use super::*;

#[derive(Debug, thiserror::Error)]
pub enum DeploymentMigrationError {
    #[error(transparent)]
    Sql(#[from] sqlx::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Placement(#[from] PlacementError),
    #[error("instance already uses {0:?} deployment")]
    SameMode(DeploymentMode),
    #[error("instance {0} already has an active deployment migration")]
    ActiveMigration(String),
    #[error("deployment migration {0} was not found")]
    NotFound(String),
    #[error("deployment migration revision changed: expected {expected}, found {actual}")]
    StaleRevision { expected: u64, actual: u64 },
    #[error("deployment migration cannot transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: MigrationStage,
        to: MigrationStage,
    },
    #[error("deployment migration revision overflowed")]
    RevisionOverflow,
    #[error("deployment migration cannot mark the target prepared without a target runtime")]
    TargetRuntimeRequired,
    #[error("deployment migration cannot advance until the source route and sessions are fenced")]
    SourceFenceRequired,
    #[error(
        "deployment migration cannot commit cutover before target preparation and source fencing"
    )]
    CutoverNotReady,
    #[error("deployment migration cutover target is not a shared placement")]
    InvalidCutoverTarget,
    #[error("deployment migration provisional reservation {0} is missing")]
    ReservationMissing(String),
    #[error("deployment migration source placement changed before cutover")]
    SourcePlacementChanged,
    #[error("invalid deployment migration {0}: {1}")]
    InvalidValue(&'static str, String),
    #[error("invalid deployment migration {0}: {1}")]
    InvalidInteger(&'static str, i64),
}
