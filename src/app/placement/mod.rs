pub(crate) mod lifecycle;
mod migration;
mod model;
mod owner;
pub(crate) mod policy;
mod repository;
pub(crate) mod runtime;
pub(crate) mod tenant;
#[cfg(test)]
pub(crate) mod test_support;

pub use migration::{
    DeploymentMigration, DeploymentMigrationError, DeploymentMigrationRepository, MigrationFailure,
    MigrationPatch, MigrationRecoverySummary, MigrationStage,
};
pub use model::{
    DeploymentMode, ENGINE_RUNTIME_SCHEMA_VERSION, EngineRuntime, EngineRuntimeStatus,
    PlacementError, ReserveTenant, RuntimeCompatibility, RuntimeReservation, TenantReservation,
    TenantReservationState,
};
pub(crate) use owner::PoolSpec;
pub use owner::{PoolLimits, PoolOwner};
pub use repository::{PlacementRepository, PlacementRepositoryError};
