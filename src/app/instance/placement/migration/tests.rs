use super::*;
use crate::{
    instance::metadata::{RuntimeKind, RuntimeMetadata},
    instance::placement::{
        ENGINE_RUNTIME_SCHEMA_VERSION, EngineRuntime, EngineRuntimeStatus, PlacementRepository,
        ReserveTenant, RuntimeReservation,
    },
    storage::{repositories::InstanceRepository, sqlite},
    utils::backend::BackendEndpoint,
};

fn metadata(instance_id: &str) -> InstanceMetadata {
    let mut metadata = crate::instance::test_support::metadata(instance_id, Protocol::Postgres);
    metadata.runtime_id = instance_id.to_string();
    metadata.public.host = "db.example.test".to_string();
    metadata.backend = BackendEndpoint::UnixSocket {
        socket_path: "/tmp/postgres.sock".to_string(),
    };
    metadata.runtime.container_name = "postgres".to_string();
    metadata.owner = Some(crate::instance::placement::test_support::owner(
        "game-server",
    ));
    metadata.database.name = "app".to_string();
    metadata.database.username = "app".to_string();
    metadata.postgres_admin_password = Some("admin".to_string());
    metadata.tenant_password = Some("tenant".to_string());
    metadata
}

fn metadata_in_mode(instance_id: &str, mode: DeploymentMode) -> InstanceMetadata {
    let mut metadata = metadata(instance_id);
    metadata.deployment_mode = mode;
    if mode == DeploymentMode::Shared {
        metadata.runtime_id = format!("pool-{instance_id}");
        metadata.postgres_admin_password = None;
    }
    metadata
}

async fn repository() -> (DeploymentMigrationRepository, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(directory.path()).await.unwrap();
    (DeploymentMigrationRepository::new(pool), directory)
}

#[tokio::test]
async fn active_workflow_is_unique_and_terminal_history_allows_retry() {
    let (repository, _directory) = repository().await;
    let first = repository
        .start(&metadata("inst-a"), DeploymentMode::Shared, None, None)
        .await
        .unwrap();
    assert!(matches!(
        repository
            .start(&metadata("inst-a"), DeploymentMode::Shared, None, None)
            .await,
        Err(DeploymentMigrationError::ActiveMigration(_))
    ));
    repository
        .transition(
            &first.migration_id,
            first.revision,
            MigrationStage::Failed,
            MigrationPatch {
                failure: Some(MigrationFailure::PreflightFailed),
                ..MigrationPatch::default()
            },
        )
        .await
        .unwrap();
    repository
        .start(&metadata("inst-a"), DeploymentMode::Shared, None, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn transition_compare_and_swap_rejects_stale_and_invalid_writers() {
    let (repository, _directory) = repository().await;
    let migration = repository
        .start(&metadata("inst-a"), DeploymentMode::Shared, None, None)
        .await
        .unwrap();
    let preflight = repository
        .transition(
            &migration.migration_id,
            migration.revision,
            MigrationStage::Preflight,
            MigrationPatch::default(),
        )
        .await
        .unwrap();
    assert!(matches!(
        repository
            .transition(
                &migration.migration_id,
                migration.revision,
                MigrationStage::Cancelled,
                MigrationPatch::default(),
            )
            .await,
        Err(DeploymentMigrationError::StaleRevision { .. })
    ));
    assert!(matches!(
        repository
            .transition(
                &migration.migration_id,
                preflight.revision,
                MigrationStage::Completed,
                MigrationPatch::default(),
            )
            .await,
        Err(DeploymentMigrationError::InvalidTransition { .. })
    ));
}

#[tokio::test]
async fn boot_recovery_classifies_every_crash_stage_in_both_directions() {
    let (repository, _directory) = repository().await;
    let cases = [
        (MigrationStage::Requested, MigrationStage::Failed),
        (MigrationStage::Preflight, MigrationStage::Failed),
        (MigrationStage::TargetPreparing, MigrationStage::RollingBack),
        (MigrationStage::TargetPrepared, MigrationStage::RollingBack),
        (MigrationStage::SourceFencing, MigrationStage::RollingBack),
        (MigrationStage::SourceFenced, MigrationStage::RollingBack),
        (MigrationStage::Exporting, MigrationStage::RollingBack),
        (MigrationStage::Exported, MigrationStage::RollingBack),
        (MigrationStage::Importing, MigrationStage::RollingBack),
        (MigrationStage::Imported, MigrationStage::RollingBack),
        (MigrationStage::Validating, MigrationStage::RollingBack),
        (MigrationStage::CutoverPending, MigrationStage::RollingBack),
        (
            MigrationStage::CutoverCommitted,
            MigrationStage::CleanupPending,
        ),
        (
            MigrationStage::VerifyingCutover,
            MigrationStage::CleanupPending,
        ),
        (
            MigrationStage::CleaningSource,
            MigrationStage::CleanupPending,
        ),
    ];
    let mut expected = Vec::new();
    for source_mode in [DeploymentMode::Dedicated, DeploymentMode::Shared] {
        let target_mode = match source_mode {
            DeploymentMode::Dedicated => DeploymentMode::Shared,
            DeploymentMode::Shared => DeploymentMode::Dedicated,
        };
        for (index, (crash_stage, recovery_stage)) in cases.iter().copied().enumerate() {
            let mode = source_mode.as_str();
            let source = metadata_in_mode(&format!("{mode}-{index}"), source_mode);
            let mut migration = repository
                .start(&source, target_mode, None, None)
                .await
                .unwrap();
            if crash_stage != MigrationStage::Requested {
                migration = advance_to(&repository, migration, crash_stage).await;
            }
            expected.push((migration.migration_id, recovery_stage));
        }
    }

    let summary = repository.recover_unfinished().await.unwrap();
    assert_eq!(summary.failed_before_mutation, 4);
    assert_eq!(summary.rollback_pending, 20);
    assert_eq!(summary.cleanup_pending, 6);
    for (migration_id, stage) in expected {
        let recovered = repository.get(&migration_id).await.unwrap().unwrap();
        assert_eq!(recovered.stage, stage, "migration {migration_id}");
        assert_eq!(
            recovered.cutover_committed,
            stage == MigrationStage::CleanupPending
        );
    }
}

#[tokio::test]
async fn dedicated_to_shared_cutover_is_one_atomic_metadata_and_reservation_commit() {
    let (repository, _directory) = repository().await;
    let instances = InstanceRepository::new(repository.pool.clone());
    let placements = PlacementRepository::new(repository.pool.clone());
    let source = metadata("inst-a");
    instances.upsert(&source).await.unwrap();
    placements
        .save(&EngineRuntime::legacy_dedicated(
            &source,
            EngineRuntimeStatus::Running,
            "postgres:18".to_string(),
        ))
        .await
        .unwrap();
    let shared_runtime = EngineRuntime {
        pending_image: None,
        desired_state: crate::instance::metadata::DesiredInstanceState::Running,
        owner: source.owner.clone(),
        schema_version: ENGINE_RUNTIME_SCHEMA_VERSION,
        runtime_id: "runtime-target".to_string(),
        protocol: source.protocol,
        deployment_mode: DeploymentMode::Shared,
        status: EngineRuntimeStatus::Running,
        backend: BackendEndpoint::UnixSocket {
            socket_path: "/tmp/shared-postgres.sock".to_string(),
        },
        runtime: RuntimeMetadata {
            kind: RuntimeKind::Docker,
            container_name: "shared-postgres".to_string(),
            network_mode: "none".to_string(),
        },
        limits: crate::utils::limits::InstanceLimits {
            disk_mib: 32768,
            ..source.limits.clone()
        },
        image: "postgres:18".to_string(),
        database_version: None,
        compatibility: None,

        max_tenants: 10,
        reserved: RuntimeReservation::default(),
        admin_secret: Some("pool-admin".to_string()),
        created_at: source.created_at.clone(),
        updated_at: source.updated_at.clone(),
    };
    placements.save(&shared_runtime).await.unwrap();
    placements
        .reserve(ReserveTenant {
            owner: shared_runtime.owner.clone().unwrap(),
            instance_id: "migration-temp",
            runtime_id: &shared_runtime.runtime_id,
            database: &source.database.name,
            username: &source.database.username,
            limits: &source.limits,
        })
        .await
        .unwrap();
    placements.mark_provisioned("migration-temp").await.unwrap();
    let pending = advance_to(
        &repository,
        repository
            .start(&source, DeploymentMode::Shared, None, None)
            .await
            .unwrap(),
        MigrationStage::CutoverPending,
    )
    .await;
    let mut target = source.clone();
    target.deployment_mode = DeploymentMode::Shared;
    target.runtime_id.clone_from(&shared_runtime.runtime_id);
    target.backend = shared_runtime.backend.clone();
    target.runtime = shared_runtime.runtime.clone();
    target.postgres_admin_password = None;
    target.limits.disk_enforced = true;
    target.limits.disk_enforcement_method = "host_linux_project_quota".to_string();
    assert_eq!(
        placements
            .root_charged_disk_mib("runtime-target")
            .await
            .unwrap(),
        12_800
    );

    let committed = repository
        .commit_dedicated_to_shared(
            &pending.migration_id,
            pending.revision,
            "migration-temp",
            &target,
        )
        .await
        .unwrap();

    assert_eq!(committed.stage, MigrationStage::CutoverCommitted);
    assert!(committed.cutover_committed);
    let stored = instances.get("inst-a").await.unwrap().unwrap();
    assert_eq!(stored.deployment_mode, DeploymentMode::Shared);
    assert_eq!(stored.runtime_id(), "runtime-target");
    assert!(stored.postgres_admin_password.is_none());
    assert_eq!(
        placements.tenants("runtime-target").await.unwrap(),
        vec!["inst-a".to_string()]
    );
    assert_eq!(
        placements
            .root_charged_disk_mib("runtime-target")
            .await
            .unwrap(),
        2_560
    );
    assert!(placements.get("inst-a").await.unwrap().is_some());
}

#[tokio::test]
async fn shared_to_dedicated_cutover_is_one_atomic_metadata_and_reservation_commit() {
    let (repository, _directory) = repository().await;
    let instances = InstanceRepository::new(repository.pool.clone());
    let placements = PlacementRepository::new(repository.pool.clone());
    let mut source = metadata_in_mode("inst-b", DeploymentMode::Shared);
    source.runtime_id = "pool-source".to_string();
    source.backend = BackendEndpoint::UnixSocket {
        socket_path: "/tmp/shared-postgres.sock".to_string(),
    };
    source.runtime.container_name = "shared-postgres".to_string();
    source.limits.disk_enforced = true;
    source.limits.disk_enforcement_method = "host_linux_project_quota".to_string();
    let source_runtime = EngineRuntime {
        pending_image: None,
        desired_state: crate::instance::metadata::DesiredInstanceState::Running,
        owner: source.owner.clone(),
        schema_version: ENGINE_RUNTIME_SCHEMA_VERSION,
        runtime_id: source.runtime_id.clone(),
        protocol: source.protocol,
        deployment_mode: DeploymentMode::Shared,
        status: EngineRuntimeStatus::Running,
        backend: source.backend.clone(),
        runtime: source.runtime.clone(),
        limits: crate::utils::limits::InstanceLimits {
            disk_mib: 32768,
            ..source.limits.clone()
        },
        image: "postgres:18".to_string(),
        database_version: None,
        compatibility: None,

        max_tenants: 10,
        reserved: RuntimeReservation::default(),
        admin_secret: Some("pool-admin".to_string()),
        created_at: source.created_at.clone(),
        updated_at: source.updated_at.clone(),
    };
    placements.save(&source_runtime).await.unwrap();
    placements
        .reserve(ReserveTenant {
            owner: source_runtime.owner.clone().unwrap(),
            instance_id: &source.instance_id,
            runtime_id: &source_runtime.runtime_id,
            database: &source.database.name,
            username: &source.database.username,
            limits: &source.limits,
        })
        .await
        .unwrap();
    placements
        .mark_provisioned(&source.instance_id)
        .await
        .unwrap();
    instances.upsert(&source).await.unwrap();
    assert_eq!(
        placements
            .root_charged_disk_mib("pool-source")
            .await
            .unwrap(),
        2_560
    );

    let mut target = source.clone();
    target.deployment_mode = DeploymentMode::Dedicated;
    target.runtime_id.clone_from(&target.instance_id);
    target.backend = BackendEndpoint::UnixSocket {
        socket_path: "/tmp/dedicated-postgres.sock".to_string(),
    };
    target.runtime.container_name = "dedicated-postgres".to_string();
    target.postgres_admin_password = Some("target-admin".to_string());
    instances
        .stage_dedicated_admin_secrets(&target)
        .await
        .unwrap();
    placements
        .save(&EngineRuntime::legacy_dedicated(
            &target,
            EngineRuntimeStatus::Running,
            "postgres:18".to_string(),
        ))
        .await
        .unwrap();
    let pending = advance_to(
        &repository,
        repository
            .start(&source, DeploymentMode::Dedicated, None, None)
            .await
            .unwrap(),
        MigrationStage::CutoverPending,
    )
    .await;
    let source_reservation_id = format!("migration_{}", pending.migration_id.replace('-', ""));

    let committed = repository
        .commit_shared_to_dedicated(
            &pending.migration_id,
            pending.revision,
            &source_reservation_id,
            &target,
        )
        .await
        .unwrap();

    assert_eq!(committed.stage, MigrationStage::CutoverCommitted);
    assert!(committed.cutover_committed);
    let stored = instances.get("inst-b").await.unwrap().unwrap();
    assert_eq!(stored.deployment_mode, DeploymentMode::Dedicated);
    assert_eq!(stored.runtime_id(), "inst-b");
    assert_eq!(
        stored.postgres_admin_password.as_deref(),
        Some("target-admin")
    );
    assert_eq!(stored.tenant_password, source.tenant_password);
    assert_eq!(
        placements.tenants("pool-source").await.unwrap(),
        vec![source_reservation_id.clone()]
    );
    assert_eq!(placements.tenant_count("pool-source").await.unwrap(), 1);
    assert_eq!(
        placements
            .root_charged_disk_mib("pool-source")
            .await
            .unwrap(),
        12_800
    );
    placements.release(&source_reservation_id).await.unwrap();
    assert_eq!(placements.tenant_count("pool-source").await.unwrap(), 0);
    assert_eq!(
        placements
            .root_charged_disk_mib("pool-source")
            .await
            .unwrap(),
        2_048
    );
    assert!(placements.get("inst-b").await.unwrap().is_some());
}

async fn advance_to(
    repository: &DeploymentMigrationRepository,
    mut migration: DeploymentMigration,
    target: MigrationStage,
) -> DeploymentMigration {
    let target_runtime_id = match migration.target_mode {
        DeploymentMode::Dedicated => migration.instance_id.clone(),
        DeploymentMode::Shared => "runtime-target".to_string(),
    };
    let path = [
        MigrationStage::Preflight,
        MigrationStage::TargetPreparing,
        MigrationStage::TargetPrepared,
        MigrationStage::SourceFencing,
        MigrationStage::SourceFenced,
        MigrationStage::Exporting,
        MigrationStage::Exported,
        MigrationStage::Importing,
        MigrationStage::Imported,
        MigrationStage::Validating,
        MigrationStage::CutoverPending,
        MigrationStage::CutoverCommitted,
        MigrationStage::VerifyingCutover,
        MigrationStage::CleaningSource,
    ];
    for stage in path {
        migration = repository
            .transition(
                &migration.migration_id,
                migration.revision,
                stage,
                MigrationPatch {
                    target_runtime_id: (stage == MigrationStage::TargetPrepared)
                        .then_some(target_runtime_id.as_str()),
                    source_fenced: (stage == MigrationStage::SourceFenced).then_some(true),
                    ..MigrationPatch::default()
                },
            )
            .await
            .unwrap();
        if stage == target {
            return migration;
        }
    }
    panic!("target stage not in test path");
}
