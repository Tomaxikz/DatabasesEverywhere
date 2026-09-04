use super::{PlacementRepository, PlacementRepositoryError, reservations::claim_matches};
use crate::{
    instances::metadata::InstanceMetadata,
    placement::{
        DeploymentMode, EngineRuntime, EngineRuntimeStatus, PlacementError, ReserveTenant,
        RuntimeCompatibility, RuntimeReservation, TenantReservation, TenantReservationState,
    },
    shared::{backend::BackendEndpoint, limits::InstanceLimits, protocol::Protocol},
    storage::{repositories::InstanceRepository, secrets::is_encrypted, sqlite},
};

#[tokio::test]
async fn stores_pool_admin_secret_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = PlacementRepository::encrypted(pool.clone(), dir.path()).unwrap();
    let mut runtime = shared_runtime("pool_secret", 4);
    runtime.admin_secret = Some("pool-admin-password".to_string());

    repository.save(&runtime).await.unwrap();

    let raw: String =
        sqlx::query_scalar("SELECT admin_secret FROM engine_runtime_auth WHERE runtime_id = ?1")
            .bind(&runtime.runtime_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(is_encrypted(&raw));
    assert!(!raw.contains("pool-admin-password"));
    let loaded = repository.get(&runtime.runtime_id).await.unwrap().unwrap();
    assert_eq!(loaded.admin_secret.as_deref(), Some("pool-admin-password"));
    assert_eq!(loaded.database_version.as_deref(), Some("18.4"));
    assert_eq!(loaded.compatibility, runtime.compatibility);
    assert!(
        sqlx::query(
            "UPDATE engine_runtimes SET compatibility_image_id = NULL WHERE runtime_id = ?1",
        )
        .bind(&runtime.runtime_id)
        .execute(&pool)
        .await
        .is_err()
    );
    assert!(
        !serde_json::to_string(&loaded)
            .unwrap()
            .contains("pool-admin")
    );
}

#[tokio::test]
async fn rejects_raw_database_version_output() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = PlacementRepository::new(pool);
    let mut runtime = shared_runtime("pool_raw_version", 4);
    runtime.database_version = Some("postgres (PostgreSQL) 18.4".to_string());

    let error = repository.save(&runtime).await.unwrap_err();
    assert!(matches!(
        error,
        PlacementRepositoryError::Placement(PlacementError::InvalidDatabaseVersion(version))
            if version == "postgres (PostgreSQL) 18.4"
    ));
}

#[tokio::test]
async fn reserves_and_releases_pool_capacity_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = PlacementRepository::new(pool);
    let runtime = shared_runtime("pool_capacity", 2);
    repository.save(&runtime).await.unwrap();
    let mut request = tenant_limits();
    request.cpu_cores = 0.1;

    repository
        .reserve(reservation(&runtime.runtime_id, "tenant_a", &request))
        .await
        .unwrap();
    repository
        .reserve(reservation(&runtime.runtime_id, "tenant_b", &request))
        .await
        .unwrap();
    let full = repository
        .reserve(reservation(&runtime.runtime_id, "tenant_c", &request))
        .await
        .unwrap_err();

    assert!(matches!(
        full,
        PlacementRepositoryError::CapacityUnavailable(_)
    ));
    assert_eq!(
        repository.tenant_count(&runtime.runtime_id).await.unwrap(),
        2
    );
    assert_eq!(
        repository.tenants(&runtime.runtime_id).await.unwrap(),
        ["tenant_a", "tenant_b"]
    );
    let loaded = repository.get(&runtime.runtime_id).await.unwrap().unwrap();
    assert_eq!(loaded.reserved.tenants, 2);
    assert!((loaded.reserved.cpu_cores - 0.2).abs() < f64::EPSILON);
    assert_eq!(loaded.reserved.memory_mib, 2048);
    assert_eq!(loaded.reserved.disk_mib, 8192);
    assert!((loaded.limits.cpu_cores - 0.45).abs() < f64::EPSILON);
    assert_eq!(loaded.limits.memory_mib, 2304);
    assert_eq!(loaded.limits.disk_mib, 10_650);

    assert!(repository.release("tenant_a").await.unwrap());
    assert!(!repository.release("tenant_a").await.unwrap());
    let one = repository.get(&runtime.runtime_id).await.unwrap().unwrap();
    assert_eq!(one.reserved.tenants, 1);
    assert!((one.reserved.cpu_cores - 0.1).abs() < f64::EPSILON);
    assert_eq!(one.reserved.memory_mib, 1024);
    assert!((one.limits.cpu_cores - 0.35).abs() < f64::EPSILON);
    assert_eq!(one.limits.memory_mib, 1280);
    assert_eq!(one.limits.disk_mib, 6349);

    assert!(repository.release("tenant_b").await.unwrap());
    let empty = repository.get(&runtime.runtime_id).await.unwrap().unwrap();
    assert_eq!(empty.reserved, RuntimeReservation::default());
    assert!((empty.limits.cpu_cores - 0.25).abs() < f64::EPSILON);
    assert_eq!(empty.limits.memory_mib, 256);
    assert_eq!(empty.limits.disk_mib, 2048);
}

#[tokio::test]
async fn root_disk_capacity_counts_only_soft_and_unattached_tenants() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool);
    let runtime = shared_runtime("pool_root_disk", 4);
    placements.save(&runtime).await.unwrap();

    let hard = shared_instance(
        "hard_tenant",
        &runtime.runtime_id,
        "hard_db",
        "hard_user",
        15432,
    );
    let mut soft = shared_instance(
        "soft_tenant",
        &runtime.runtime_id,
        "soft_db",
        "soft_user",
        15433,
    );
    soft.limits.disk_enforced = false;
    soft.limits.disk_enforcement_method = "shared_catalog_guard".to_string();
    let orphan_limits = tenant_limits();

    for metadata in [&hard, &soft] {
        placements
            .reserve(metadata_reservation(&runtime.runtime_id, metadata))
            .await
            .unwrap();
        placements
            .mark_provisioned(&metadata.instance_id)
            .await
            .unwrap();
        instances.upsert(metadata).await.unwrap();
    }
    placements
        .reserve(reservation(
            &runtime.runtime_id,
            "orphan_tenant",
            &orphan_limits,
        ))
        .await
        .unwrap();

    // The aggregate reservation remains the admission and CPU/RAM truth.
    let aggregate = placements.get(&runtime.runtime_id).await.unwrap().unwrap();
    assert_eq!(aggregate.reserved.disk_mib, 12_288);
    assert_eq!(aggregate.limits.disk_mib, 14_951);
    // The hard tenant is charged to its child project. The soft tenant and
    // unattached reservation remain charged to the shared root.
    assert_eq!(
        placements
            .root_charged_disk_mib(&runtime.runtime_id)
            .await
            .unwrap(),
        10_855
    );

    soft.limits.disk_enforced = true;
    soft.limits.disk_enforcement_method = "host_linux_project_quota".to_string();
    instances.upsert(&soft).await.unwrap();
    assert_eq!(
        placements
            .root_charged_disk_mib(&runtime.runtime_id)
            .await
            .unwrap(),
        6_759
    );

    assert!(instances.delete(&hard.instance_id).await.unwrap());
    assert_eq!(
        placements
            .root_charged_disk_mib(&runtime.runtime_id)
            .await
            .unwrap(),
        6_554
    );
    assert!(placements.release("orphan_tenant").await.unwrap());
    assert_eq!(
        placements
            .root_charged_disk_mib(&runtime.runtime_id)
            .await
            .unwrap(),
        2_253
    );
}

#[tokio::test]
async fn spill_cap_survives_provision_resize_recovery_and_delete() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool.clone());
    let runtime = shared_runtime("pool_spill_cap", 2);
    placements.save(&runtime).await.unwrap();

    let mut tenant = shared_instance(
        "large_tenant",
        &runtime.runtime_id,
        "large_db",
        "large_user",
        15434,
    );
    tenant.limits.disk_mib = 163_840;
    placements
        .reserve(metadata_reservation(&runtime.runtime_id, &tenant))
        .await
        .unwrap();

    // A provisional reservation is fully root-charged and also gets the
    // capped engine-global spill reserve.
    assert_eq!(
        placements
            .root_charged_disk_mib(&runtime.runtime_id)
            .await
            .unwrap(),
        174_080
    );
    placements
        .mark_provisioned(&tenant.instance_id)
        .await
        .unwrap();
    instances.upsert(&tenant).await.unwrap();
    assert_eq!(
        placements
            .root_charged_disk_mib(&runtime.runtime_id)
            .await
            .unwrap(),
        10_240
    );

    let mut grown = tenant.limits.clone();
    grown.disk_mib = 200_000;
    let resized = placements
        .resize(&tenant.instance_id, &grown)
        .await
        .unwrap();
    assert_eq!(resized.limits.disk_mib, 210_240);
    assert_eq!(
        placements
            .root_charged_disk_mib(&runtime.runtime_id)
            .await
            .unwrap(),
        10_240
    );

    // Simulate an older durable row that predates spill accounting. Reads use
    // reservation truth, and the next save repairs the normalized columns.
    sqlx::query(
        r#"
        UPDATE engine_runtimes
        SET limit_disk_mib = 202048,
            limits_json = json_set(limits_json, '$.disk_mib', 202048)
        WHERE runtime_id = ?1
        "#,
    )
    .bind(&runtime.runtime_id)
    .execute(&pool)
    .await
    .unwrap();
    let recovered = placements.get(&runtime.runtime_id).await.unwrap().unwrap();
    assert_eq!(recovered.limits.disk_mib, 210_240);
    placements.save(&recovered).await.unwrap();
    let stored: i64 =
        sqlx::query_scalar("SELECT limit_disk_mib FROM engine_runtimes WHERE runtime_id = ?1")
            .bind(&runtime.runtime_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored, 210_240);

    assert!(instances.delete(&tenant.instance_id).await.unwrap());
    let empty = placements.get(&runtime.runtime_id).await.unwrap().unwrap();
    assert_eq!(empty.reserved, RuntimeReservation::default());
    assert_eq!(empty.limits.disk_mib, 2048);
}

#[tokio::test]
async fn stale_state_save_cannot_undo_new_pool_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = PlacementRepository::new(pool);
    let mut stale = shared_runtime("pool_state_race", 4);
    repository.save(&stale).await.unwrap();

    let requested = tenant_limits();
    let reserved = repository
        .reserve(reservation(&stale.runtime_id, "tenant_a", &requested))
        .await
        .unwrap();
    stale.status = EngineRuntimeStatus::Failed;
    repository.save(&stale).await.unwrap();

    let loaded = repository.get(&stale.runtime_id).await.unwrap().unwrap();
    assert_eq!(loaded.status, EngineRuntimeStatus::Failed);
    assert_eq!(loaded.reserved, reserved.reserved);
    assert_eq!(loaded.limits, reserved.limits);
}

#[tokio::test]
async fn failed_resize_rolls_back_runtime_and_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = PlacementRepository::new(pool.clone());
    let runtime = shared_runtime("pool_resize_rollback", 2);
    repository.save(&runtime).await.unwrap();
    let original = tenant_limits();
    repository
        .reserve(reservation(&runtime.runtime_id, "unattached", &original))
        .await
        .unwrap();
    let mut larger = original.clone();
    larger.memory_mib = 3072;

    let error = repository.resize("unattached", &larger).await.unwrap_err();
    assert!(matches!(
        error,
        PlacementRepositoryError::ReservationNotAttached(instance)
            if instance == "unattached"
    ));
    let loaded = repository.get(&runtime.runtime_id).await.unwrap().unwrap();
    assert_eq!(loaded.reserved.memory_mib, original.memory_mib);
    assert_eq!(loaded.limits.memory_mib, original.memory_mib + 256);
    let stored: i64 = sqlx::query_scalar(
        "SELECT memory_mib FROM engine_runtime_reservations WHERE instance_id = 'unattached'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored, i64::try_from(original.memory_mib).unwrap());
}

#[tokio::test]
async fn concurrent_last_slot_has_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = PlacementRepository::new(pool);
    let runtime = shared_runtime("pool_race", 1);
    repository.save(&runtime).await.unwrap();
    let request = tenant_limits();

    let left = repository.clone();
    let right = repository.clone();
    let runtime_id = runtime.runtime_id.clone();
    let (first, second) = tokio::join!(
        left.reserve(reservation(&runtime_id, "race_a", &request)),
        right.reserve(reservation(&runtime_id, "race_b", &request))
    );

    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert_eq!(
        repository.tenant_count(&runtime.runtime_id).await.unwrap(),
        1
    );
}

#[tokio::test]
async fn creating_pool_reserves_its_first_tenant_before_launch() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = PlacementRepository::new(pool);
    let mut runtime = shared_runtime("pool_starting", 4);
    runtime.status = EngineRuntimeStatus::Creating;
    repository.save(&runtime).await.unwrap();
    let limits = tenant_limits();

    assert!(matches!(
        repository
            .reserve(reservation(&runtime.runtime_id, "normal", &limits))
            .await
            .unwrap_err(),
        PlacementRepositoryError::CapacityUnavailable(_)
    ));
    let reserved = repository
        .reserve_starting(reservation(&runtime.runtime_id, "first", &limits))
        .await
        .unwrap();

    assert_eq!(reserved.status, EngineRuntimeStatus::Creating);
    assert_eq!(reserved.reserved.tenants, 1);
    assert_eq!(reserved.reserved.memory_mib, limits.memory_mib);
    assert_eq!(reserved.limits.memory_mib, limits.memory_mib + 256);
    assert!(
        repository
            .find_shared(Protocol::Postgres, "postgres:18", &limits)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        repository
            .reserve_starting(reservation(&runtime.runtime_id, "second", &limits))
            .await
            .unwrap_err(),
        PlacementRepositoryError::CapacityUnavailable(_)
    ));
}

#[tokio::test]
async fn concurrent_resizes_recompute_exact_pool_totals() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool);
    let runtime = shared_runtime("pool_resize_race", 4);
    placements.save(&runtime).await.unwrap();
    let first = shared_instance("resize_a", &runtime.runtime_id, "db_a", "user_a", 15432);
    let second = shared_instance("resize_b", &runtime.runtime_id, "db_b", "user_b", 15433);
    for metadata in [&first, &second] {
        placements
            .reserve(metadata_reservation(&runtime.runtime_id, metadata))
            .await
            .unwrap();
        placements
            .mark_provisioned(&metadata.instance_id)
            .await
            .unwrap();
        instances.upsert(metadata).await.unwrap();
    }

    let mut first_limits = first.limits.clone();
    first_limits.cpu_cores = 0.1;
    first_limits.memory_mib = 1536;
    first_limits.disk_mib = 5120;
    let mut second_limits = second.limits.clone();
    second_limits.cpu_cores = 0.2;
    second_limits.memory_mib = 2048;
    second_limits.disk_mib = 6144;
    let left = placements.clone();
    let right = placements.clone();
    let (left_result, right_result) = tokio::join!(
        left.resize(&first.instance_id, &first_limits),
        right.resize(&second.instance_id, &second_limits),
    );
    left_result.unwrap();
    right_result.unwrap();

    let loaded = placements.get(&runtime.runtime_id).await.unwrap().unwrap();
    let reserved_cpu = first_limits.cpu_cores + second_limits.cpu_cores;
    assert_eq!(loaded.reserved.tenants, 2);
    assert_eq!(loaded.reserved.cpu_cores.to_bits(), reserved_cpu.to_bits());
    assert_eq!(loaded.reserved.memory_mib, 3584);
    assert_eq!(loaded.reserved.disk_mib, 11264);
    assert_eq!(
        loaded.limits.cpu_cores.to_bits(),
        (reserved_cpu + 0.25).to_bits()
    );
    assert_eq!(loaded.limits.memory_mib, 3840);
    assert_eq!(loaded.limits.disk_mib, 13_876);
}

#[tokio::test]
async fn resize_rejects_a_non_running_pool_without_mutating_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool);
    let runtime = shared_runtime("pool_stopped_resize", 2);
    placements.save(&runtime).await.unwrap();
    let metadata = shared_instance(
        "stopped_resize",
        &runtime.runtime_id,
        "stopped_db",
        "stopped_user",
        15432,
    );
    placements
        .reserve(metadata_reservation(&runtime.runtime_id, &metadata))
        .await
        .unwrap();
    placements
        .mark_provisioned(&metadata.instance_id)
        .await
        .unwrap();
    instances.upsert(&metadata).await.unwrap();
    let mut stopped = placements.get(&runtime.runtime_id).await.unwrap().unwrap();
    stopped.status = EngineRuntimeStatus::Stopped;
    placements.save(&stopped).await.unwrap();
    let before = placements.get(&runtime.runtime_id).await.unwrap().unwrap();
    let mut requested = metadata.limits.clone();
    requested.memory_mib += 1024;

    assert!(matches!(
        placements
            .resize(&metadata.instance_id, &requested)
            .await
            .unwrap_err(),
        PlacementRepositoryError::CapacityUnavailable(_)
    ));
    let after = placements.get(&runtime.runtime_id).await.unwrap().unwrap();
    assert_eq!(after.reserved, before.reserved);
    assert_eq!(after.limits, before.limits);
}

#[tokio::test]
async fn instance_placement_matches_runtime_and_restricts_pool_delete() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool.clone());
    let runtime = shared_runtime("pool_attached", 2);
    placements.save(&runtime).await.unwrap();

    let mut metadata = dedicated_instance("tenant_attached");
    instances.upsert(&metadata).await.unwrap();
    placements
        .reserve(metadata_reservation(&runtime.runtime_id, &metadata))
        .await
        .unwrap();
    placements
        .mark_provisioned(&metadata.instance_id)
        .await
        .unwrap();
    sqlx::query(
        r#"
        UPDATE instance_metadata
        SET deployment_mode = 'shared', runtime_id = ?1
        WHERE instance_id = ?2
        "#,
    )
    .bind(&runtime.runtime_id)
    .bind(&metadata.instance_id)
    .execute(&pool)
    .await
    .unwrap();

    let mismatch = sqlx::query(
        "UPDATE instance_metadata SET deployment_mode = 'dedicated' WHERE instance_id = ?1",
    )
    .bind(&metadata.instance_id)
    .execute(&pool)
    .await;
    assert!(mismatch.is_err());
    assert!(placements.delete(&runtime.runtime_id).await.is_err());

    metadata.deployment_mode = DeploymentMode::Shared;
    metadata.runtime_id = runtime.runtime_id.clone();
    instances.upsert(&metadata).await.unwrap();

    let rename_metadata = sqlx::query(
        "UPDATE instance_metadata SET database_name = 'other_db' WHERE instance_id = ?1",
    )
    .bind(&metadata.instance_id)
    .execute(&pool)
    .await;
    assert!(rename_metadata.is_err());
    let move_reservation = sqlx::query(
        "UPDATE engine_runtime_reservations SET database_name = 'other_db' WHERE instance_id = ?1",
    )
    .bind(&metadata.instance_id)
    .execute(&pool)
    .await;
    assert!(move_reservation.is_err());
    let detach_reservation =
        sqlx::query("DELETE FROM engine_runtime_reservations WHERE instance_id = ?1")
            .bind(&metadata.instance_id)
            .execute(&pool)
            .await;
    assert!(detach_reservation.is_err());

    let mut larger = metadata.limits.clone();
    larger.memory_mib = 2048;
    placements
        .resize(&metadata.instance_id, &larger)
        .await
        .unwrap();
    let resized = instances.get(&metadata.instance_id).await.unwrap().unwrap();
    assert_eq!(resized.limits.memory_mib, 2048);
    let resized_runtime = placements.get(&runtime.runtime_id).await.unwrap().unwrap();
    assert_eq!(resized_runtime.reserved.memory_mib, 2048);
    assert_eq!(resized_runtime.limits.memory_mib, 2304);
    assert!(instances.delete(&metadata.instance_id).await.unwrap());
    let empty_runtime = placements.get(&runtime.runtime_id).await.unwrap().unwrap();
    assert_eq!(empty_runtime.reserved, RuntimeReservation::default());
    assert!((empty_runtime.limits.cpu_cores - 0.25).abs() < f64::EPSILON);
    assert_eq!(empty_runtime.limits.memory_mib, 256);
    assert_eq!(empty_runtime.limits.disk_mib, 2048);
    assert!(placements.delete(&runtime.runtime_id).await.unwrap());
}

#[tokio::test]
async fn shared_tenant_database_and_username_are_pool_unique() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool);
    let runtime = shared_runtime("pool_identity", 4);
    placements.save(&runtime).await.unwrap();

    let first = shared_instance(
        "identity_a",
        &runtime.runtime_id,
        "tenant_db",
        "tenant_user",
        15432,
    );
    placements
        .check_tenant_identity(&runtime.runtime_id, "tenant_db", "tenant_user")
        .await
        .unwrap();
    placements
        .reserve(metadata_reservation(&runtime.runtime_id, &first))
        .await
        .unwrap();
    placements
        .mark_provisioned(&first.instance_id)
        .await
        .unwrap();
    instances.upsert(&first).await.unwrap();

    assert!(matches!(
        placements
            .check_tenant_identity(&runtime.runtime_id, "tenant_db", "other_user")
            .await
            .unwrap_err(),
        PlacementRepositoryError::DatabaseInUse { .. }
    ));
    assert!(matches!(
        placements
            .check_tenant_identity(&runtime.runtime_id, "other_db", "tenant_user")
            .await
            .unwrap_err(),
        PlacementRepositoryError::UsernameInUse { .. }
    ));
    placements
        .check_tenant_identity(&runtime.runtime_id, "other_db", "other_user")
        .await
        .unwrap();

    let duplicate_database = shared_instance(
        "identity_b",
        &runtime.runtime_id,
        "tenant_db",
        "other_user",
        15433,
    );
    let error = placements
        .reserve(metadata_reservation(
            &runtime.runtime_id,
            &duplicate_database,
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        PlacementRepositoryError::DatabaseInUse { .. }
    ));

    let duplicate_username = shared_instance(
        "identity_c",
        &runtime.runtime_id,
        "other_db",
        "tenant_user",
        15434,
    );
    let error = placements
        .reserve(metadata_reservation(
            &runtime.runtime_id,
            &duplicate_username,
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        PlacementRepositoryError::UsernameInUse { .. }
    ));
}

#[tokio::test]
async fn shared_route_identity_is_global_across_pools() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool);
    let first_runtime = shared_runtime("pool_route_a", 1);
    let second_runtime = shared_runtime("pool_route_b", 1);
    placements.save(&first_runtime).await.unwrap();
    placements.save(&second_runtime).await.unwrap();

    let first = shared_instance(
        "route_owner_a",
        &first_runtime.runtime_id,
        "same_database",
        "same_username",
        15432,
    );
    let second = shared_instance(
        "route_owner_b",
        &second_runtime.runtime_id,
        "same_database",
        "same_username",
        15433,
    );

    // A migration may provision the same physical identity in a different pool
    // before cutover, so reservations are intentionally scoped to one runtime.
    for (runtime, metadata) in [(&first_runtime, &first), (&second_runtime, &second)] {
        placements
            .reserve(metadata_reservation(&runtime.runtime_id, metadata))
            .await
            .unwrap();
        placements
            .mark_provisioned(&metadata.instance_id)
            .await
            .unwrap();
    }

    instances.upsert(&first).await.unwrap();
    let error = instances.upsert(&second).await.unwrap_err();
    assert!(matches!(
        error,
        crate::storage::repositories::RepositoryError::Sqlx(sqlx::Error::Database(source))
            if source.is_unique_violation()
    ));
    assert!(instances.get(&first.instance_id).await.unwrap().is_some());
    assert!(instances.get(&second.instance_id).await.unwrap().is_none());
}

#[tokio::test]
async fn provisional_identity_is_durable_and_blocks_takeover() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let placements = PlacementRepository::new(pool);
    let runtime = shared_runtime("pool_provisional", 4);
    placements.save(&runtime).await.unwrap();
    let limits = tenant_limits();
    placements
        .reserve(ReserveTenant {
            instance_id: "owner-a",
            runtime_id: &runtime.runtime_id,
            database: "durable_db",
            username: "durable_user",
            limits: &limits,
        })
        .await
        .unwrap();

    let stored = placements
        .get_reservation("owner-a")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.database, "durable_db");
    assert_eq!(stored.username, "durable_user");
    assert_eq!(stored.state, TenantReservationState::Reserved);
    assert_eq!(
        placements.reservations(&runtime.runtime_id).await.unwrap(),
        vec![stored]
    );
    assert!(matches!(
        placements
            .check_tenant_identity(&runtime.runtime_id, "durable_db", "other_user")
            .await
            .unwrap_err(),
        PlacementRepositoryError::DatabaseInUse { .. }
    ));
    assert!(matches!(
        placements
            .reserve(ReserveTenant {
                instance_id: "owner-b",
                runtime_id: &runtime.runtime_id,
                database: "durable_db",
                username: "other_user",
                limits: &limits,
            })
            .await
            .unwrap_err(),
        PlacementRepositoryError::DatabaseInUse { .. }
    ));

    placements.mark_provisioned("owner-a").await.unwrap();
    let provisioned = placements.mark_provisioned("owner-a").await.unwrap();
    assert_eq!(provisioned.state, TenantReservationState::Provisioned);
    assert_eq!(
        placements.reservations(&runtime.runtime_id).await.unwrap(),
        vec![provisioned]
    );
}

#[tokio::test]
async fn shared_metadata_cannot_attach_until_provisioning_is_durable() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool);
    let runtime = shared_runtime("pool_attach_stage", 2);
    placements.save(&runtime).await.unwrap();
    let metadata = shared_instance(
        "staged-owner",
        &runtime.runtime_id,
        "staged_db",
        "staged_user",
        15436,
    );
    placements
        .reserve(metadata_reservation(&runtime.runtime_id, &metadata))
        .await
        .unwrap();

    let error = instances.upsert(&metadata).await.unwrap_err();
    assert!(error.to_string().contains("exact runtime reservation"));

    placements
        .mark_provisioned(&metadata.instance_id)
        .await
        .unwrap();
    instances.upsert(&metadata).await.unwrap();
}

#[tokio::test]
async fn orphan_scan_excludes_attached_tenants_and_active_migrations() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool.clone());
    let runtime = shared_runtime("pool_orphans", 5);
    placements.save(&runtime).await.unwrap();
    let limits = tenant_limits();

    placements
        .reserve(ReserveTenant {
            instance_id: "plain-orphan",
            runtime_id: &runtime.runtime_id,
            database: "plain_db",
            username: "plain_user",
            limits: &limits,
        })
        .await
        .unwrap();

    let attached = shared_instance(
        "attached-owner",
        &runtime.runtime_id,
        "attached_db",
        "attached_user",
        15435,
    );
    placements
        .reserve(metadata_reservation(&runtime.runtime_id, &attached))
        .await
        .unwrap();
    placements
        .mark_provisioned(&attached.instance_id)
        .await
        .unwrap();
    instances.upsert(&attached).await.unwrap();

    let migration_id = "11111111-2222-4333-8444-555555555555";
    let temp_id = "migration_11111111222243338444555555555555";
    placements
        .reserve(ReserveTenant {
            instance_id: temp_id,
            runtime_id: &runtime.runtime_id,
            database: "migration_db",
            username: "migration_user",
            limits: &limits,
        })
        .await
        .unwrap();
    sqlx::query(
        r#"
        INSERT INTO deployment_migrations (
            migration_id, instance_id, protocol, source_mode, target_mode,
            source_runtime_id, stage, created_at, updated_at
        ) VALUES (
            ?1, 'migration-source', 'postgres', 'dedicated', 'shared',
            'migration-source', 'target_preparing', ?2, ?2
        )
        "#,
    )
    .bind(migration_id)
    .bind("2026-08-27T00:00:00Z")
    .execute(&pool)
    .await
    .unwrap();

    let orphans = placements.list_orphans().await.unwrap();
    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].instance_id, "plain-orphan");
    assert!(
        placements
            .get_orphan("attached-owner")
            .await
            .unwrap()
            .is_none()
    );
    assert!(placements.get_orphan(temp_id).await.unwrap().is_none());
}

#[tokio::test]
async fn database_rejects_unsupported_shared_protocol_even_without_model_validation() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let error = sqlx::query(
        r#"
        INSERT INTO engine_runtimes (
            runtime_id, schema_version, protocol, deployment_mode, status,
            backend_kind, backend_socket_path, runtime_kind, container_name,
            network, limits_json, limit_cpu_cores, limit_memory_mib,
            limit_disk_mib, image, compatibility_key, max_tenants,
            created_at, updated_at
        ) VALUES (
            'redis_shared', 1, 'redis', 'shared', 'running',
            'unix_socket', '/run/redis.sock', 'docker', 'redis_shared',
            'none', '{}', 1, 1024, 1024, 'redis:8', 'redis:8', 10,
            '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
        )
        "#,
    )
    .execute(&pool)
    .await;
    assert!(error.is_err());
}

#[tokio::test]
async fn database_rejects_reservations_on_dedicated_runtimes() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let instances = InstanceRepository::new(pool.clone());
    instances
        .upsert(&dedicated_instance("dedicated_reservation"))
        .await
        .unwrap();

    let error = sqlx::query(
        r#"
        INSERT INTO engine_runtime_reservations (
            instance_id, runtime_id, database_name, database_username, state,
            cpu_cores, memory_mib, disk_mib,
            created_at, updated_at
        ) VALUES (
            'invalid_tenant', 'dedicated_reservation', 'invalid_db', 'invalid_user',
            'reserved', 1, 1024, 4096,
            '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(error.to_string().contains("shared runtime"));
}

#[tokio::test]
async fn orphan_reservation_keeps_its_pool_identity_immutable() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let placements = PlacementRepository::new(pool.clone());
    let runtime = shared_runtime("pool_orphan_identity", 1);
    placements.save(&runtime).await.unwrap();
    placements
        .reserve(reservation(
            &runtime.runtime_id,
            "orphan-owner",
            &tenant_limits(),
        ))
        .await
        .unwrap();

    // Reservations intentionally exist before instance metadata while a
    // tenant is being provisioned. That crash-safe window must not permit the
    // owning runtime to become dedicated or change protocol underneath the
    // orphan claim.
    for update in [
        "UPDATE engine_runtimes SET deployment_mode = 'dedicated', max_tenants = 1 WHERE runtime_id = ?1",
        "UPDATE engine_runtimes SET protocol = 'mysql' WHERE runtime_id = ?1",
    ] {
        let error = sqlx::query(update)
            .bind(&runtime.runtime_id)
            .execute(&pool)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("identity is in use"));
    }

    let stored = placements
        .get_reservation("orphan-owner")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.runtime_id, runtime.runtime_id);
}

#[tokio::test]
async fn finds_only_running_compatible_pools_with_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = PlacementRepository::new(pool);
    let matching = shared_runtime("matching", 2);
    let mut wrong_image = shared_runtime("wrong_image", 2);
    wrong_image.image = "postgres:17".to_string();
    let mut stopped = shared_runtime("stopped", 2);
    stopped.status = EngineRuntimeStatus::Stopped;
    repository.save(&matching).await.unwrap();
    repository.save(&wrong_image).await.unwrap();
    repository.save(&stopped).await.unwrap();

    let found = repository
        .find_shared(Protocol::Postgres, "postgres:18", &tenant_limits())
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].runtime_id, "matching");
}

#[tokio::test]
async fn shared_placement_fills_existing_pools_before_spreading() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let repository = PlacementRepository::new(pool);
    let fuller = shared_runtime("fuller", 4);
    let emptier = shared_runtime("emptier", 4);
    repository.save(&fuller).await.unwrap();
    repository.save(&emptier).await.unwrap();
    repository
        .reserve(reservation(
            &fuller.runtime_id,
            "tenant-a",
            &tenant_limits(),
        ))
        .await
        .unwrap();

    let found = repository
        .find_shared(Protocol::Postgres, "postgres:18", &tenant_limits())
        .await
        .unwrap();

    assert_eq!(found.len(), 2);
    assert_eq!(found[0].runtime_id, fuller.runtime_id);
    assert_eq!(found[1].runtime_id, emptier.runtime_id);
}

fn shared_runtime(runtime_id: &str, max_tenants: u32) -> EngineRuntime {
    let mut runtime =
        crate::placement::test_support::runtime(runtime_id, Protocol::Postgres, "postgres:18");
    runtime.backend = BackendEndpoint::UnixSocket {
        socket_path: format!("/run/dbev/{runtime_id}/postgres.sock"),
    };
    runtime.runtime.container_name = format!("dbe-pool-{runtime_id}");
    runtime.limits = InstanceLimits {
        cpu_cores: 4.0,
        memory_mib: 8192,
        disk_mib: 32768,
        disk_enforced: true,
        disk_enforcement_method: "fusequota".to_string(),
    };
    runtime.database_version = Some("18.4".to_string());
    runtime.compatibility = Some(RuntimeCompatibility {
        container_id: format!("container-{runtime_id}"),
        image_id: "sha256:postgres18".to_string(),
        probe_revision: 1,
    });
    runtime.compatibility_key = "postgres:18:default".to_string();
    runtime.max_tenants = max_tenants;
    runtime
}

fn dedicated_instance(instance_id: &str) -> InstanceMetadata {
    let mut metadata = crate::instances::test_support::metadata(instance_id, Protocol::Postgres);
    metadata.public.host = "db.example.test".to_string();
    metadata.public.port = 15432;
    metadata.backend = BackendEndpoint::UnixSocket {
        socket_path: format!("/run/dbev/{instance_id}/postgres.sock"),
    };
    metadata.runtime.container_name = format!("dbe-{instance_id}");
    metadata.database.name = format!("db_{instance_id}");
    metadata.database.username = format!("user_{instance_id}");
    metadata.limits = tenant_limits();
    metadata
}

fn shared_instance(
    instance_id: &str,
    runtime_id: &str,
    database: &str,
    username: &str,
    public_port: u16,
) -> InstanceMetadata {
    let mut metadata = dedicated_instance(instance_id);
    metadata.deployment_mode = DeploymentMode::Shared;
    metadata.runtime_id = runtime_id.to_string();
    metadata.database.name = database.to_string();
    metadata.database.username = username.to_string();
    metadata.public.port = public_port;
    metadata
}

fn tenant_limits() -> InstanceLimits {
    InstanceLimits {
        cpu_cores: 1.0,
        memory_mib: 1024,
        disk_mib: 4096,
        disk_enforced: true,
        disk_enforcement_method: "pool_budget".to_string(),
    }
}

#[test]
fn lost_reservation_ack_only_adopts_the_exact_unprovisioned_claim() {
    let limits = tenant_limits();
    let mut stored = TenantReservation {
        instance_id: "tenant-a".to_string(),
        runtime_id: "pool-a".to_string(),
        database: "database-a".to_string(),
        username: "user-a".to_string(),
        state: TenantReservationState::Reserved,
        limits: limits.clone(),
    };

    assert!(claim_matches(
        &stored,
        "pool-a",
        "database-a",
        "user-a",
        &limits
    ));
    stored.state = TenantReservationState::Provisioned;
    assert!(!claim_matches(
        &stored,
        "pool-a",
        "database-a",
        "user-a",
        &limits
    ));
    stored.state = TenantReservationState::Reserved;
    stored.limits.memory_mib += 1;
    assert!(!claim_matches(
        &stored,
        "pool-a",
        "database-a",
        "user-a",
        &limits
    ));
}

fn reservation<'a>(
    runtime_id: &'a str,
    instance_id: &'a str,
    limits: &'a InstanceLimits,
) -> ReserveTenant<'a> {
    ReserveTenant {
        instance_id,
        runtime_id,
        database: instance_id,
        username: instance_id,
        limits,
    }
}

fn metadata_reservation<'a>(
    runtime_id: &'a str,
    metadata: &'a InstanceMetadata,
) -> ReserveTenant<'a> {
    ReserveTenant {
        instance_id: &metadata.instance_id,
        runtime_id,
        database: &metadata.database.name,
        username: &metadata.database.username,
        limits: &metadata.limits,
    }
}
