use super::{PlacementRepository, PlacementRepositoryError, reservations::claim_matches};
use crate::{
    databases::protocol::Protocol,
    server::metadata::InstanceMetadata,
    server::placement::{
        DeploymentMode, EngineRuntime, EngineRuntimeStatus, PlacementError, ReserveTenant,
        RuntimeCompatibility, RuntimeReservation, TenantReservation, TenantReservationState,
    },
    storage::{repositories::InstanceRepository, secrets::is_encrypted, sqlite},
    utils::{backend::BackendEndpoint, limits::InstanceLimits},
};

#[tokio::test]
async fn stores_pool_admin_secret_encrypted() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let repository = PlacementRepository::encrypted(pool.clone(), dir.path())?;
    let mut runtime = shared_runtime("pool_secret", 4);
    runtime.admin_secret = Some("pool-admin-password".to_string());

    repository.save(&runtime).await?;

    let raw: String =
        sqlx::query_scalar("SELECT admin_secret FROM engine_runtime_auth WHERE runtime_id = ?1")
            .bind(&runtime.runtime_id)
            .fetch_one(&pool)
            .await?;
    assert!(is_encrypted(&raw));
    assert!(!raw.contains("pool-admin-password"));
    let loaded = repository
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;
    assert!(repository.get("pool_secret' OR 1=1 --").await?.is_none());
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
    assert!(!serde_json::to_string(&loaded)?.contains("pool-admin"));

    Ok(())
}

#[tokio::test]
async fn rejects_raw_database_version_output() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let repository = PlacementRepository::new(pool);
    let mut runtime = shared_runtime("pool_raw_version", 4);
    runtime.database_version = Some("postgres (PostgreSQL) 18.4".to_string());

    let error = repository
        .save(&runtime)
        .await
        .expect_err("save should return an error");
    assert!(matches!(
        error,
        PlacementRepositoryError::Placement(PlacementError::InvalidDatabaseVersion(version))
            if version == "postgres (PostgreSQL) 18.4"
    ));

    Ok(())
}

#[tokio::test]
async fn reserves_and_releases_pool_capacity_atomically() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let repository = PlacementRepository::new(pool);
    let runtime = shared_runtime("pool_capacity", 2);
    repository.save(&runtime).await?;
    let mut request = tenant_limits();
    request.cpu_cores = 0.1;

    repository
        .reserve(reservation(&runtime.runtime_id, "tenant_a", &request))
        .await?;
    repository
        .reserve(reservation(&runtime.runtime_id, "tenant_b", &request))
        .await?;
    let full = repository
        .reserve(reservation(&runtime.runtime_id, "tenant_c", &request))
        .await
        .expect_err("reservation should return an error");

    assert!(matches!(
        full,
        PlacementRepositoryError::CapacityUnavailable(_)
    ));
    assert_eq!(repository.tenant_count(&runtime.runtime_id).await?, 2);
    assert_eq!(
        repository.tenants(&runtime.runtime_id).await?,
        ["tenant_a", "tenant_b"]
    );
    let loaded = repository
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;
    assert_eq!(loaded.reserved.tenants, 2);

    assert_eq!(loaded.reserved.disk_mib, 8192);
    assert_eq!(loaded.limits.cpu_cores, runtime.limits.cpu_cores);
    assert_eq!(loaded.limits.memory_mib, runtime.limits.memory_mib);
    assert_eq!(loaded.limits.disk_mib, runtime.limits.disk_mib);

    assert!(repository.release("tenant_a").await?);
    assert!(!repository.release("tenant_a").await?);
    let one = repository
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;
    assert_eq!(one.reserved.tenants, 1);

    assert_eq!(one.limits.cpu_cores, runtime.limits.cpu_cores);
    assert_eq!(one.limits.memory_mib, runtime.limits.memory_mib);
    assert_eq!(one.limits.disk_mib, runtime.limits.disk_mib);

    assert!(repository.release("tenant_b").await?);
    let empty = repository
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;
    assert_eq!(empty.reserved, RuntimeReservation::default());
    assert_eq!(empty.limits.cpu_cores, runtime.limits.cpu_cores);
    assert_eq!(empty.limits.memory_mib, runtime.limits.memory_mib);
    assert_eq!(empty.limits.disk_mib, runtime.limits.disk_mib);

    Ok(())
}

#[tokio::test]
async fn root_disk_capacity_counts_only_soft_and_unattached_tenants() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool);
    let runtime = shared_runtime("pool_root_disk", 4);
    placements.save(&runtime).await?;

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
            .await?;
        placements.mark_provisioned(&metadata.instance_id).await?;
        instances.upsert(metadata).await?;
    }
    placements
        .reserve(reservation(
            &runtime.runtime_id,
            "orphan_tenant",
            &orphan_limits,
        ))
        .await?;

    // Tenant disk is reserved within the unchanged physical pool budget.
    let aggregate = placements
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;
    assert_eq!(aggregate.reserved.disk_mib, 12_288);
    assert_eq!(aggregate.limits.disk_mib, runtime.limits.disk_mib);
    // The hard tenant is charged to its child project. The soft tenant and
    // unattached reservation remain charged to the shared root.
    assert_eq!(
        placements
            .root_charged_disk_mib(&runtime.runtime_id)
            .await?,
        10_855
    );

    soft.limits.disk_enforced = true;
    soft.limits.disk_enforcement_method = "host_linux_project_quota".to_string();
    instances.upsert(&soft).await?;
    assert_eq!(
        placements
            .root_charged_disk_mib(&runtime.runtime_id)
            .await?,
        6_759
    );

    assert!(instances.delete(&hard.instance_id).await?);
    assert_eq!(
        placements
            .root_charged_disk_mib(&runtime.runtime_id)
            .await?,
        6_554
    );
    assert!(placements.release("orphan_tenant").await?);
    assert_eq!(
        placements
            .root_charged_disk_mib(&runtime.runtime_id)
            .await?,
        2_253
    );

    Ok(())
}

#[tokio::test]
async fn mariadb_root_uses_full_pool_except_for_legacy_child_projects() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let db = sqlite::connect(dir.path()).await?;
    let placements = PlacementRepository::new(db.clone());
    let instances = InstanceRepository::new(db);
    let id = "maria_pool";
    let mut runtime = shared_runtime(id, 4);
    runtime.protocol = Protocol::Mariadb;
    runtime.image = "mariadb:12.3.2".into();
    placements.save(&runtime).await?;
    let capacity = runtime.limits.disk_mib;
    assert_eq!(placements.root_charged_disk_mib(id).await?, capacity);

    let mut tenant = shared_instance("tenant_a", id, "db_a", "user_a", 13306);
    tenant.protocol = Protocol::Mariadb;
    placements
        .reserve(metadata_reservation(id, &tenant))
        .await?;
    placements.mark_provisioned(&tenant.instance_id).await?;
    tenant.limits.disk_enforced = false;
    tenant.limits.disk_enforcement_method =
        crate::server::placement::tenant::disk::POOL_ONLY_METHOD.into();
    instances.upsert(&tenant).await?;
    assert_eq!(placements.root_charged_disk_mib(id).await?, capacity);

    tenant.limits.disk_enforced = true;
    tenant.limits.disk_enforcement_method = "host_xfs_project_quota".into();
    instances.upsert(&tenant).await?;
    assert_eq!(
        placements.root_charged_disk_mib(id).await?,
        capacity - tenant.limits.disk_mib
    );
    Ok(())
}

#[tokio::test]
async fn spill_cap_survives_provision_resize_recovery_and_delete() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool.clone());
    let mut runtime = shared_runtime("pool_spill_cap", 2);
    runtime.limits.disk_mib = 262_144;
    placements.save(&runtime).await?;

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
        .await?;

    // A provisional reservation is fully root-charged and also gets the
    // capped engine-global spill reserve.
    assert_eq!(
        placements
            .root_charged_disk_mib(&runtime.runtime_id)
            .await?,
        174_080
    );
    placements.mark_provisioned(&tenant.instance_id).await?;
    instances.upsert(&tenant).await?;
    assert_eq!(
        placements
            .root_charged_disk_mib(&runtime.runtime_id)
            .await?,
        10_240
    );

    let mut grown = tenant.limits.clone();
    grown.disk_mib = 200_000;
    let resized = placements.resize(&tenant.instance_id, &grown).await?;
    assert_eq!(resized.limits.disk_mib, runtime.limits.disk_mib);
    assert_eq!(
        placements
            .root_charged_disk_mib(&runtime.runtime_id)
            .await?,
        10_240
    );

    // Reopening and saving preserves the operator's fixed capacity.
    let recovered = placements
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;
    assert_eq!(recovered.limits, runtime.limits);
    placements.save(&recovered).await?;

    assert!(instances.delete(&tenant.instance_id).await?);
    let empty = placements
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;
    assert_eq!(empty.reserved, RuntimeReservation::default());
    assert_eq!(empty.limits.disk_mib, runtime.limits.disk_mib);

    Ok(())
}

#[tokio::test]
async fn stale_state_save_cannot_undo_new_pool_capacity() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let repository = PlacementRepository::new(pool);
    let mut stale = shared_runtime("pool_state_race", 4);
    repository.save(&stale).await?;

    let requested = tenant_limits();
    let reserved = repository
        .reserve(reservation(&stale.runtime_id, "tenant_a", &requested))
        .await?;
    stale.status = EngineRuntimeStatus::Failed;
    repository.save(&stale).await?;

    let loaded = repository
        .get(&stale.runtime_id)
        .await?
        .context("get should provide a value")?;
    assert_eq!(loaded.status, EngineRuntimeStatus::Failed);
    assert_eq!(loaded.reserved, reserved.reserved);
    assert_eq!(loaded.limits, reserved.limits);

    Ok(())
}

#[tokio::test]
async fn failed_resize_rolls_back_runtime_and_reservation() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let repository = PlacementRepository::new(pool.clone());
    let runtime = shared_runtime("pool_resize_rollback", 2);
    repository.save(&runtime).await?;
    let original = tenant_limits();
    repository
        .reserve(reservation(&runtime.runtime_id, "unattached", &original))
        .await?;
    let mut larger = original.clone();
    larger.memory_mib = 3072;

    let error = repository
        .resize("unattached", &larger)
        .await
        .expect_err("resize should return an error");
    assert!(matches!(
        error,
        PlacementRepositoryError::ReservationNotAttached(instance)
            if instance == "unattached"
    ));
    let loaded = repository
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;

    assert_eq!(loaded.limits.memory_mib, runtime.limits.memory_mib);
    let stored: i64 = sqlx::query_scalar(
        "SELECT memory_mib FROM engine_runtime_reservations WHERE instance_id = 'unattached'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(stored, i64::try_from(original.memory_mib)?);

    Ok(())
}

#[tokio::test]
async fn concurrent_last_slot_has_one_winner() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let repository = PlacementRepository::new(pool);
    let runtime = shared_runtime("pool_race", 1);
    repository.save(&runtime).await?;
    let request = tenant_limits();

    let left = repository.clone();
    let right = repository.clone();
    let runtime_id = runtime.runtime_id.clone();
    let (first, second) = tokio::join!(
        left.reserve(reservation(&runtime_id, "race_a", &request)),
        right.reserve(reservation(&runtime_id, "race_b", &request))
    );

    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    // The loser must observe the committed capacity, not a SQLite lock error.
    let loser = first
        .err()
        .or_else(|| second.err())
        .context("expected a value from or_else")?;
    assert!(matches!(
        loser,
        PlacementRepositoryError::CapacityUnavailable(_)
    ));
    assert_eq!(repository.tenant_count(&runtime.runtime_id).await?, 1);

    Ok(())
}

#[tokio::test]
async fn parallel_pool_recovery_preserves_tenant_state() -> anyhow::Result<()> {
    use anyhow::Context as _;

    use crate::server::{
        manager::InstanceManager,
        metadata::{DesiredInstanceState, InstanceStatus},
        state::InstanceStore,
    };
    use futures::StreamExt;
    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let placements = PlacementRepository::encrypted(pool.clone(), dir.path())?;
    let instances = InstanceRepository::encrypted(pool.clone(), dir.path())?;
    let manager = InstanceManager::new(InstanceStore::default(), instances.clone());
    let mut runtimes = Vec::new();
    for index in 0..8 {
        let mut runtime = shared_runtime(&format!("recovery_{index}"), 2);
        runtime.admin_secret = Some(format!("admin-{index}"));
        placements.save(&runtime).await?;
        for child in 0..2 {
            let id = format!("tenant_{index}_{child}");
            let mut tenant = shared_instance(&id, &runtime.runtime_id, &id, &id, 15432);
            tenant.tenant_password = Some(format!("secret-{id}"));
            if child == 0 {
                tenant.desired_state = DesiredInstanceState::Stopped;
                tenant.status = InstanceStatus::Stopped;
            }
            placements
                .reserve(metadata_reservation(&runtime.runtime_id, &tenant))
                .await?;
            placements.mark_provisioned(&id).await?;
            manager.upsert_preserving_fence(tenant).await?;
        }
        runtimes.push(
            placements
                .get(&runtime.runtime_id)
                .await?
                .context("get should provide a value")?,
        );
    }

    // Exercise the same persistence fan-out as restore_shared_limits, with
    // more pools than SQLite connections. No engine or filesystem work is
    // serialized to avoid the read-to-write upgrade race.
    let recovery = futures::stream::iter(runtimes.iter().cloned())
        .map(|mut runtime| {
            let placements = &placements;
            let manager = &manager;
            async move {
                for status in [EngineRuntimeStatus::Stopped, EngineRuntimeStatus::Running] {
                    runtime.status = status;
                    crate::server::placement::lifecycle::save_runtime(
                        placements,
                        manager,
                        runtime.clone(),
                    )
                    .await?;
                }
                Ok::<_, anyhow::Error>(())
            }
        })
        .buffer_unordered(8)
        .collect::<Vec<_>>();
    for result in tokio::time::timeout(std::time::Duration::from_secs(15), recovery).await? {
        result?;
    }
    pool.close().await;
    let reopened = sqlite::connect(dir.path()).await?;
    let placements = PlacementRepository::encrypted(reopened.clone(), dir.path())?;
    let instances = InstanceRepository::encrypted(reopened.clone(), dir.path())?;
    for runtime in runtimes {
        let stored = placements
            .get(&runtime.runtime_id)
            .await?
            .context("get should provide a value")?;
        assert_eq!(stored.status, EngineRuntimeStatus::Running);
        assert_eq!(stored.reserved, runtime.reserved);
        assert_eq!(stored.admin_secret, runtime.admin_secret);
        for id in placements.tenants(&runtime.runtime_id).await? {
            let tenant = instances
                .get(&id)
                .await?
                .context("get should provide a value")?;
            assert_eq!(tenant.owner, runtime.owner);
            assert_eq!(tenant.runtime_id, runtime.runtime_id);
            assert_eq!(tenant.tenant_password, Some(format!("secret-{id}")));
            assert_eq!(
                tenant.status,
                if id.ends_with("_0") {
                    InstanceStatus::Stopped
                } else {
                    InstanceStatus::Running
                }
            );
        }
    }
    reopened.close().await;

    Ok(())
}

#[tokio::test]
async fn empty_pool_survives_and_only_accepts_databases_when_running() -> anyhow::Result<()> {
    use anyhow::Context as _;

    use crate::server::metadata::DesiredInstanceState;
    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let repository = PlacementRepository::new(pool);
    let mut runtime = shared_runtime("pool_starting", 4);
    let limits = tenant_limits();
    for (status, desired) in [
        (EngineRuntimeStatus::Creating, DesiredInstanceState::Running),
        (EngineRuntimeStatus::Stopped, DesiredInstanceState::Stopped),
        (EngineRuntimeStatus::Running, DesiredInstanceState::Stopped),
    ] {
        runtime.status = status;
        runtime.desired_state = desired;
        repository.save(&runtime).await?;
        let stored = repository
            .get(&runtime.runtime_id)
            .await?
            .context("get should provide a value")?;
        assert_eq!(stored.desired_state, desired);
        assert_eq!(stored.reserved.tenants, 0);
        assert!(
            repository
                .reserve(reservation(&runtime.runtime_id, "first", &limits))
                .await
                .is_err()
        );
        assert!(
            repository
                .server_pool(runtime.protocol, runtime.owner.as_ref().context("empty pool survives and only accepts databases when running should provide a value")?)
                .await
                ?
                .is_some()
        );
    }
    runtime.status = EngineRuntimeStatus::Running;
    runtime.desired_state = DesiredInstanceState::Running;
    repository.save(&runtime).await?;
    repository
        .reserve(reservation(&runtime.runtime_id, "first", &limits))
        .await?;
    repository.release("first").await?;
    let stored = repository
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;
    assert_eq!(stored.reserved.tenants, 0);
    assert_eq!(stored.limits, runtime.limits);

    Ok(())
}

#[tokio::test]
async fn concurrent_resizes_recompute_exact_pool_totals() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool);
    let runtime = shared_runtime("pool_resize_race", 4);
    placements.save(&runtime).await?;
    let first = shared_instance("resize_a", &runtime.runtime_id, "db_a", "user_a", 15432);
    let second = shared_instance("resize_b", &runtime.runtime_id, "db_b", "user_b", 15433);
    for metadata in [&first, &second] {
        placements
            .reserve(metadata_reservation(&runtime.runtime_id, metadata))
            .await?;
        placements.mark_provisioned(&metadata.instance_id).await?;
        instances.upsert(metadata).await?;
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
    left_result?;
    right_result?;

    let loaded = placements
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;
    assert_eq!(loaded.reserved.tenants, 2);

    assert_eq!(loaded.reserved.disk_mib, 11264);
    assert_eq!(
        loaded.limits.cpu_cores.to_bits(),
        runtime.limits.cpu_cores.to_bits()
    );
    assert_eq!(loaded.limits.memory_mib, runtime.limits.memory_mib);
    assert_eq!(loaded.limits.disk_mib, runtime.limits.disk_mib);

    Ok(())
}

#[tokio::test]
async fn resize_rejects_a_non_running_pool_without_mutating_capacity() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool);
    let runtime = shared_runtime("pool_stopped_resize", 2);
    placements.save(&runtime).await?;
    let metadata = shared_instance(
        "stopped_resize",
        &runtime.runtime_id,
        "stopped_db",
        "stopped_user",
        15432,
    );
    placements
        .reserve(metadata_reservation(&runtime.runtime_id, &metadata))
        .await?;
    placements.mark_provisioned(&metadata.instance_id).await?;
    instances.upsert(&metadata).await?;
    let mut stopped = placements
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;
    stopped.status = EngineRuntimeStatus::Stopped;
    placements.save(&stopped).await?;
    let before = placements
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;
    let mut requested = metadata.limits.clone();
    requested.memory_mib += 1024;

    assert!(matches!(
        placements
            .resize(&metadata.instance_id, &requested)
            .await
            .expect_err("resize should return an error"),
        PlacementRepositoryError::CapacityUnavailable(_)
    ));
    let after = placements
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;
    assert_eq!(after.reserved, before.reserved);
    assert_eq!(after.limits, before.limits);

    Ok(())
}

#[tokio::test]
async fn instance_placement_matches_runtime_and_restricts_pool_delete() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool.clone());
    let runtime = shared_runtime("pool_attached", 2);
    placements.save(&runtime).await?;

    let mut metadata = dedicated_instance("tenant_attached");
    metadata.owner = runtime.owner.clone();
    instances.upsert(&metadata).await?;
    placements
        .reserve(metadata_reservation(&runtime.runtime_id, &metadata))
        .await?;
    placements.mark_provisioned(&metadata.instance_id).await?;
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
    .await?;

    let mismatch = sqlx::query(
        "UPDATE instance_metadata SET deployment_mode = 'dedicated' WHERE instance_id = ?1",
    )
    .bind(&metadata.instance_id)
    .execute(&pool)
    .await;
    assert!(mismatch.is_err());
    assert!(placements.delete(&runtime.runtime_id).await.is_err());

    metadata.deployment_mode = DeploymentMode::Shared;
    metadata.owner = runtime.owner.clone();
    metadata.runtime_id = runtime.runtime_id.clone();
    instances.upsert(&metadata).await?;

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
    placements.resize(&metadata.instance_id, &larger).await?;
    let resized = instances
        .get(&metadata.instance_id)
        .await?
        .context("get should provide a value")?;
    assert_eq!(resized.limits.memory_mib, 2048);
    let resized_runtime = placements
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;
    assert_eq!(resized_runtime.limits.memory_mib, runtime.limits.memory_mib);
    assert!(instances.delete(&metadata.instance_id).await?);
    let empty_runtime = placements
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;
    assert_eq!(empty_runtime.reserved, RuntimeReservation::default());
    assert_eq!(empty_runtime.limits.cpu_cores, runtime.limits.cpu_cores);
    assert_eq!(empty_runtime.limits.memory_mib, runtime.limits.memory_mib);
    assert_eq!(empty_runtime.limits.disk_mib, runtime.limits.disk_mib);
    assert!(placements.delete(&runtime.runtime_id).await?);

    Ok(())
}

#[tokio::test]
async fn shared_tenant_database_and_username_are_pool_unique() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool);
    let runtime = shared_runtime("pool_identity", 4);
    placements.save(&runtime).await?;

    let first = shared_instance(
        "identity_a",
        &runtime.runtime_id,
        "tenant_db",
        "tenant_user",
        15432,
    );
    placements
        .check_tenant_identity(&runtime.runtime_id, "tenant_db", "tenant_user")
        .await?;
    placements
        .reserve(metadata_reservation(&runtime.runtime_id, &first))
        .await?;
    placements.mark_provisioned(&first.instance_id).await?;
    instances.upsert(&first).await?;

    assert!(matches!(
        placements
            .check_tenant_identity(&runtime.runtime_id, "tenant_db", "other_user")
            .await
            .expect_err("check tenant identity should return an error"),
        PlacementRepositoryError::DatabaseInUse { .. }
    ));
    assert!(matches!(
        placements
            .check_tenant_identity(&runtime.runtime_id, "other_db", "tenant_user")
            .await
            .expect_err("check tenant identity should return an error"),
        PlacementRepositoryError::UsernameInUse { .. }
    ));
    placements
        .check_tenant_identity(&runtime.runtime_id, "other_db", "other_user")
        .await?;

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
        .expect_err("metadata reservation should return an error");
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
        .expect_err("metadata reservation should return an error");
    assert!(matches!(
        error,
        PlacementRepositoryError::UsernameInUse { .. }
    ));

    Ok(())
}

#[tokio::test]
async fn shared_route_identity_is_global_across_pools() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool);
    let first_runtime = shared_runtime("pool_route_a", 1);
    let second_runtime = shared_runtime("pool_route_b", 1);
    placements.save(&first_runtime).await?;
    placements.save(&second_runtime).await?;

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
            .await?;
        placements.mark_provisioned(&metadata.instance_id).await?;
    }

    instances.upsert(&first).await?;
    let error = instances
        .upsert(&second)
        .await
        .expect_err("upsert should return an error");
    assert!(matches!(
        error,
        crate::storage::repositories::RepositoryError::Sqlx(sqlx::Error::Database(source))
            if source.is_unique_violation()
    ));
    assert!(instances.get(&first.instance_id).await?.is_some());
    assert!(instances.get(&second.instance_id).await?.is_none());

    Ok(())
}

#[tokio::test]
async fn provisional_identity_is_durable_and_blocks_takeover() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let placements = PlacementRepository::new(pool);
    let runtime = shared_runtime("pool_provisional", 4);
    placements.save(&runtime).await?;
    let limits = tenant_limits();
    placements
        .reserve(ReserveTenant {
            owner: runtime.owner.clone().context(
                "provisional identity is durable and blocks takeover should provide a value",
            )?,
            instance_id: "owner-a",
            runtime_id: &runtime.runtime_id,
            database: "durable_db",
            username: "durable_user",
            limits: &limits,
        })
        .await?;

    let stored = placements
        .get_reservation("owner-a")
        .await?
        .context("get reservation should provide a value")?;
    assert_eq!(stored.database, "durable_db");
    assert_eq!(stored.username, "durable_user");
    assert_eq!(stored.state, TenantReservationState::Reserved);
    assert_eq!(
        placements.reservations(&runtime.runtime_id).await?,
        vec![stored]
    );
    assert!(matches!(
        placements
            .check_tenant_identity(&runtime.runtime_id, "durable_db", "other_user")
            .await
            .expect_err("check tenant identity should return an error"),
        PlacementRepositoryError::DatabaseInUse { .. }
    ));
    assert!(matches!(
        placements
            .reserve(ReserveTenant {
                owner: runtime.owner.clone().context(
                    "provisional identity is durable and blocks takeover should provide a value"
                )?,
                instance_id: "owner-b",
                runtime_id: &runtime.runtime_id,
                database: "durable_db",
                username: "other_user",
                limits: &limits,
            })
            .await
            .expect_err("reserve should return an error"),
        PlacementRepositoryError::DatabaseInUse { .. }
    ));

    placements.mark_provisioned("owner-a").await?;
    let provisioned = placements.mark_provisioned("owner-a").await?;
    assert_eq!(provisioned.state, TenantReservationState::Provisioned);
    assert_eq!(
        placements.reservations(&runtime.runtime_id).await?,
        vec![provisioned]
    );

    Ok(())
}

#[tokio::test]
async fn shared_metadata_cannot_attach_until_provisioning_is_durable() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool);
    let runtime = shared_runtime("pool_attach_stage", 2);
    placements.save(&runtime).await?;
    let metadata = shared_instance(
        "staged-owner",
        &runtime.runtime_id,
        "staged_db",
        "staged_user",
        15436,
    );
    placements
        .reserve(metadata_reservation(&runtime.runtime_id, &metadata))
        .await?;

    let error = instances
        .upsert(&metadata)
        .await
        .expect_err("upsert should return an error");
    assert!(error.to_string().contains("exact runtime reservation"));

    placements.mark_provisioned(&metadata.instance_id).await?;
    instances.upsert(&metadata).await?;

    Ok(())
}

#[tokio::test]
async fn orphan_scan_excludes_attached_tenants_and_active_migrations() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let placements = PlacementRepository::new(pool.clone());
    let instances = InstanceRepository::new(pool.clone());
    let runtime = shared_runtime("pool_orphans", 5);
    placements.save(&runtime).await?;
    let limits = tenant_limits();

    placements
        .reserve(ReserveTenant {
            owner: runtime
                .owner
                .clone()
                .context("expected a value from clone")?,
            instance_id: "plain-orphan",
            runtime_id: &runtime.runtime_id,
            database: "plain_db",
            username: "plain_user",
            limits: &limits,
        })
        .await?;

    let attached = shared_instance(
        "attached-owner",
        &runtime.runtime_id,
        "attached_db",
        "attached_user",
        15435,
    );
    placements
        .reserve(metadata_reservation(&runtime.runtime_id, &attached))
        .await?;
    placements.mark_provisioned(&attached.instance_id).await?;
    instances.upsert(&attached).await?;

    let migration_id = "11111111-2222-4333-8444-555555555555";
    let temp_id = "migration_11111111222243338444555555555555";
    placements
        .reserve(ReserveTenant {
            owner: runtime
                .owner
                .clone()
                .context("expected a value from clone")?,
            instance_id: temp_id,
            runtime_id: &runtime.runtime_id,
            database: "migration_db",
            username: "migration_user",
            limits: &limits,
        })
        .await?;
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
    .await?;

    let orphans = placements.list_orphans().await?;
    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].instance_id, "plain-orphan");
    assert!(placements.get_orphan("attached-owner").await?.is_none());
    assert!(placements.get_orphan(temp_id).await?.is_none());
    assert!(
        placements
            .get_orphan("plain-orphan' OR 1=1 --")
            .await?
            .is_none()
    );

    Ok(())
}

#[tokio::test]
async fn database_rejects_unsupported_shared_protocol_even_without_model_validation()
-> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let error = sqlx::query(
        r#"
        INSERT INTO engine_runtimes (
            runtime_id, schema_version, protocol, deployment_mode, status,
            backend_kind, backend_socket_path, runtime_kind, container_name,
            network, limits_json, limit_cpu_cores, limit_memory_mib,
            limit_disk_mib, image, max_tenants,
            created_at, updated_at
        ) VALUES (
            'redis_shared', 1, 'redis', 'shared', 'running',
            'unix_socket', '/run/redis.sock', 'docker', 'redis_shared',
            'none', '{}', 1, 1024, 1024, 'redis:8', 10,
            '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
        )
        "#,
    )
    .execute(&pool)
    .await;
    assert!(error.is_err());

    Ok(())
}

#[tokio::test]
async fn database_rejects_reservations_on_dedicated_runtimes() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let instances = InstanceRepository::new(pool.clone());
    instances
        .upsert(&dedicated_instance("dedicated_reservation"))
        .await?;

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
    .expect_err("execute should return an error");
    assert!(
        error.to_string().contains("reservation") || error.to_string().contains("shared runtime")
    );

    Ok(())
}

#[tokio::test]
async fn orphan_reservation_keeps_its_pool_identity_immutable() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let placements = PlacementRepository::new(pool.clone());
    let runtime = shared_runtime("pool_orphan_identity", 1);
    placements.save(&runtime).await?;
    placements
        .reserve(reservation(
            &runtime.runtime_id,
            "orphan-owner",
            &tenant_limits(),
        ))
        .await?;

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
            .expect_err("execute should return an error");
        assert!(error.to_string().contains("immutable"));
    }

    let stored = placements
        .get_reservation("orphan-owner")
        .await?
        .context("get reservation should provide a value")?;
    assert_eq!(stored.runtime_id, runtime.runtime_id);

    Ok(())
}

#[tokio::test]
async fn server_pool_identity_survives_full_and_failed_states() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    let repository = PlacementRepository::new(pool);
    let mut runtime = shared_runtime("server-a", 1);
    let owner = runtime
        .owner
        .clone()
        .context("expected a value from clone")?;
    repository.save(&runtime).await?;
    repository
        .reserve(reservation(
            &runtime.runtime_id,
            "tenant_a",
            &tenant_limits(),
        ))
        .await?;
    assert_eq!(
        repository
            .server_pool(Protocol::Postgres, &owner)
            .await?
            .context("server pool should provide a value")?
            .runtime_id,
        runtime.runtime_id
    );
    runtime = repository
        .get(&runtime.runtime_id)
        .await?
        .context("get should provide a value")?;
    runtime.status = EngineRuntimeStatus::Failed;
    repository.save(&runtime).await?;
    assert_eq!(
        repository
            .server_pool(Protocol::Postgres, &owner)
            .await?
            .context("server pool should provide a value")?
            .status,
        EngineRuntimeStatus::Failed
    );
    assert!(
        repository
            .server_pool(Protocol::Mysql, &owner)
            .await?
            .is_none()
    );
    assert!(
        repository
            .server_pool(
                Protocol::Postgres,
                &crate::server::placement::test_support::owner("server-b")
            )
            .await?
            .is_none()
    );
    let mut duplicate = shared_runtime("different-id", 1);
    duplicate.owner = Some(owner);
    assert!(repository.save(&duplicate).await.is_err());

    Ok(())
}

fn shared_runtime(runtime_id: &str, max_tenants: u32) -> EngineRuntime {
    let mut runtime = crate::server::placement::test_support::runtime(
        runtime_id,
        Protocol::Postgres,
        "postgres:18",
    );
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

    runtime.max_tenants = max_tenants;
    runtime
}

fn dedicated_instance(instance_id: &str) -> InstanceMetadata {
    let mut metadata = crate::server::test_support::metadata(instance_id, Protocol::Postgres);
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
    metadata.owner = Some(crate::server::placement::test_support::owner(runtime_id));
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
        owner: crate::server::placement::test_support::owner(runtime_id),
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
        owner: crate::server::placement::test_support::owner(runtime_id),
        instance_id: &metadata.instance_id,
        runtime_id,
        database: &metadata.database.name,
        username: &metadata.database.username,
        limits: &metadata.limits,
    }
}
