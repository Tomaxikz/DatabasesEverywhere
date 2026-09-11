use super::PlacementRepository;
use crate::{
    placement::{
        DeploymentMode, EngineRuntimeStatus, ReserveTenant,
        test_support::{owner, runtime},
    },
    shared::{limits::InstanceLimits, protocol::Protocol},
    storage::{repositories::InstanceRepository, sqlite},
};

#[tokio::test]
async fn every_shared_engine_enforces_server_and_panel_ownership() {
    for protocol in Protocol::ALL
        .into_iter()
        .filter(|protocol| DeploymentMode::Shared.supports(*protocol))
    {
        let dir = tempfile::tempdir().unwrap();
        let db = sqlite::connect(dir.path()).await.unwrap();
        let pools = PlacementRepository::new(db.clone());
        let mut first = runtime("pool-a", protocol, "test-image");
        first.owner = Some(owner("server-a"));
        first.limits.disk_mib = 4096;
        let mut second = runtime("pool-b", protocol, "test-image");
        second.owner = Some(owner("server-b"));
        pools.save(&first).await.unwrap();
        pools.save(&second).await.unwrap();
        let limits = InstanceLimits {
            disk_mib: 128,
            ..InstanceLimits::default()
        };

        for wrong_owner in [
            owner("server-b"),
            crate::placement::PoolOwner {
                panel_id: "other-panel".into(),
                server_id: "server-a".into(),
            },
        ] {
            assert!(
                pools
                    .reserve(ReserveTenant {
                        owner: wrong_owner,
                        instance_id: "wrong-tenant",
                        runtime_id: &first.runtime_id,
                        database: "wrong_db",
                        username: "wrong_user",
                        limits: &limits,
                    })
                    .await
                    .is_err(),
                "{protocol}"
            );
            assert!(
                pools
                    .get_reservation("wrong-tenant")
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        let reserved = pools
            .reserve(ReserveTenant {
                owner: owner("server-a"),
                instance_id: "tenant-a",
                runtime_id: &first.runtime_id,
                database: "tenant_db",
                username: "tenant_user",
                limits: &limits,
            })
            .await
            .unwrap();
        assert_eq!(
            reserved.limits, first.limits,
            "{protocol}: creation changed pool limits"
        );

        assert_eq!(reserved.reserved.disk_mib, 128);

        let instances = InstanceRepository::new(db.clone());
        let mut tenant = crate::instances::test_support::metadata("tenant-a", protocol);
        tenant.deployment_mode = DeploymentMode::Shared;
        tenant.runtime_id = first.runtime_id.clone();
        tenant.owner = Some(owner("server-b"));
        tenant.database.name = "tenant_db".into();
        tenant.database.username = "tenant_user".into();
        tenant.limits = limits;
        tenant.backend = first.backend.clone();
        tenant.runtime = first.runtime.clone();
        assert!(
            instances.upsert(&tenant).await.is_err(),
            "{protocol}: foreign metadata accepted"
        );
        tenant.owner = Some(owner("server-a"));
        pools.mark_provisioned("tenant-a").await.unwrap();
        instances.upsert(&tenant).await.unwrap();
        let mut reassigned = tenant.clone();
        reassigned.owner = second.owner.clone();
        reassigned.runtime_id = second.runtime_id.clone();
        assert!(
            instances.upsert(&reassigned).await.is_err(),
            "{protocol}: tenant ownership changed"
        );
        instances.delete("tenant-a").await.unwrap();
        let after_delete = pools.get(&first.runtime_id).await.unwrap().unwrap();
        assert_eq!(
            after_delete.limits, first.limits,
            "{protocol}: delete resized pool"
        );
        assert_eq!(after_delete.reserved.tenants, 0);

        let mut other_panel = runtime("pool-c", protocol, "test-image");
        other_panel.owner = Some(crate::placement::PoolOwner {
            panel_id: "other-panel".into(),
            server_id: "server-a".into(),
        });
        pools.save(&other_panel).await.unwrap();
        let mut duplicate = runtime("duplicate", protocol, "different-image");
        duplicate.owner = first.owner.clone();
        assert!(
            pools.save(&duplicate).await.is_err(),
            "{protocol}: second engine accepted"
        );
        let mut changed = first.clone();
        changed.owner = second.owner.clone();
        assert!(
            pools.save(&changed).await.is_err(),
            "{protocol}: owner changed"
        );
        first.status = EngineRuntimeStatus::Stopped;
        pools.save(&first).await.unwrap();
        assert!(
            pools.save(&duplicate).await.is_err(),
            "{protocol}: stopped pool allowed replacement"
        );
    }
}

#[tokio::test]
async fn racing_first_pools_have_one_durable_winner() {
    let dir = tempfile::tempdir().unwrap();
    let db = sqlite::connect(dir.path()).await.unwrap();
    let pools = PlacementRepository::new(db);
    let mut tasks = tokio::task::JoinSet::new();
    for number in 0..8 {
        let pools = pools.clone();
        tasks.spawn(async move {
            let mut pool = runtime(&format!("pool-{number}"), Protocol::Mysql, "mysql:8.4");
            pool.owner = Some(owner("same-server"));
            pool.status = EngineRuntimeStatus::Creating;
            pools.save(&pool).await.is_ok()
        });
    }
    let mut winners = 0;
    while let Some(result) = tasks.join_next().await {
        winners += usize::from(result.unwrap());
    }
    assert_eq!(winners, 1);
    assert_eq!(pools.list().await.unwrap().len(), 1);
}

#[tokio::test]
async fn pool_disk_budget_is_fixed_even_when_memory_reservations_would_fit() {
    let dir = tempfile::tempdir().unwrap();
    let db = sqlite::connect(dir.path()).await.unwrap();
    let pools = PlacementRepository::new(db);
    let mut pool = runtime("disk-pool", Protocol::Mysql, "mysql:8.4");
    pool.limits.disk_mib = 1600; // 512 MiB engine + two 512 MiB tenants + spill.
    pools.save(&pool).await.unwrap();
    let limits = InstanceLimits {
        disk_mib: 512,
        ..InstanceLimits::default()
    };
    for (id, accepted) in [("first", true), ("second", true), ("third", false)] {
        let result = pools
            .reserve(ReserveTenant {
                owner: pool.owner.clone().unwrap(),
                instance_id: id,
                runtime_id: &pool.runtime_id,
                database: id,
                username: id,
                limits: &limits,
            })
            .await;
        assert_eq!(result.is_ok(), accepted);
    }
    assert_eq!(
        pools
            .get(&pool.runtime_id)
            .await
            .unwrap()
            .unwrap()
            .limits
            .disk_mib,
        1600
    );
}

#[tokio::test]
async fn unowned_pools_are_quarantined_without_deleting_data_or_blocking_containment() {
    let db = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    sqlx::raw_sql(r#"
        CREATE TABLE engine_runtimes(runtime_id TEXT PRIMARY KEY, protocol TEXT, deployment_mode TEXT, status TEXT, tenant_count INTEGER, reserved_cpu_cores REAL, reserved_memory_mib INTEGER, reserved_disk_mib INTEGER);
        CREATE INDEX uq_engine_runtimes_shared_compatibility ON engine_runtimes(runtime_id);
        CREATE TABLE instance_metadata(instance_id TEXT PRIMARY KEY, runtime_id TEXT, deployment_mode TEXT, status TEXT, metadata_json TEXT);
        CREATE TABLE engine_runtime_reservations(instance_id TEXT PRIMARY KEY, runtime_id TEXT, disk_mib INTEGER);
        CREATE TABLE deployment_migrations(migration_id TEXT PRIMARY KEY);
        CREATE TRIGGER trg_instance_release_runtime_reservation AFTER DELETE ON instance_metadata BEGIN SELECT 1; END;
        INSERT INTO engine_runtimes VALUES ('old-pool','mysql','shared','running',1,1,1024,512);
        INSERT INTO instance_metadata VALUES ('old-tenant','old-pool','shared','running','{"status":"running"}');
        INSERT INTO engine_runtime_reservations VALUES ('old-tenant','old-pool',512);
    "#).execute(&db).await.unwrap();
    sqlx::raw_sql(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/migrations/20260905120000_server_private_pools.sql"
    )))
    .execute(&db)
    .await
    .unwrap();
    for query in [
        "SELECT status FROM engine_runtimes",
        "SELECT status FROM instance_metadata",
    ] {
        let status: String = sqlx::query_scalar(query).fetch_one(&db).await.unwrap();
        assert_eq!(status, "quarantined");
    }
    sqlx::query("INSERT INTO engine_runtimes(runtime_id,protocol,deployment_mode,status) VALUES ('old-pool','mysql','shared','quarantined') ON CONFLICT(runtime_id) DO UPDATE SET status=excluded.status")
        .execute(&db).await.unwrap();
    sqlx::query("INSERT INTO instance_metadata(instance_id,runtime_id,deployment_mode,status,metadata_json) VALUES ('old-tenant','old-pool','shared','quarantined','{\"status\":\"quarantined\"}') ON CONFLICT(instance_id) DO UPDATE SET status=excluded.status,metadata_json=excluded.metadata_json")
        .execute(&db).await.unwrap();
    assert!(
        sqlx::query("UPDATE engine_runtimes SET status='running' WHERE runtime_id='old-pool'")
            .execute(&db)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE instance_metadata SET status='running' WHERE instance_id='old-tenant'")
            .execute(&db)
            .await
            .is_err()
    );
    assert!(sqlx::query("INSERT INTO engine_runtimes(runtime_id,protocol,deployment_mode,status) VALUES ('new-unowned','mysql','shared','quarantined')").execute(&db).await.is_err());
    assert!(sqlx::query("UPDATE engine_runtimes SET owner_panel='panel',owner_server='guessed' WHERE runtime_id='old-pool'").execute(&db).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM engine_runtime_reservations")
            .fetch_one(&db)
            .await
            .unwrap(),
        1
    );
}
