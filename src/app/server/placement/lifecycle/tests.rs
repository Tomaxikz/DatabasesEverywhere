use super::*;
use super::{
    boot::container_ids_match, limits::needs_pool_adoption,
    start_disk::shared_disk_target_is_current,
};
use crate::{
    config::DiskLimitMode,
    databases::protocol::Protocol,
    runtime::docker::DockerContainerStatus,
    server::compatibility::COMPATIBILITY_PROBE_REVISION,
    server::disk::soft::SoftDiskTarget,
    server::metadata::{DesiredInstanceState, InstanceStatus},
    server::placement::{
        EngineRuntime, EngineRuntimeStatus, PlacementRepository, ReserveTenant,
        RuntimeCompatibility, TenantReservationState,
    },
    server::{manager::InstanceManager, state::InstanceStore},
    storage::{repositories::InstanceRepository, sqlite},
    utils::{
        backend::BackendEndpoint,
        limits::{InstanceLimits, mib_to_bytes},
    },
};

#[tokio::test]
async fn runtime_tenant_lookup_preserves_provisioning_state() {
    let directory = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(directory.path()).await.unwrap();
    let placements = PlacementRepository::new(pool.clone());
    let manager = InstanceManager::new(
        InstanceStore::default(),
        InstanceRepository::new(pool.clone()),
    );
    let runtime = runtime();
    placements.save(&runtime).await.unwrap();
    let limits = InstanceLimits {
        cpu_cores: 0.1,
        memory_mib: 128,
        disk_mib: 256,
        ..InstanceLimits::default()
    };
    placements
        .reserve(ReserveTenant {
            owner: runtime.owner.clone().unwrap(),
            instance_id: "tenant-in-progress",
            runtime_id: &runtime.runtime_id,
            database: "tenant_db",
            username: "tenant_user",
            limits: &limits,
        })
        .await
        .unwrap();

    let tenants = runtime_tenants(&placements, &manager, &runtime.runtime_id).await;
    assert_eq!(
        tenants.get("tenant-in-progress"),
        Some(&Some(TenantReservationState::Reserved))
    );

    placements
        .mark_provisioned("tenant-in-progress")
        .await
        .unwrap();
    let tenants = runtime_tenants(&placements, &manager, &runtime.runtime_id).await;
    assert_eq!(
        tenants.get("tenant-in-progress"),
        Some(&Some(TenantReservationState::Provisioned))
    );
}

#[test]
fn pool_root_is_adopted_once_when_upgrading_from_soft_enforcement() {
    for (mode, method, expected) in [
        (DiskLimitMode::ProjectQuota, "soft_scanner", true),
        (DiskLimitMode::ProjectQuota, "shared_pool_reservation", true),
        (DiskLimitMode::ProjectQuota, "host_xfs_project_quota", false),
        (DiskLimitMode::FuseQuota, "soft_scanner", false),
    ] {
        assert_eq!(needs_pool_adoption(mode, method), expected, "{method}");
    }
}

#[test]
fn shared_boot_actions_never_activate_quarantined_or_deleting_pools() {
    for (status, action) in [
        (EngineRuntimeStatus::Booting, Some(SharedBootAction::Start)),
        (EngineRuntimeStatus::Running, None),
        (EngineRuntimeStatus::Creating, None),
        (EngineRuntimeStatus::Stopped, Some(SharedBootAction::Start)),
        (EngineRuntimeStatus::Failed, Some(SharedBootAction::Restart)),
        (EngineRuntimeStatus::Quarantined, None),
        (EngineRuntimeStatus::Deleting, None),
    ] {
        assert_eq!(
            shared_boot_action(status, DesiredInstanceState::Running),
            action
        );
        assert_eq!(
            shared_boot_action(status, DesiredInstanceState::Stopped),
            None
        );
    }
}

#[test]
fn tenant_status_follows_pool_and_desired_state_without_losing_quarantine() {
    for (pool, desired, current, expected) in [
        (
            EngineRuntimeStatus::Running,
            DesiredInstanceState::Stopped,
            InstanceStatus::Stopped,
            InstanceStatus::Stopped,
        ),
        (
            EngineRuntimeStatus::Running,
            DesiredInstanceState::Running,
            InstanceStatus::Failed,
            InstanceStatus::Running,
        ),
        (
            EngineRuntimeStatus::Failed,
            DesiredInstanceState::Running,
            InstanceStatus::Running,
            InstanceStatus::Failed,
        ),
        (
            EngineRuntimeStatus::Running,
            DesiredInstanceState::Running,
            InstanceStatus::Quarantined,
            InstanceStatus::Quarantined,
        ),
    ] {
        assert_eq!(tenant_status(pool, desired, current), expected);
    }
}

#[test]
fn container_identity_and_event_staleness_handle_docker_short_ids() {
    assert!(container_ids_match(
        "0123456789abcdef",
        "sha256:0123456789abcdef0123456789abcdef"
    ));
    assert!(!container_ids_match("old-container", "new-container"));
    for (event, current, stale) in [
        (Some("old-container"), Some("new-container"), true),
        (
            Some("0123456789abcdef"),
            Some("sha256:0123456789abcdef0123456789abcdef"),
            false,
        ),
        (Some("destroyed-container"), None, false),
        (None, Some("current-container"), false),
    ] {
        assert_eq!(container_event_is_known_stale(event, current), stale);
    }
}

#[test]
fn shared_attestation_reuse_requires_exact_container_image_and_revision() {
    let mut runtime = runtime();
    for (container, image, expected) in [
        ("container-id", "sha256:image-id", true),
        ("replacement-id", "sha256:image-id", false),
        ("container-id", "sha256:new-image", false),
    ] {
        assert_eq!(
            compatibility::attestation_matches(&runtime, container, image),
            expected
        );
    }
    runtime.compatibility.as_mut().unwrap().probe_revision =
        COMPATIBILITY_PROBE_REVISION.saturating_add(1);
    assert!(!compatibility::attestation_matches(
        &runtime,
        "container-id",
        "sha256:image-id"
    ));
}

#[test]
fn docker_observation_maps_to_pool_status_without_tenant_identity() {
    for (docker, runtime) in [
        (DockerContainerStatus::Running, EngineRuntimeStatus::Running),
        (DockerContainerStatus::Created, EngineRuntimeStatus::Stopped),
        (
            DockerContainerStatus::Starting,
            EngineRuntimeStatus::Booting,
        ),
        (DockerContainerStatus::Failed, EngineRuntimeStatus::Failed),
    ] {
        assert_eq!(classify_runtime_status(docker), runtime);
    }
}

#[test]
fn aggregate_soft_disk_target_is_keyed_only_by_runtime_id() {
    let runtime = runtime();
    let target = SoftDiskTarget {
        instance_id: runtime.runtime_id.clone(),
        created_at: runtime.created_at.clone(),
        protocol: runtime.protocol,
        data_path: std::path::PathBuf::from("/var/lib/dbev/pool-postgres"),
        limit_bytes: mib_to_bytes(runtime.limits.disk_mib),
        durable_blocked: false,
    };
    assert!(shared_disk_target_is_current(&runtime, &target));

    let tenant_target = SoftDiskTarget {
        instance_id: "tenant-postgres".to_string(),
        ..target
    };
    assert!(!shared_disk_target_is_current(&runtime, &tenant_target));
}

fn runtime() -> EngineRuntime {
    let mut runtime = crate::server::placement::test_support::runtime(
        "pool-postgres",
        Protocol::Postgres,
        "postgres:18",
    );
    runtime.backend = BackendEndpoint::UnixSocket {
        socket_path: "/run/dbev/pool-postgres/postgres.sock".to_string(),
    };
    runtime.database_version = Some("18.4".to_string());
    runtime.compatibility = Some(RuntimeCompatibility {
        container_id: "container-id".to_string(),
        image_id: "sha256:image-id".to_string(),
        probe_revision: COMPATIBILITY_PROBE_REVISION,
    });

    runtime.max_tenants = 32;
    runtime.created_at = "2026-08-27T00:00:00Z".to_string();
    runtime.updated_at = runtime.created_at.clone();
    runtime
}
