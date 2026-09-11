use super::*;

use crate::instances::test_support::shared_metadata;

#[test]
fn runtime_identity_errors_identify_each_field_without_reassigning_ownership() {
    for field in [
        "none",
        "runtime_deployment_mode",
        "protocol",
        "runtime_id",
        "tenant_owner_missing",
        "runtime_owner_missing",
        "owner",
        "both_owners_missing",
    ] {
        let mut metadata = crate::instances::test_support::metadata("tenant-a", Protocol::Postgres);
        let mut runtime =
            crate::placement::test_support::runtime("pool-a", Protocol::Postgres, "postgres:18.4");
        metadata.deployment_mode = DeploymentMode::Shared;
        metadata.runtime_id = runtime.runtime_id.clone();
        metadata.owner = runtime.owner.clone();
        match field {
            "none" => {}
            "runtime_deployment_mode" => runtime.deployment_mode = DeploymentMode::Dedicated,
            "protocol" => runtime.protocol = Protocol::Clickhouse,
            "runtime_id" => runtime.runtime_id = "another-pool".into(),
            "tenant_owner_missing" => metadata.owner = None,
            "runtime_owner_missing" => runtime.owner = None,
            "owner" => runtime.owner.as_mut().unwrap().server_id = "private-other-server".into(),
            "both_owners_missing" => {
                metadata.owner = None;
                runtime.owner = None;
            }
            _ => unreachable!(),
        }
        let original_owner = metadata.owner.clone();
        let original_runtime_owner = runtime.owner.clone();
        let result = check_runtime_identity(&metadata, &runtime);
        if field == "none" {
            assert!(result.is_ok());
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.status(), http::StatusCode::CONFLICT);
            let message = error.to_string();
            if field == "both_owners_missing" {
                assert!(message.contains("tenant_owner_missing"));
                assert!(message.contains("runtime_owner_missing"));
            } else {
                assert!(message.contains(field), "{message}");
            }
            assert!(!message.contains("private-other-server"));
        }
        assert_eq!(metadata.owner, original_owner);
        assert_eq!(runtime.owner, original_runtime_owner);
    }
}

#[test]
fn destructive_shared_states_cannot_be_cleared_by_power_actions() {
    for status in [InstanceStatus::Quarantined, InstanceStatus::Deleting] {
        let mut metadata = shared_metadata();
        metadata.status = status;
        metadata.desired_state = DesiredInstanceState::Stopped;
        assert!(check_power_state(&metadata).is_err());
    }
}

#[test]
fn only_an_eligible_unfenced_route_is_restored_after_mutation() {
    let mut metadata = shared_metadata();
    assert!(route_was_open(&metadata, false));
    assert!(!route_was_open(&metadata, true));

    metadata.disk_limit_blocked = true;
    assert!(!route_was_open(&metadata, false));
    metadata.disk_limit_blocked = false;
    metadata.desired_state = DesiredInstanceState::Stopped;
    assert!(!route_was_open(&metadata, false));
    metadata.desired_state = DesiredInstanceState::Running;
    metadata.status = InstanceStatus::Failed;
    assert!(!route_was_open(&metadata, false));
}

#[test]
fn shared_logs_are_fail_closed() {
    assert!(reject_logs().to_string().contains("pool-wide"));
}

#[test]
fn resize_commit_matching_checks_every_reserved_limit() {
    let expected = InstanceLimits::default();
    let mut changed = expected.clone();
    assert!(limits_match(&expected, &changed));
    changed.disk_mib += 1;
    assert!(!limits_match(&expected, &changed));
    changed = expected.clone();
    changed.disk_enforcement_method = "shared_pool_reservation".to_string();
    assert!(!limits_match(&expected, &changed));
}

#[test]
fn post_runtime_lock_state_keeps_new_quota_blocks_for_repair() {
    let stale = shared_metadata();
    let mut current = stale.clone();
    current.disk_limit_blocked = true;

    assert!(same_shared_identity(&stale, &current));
    assert!(check_power_state(&stale).is_ok());
    // Start is admitted far enough to reapply a hard boundary. If the
    // result is still soft, the locked usage check rejects it later.
    assert!(check_power_state(&current).is_ok());

    current.runtime_id = "pool-b".to_string();
    assert!(!same_shared_identity(&stale, &current));
}

#[test]
fn hard_disk_state_clears_a_legacy_soft_block() {
    let mut metadata = shared_metadata();
    metadata.disk_limit_blocked = true;
    let enforcement = DiskEnforcement {
        enforced: true,
        method: "host_xfs_project_quota".to_string(),
        container_data_path: None,
    };

    assert!(
        tenant::disk::update_state(
            &mut metadata.limits,
            &mut metadata.disk_limit_blocked,
            &enforcement,
        )
        .unwrap()
    );
    assert!(metadata.limits.disk_enforced);
    assert_eq!(
        metadata.limits.disk_enforcement_method,
        "host_xfs_project_quota"
    );
    assert!(!metadata.disk_limit_blocked);
}

#[test]
fn existing_hard_disk_state_cannot_silently_downgrade() {
    let mut metadata = shared_metadata();
    metadata.limits.disk_enforced = true;
    metadata.limits.disk_enforcement_method = "host_xfs_project_quota".to_string();
    let soft = DiskEnforcement {
        enforced: false,
        method: "shared_catalog_guard".to_string(),
        container_data_path: None,
    };

    assert!(
        tenant::disk::update_state(
            &mut metadata.limits,
            &mut metadata.disk_limit_blocked,
            &soft,
        )
        .is_err()
    );
    assert!(metadata.limits.disk_enforced);
    assert_eq!(
        metadata.limits.disk_enforcement_method,
        "host_xfs_project_quota"
    );
}

#[test]
fn status_reconcile_never_reopens_unsafe_tenant_state() {
    for current in [InstanceStatus::Quarantined, InstanceStatus::Deleting] {
        assert_eq!(
            reconciled_tenant_status(
                current,
                DesiredInstanceState::Running,
                EngineRuntimeStatus::Running,
                DockerContainerStatus::Running,
                false,
            ),
            current
        );
    }
    assert_eq!(
        reconciled_tenant_status(
            InstanceStatus::Failed,
            DesiredInstanceState::Running,
            EngineRuntimeStatus::Running,
            DockerContainerStatus::Running,
            false,
        ),
        InstanceStatus::Failed
    );
}

#[test]
fn status_reconcile_only_keeps_an_already_open_tenant_running() {
    assert_eq!(
        reconciled_tenant_status(
            InstanceStatus::Running,
            DesiredInstanceState::Running,
            EngineRuntimeStatus::Running,
            DockerContainerStatus::Running,
            false,
        ),
        InstanceStatus::Running
    );
    assert_eq!(
        reconciled_tenant_status(
            InstanceStatus::Running,
            DesiredInstanceState::Running,
            EngineRuntimeStatus::Failed,
            DockerContainerStatus::Running,
            false,
        ),
        InstanceStatus::Failed
    );
}

#[test]
fn status_reconcile_does_not_republish_an_intentionally_fenced_route() {
    assert_eq!(
        reconciled_tenant_status(
            InstanceStatus::Running,
            DesiredInstanceState::Running,
            EngineRuntimeStatus::Running,
            DockerContainerStatus::Running,
            true,
        ),
        InstanceStatus::Failed
    );
    assert_eq!(
        reconciled_tenant_status(
            InstanceStatus::Running,
            DesiredInstanceState::Stopped,
            EngineRuntimeStatus::Running,
            DockerContainerStatus::Running,
            true,
        ),
        InstanceStatus::Stopped
    );
}
