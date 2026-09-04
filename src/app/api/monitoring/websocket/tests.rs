use super::*;
use crate::api::monitoring::{
    activity::ActivitySources,
    resources::{CpuReport, DiskReport, MemoryReport, NetworkReport},
};

fn activity(instance_id: &str) -> TenantActivity {
    TenantActivity {
        current: crate::monitoring::ActivityCurrent {
            instance_id: instance_id.to_string(),
            stats_epoch: "epoch-test".to_string(),
            sampled_at_unix: 1,
            accepted: crate::monitoring::OperationCounts::default(),
            operations_measured: false,
            rejected: crate::monitoring::OperationCounts::default(),
            active_connections: 0,
            opened_connections: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            cpu_time_micros: None,
            peak_query_memory_bytes: None,
        },
        sources: ActivitySources {
            connections: "gateway_authenticated_exact",
            network: "gateway_route_exact",
            operations: "gateway_protocol_observed",
            cpu_time: "unavailable",
            peak_query_memory: "unavailable",
        },
    }
}

fn monitoring_instance(
    instance_id: impl Into<String>,
    deployment_mode: crate::placement::DeploymentMode,
    cpu_usage_percent: Option<f64>,
) -> MonitoringInstance {
    let instance_id = instance_id.into();
    let shared = deployment_mode == crate::placement::DeploymentMode::Shared;
    let runtime_id = if shared {
        "mysql_pool_one".to_string()
    } else {
        instance_id.clone()
    };
    let scope = if shared {
        ResourceScope::SharedTenant
    } else {
        ResourceScope::DedicatedInstance
    };
    let resources = ResourceReport {
        instance_id: instance_id.clone(),
        runtime_id: runtime_id.clone(),
        deployment_mode,
        scope,
        protocol: "mysql".to_string(),
        status: "running".to_string(),
        cpu: CpuReport {
            configured_cores: 1.0,
            usage_percent: cpu_usage_percent,
        },
        memory: MemoryReport {
            configured_mib: 512,
            usage_bytes: (!shared).then_some(128),
            limit_bytes: (!shared).then_some(512 * 1024 * 1024),
        },
        disk: DiskReport {
            configured_mib: 1_024,
            limit_bytes: 1_024 * 1024 * 1024,
            used_bytes: 64,
            enforced: false,
            enforcement_method: "none".to_string(),
            enforcement_strength: "none",
            scanner_logical_bytes: None,
            scanner_physical_bytes: None,
            scanner_growth_bytes_per_second: None,
            scanner_peak_growth_bytes_per_second: None,
            scanner_predicted_seconds_to_limit: None,
            scanner_stop_threshold_bytes: None,
            scanner_recovery_threshold_bytes: None,
            scanner_restart_blocked: None,
            scanner_sample_age_seconds: None,
        },
        network: NetworkReport {
            rx_bytes: Some(0),
            tx_bytes: Some(0),
        },
        pool: None,
    };
    MonitoringInstance {
        instance_id: instance_id.clone(),
        instance_generation: "generation-a".to_string(),
        runtime_id,
        deployment_mode,
        resource_scope: scope,
        protocol: "mysql".to_string(),
        status: "running".to_string(),
        runtime: "docker",
        activity: activity(&instance_id),
        resources: Some(resources),
        resource_error: None,
    }
}

#[test]
fn monitoring_serializes_cpu_as_percentage_points_without_rescaling() {
    let instance = monitoring_instance(
        "inst_cpu",
        crate::placement::DeploymentMode::Dedicated,
        Some(11.0),
    );

    let json = serde_json::to_value(instance).unwrap();
    assert_eq!(
        json["resources"]["cpu"]["usage_percent"],
        serde_json::json!(11.0)
    );
    assert!(json.get("cpu_usage_percent").is_none());
}

#[test]
fn shared_monitoring_omits_physical_pool_capacity() {
    let instance =
        monitoring_instance("tenant_one", crate::placement::DeploymentMode::Shared, None);

    let json = serde_json::to_value(instance).unwrap();
    assert_eq!(
        json["resources"]["cpu"]["usage_percent"],
        serde_json::Value::Null
    );
    assert_eq!(
        json["resources"]["memory"]["limit_bytes"],
        serde_json::Value::Null
    );
    assert!(json["resources"].get("pool").is_none());
    assert!(json.get("cpu_limit_cores").is_none());
    assert_eq!(
        json["activity"]["sources"]["operations"],
        serde_json::json!("gateway_protocol_observed")
    );
}

#[test]
fn hundreds_of_instances_are_sent_as_bounded_ordered_batches() {
    let instances = (0..300)
        .map(|index| {
            monitoring_instance(
                format!("tenant-{index:04}"),
                crate::placement::DeploymentMode::Shared,
                None,
            )
        })
        .collect();
    let snapshot = MonitoringSnapshotData {
        instances,
        install_progress: Vec::new(),
    };
    let batches = snapshot
        .filtered(&InstanceAuthorization::All)
        .batches(42, 1_788_220_800)
        .unwrap();

    assert!(batches.len() > 1);
    assert_eq!(
        batches
            .iter()
            .map(|batch| batch.instances.len())
            .sum::<usize>(),
        300
    );
    let mut delivered = batches.iter().rev().collect::<Vec<_>>();
    delivered.sort_unstable_by_key(|batch| batch.batch_index);
    let reconstructed = delivered
        .into_iter()
        .flat_map(|batch| batch.instances.iter())
        .map(|instance| instance.instance_id.as_str())
        .collect::<Vec<_>>();
    let expected = (0..300)
        .map(|index| format!("tenant-{index:04}"))
        .collect::<Vec<_>>();
    assert_eq!(
        reconstructed,
        expected.iter().map(String::as_str).collect::<Vec<_>>()
    );
    for (index, batch) in batches.iter().enumerate() {
        assert_eq!(batch.sequence, 42);
        assert_eq!(batch.batch_index, index as u32);
        assert_eq!(batch.batch_count, batches.len() as u32);
        assert!(serde_json::to_vec(batch).unwrap().len() <= WEBSOCKET_MAX_MESSAGE_BYTES);
    }
}

#[test]
fn websocket_job_access_obeys_scoped_and_node_wide_claims() {
    let cases = [
        (
            "foreign job without query",
            vec!["inst_allowed"],
            false,
            "job-foreign",
            "inst_foreign",
            "inst_allowed",
            false,
            false,
        ),
        (
            "foreign job ID lookup",
            vec!["inst_allowed"],
            false,
            "job-foreign",
            "inst_foreign",
            "inst_allowed",
            true,
            false,
        ),
        (
            "own job event",
            vec!["inst_allowed"],
            false,
            "job-own",
            "inst_allowed",
            "inst_allowed",
            false,
            true,
        ),
        (
            "node-wide claim",
            Vec::new(),
            true,
            "job-any",
            "inst_any",
            "inst_any",
            false,
            true,
        ),
        (
            "empty scoped claim",
            Vec::new(),
            false,
            "job-any",
            "inst_any",
            "inst_any",
            false,
            false,
        ),
    ];

    for (name, instances, all_instances, job_id, job_instance, route_instance, query, expected) in
        cases
    {
        let mut claims = claims_for_instances(instances);
        claims.all_instances = all_instances;
        let job = sample_job(job_id, job_instance);
        let query = ImportExportQuery {
            job_id: query.then(|| job.job_id.clone()),
        };
        assert_eq!(
            job_matches_access(&job, route_instance, &query, &claims),
            expected,
            "access case failed: {name}"
        );
    }
}

fn claims_for_instances(instances: Vec<&str>) -> Claims {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let instances = instances
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let instance_generation_digest = (!instances.is_empty()).then(|| {
        jwt::instance_generation_digest(
            &instances
                .iter()
                .map(|instance_id| (instance_id.clone(), "generation-a".to_string()))
                .collect::<Vec<_>>(),
        )
    });
    Claims {
        iss: crate::constants::jwt::ISSUER.to_string(),
        aud: crate::constants::jwt::AUDIENCE.to_string(),
        sub: "test-user".to_string(),
        all_instances: false,
        instances,
        instance_generation_digest,
        scopes: vec![scopes::IMPORT_EXPORT_READ.to_string()],
        iat: now,
        nbf: now,
        exp: now + 60,
        jti: "test-jti".to_string(),
    }
}

#[test]
fn selected_authorization_is_bound_to_the_instance_generation() {
    let claims = claims_for_instances(vec!["tenant_one"]);
    let authorized = InstanceAuthorization::selected(
        &claims,
        vec![("tenant_one".to_string(), "generation-a".to_string())],
    )
    .unwrap();
    assert!(authorized.allows("tenant_one", "generation-a"));
    assert!(!authorized.allows("tenant_one", "generation-b"));

    let mut snapshot = MonitoringSnapshotData {
        instances: vec![
            monitoring_instance(
                "tenant_one",
                crate::placement::DeploymentMode::Dedicated,
                None,
            ),
            monitoring_instance(
                "tenant_unrelated",
                crate::placement::DeploymentMode::Dedicated,
                None,
            ),
        ],
        install_progress: Vec::new(),
    };
    assert_eq!(
        snapshot
            .filtered(&authorized)
            .instances
            .iter()
            .map(|instance| instance.instance_id.as_str())
            .collect::<Vec<_>>(),
        ["tenant_one"]
    );
    snapshot.instances[0].instance_generation = "generation-b".to_string();
    assert!(snapshot.filtered(&authorized).instances.is_empty());

    assert!(
        InstanceAuthorization::selected(
            &claims,
            vec![("tenant_one".to_string(), "generation-b".to_string())]
        )
        .is_err()
    );

    let mut legacy = claims;
    legacy.instance_generation_digest = None;
    assert!(
        InstanceAuthorization::selected(
            &legacy,
            vec![("tenant_one".to_string(), "generation-a".to_string())]
        )
        .is_err()
    );
}

#[tokio::test]
async fn selected_snapshot_candidates_exclude_unrelated_and_recreated_instances() {
    let instances = crate::instances::state::InstanceStore::default();
    instances
        .upsert(instance_metadata("allowed", "generation-a"))
        .await;
    instances
        .upsert(instance_metadata("unrelated", "generation-z"))
        .await;
    let authorization = InstanceAuthorization::Selected(HashMap::from([(
        "allowed".to_string(),
        "generation-a".to_string(),
    )]));

    let selected = authorization.metadata(&instances).await;
    assert_eq!(
        selected
            .iter()
            .map(|instance| instance.instance_id.as_str())
            .collect::<Vec<_>>(),
        ["allowed"]
    );
    let mut all = InstanceAuthorization::All
        .metadata(&instances)
        .await
        .into_iter()
        .map(|instance| instance.instance_id)
        .collect::<Vec<_>>();
    all.sort_unstable();
    assert_eq!(all, ["allowed", "unrelated"]);

    instances
        .upsert(instance_metadata("allowed", "generation-b"))
        .await;
    assert!(authorization.metadata(&instances).await.is_empty());
}

fn instance_metadata(instance_id: &str, generation: &str) -> InstanceMetadata {
    let mut metadata = crate::instances::test_support::metadata(
        instance_id,
        crate::shared::protocol::Protocol::Mysql,
    );
    metadata.backend = crate::shared::backend::BackendEndpoint::UnixSocket {
        socket_path: format!("/tmp/{instance_id}.sock"),
    };
    metadata.runtime.container_name = instance_id.to_string();
    metadata.database.name = instance_id.to_string();
    metadata.database.username = instance_id.to_string();
    metadata.created_at = generation.to_string();
    metadata.updated_at = generation.to_string();
    metadata
}

fn sample_job(job_id: &str, instance_id: &str) -> ImportExportJob {
    ImportExportJob {
        job_id: job_id.to_string(),
        instance_id: instance_id.to_string(),
        action: ImportExportAction::Export,
        status: ImportExportStatus::Succeeded,
        artifact_path: Some(format!("/tmp/{instance_id}.sql")),
        replay_options: None,
        error: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    }
}
