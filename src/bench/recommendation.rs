use anyhow::Context;
use serde::Deserialize;

use crate::{config::Config, shared::protocol::Protocol};

use super::{
    http::BenchClient,
    metrics::{
        JobBenchmarkReport, ManualActiveJobsRecommendationReport, ManualActiveJobsWorkloadReport,
        SchedulerCapacityReport, SchedulerJobCostReport,
    },
};

const METHOD: &str = "model_based_single_job_v1";
const ENDPOINT: &str = "/api/system/import-export-scheduler/recommendation";

#[derive(Debug, Deserialize)]
struct SchedulerRecommendationWire {
    scheduler: SchedulerSnapshotWire,
    estimate: SchedulerJobCostReport,
    recommended_active_jobs: usize,
    max_queued_jobs: usize,
    max_queued_jobs_per_instance: usize,
}

#[derive(Debug, Deserialize)]
struct SchedulerSnapshotWire {
    capacity: SchedulerCapacityReport,
}

pub(super) async fn build_manual_active_jobs_recommendation(
    client: &BenchClient,
    config: &Config,
    system: &serde_json::Value,
    protocol: Protocol,
    target_disk_mib: Option<u64>,
    jobs: &[JobBenchmarkReport],
) -> ManualActiveJobsRecommendationReport {
    let server_node_uuid = system["uuid"].as_str().map(str::to_string);
    let mut report = ManualActiveJobsRecommendationReport {
        method: METHOD.to_string(),
        status: "unavailable".to_string(),
        unavailable_reason: None,
        identity_verified: false,
        configured_node_uuid: config.uuid.clone(),
        server_node_uuid,
        scheduler_capacity: None,
        max_queued_jobs: None,
        max_queued_jobs_per_instance: None,
        configured_max_upload_worst_case: None,
        representative_exported_dump: None,
        representative_unavailable_reason: None,
        caveats: vec![
            "This is a conservative resource-cost model from one benchmark instance, not an empirical concurrent saturation test."
                .to_string(),
            "The result applies to this daemon identity, scheduler budgets, protocol, target disk allocation, and dump-size assumptions."
                .to_string(),
            "Dynamic mode remains safer for mixed dump sizes because a single manual ceiling cannot weight large and small jobs differently."
                .to_string(),
            "A recommendation of 0 means no job is safe under current live capacity; it is a blocked-headroom signal, not a valid manual configuration value."
                .to_string(),
            "CPU and I/O are concurrency weights, so a raw zero ratio may still recommend one isolated job when its memory estimate fits."
                .to_string(),
        ],
    };

    if let Err(reason) = verify_benchmark_daemon_identity(config, system) {
        report.unavailable_reason = Some(reason);
        return report;
    }
    report.identity_verified = true;

    let Some(target_disk_mib) = target_disk_mib else {
        report.unavailable_reason =
            Some("target instance response did not include limits.disk_mib".to_string());
        return report;
    };
    let protocol_name = protocol.as_str();
    let worst_case_path = format!(
        "{ENDPOINT}?protocol={protocol_name}&action=import&target_disk_mib={target_disk_mib}&mode=wipe&compressed=true"
    );
    let worst_case = match request_scheduler_recommendation(
        client,
        &worst_case_path,
        "scheduler configured-maximum recommendation",
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            report.unavailable_reason = Some(error.to_string());
            return report;
        }
    };
    let worst_recommended = mode_independent_recommendation(&worst_case);
    report.scheduler_capacity = Some(worst_case.scheduler.capacity.clone());
    report.max_queued_jobs = Some(worst_case.max_queued_jobs);
    report.max_queued_jobs_per_instance = Some(worst_case.max_queued_jobs_per_instance);
    report.configured_max_upload_worst_case = Some(workload_recommendation(
        "configured_max_upload_worst_case",
        protocol_name,
        "wipe",
        true,
        &worst_case,
        worst_recommended,
    ));
    report.status = "available".to_string();

    let representative_size = jobs
        .iter()
        .find(|job| job.action == "export" && job.status == "succeeded")
        .and_then(|job| job.artifact_size_bytes);
    let Some(representative_size) = representative_size.filter(|size| *size > 0) else {
        report.representative_unavailable_reason =
            Some("the benchmark export did not produce a non-empty artifact size".to_string());
        return report;
    };
    let representative_mode = if representative_import_replaces_data(protocol) {
        "wipe"
    } else {
        "merge"
    };
    let representative_compressed = native_export_is_compressed(protocol);
    let representative_path = format!(
        "{ENDPOINT}?protocol={protocol_name}&action=import&size_bytes={representative_size}&target_disk_mib={target_disk_mib}&mode={representative_mode}&compressed={representative_compressed}"
    );
    match request_scheduler_recommendation(
        client,
        &representative_path,
        "scheduler representative-dump recommendation",
    )
    .await
    {
        Ok(response) => {
            let recommended = mode_independent_recommendation(&response);
            report.representative_exported_dump = Some(workload_recommendation(
                "representative_exported_dump",
                protocol_name,
                representative_mode,
                representative_compressed,
                &response,
                recommended,
            ));
        }
        Err(error) => report.representative_unavailable_reason = Some(error.to_string()),
    }
    report
}

fn verify_benchmark_daemon_identity(
    config: &Config,
    system: &serde_json::Value,
) -> Result<(), String> {
    let server_uuid = system["uuid"]
        .as_str()
        .ok_or_else(|| "system response did not contain the daemon UUID".to_string())?;
    if server_uuid != config.uuid {
        return Err(format!(
            "benchmark config UUID {} does not match target daemon UUID {server_uuid}; refusing to infer a local configuration limit for another daemon",
            config.uuid
        ));
    }
    let server_token_id = system["token_id"]
        .as_str()
        .ok_or_else(|| "system response did not contain the daemon token_id".to_string())?;
    if server_token_id != config.token_id {
        return Err(
            "benchmark config token_id does not match the target daemon; refusing to infer a configuration limit"
                .to_string(),
        );
    }
    Ok(())
}

async fn request_scheduler_recommendation(
    client: &BenchClient,
    path: &str,
    phase: &str,
) -> anyhow::Result<SchedulerRecommendationWire> {
    let value = client.required_json(path, phase).await?;
    serde_json::from_value(value)
        .with_context(|| format!("{phase} response did not match the scheduler contract"))
}

fn mode_independent_recommendation(response: &SchedulerRecommendationWire) -> usize {
    response.recommended_active_jobs
}

fn workload_recommendation(
    workload: &str,
    protocol: &str,
    mode: &str,
    compressed: bool,
    response: &SchedulerRecommendationWire,
    recommended: usize,
) -> ManualActiveJobsWorkloadReport {
    let capacity = &response.scheduler.capacity;
    ManualActiveJobsWorkloadReport {
        workload: workload.to_string(),
        protocol: protocol.to_string(),
        mode: mode.to_string(),
        compressed,
        estimate: response.estimate.clone(),
        memory_ceiling_jobs: resource_ratio(
            capacity.memory_budget_mib,
            response.estimate.memory_mib,
        ),
        io_ceiling_jobs: resource_ratio(capacity.io_budget_mib, response.estimate.io_mib),
        cpu_ceiling_jobs: capacity.cpu_units / response.estimate.cpu_units.max(1),
        configured_active_ceiling_jobs: capacity.max_active_jobs,
        recommended_manual_max_active_jobs: recommended,
    }
}

fn resource_ratio(total: u64, per_job: u64) -> usize {
    usize::try_from(total / per_job.max(1)).unwrap_or(usize::MAX)
}

fn native_export_is_compressed(protocol: Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Mongodb | Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
    )
}

fn representative_import_replaces_data(protocol: Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recommendation_identity_requires_both_uuid_and_token_id() {
        let config = Config {
            uuid: "node-one".to_string(),
            token_id: "token-one".to_string(),
            ..Config::default()
        };
        let matching = serde_json::json!({
            "uuid": "node-one",
            "token_id": "token-one"
        });
        assert!(verify_benchmark_daemon_identity(&config, &matching).is_ok());

        let wrong_node = serde_json::json!({
            "uuid": "node-two",
            "token_id": "token-one"
        });
        assert!(
            verify_benchmark_daemon_identity(&config, &wrong_node)
                .unwrap_err()
                .contains("does not match")
        );
        let wrong_token = serde_json::json!({
            "uuid": "node-one",
            "token_id": "token-two"
        });
        assert!(
            verify_benchmark_daemon_identity(&config, &wrong_token)
                .unwrap_err()
                .contains("token_id")
        );
    }

    #[test]
    fn workload_report_exposes_each_model_ceiling() {
        let response = SchedulerRecommendationWire {
            scheduler: SchedulerSnapshotWire {
                capacity: SchedulerCapacityReport {
                    mode: "dynamic".to_string(),
                    max_active_jobs: 64,
                    memory_budget_mib: 8_192,
                    io_budget_mib: 16_384,
                    cpu_units: 32,
                },
            },
            estimate: SchedulerJobCostReport {
                input_size_bytes: 4 * 1024 * 1024 * 1024,
                memory_mib: 512,
                io_mib: 4_096,
                cpu_units: 4,
            },
            recommended_active_jobs: 4,
            max_queued_jobs: 4_096,
            max_queued_jobs_per_instance: 64,
        };

        let report = workload_recommendation(
            "representative_exported_dump",
            "mongodb",
            "merge",
            true,
            &response,
            mode_independent_recommendation(&response),
        );

        assert_eq!(report.memory_ceiling_jobs, 16);
        assert_eq!(report.io_ceiling_jobs, 4);
        assert_eq!(report.cpu_ceiling_jobs, 8);
        assert_eq!(report.recommended_manual_max_active_jobs, 4);
    }

    #[test]
    fn blocked_headroom_preserves_zero_raw_and_recommended_ceilings() {
        let response = SchedulerRecommendationWire {
            scheduler: SchedulerSnapshotWire {
                capacity: SchedulerCapacityReport {
                    mode: "dynamic".to_string(),
                    max_active_jobs: 256,
                    memory_budget_mib: 128,
                    io_budget_mib: 256,
                    cpu_units: 1,
                },
            },
            estimate: SchedulerJobCostReport {
                input_size_bytes: 8 * 1024 * 1024 * 1024,
                memory_mib: 640,
                io_mib: 32_768,
                cpu_units: 4,
            },
            recommended_active_jobs: 0,
            max_queued_jobs: 4_096,
            max_queued_jobs_per_instance: 64,
        };

        let report = workload_recommendation(
            "configured_max_upload_worst_case",
            "mongodb",
            "wipe",
            true,
            &response,
            mode_independent_recommendation(&response),
        );
        assert_eq!(report.memory_ceiling_jobs, 0);
        assert_eq!(report.io_ceiling_jobs, 0);
        assert_eq!(report.cpu_ceiling_jobs, 0);
        assert_eq!(report.recommended_manual_max_active_jobs, 0);
    }
}
