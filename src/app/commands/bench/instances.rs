use anyhow::{Context, anyhow};
use serde::Deserialize;

use super::{args::BenchArgs, http::BenchClient, metrics::TargetInstanceReport};
use crate::{databases::protocol::Protocol, utils::ids::validate_instance_id};

pub(super) async fn select_explicit_instance(
    client: &BenchClient,
    args: &BenchArgs,
    instance_id: &str,
) -> anyhow::Result<SelectedBenchmarkInstance> {
    validate_instance_id(instance_id)
        .map_err(|error| anyhow!("invalid --bench-instance: {error}"))?;
    let instance = client
        .required_json(
            &format!("/api/instances/{instance_id}"),
            "instance preflight",
        )
        .await?;
    let protocol = instance["protocol"]
        .as_str()
        .ok_or_else(|| anyhow!("instance response did not contain protocol"))?
        .parse::<Protocol>()
        .context("instance response contained an unsupported protocol")?;
    let status = instance["status"]
        .as_str()
        .ok_or_else(|| anyhow!("instance response did not contain status"))?
        .to_string();
    let disk_mib = instance["limits"]["disk_mib"].as_u64();
    if args.bench_recommend_manual_active_jobs && disk_mib.is_none() {
        return Err(anyhow!(
            "manual active-job recommendation requires limits.disk_mib in the instance response"
        ));
    }
    if args.bench_import_export && status != "running" {
        return Err(anyhow!(
            "destructive import/export benchmark requires a running instance; {instance_id} is {status}"
        ));
    }
    Ok(SelectedBenchmarkInstance {
        instance_id: instance_id.to_string(),
        protocol,
        initial_status: status,
        disk_mib,
    })
}

pub(super) async fn select_random_instances(
    client: &BenchClient,
    args: &BenchArgs,
    benchmark_id: &str,
    warnings: &mut Vec<String>,
) -> anyhow::Result<Vec<SelectedBenchmarkInstance>> {
    let value = client
        .required_json("/api/instances", "instance discovery")
        .await?;
    let mut running = serde_json::from_value::<Vec<InstanceListEntry>>(value)
        .context("instance discovery response was not a valid instance list")?
        .into_iter()
        .filter(|instance| instance.status == "running")
        .map(|instance| SelectedBenchmarkInstance {
            instance_id: instance.instance_id,
            protocol: instance.protocol,
            initial_status: instance.status,
            disk_mib: None,
        })
        .collect::<Vec<_>>();
    if running.is_empty() {
        return Err(anyhow!(
            "--max_instances {} requested automatic selection, but the daemon has no running instances",
            args.bench_max_instances
        ));
    }
    shuffle_instances(&mut running, benchmark_seed(benchmark_id));
    if running.len() < args.bench_max_instances {
        warnings.push(format!(
            "--max_instances requested {}, but only {} running instances were available; all available instances were selected",
            args.bench_max_instances,
            running.len()
        ));
    }
    running.truncate(args.bench_max_instances);
    for instance in &running {
        validate_instance_id(&instance.instance_id).map_err(|error| {
            anyhow!(
                "daemon returned invalid instance ID {}: {error}",
                instance.instance_id
            )
        })?;
    }
    Ok(running)
}

#[derive(Debug, Deserialize)]
pub(super) struct InstanceListEntry {
    instance_id: String,
    protocol: Protocol,
    status: String,
}

#[derive(Debug)]
pub(super) struct SelectedBenchmarkInstance {
    pub(super) instance_id: String,
    pub(super) protocol: Protocol,
    pub(super) initial_status: String,
    pub(super) disk_mib: Option<u64>,
}

impl SelectedBenchmarkInstance {
    pub(super) fn report(&self) -> TargetInstanceReport {
        TargetInstanceReport {
            instance_id: self.instance_id.clone(),
            protocol: self.protocol.to_string(),
            initial_status: self.initial_status.clone(),
            final_status: None,
        }
    }
}

pub(super) fn benchmark_seed(benchmark_id: &str) -> u64 {
    uuid::Uuid::parse_str(benchmark_id)
        .map(|id| {
            let value = id.as_u128();
            (value as u64) ^ ((value >> 64) as u64)
        })
        .unwrap_or_else(|_| {
            benchmark_id
                .bytes()
                .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
                    (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
                })
        })
}

pub(super) fn shuffle_instances(instances: &mut [SelectedBenchmarkInstance], seed: u64) {
    let mut state = if seed == 0 {
        0x9e37_79b9_7f4a_7c15
    } else {
        seed
    };
    for index in (1..instances.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        instances.swap(index, state as usize % (index + 1));
    }
}
