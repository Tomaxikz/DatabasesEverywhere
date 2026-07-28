use std::{
    collections::HashMap,
    path::Path,
    time::{Duration, Instant},
};

use bollard::models::{ContainerCpuStats, ContainerStatsResponse};
use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{MissedTickBehavior, timeout},
};

use crate::{runtime::docker::DockerRuntime, shared::protocol::Protocol};

use super::metrics::{ResourceSample, ResourceSummary};

const INSTANCE_STATS_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone)]
pub struct InstanceSampleTarget {
    pub instance_id: String,
    pub protocol: Protocol,
}

#[derive(Debug, Clone)]
struct SamplerControl {
    phase: String,
    stop: bool,
}

struct SamplerOutput {
    samples: Vec<ResourceSample>,
    failed_instance_samples: usize,
}

pub struct ResourceSampler {
    control: watch::Sender<SamplerControl>,
    task: JoinHandle<SamplerOutput>,
    daemon_pid: Option<u32>,
    benchmark_pid: u32,
    instance_sampling_enabled: bool,
}

impl ResourceSampler {
    pub fn start(
        locks_root: &str,
        interval: Duration,
        docker: Option<DockerRuntime>,
        instances: Vec<InstanceSampleTarget>,
    ) -> (Self, Vec<String>) {
        let benchmark_pid = std::process::id();
        let (daemon_pid, mut warnings) = read_daemon_pid(locks_root);
        if daemon_pid == Some(benchmark_pid) {
            warnings.push(
                "daemon lock points at the benchmark process; daemon resource sampling disabled"
                    .to_string(),
            );
        }
        let daemon_pid = daemon_pid.filter(|pid| *pid != benchmark_pid);
        let instance_sampling_enabled = docker.is_some() && !instances.is_empty();
        if !instances.is_empty() && docker.is_none() {
            warnings.push(
                "container runtime was unavailable; selected instance CPU/RAM sampling is disabled"
                    .to_string(),
            );
        }
        let (control, receiver) = watch::channel(SamplerControl {
            phase: "preflight".to_string(),
            stop: false,
        });
        let task = tokio::spawn(run_sampler(
            receiver,
            interval,
            daemon_pid,
            benchmark_pid,
            docker,
            instances,
        ));
        (
            Self {
                control,
                task,
                daemon_pid,
                benchmark_pid,
                instance_sampling_enabled,
            },
            warnings,
        )
    }

    pub fn set_phase(&self, phase: impl Into<String>) {
        self.control
            .send_modify(|control| control.phase = phase.into());
    }

    pub async fn finish(self) -> (ResourceSummary, Vec<ResourceSample>, Vec<String>) {
        self.control.send_modify(|control| control.stop = true);
        match self.task.await {
            Ok(output) => {
                let summary = ResourceSummary::from_samples(
                    &output.samples,
                    self.daemon_pid,
                    self.benchmark_pid,
                    self.instance_sampling_enabled,
                    output.failed_instance_samples,
                );
                (summary, output.samples, Vec::new())
            }
            Err(error) => {
                let samples = Vec::new();
                (
                    ResourceSummary::from_samples(
                        &samples,
                        self.daemon_pid,
                        self.benchmark_pid,
                        self.instance_sampling_enabled,
                        0,
                    ),
                    samples,
                    vec![format!("resource sampler task failed: {error}")],
                )
            }
        }
    }
}

async fn run_sampler(
    mut control: watch::Receiver<SamplerControl>,
    interval: Duration,
    daemon_pid: Option<u32>,
    benchmark_pid: u32,
    docker: Option<DockerRuntime>,
    instances: Vec<InstanceSampleTarget>,
) -> SamplerOutput {
    let started = Instant::now();
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut previous_process = HashMap::<u32, ProcessCounter>::new();
    let mut previous_container = HashMap::<String, ContainerCpuCounter>::new();
    let mut samples = Vec::new();
    let mut failed_instance_samples = 0_usize;
    let mut instance_cursor = 0_usize;

    loop {
        tokio::select! {
            changed = control.changed() => {
                if changed.is_err() || control.borrow().stop {
                    break;
                }
            }
            _ = ticker.tick() => {
                let phase = control.borrow().phase.clone();
                let host = read_host_cpu_counter();
                let daemon = daemon_pid.and_then(|pid| {
                    sample_process(pid, host, &mut previous_process)
                });
                let benchmark = sample_process(benchmark_pid, host, &mut previous_process);
                let mut instance_id = None;
                let mut instance_protocol = None;
                let mut instance_sample_failed = false;
                let mut instance_cpu_percent = None;
                let mut instance_memory_bytes = None;
                if let (Some(docker), Some(instance)) = (
                    &docker,
                    (!instances.is_empty()).then(|| {
                        let instance = &instances[instance_cursor % instances.len()];
                        instance_cursor = instance_cursor.wrapping_add(1);
                        instance
                    }),
                ) {
                    instance_id = Some(instance.instance_id.clone());
                    instance_protocol = Some(instance.protocol.to_string());
                    match timeout(
                        INSTANCE_STATS_TIMEOUT,
                        docker.stats(instance.protocol, &instance.instance_id),
                    )
                        .await
                    {
                        Ok(Ok(stats)) => {
                            instance_cpu_percent = sample_container_cpu(
                                &instance.instance_id,
                                &stats,
                                &mut previous_container,
                            );
                            instance_memory_bytes = memory_usage_bytes(&stats);
                        }
                        Ok(Err(_)) | Err(_) => {
                            failed_instance_samples += 1;
                            instance_sample_failed = true;
                        }
                    }
                }
                samples.push(ResourceSample {
                    elapsed_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                    phase,
                    daemon_cpu_percent: daemon.and_then(|sample| sample.cpu_percent),
                    daemon_rss_bytes: daemon.and_then(|sample| sample.rss_bytes),
                    benchmark_cpu_percent: benchmark.and_then(|sample| sample.cpu_percent),
                    benchmark_rss_bytes: benchmark.and_then(|sample| sample.rss_bytes),
                    instance_id,
                    instance_protocol,
                    instance_sample_failed,
                    instance_cpu_percent,
                    instance_memory_bytes,
                });
            }
        }
    }
    SamplerOutput {
        samples,
        failed_instance_samples,
    }
}

#[derive(Debug, Clone, Copy)]
struct HostCpuCounter {
    total_ticks: u64,
    logical_cpus: u64,
}

#[derive(Debug, Clone, Copy)]
struct ProcessCounter {
    process_ticks: u64,
    host_ticks: u64,
}

#[derive(Debug, Clone, Copy)]
struct ProcessSample {
    cpu_percent: Option<f64>,
    rss_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct ContainerCpuCounter {
    total_usage: u64,
    system_usage: u64,
    online_cpus: u64,
}

fn sample_process(
    pid: u32,
    host: Option<HostCpuCounter>,
    previous: &mut HashMap<u32, ProcessCounter>,
) -> Option<ProcessSample> {
    let process_ticks = read_process_ticks(pid)?;
    let rss_bytes = read_process_rss(pid);
    let cpu_percent = host.and_then(|host| {
        let current = ProcessCounter {
            process_ticks,
            host_ticks: host.total_ticks,
        };
        let value = previous.get(&pid).and_then(|previous| {
            let process_delta = current.process_ticks.checked_sub(previous.process_ticks)?;
            let host_delta = current.host_ticks.checked_sub(previous.host_ticks)?;
            if host_delta == 0 {
                return None;
            }
            Some(process_delta as f64 / host_delta as f64 * host.logical_cpus.max(1) as f64 * 100.0)
        });
        previous.insert(pid, current);
        value
    });
    Some(ProcessSample {
        cpu_percent,
        rss_bytes,
    })
}

fn read_daemon_pid(locks_root: &str) -> (Option<u32>, Vec<String>) {
    let path = Path::new(locks_root).join("daemon.lock");
    match std::fs::read_to_string(&path) {
        Ok(value) => match value.trim().parse::<u32>() {
            Ok(pid) => (Some(pid), Vec::new()),
            Err(error) => (
                None,
                vec![format!(
                    "could not parse daemon PID from {}: {error}",
                    path.display()
                )],
            ),
        },
        Err(error) => (
            None,
            vec![format!(
                "could not read daemon PID from {}: {error}",
                path.display()
            )],
        ),
    }
}

#[cfg(target_os = "linux")]
fn read_host_cpu_counter() -> Option<HostCpuCounter> {
    let contents = std::fs::read_to_string("/proc/stat").ok()?;
    parse_host_cpu_counter(&contents)
}

#[cfg(not(target_os = "linux"))]
fn read_host_cpu_counter() -> Option<HostCpuCounter> {
    None
}

#[cfg(any(target_os = "linux", test))]
fn parse_host_cpu_counter(contents: &str) -> Option<HostCpuCounter> {
    let mut lines = contents.lines();
    let aggregate = lines.next()?;
    let mut fields = aggregate.split_whitespace();
    if fields.next()? != "cpu" {
        return None;
    }
    // Linux reports guest and guest_nice inside user and nice already. Only the
    // first eight counters belong in the denominator or guest time is counted
    // twice and process CPU is understated.
    let total_ticks = fields.take(8).try_fold(0_u64, |total, field| {
        field
            .parse::<u64>()
            .ok()
            .and_then(|value| total.checked_add(value))
    })?;
    let logical_cpus = contents
        .lines()
        .filter(|line| {
            line.strip_prefix("cpu")
                .is_some_and(|rest| rest.as_bytes().first().is_some_and(u8::is_ascii_digit))
        })
        .count() as u64;
    Some(HostCpuCounter {
        total_ticks,
        logical_cpus: logical_cpus.max(1),
    })
}

#[cfg(target_os = "linux")]
fn read_process_ticks(pid: u32) -> Option<u64> {
    let contents = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_process_ticks(&contents)
}

#[cfg(not(target_os = "linux"))]
fn read_process_ticks(_pid: u32) -> Option<u64> {
    None
}

#[cfg(any(target_os = "linux", test))]
fn parse_process_ticks(contents: &str) -> Option<u64> {
    let command_end = contents.rfind(')')?;
    let fields = contents
        .get(command_end + 1..)?
        .split_whitespace()
        .collect::<Vec<_>>();
    let user_ticks = fields.get(11)?.parse::<u64>().ok()?;
    let system_ticks = fields.get(12)?.parse::<u64>().ok()?;
    user_ticks.checked_add(system_ticks)
}

#[cfg(target_os = "linux")]
fn read_process_rss(pid: u32) -> Option<u64> {
    let contents = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_process_rss(&contents)
}

#[cfg(not(target_os = "linux"))]
fn read_process_rss(_pid: u32) -> Option<u64> {
    None
}

#[cfg(any(target_os = "linux", test))]
fn parse_process_rss(contents: &str) -> Option<u64> {
    let line = contents.lines().find(|line| line.starts_with("VmRSS:"))?;
    let kibibytes = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    kibibytes.checked_mul(1024)
}

fn cpu_percent(stats: &ContainerStatsResponse) -> Option<f64> {
    let current = container_cpu_counter(stats.cpu_stats.as_ref())?;
    let previous = container_cpu_counter(stats.precpu_stats.as_ref())?;
    container_cpu_percent(current, previous)
}

fn sample_container_cpu(
    instance_id: &str,
    stats: &ContainerStatsResponse,
    previous: &mut HashMap<String, ContainerCpuCounter>,
) -> Option<f64> {
    let current = container_cpu_counter(stats.cpu_stats.as_ref())?;
    let percent = previous
        .get(instance_id)
        .copied()
        .and_then(|previous| container_cpu_percent(current, previous))
        .or_else(|| cpu_percent(stats));
    previous.insert(instance_id.to_string(), current);
    percent
}

fn container_cpu_counter(stats: Option<&ContainerCpuStats>) -> Option<ContainerCpuCounter> {
    let stats = stats?;
    Some(ContainerCpuCounter {
        total_usage: stats.cpu_usage.as_ref()?.total_usage?,
        system_usage: stats.system_cpu_usage?,
        online_cpus: u64::from(stats.online_cpus.unwrap_or(1)).max(1),
    })
}

fn container_cpu_percent(
    current: ContainerCpuCounter,
    previous: ContainerCpuCounter,
) -> Option<f64> {
    let cpu_delta = current.total_usage.checked_sub(previous.total_usage)?;
    let system_delta = current.system_usage.checked_sub(previous.system_usage)?;
    if system_delta == 0 {
        return None;
    }
    Some(cpu_delta as f64 / system_delta as f64 * current.online_cpus as f64 * 100.0)
}

fn memory_usage_bytes(stats: &ContainerStatsResponse) -> Option<u64> {
    stats.memory_stats.as_ref()?.usage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_process_ticks_after_parenthesized_command() {
        let stat = "42 (dbev worker) S 1 2 3 4 5 6 7 8 9 10 120 30 0 0";

        assert_eq!(parse_process_ticks(stat), Some(150));
    }

    #[test]
    fn parses_host_ticks_and_cpu_count() {
        let stat = "cpu  1 2 3 4 5 6 7 8 9 10\ncpu0 1 2\ncpu1 1 2\nintr 0\n";
        let parsed = parse_host_cpu_counter(stat).unwrap();

        assert_eq!(parsed.total_ticks, 36);
        assert_eq!(parsed.logical_cpus, 2);
    }

    #[test]
    fn parses_resident_memory_in_bytes() {
        assert_eq!(
            parse_process_rss("Name:\tdbev\nVmRSS:\t  2048 kB\n"),
            Some(2_097_152)
        );
    }

    #[test]
    fn parses_container_cpu_and_memory_counters() {
        let stats = serde_json::from_value::<ContainerStatsResponse>(serde_json::json!({
            "cpu_stats": {
                "cpu_usage": { "total_usage": 150 },
                "system_cpu_usage": 1_100,
                "online_cpus": 4
            },
            "precpu_stats": {
                "cpu_usage": { "total_usage": 100 },
                "system_cpu_usage": 1_000
            },
            "memory_stats": { "usage": 4096 }
        }))
        .unwrap();

        assert_eq!(cpu_percent(&stats), Some(200.0));
        assert_eq!(memory_usage_bytes(&stats), Some(4096));
    }

    #[test]
    fn computes_container_cpu_across_one_shot_samples_without_precpu_stats() {
        let first = serde_json::from_value::<ContainerStatsResponse>(serde_json::json!({
            "cpu_stats": {
                "cpu_usage": { "total_usage": 100 },
                "system_cpu_usage": 1_000,
                "online_cpus": 4
            }
        }))
        .unwrap();
        let second = serde_json::from_value::<ContainerStatsResponse>(serde_json::json!({
            "cpu_stats": {
                "cpu_usage": { "total_usage": 150 },
                "system_cpu_usage": 1_100,
                "online_cpus": 4
            }
        }))
        .unwrap();
        let mut previous = HashMap::new();

        assert_eq!(
            sample_container_cpu("instance-one", &first, &mut previous),
            None
        );
        assert_eq!(
            sample_container_cpu("instance-one", &second, &mut previous),
            Some(200.0)
        );
    }
}
