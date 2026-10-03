use std::fmt::Write as _;

use crate::commands::bench::metrics::{RequestSample, ResourceSample};

pub(super) fn request_samples_csv(samples: &[RequestSample]) -> String {
    let mut output =
        "phase,target,index,duration_micros,duration_ms,status_code,success,error\n".to_string();
    for sample in samples {
        let _ = writeln!(
            output,
            "{},{},{},{},{:.3},{},{},{}",
            csv_field(&sample.phase),
            csv_field(&sample.target),
            sample.index,
            sample.duration_micros,
            sample.duration_micros as f64 / 1_000.0,
            sample
                .status_code
                .map(|status| status.to_string())
                .unwrap_or_default(),
            sample.success,
            csv_field(sample.error.as_deref().unwrap_or_default())
        );
    }
    output
}

pub(super) fn resource_samples_csv(samples: &[ResourceSample]) -> String {
    let mut output = "elapsed_ms,phase,daemon_cpu_percent,daemon_rss_bytes,benchmark_cpu_percent,benchmark_rss_bytes,instance_id,instance_protocol,instance_sample_failed,instance_cpu_percent,instance_memory_bytes\n".to_string();
    for sample in samples {
        let _ = writeln!(
            output,
            "{},{},{},{},{},{},{},{},{},{},{}",
            sample.elapsed_ms,
            csv_field(&sample.phase),
            csv_optional_f64(sample.daemon_cpu_percent),
            csv_optional_u64(sample.daemon_rss_bytes),
            csv_optional_f64(sample.benchmark_cpu_percent),
            csv_optional_u64(sample.benchmark_rss_bytes),
            csv_field(sample.instance_id.as_deref().unwrap_or_default()),
            csv_field(sample.instance_protocol.as_deref().unwrap_or_default()),
            sample.instance_sample_failed,
            csv_optional_f64(sample.instance_cpu_percent),
            csv_optional_u64(sample.instance_memory_bytes),
        );
    }
    output
}

pub(super) fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn csv_optional_f64(value: Option<f64>) -> String {
    value.map(|value| format!("{value:.6}")).unwrap_or_default()
}

fn csv_optional_u64(value: Option<u64>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}
