use csv::Writer;

use crate::commands::bench::metrics::{RequestSample, ResourceSample};

pub(super) fn request_samples_csv(samples: &[RequestSample]) -> csv::Result<Vec<u8>> {
    let mut output = Writer::from_writer(Vec::new());
    output.write_record([
        "phase",
        "target",
        "index",
        "duration_micros",
        "duration_ms",
        "status_code",
        "success",
        "error",
    ])?;
    for sample in samples {
        output.serialize((
            &sample.phase,
            &sample.target,
            sample.index,
            sample.duration_micros,
            format!("{:.3}", sample.duration_micros as f64 / 1_000.0),
            sample.status_code,
            sample.success,
            &sample.error,
        ))?;
    }
    Ok(output.into_inner().map_err(|error| error.into_error())?)
}

pub(super) fn resource_samples_csv(samples: &[ResourceSample]) -> csv::Result<Vec<u8>> {
    let mut output = Writer::from_writer(Vec::new());
    output.write_record([
        "elapsed_ms",
        "phase",
        "daemon_cpu_percent",
        "daemon_rss_bytes",
        "benchmark_cpu_percent",
        "benchmark_rss_bytes",
        "instance_id",
        "instance_protocol",
        "instance_sample_failed",
        "instance_cpu_percent",
        "instance_memory_bytes",
    ])?;
    for sample in samples {
        output.serialize((
            sample.elapsed_ms,
            &sample.phase,
            sample.daemon_cpu_percent.map(|value| format!("{value:.6}")),
            sample.daemon_rss_bytes,
            sample
                .benchmark_cpu_percent
                .map(|value| format!("{value:.6}")),
            sample.benchmark_rss_bytes,
            &sample.instance_id,
            &sample.instance_protocol,
            sample.instance_sample_failed,
            sample
                .instance_cpu_percent
                .map(|value| format!("{value:.6}")),
            sample.instance_memory_bytes,
        ))?;
    }
    Ok(output.into_inner().map_err(|error| error.into_error())?)
}
