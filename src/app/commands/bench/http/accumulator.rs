use std::time::Duration;

use hdrhistogram::Histogram;
use reqwest::StatusCode;

use super::{
    LATENCY_SIGNIFICANT_DIGITS, MAX_RECORDED_LATENCY_MICROS, MAX_RETAINED_REQUEST_SAMPLES, PhaseRun,
};
use crate::commands::bench::metrics::{HttpPhaseReport, PhaseCounts, RequestSample};

pub(super) struct PhaseAccumulator {
    counts: PhaseCounts,
    all_latencies: Histogram<u64>,
    successful_latencies: Histogram<u64>,
    retained_samples: Vec<RequestSample>,
    reservoir_rng: XorShift64,
}

impl PhaseAccumulator {
    pub(super) fn new(seed: u64) -> Self {
        Self {
            counts: PhaseCounts::default(),
            all_latencies: latency_histogram(),
            successful_latencies: latency_histogram(),
            retained_samples: Vec::with_capacity(MAX_RETAINED_REQUEST_SAMPLES.min(1_024)),
            reservoir_rng: XorShift64::new(seed),
        }
    }

    pub(super) fn record(&mut self, sample: RequestSample) {
        let counts = &mut self.counts;
        counts.attempted_requests += 1;
        if sample.success {
            counts.successful_requests += 1;
        }
        if sample.status_code == Some(StatusCode::TOO_MANY_REQUESTS.as_u16()) {
            counts.rate_limited_requests += 1;
        }
        if let Some(status) = sample.status_code {
            *counts.status_codes.entry(status.to_string()).or_default() += 1;
        } else {
            counts.transport_errors += 1;
        }
        *counts
            .target_requests
            .entry(sample.target.clone())
            .or_default() += 1;

        let latency = sample.duration_micros.clamp(1, MAX_RECORDED_LATENCY_MICROS);
        let _ = self.all_latencies.record(latency);
        if sample.success {
            let _ = self.successful_latencies.record(latency);
        }

        if self.retained_samples.len() < MAX_RETAINED_REQUEST_SAMPLES {
            self.retained_samples.push(sample);
            return;
        }
        let replacement = self
            .reservoir_rng
            .index_below(self.counts.attempted_requests as u64) as usize;
        if replacement < MAX_RETAINED_REQUEST_SAMPLES {
            self.retained_samples[replacement] = sample;
        }
    }

    pub(super) fn finish(
        mut self,
        name: &str,
        wall_duration: Duration,
        active_load_duration: Duration,
    ) -> PhaseRun {
        self.retained_samples
            .sort_unstable_by_key(|sample| sample.index);
        let report = HttpPhaseReport::from_histograms(
            name,
            wall_duration,
            active_load_duration,
            self.counts,
            self.retained_samples.len(),
            &self.all_latencies,
            &self.successful_latencies,
        );
        PhaseRun {
            report,
            samples: self.retained_samples,
        }
    }
}

fn latency_histogram() -> Histogram<u64> {
    Histogram::new_with_max(MAX_RECORDED_LATENCY_MICROS, LATENCY_SIGNIFICANT_DIGITS)
        .expect("valid benchmark latency histogram")
}

struct XorShift64(u64);

impl XorShift64 {
    pub(super) fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn index_below(&mut self, upper_exclusive: u64) -> u64 {
        if upper_exclusive <= 1 {
            return 0;
        }
        let rejection_threshold = upper_exclusive.wrapping_neg() % upper_exclusive;
        loop {
            let value = self.next();
            if value >= rejection_threshold {
                return value % upper_exclusive;
            }
        }
    }
}
