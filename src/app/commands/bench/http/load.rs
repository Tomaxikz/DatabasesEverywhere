use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use futures::{StreamExt, stream};
use reqwest::Method;

use super::{
    API_RATE_LIMIT_WINDOW, BenchClient, FixedWindowPacing, LoadTarget, MAX_PACED_BATCH_REQUESTS,
    PhaseRun, accumulator::PhaseAccumulator,
};
use crate::commands::bench::metrics::HttpPhaseReport;

impl BenchClient {
    pub(in crate::commands::bench) async fn benchmark_sequential(&self, count: usize) -> PhaseRun {
        let started = Instant::now();
        let mut samples = Vec::with_capacity(count);
        for index in 0..count {
            samples.push(
                self.request(
                    Method::GET,
                    "/api/heartbeat",
                    None,
                    "http_sequential",
                    index,
                )
                .await
                .sample,
            );
        }
        PhaseRun {
            report: HttpPhaseReport::from_samples("http_sequential", started.elapsed(), &samples),
            samples,
        }
    }

    pub(in crate::commands::bench) async fn benchmark_concurrent(
        &self,
        count: usize,
        concurrency: usize,
        targets: Vec<LoadTarget>,
        reservoir_seed: u64,
    ) -> PhaseRun {
        let started = Instant::now();
        let targets = Arc::new(normalize_load_targets(targets));
        let mut accumulator = PhaseAccumulator::new(reservoir_seed);
        let active = self
            .run_concurrent_batch(
                0,
                count,
                concurrency,
                &targets,
                "http_concurrent",
                &mut accumulator,
            )
            .await;
        accumulator.finish("http_concurrent", started.elapsed(), active)
    }

    pub(in crate::commands::bench) async fn benchmark_concurrency(
        &self,
        duration: Duration,
        concurrency: usize,
        targets: Vec<LoadTarget>,
        reservoir_seed: u64,
        pacing: Option<FixedWindowPacing>,
    ) -> PhaseRun {
        let started = Instant::now();
        let deadline = started + duration;
        let targets = Arc::new(normalize_load_targets(targets));
        let mut accumulator = PhaseAccumulator::new(reservoir_seed);

        let active_load_duration = if let Some(pacing) = pacing {
            self.run_paced_load(pacing, deadline, concurrency, &targets, &mut accumulator)
                .await
        } else {
            self.run_unpaced_load(deadline, concurrency, &targets, &mut accumulator)
                .await;
            started.elapsed()
        };
        accumulator.finish(
            "http_concurrent_timed",
            started.elapsed(),
            active_load_duration,
        )
    }

    async fn run_paced_load(
        &self,
        pacing: FixedWindowPacing,
        deadline: Instant,
        concurrency: usize,
        targets: &Arc<Vec<LoadTarget>>,
        accumulator: &mut PhaseAccumulator,
    ) -> Duration {
        let mut active_load_duration = Duration::ZERO;
        let mut window_started = pacing.window_started;
        let window_budget = pacing.requests_per_window.max(1);
        let mut sent_in_window = 0_usize;
        let mut next_index = 0_usize;
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            while now.duration_since(window_started) >= API_RATE_LIMIT_WINDOW {
                window_started += API_RATE_LIMIT_WINDOW;
                sent_in_window = 0;
            }
            if sent_in_window >= window_budget {
                let wake_at = (window_started + API_RATE_LIMIT_WINDOW).min(deadline);
                tokio::time::sleep_until(tokio::time::Instant::from_std(wake_at)).await;
                continue;
            }
            let batch_count = (window_budget - sent_in_window).min(MAX_PACED_BATCH_REQUESTS);
            active_load_duration += self
                .run_concurrent_batch(
                    next_index,
                    batch_count,
                    concurrency,
                    targets,
                    "http_concurrent_timed",
                    accumulator,
                )
                .await;
            next_index = next_index.saturating_add(batch_count);
            sent_in_window = sent_in_window.saturating_add(batch_count);
        }
        active_load_duration
    }

    async fn run_unpaced_load(
        &self,
        deadline: Instant,
        concurrency: usize,
        targets: &Arc<Vec<LoadTarget>>,
        accumulator: &mut PhaseAccumulator,
    ) {
        let indices = stream::unfold(0_usize, move |index| async move {
            (Instant::now() < deadline).then_some((index, index.saturating_add(1)))
        });
        let requests = indices
            .map(|index| {
                let client = self.clone();
                let target = choose_load_target(targets, index).clone();
                async move {
                    client
                        .request(
                            Method::GET,
                            &target.path,
                            None,
                            "http_concurrent_timed",
                            index,
                        )
                        .await
                        .sample
                }
            })
            .buffer_unordered(concurrency.max(1));
        tokio::pin!(requests);
        while let Some(sample) = requests.next().await {
            accumulator.record(sample);
        }
    }

    async fn run_concurrent_batch(
        &self,
        start_index: usize,
        count: usize,
        concurrency: usize,
        targets: &Arc<Vec<LoadTarget>>,
        phase: &'static str,
        accumulator: &mut PhaseAccumulator,
    ) -> Duration {
        let started = Instant::now();
        let requests = stream::iter(start_index..start_index.saturating_add(count))
            .map(|index| {
                let client = self.clone();
                let target = choose_load_target(targets, index).clone();
                async move {
                    client
                        .request(Method::GET, &target.path, None, phase, index)
                        .await
                        .sample
                }
            })
            .buffer_unordered(concurrency.max(1));
        tokio::pin!(requests);
        while let Some(sample) = requests.next().await {
            accumulator.record(sample);
        }
        started.elapsed()
    }
}

fn normalize_load_targets(mut targets: Vec<LoadTarget>) -> Vec<LoadTarget> {
    if targets.is_empty() {
        targets.push(LoadTarget::heartbeat());
    } else if targets[0].path != "/api/heartbeat" {
        targets.insert(0, LoadTarget::heartbeat());
    }
    targets
}

fn choose_load_target(targets: &[LoadTarget], index: usize) -> &LoadTarget {
    if targets.len() <= 1 || index.is_multiple_of(2) {
        &targets[0]
    } else {
        &targets[1 + (index / 2) % (targets.len() - 1)]
    }
}
