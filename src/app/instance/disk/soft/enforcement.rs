use super::*;

impl SoftDiskLimiter {
    pub(super) async fn record_sample(
        &self,
        target: &SoftDiskTarget,
        usage: DirectoryUsage,
    ) -> SampleDecision {
        let now = Instant::now();
        let fingerprint = TargetFingerprint::from(target);
        let mut states = self.states.lock().await;
        let previous = states
            .get(&target.instance_id)
            .filter(|state| state.target == fingerprint);
        let growth_bytes_per_second = growth::growth_rate(
            previous,
            usage.physical_bytes,
            now,
            Duration::from_secs(self.config.scan_interval_seconds.max(1)),
        );
        let peak_growth_bytes_per_second = previous.map_or(growth_bytes_per_second, |state| {
            state
                .snapshot
                .peak_growth_bytes_per_second
                .max(growth_bytes_per_second)
        });
        let (stop_threshold_bytes, recovery_threshold_bytes) = thresholds(
            &self.config,
            target.protocol,
            target.limit_bytes,
            growth_bytes_per_second,
        );
        let was_blocked =
            target.durable_blocked || previous.is_some_and(|state| state.snapshot.blocked);
        let recovered = was_blocked && usage.physical_bytes < recovery_threshold_bytes;
        let blocked = if recovered {
            false
        } else {
            was_blocked || usage.physical_bytes >= stop_threshold_bytes
        };
        let must_stop = !was_blocked && blocked;
        let predicted_seconds_to_limit = predict_seconds_to_limit(
            usage.physical_bytes,
            target.limit_bytes,
            growth_bytes_per_second,
        );
        let near_limit =
            usage.physical_bytes >= target.limit_bytes.saturating_mul(WARNING_USAGE_PERCENT) / 100;
        let warning_horizon_seconds =
            full_scan_interval_secs(&self.config, target.protocol).saturating_mul(2);
        let limit_reached_soon =
            predicted_seconds_to_limit.is_some_and(|seconds| seconds <= warning_horizon_seconds);
        let warning_now = !blocked && (near_limit || limit_reached_soon);
        let previously_warned = previous.is_some_and(|state| state.warned);
        let warning = warning_now && !previously_warned;
        let warned = warning_now;
        let snapshot = SoftDiskSnapshot {
            usage,
            limit_bytes: target.limit_bytes,
            stop_threshold_bytes,
            recovery_threshold_bytes,
            growth_bytes_per_second,
            peak_growth_bytes_per_second,
            predicted_seconds_to_limit,
            blocked,
            sampled_at: now,
        };
        states.insert(
            target.instance_id.clone(),
            TrackerState {
                target: fingerprint,
                snapshot: snapshot.clone(),
                warned,
            },
        );
        SampleDecision {
            snapshot,
            warning,
            must_stop,
            already_blocked: was_blocked && !recovered,
            recovered,
        }
    }

    pub(super) async fn enforce_unmeasurable<R: SoftDiskRuntime>(
        &self,
        runtime: &R,
        target: &SoftDiskTarget,
        error: String,
    ) -> Result<ScanOutcome, String> {
        let consecutive_failures = self.record_target_scan_failure(target).await;
        let threshold = self.config.max_consecutive_scan_failures.max(1);
        if consecutive_failures < threshold {
            return Err(format!(
                "{error}; soft disk usage is unmeasurable ({consecutive_failures}/{threshold} consecutive failures before fail-closed stop)"
            ));
        }

        let snapshot = self.blocked_scan_snapshot(target).await;
        let reason = SoftDiskBlockReason::Unmeasurable {
            consecutive_failures,
            error,
        };
        let exceeded = SoftDiskLimitExceeded {
            snapshot: snapshot.clone(),
            reason,
        };
        let outcome = runtime
            .enforce_disk_stop(target, &exceeded, self.shutdown_grace())
            .await?;
        Ok(ScanOutcome::Stopped { snapshot, outcome })
    }

    async fn record_target_scan_failure(&self, target: &SoftDiskTarget) -> u8 {
        let mut failures = self.scan_failures.lock().await;
        let fingerprint = TargetFingerprint::from(target);
        let state = failures
            .entry(target.instance_id.clone())
            .or_insert_with(|| TargetScanFailures {
                target: fingerprint.clone(),
                consecutive: 0,
            });
        if state.target != fingerprint {
            *state = TargetScanFailures {
                target: fingerprint,
                consecutive: 0,
            };
        }
        state.consecutive = state.consecutive.saturating_add(1);
        state.consecutive
    }

    pub(super) async fn enforce_capacity_outage<R: SoftDiskRuntime>(
        &self,
        runtime: &R,
        target: &SoftDiskTarget,
        error: String,
    ) -> Result<ScanOutcome, String> {
        let consecutive_failures = {
            let mut failures = self.capacity_outage_failures.lock().await;
            *failures = failures.saturating_add(1);
            *failures
        };
        let threshold = self.config.max_consecutive_scan_failures.max(1);
        if consecutive_failures < threshold {
            return Err(format!(
                "soft disk scanner capacity outage: {error} ({consecutive_failures}/{threshold} global failures before fail-closed fleet stop)"
            ));
        }

        let snapshot = self.blocked_scan_snapshot(target).await;
        let exceeded = SoftDiskLimitExceeded {
            snapshot: snapshot.clone(),
            reason: SoftDiskBlockReason::ScannerCapacityOutage {
                consecutive_failures,
                error,
            },
        };
        let outcome = runtime
            .enforce_disk_stop(target, &exceeded, self.shutdown_grace())
            .await?;
        Ok(ScanOutcome::Stopped { snapshot, outcome })
    }

    async fn blocked_scan_snapshot(&self, target: &SoftDiskTarget) -> SoftDiskSnapshot {
        let now = Instant::now();
        let fingerprint = TargetFingerprint::from(target);
        let mut states = self.states.lock().await;
        let previous = states
            .get(&target.instance_id)
            .filter(|state| state.target == fingerprint);
        let usage = previous.map_or_else(DirectoryUsage::default, |state| state.snapshot.usage);
        let growth_bytes_per_second =
            previous.map_or(0.0, |state| state.snapshot.growth_bytes_per_second);
        let peak_growth_bytes_per_second =
            previous.map_or(0.0, |state| state.snapshot.peak_growth_bytes_per_second);
        let (stop_threshold_bytes, recovery_threshold_bytes) = thresholds(
            &self.config,
            target.protocol,
            target.limit_bytes,
            growth_bytes_per_second,
        );
        let snapshot = SoftDiskSnapshot {
            usage,
            limit_bytes: target.limit_bytes,
            stop_threshold_bytes,
            recovery_threshold_bytes,
            growth_bytes_per_second,
            peak_growth_bytes_per_second,
            predicted_seconds_to_limit: predict_seconds_to_limit(
                usage.physical_bytes,
                target.limit_bytes,
                growth_bytes_per_second,
            ),
            blocked: true,
            sampled_at: now,
        };
        states.insert(
            target.instance_id.clone(),
            TrackerState {
                target: fingerprint,
                snapshot: snapshot.clone(),
                warned: false,
            },
        );
        snapshot
    }
}

pub(crate) async fn stop_with_kill_fallback<R: SoftDiskRuntime + ?Sized>(
    runtime: &R,
    target: &SoftDiskTarget,
    grace: Duration,
) -> Result<StopOutcome, String> {
    match tokio::time::timeout(grace, runtime.graceful_stop(target, grace)).await {
        Ok(Ok(())) => Ok(StopOutcome::Graceful),
        Ok(Err(graceful_error)) => {
            runtime.force_kill(target).await.map_err(|kill_error| {
                format!(
                    "graceful stop failed ({graceful_error}); force kill also failed ({kill_error})"
                )
            })?;
            Ok(StopOutcome::Forced)
        }
        Err(_) => {
            runtime.force_kill(target).await?;
            Ok(StopOutcome::Forced)
        }
    }
}
