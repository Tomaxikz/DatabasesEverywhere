use super::*;

pub(super) trait SchedulerResourceProvider: std::fmt::Debug + Send + Sync {
    fn sample(&self) -> SchedulerResourceSample;
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SchedulerResourceSample {
    pub(super) available_memory_mib: Option<u64>,
    pub(super) cpu_units: Option<usize>,
    pub(super) memory_valid: bool,
    pub(super) cpu_valid: bool,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SchedulerCapacity {
    pub mode: SchedulerMode,
    pub max_active_jobs: usize,
    pub memory_budget_mib: u64,
    pub io_budget_mib: u64,
    pub cpu_units: usize,
}

impl SchedulerCapacity {
    pub fn detect(
        config: &ImportExportSchedulerConfig,
        max_upload_bytes: u64,
        max_total_upload_bytes: u64,
    ) -> Self {
        Self::detect_with_provider(
            config,
            max_upload_bytes,
            max_total_upload_bytes,
            &HostResourceProvider,
        )
    }

    pub(super) fn detect_with_provider(
        config: &ImportExportSchedulerConfig,
        max_upload_bytes: u64,
        max_total_upload_bytes: u64,
        provider: &dyn SchedulerResourceProvider,
    ) -> Self {
        let sample = provider.sample();
        let mode = if config.dynamic_limiter_enabled {
            SchedulerMode::Dynamic
        } else {
            SchedulerMode::Manual
        };
        let memory_budget_mib = if config.dynamic_memory_budget_mib == 0 {
            let available = if sample.memory_valid {
                sample
                    .available_memory_mib
                    .unwrap_or(FALLBACK_AVAILABLE_MEMORY_MIB)
            } else {
                1
            };
            memory_budget_from_available(available)
        } else {
            config.dynamic_memory_budget_mib
        };
        let io_budget_mib = if config.dynamic_io_budget_mib == 0 {
            let one_maximum_physical_restore =
                super::super::MAX_DATA_ARCHIVE_BYTES.saturating_mul(2);
            bytes_to_mib_ceil(
                max_total_upload_bytes
                    .max(max_upload_bytes.saturating_mul(6))
                    .max(one_maximum_physical_restore),
            )
            .max(256)
        } else {
            config.dynamic_io_budget_mib
        };
        let cpu_units = if config.dynamic_cpu_units == 0 {
            sample
                .cpu_valid
                .then_some(sample.cpu_units)
                .flatten()
                .unwrap_or(1)
        } else {
            config.dynamic_cpu_units
        };
        let max_active_jobs = match mode {
            SchedulerMode::Dynamic => config.dynamic_max_active_jobs,
            SchedulerMode::Manual => config.manual_max_active_jobs,
        };
        Self {
            mode,
            max_active_jobs,
            memory_budget_mib,
            io_budget_mib,
            cpu_units: cpu_units.max(1),
        }
    }

    pub fn recommended_active_jobs(self, cost: JobResourceCost) -> usize {
        if self.mode == SchedulerMode::Manual {
            return self.max_active_jobs;
        }
        self.model_recommended_active_jobs(cost, self.max_active_jobs)
    }

    pub fn model_recommended_active_jobs(self, cost: JobResourceCost, maximum: usize) -> usize {
        let by_memory = ratio(self.memory_budget_mib, cost.memory_mib);
        if by_memory == 0 {
            return 0;
        }
        let by_io = ratio(self.io_budget_mib, cost.io_mib).max(1);
        let by_cpu = (self.cpu_units / cost.cpu_units.max(1)).max(1);
        maximum.min(by_memory).min(by_io).min(by_cpu)
    }
}

pub(super) fn memory_budget_from_available(available_mib: u64) -> u64 {
    available_mib.saturating_mul(3).saturating_div(5).max(1)
}
