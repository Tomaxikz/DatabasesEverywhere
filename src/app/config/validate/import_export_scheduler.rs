use super::ConfigValidationError;

pub(super) fn validate(
    artifacts: &crate::config::ArtifactConfig,
) -> Result<(), ConfigValidationError> {
    let scheduler = &artifacts.import_export_scheduler;
    let invalid = |field| ConfigValidationError::InvalidImportExportSchedulerConfig { field };
    if !(64..=8_192).contains(&scheduler.max_queued_jobs) {
        return Err(invalid("max_queued_jobs"));
    }
    if scheduler.max_queued_jobs_per_instance == 0
        || scheduler.max_queued_jobs_per_instance > 256
        || scheduler.max_queued_jobs_per_instance > scheduler.max_queued_jobs
    {
        return Err(invalid("max_queued_jobs_per_instance"));
    }
    if scheduler.manual_max_active_jobs == 0
        || scheduler.manual_max_active_jobs > 1_024
        || scheduler.manual_max_active_jobs > scheduler.max_queued_jobs
    {
        return Err(invalid("manual_max_active_jobs"));
    }
    if scheduler.dynamic_max_active_jobs == 0
        || scheduler.dynamic_max_active_jobs > 1_024
        || scheduler.dynamic_max_active_jobs > scheduler.max_queued_jobs
    {
        return Err(invalid("dynamic_max_active_jobs"));
    }
    if scheduler.dynamic_memory_budget_mib != 0
        && !(128..=16 * 1024 * 1024).contains(&scheduler.dynamic_memory_budget_mib)
    {
        return Err(invalid("dynamic_memory_budget_mib"));
    }
    if scheduler.dynamic_io_budget_mib != 0
        && !(256..=64 * 1024 * 1024).contains(&scheduler.dynamic_io_budget_mib)
    {
        return Err(invalid("dynamic_io_budget_mib"));
    }
    if scheduler.dynamic_cpu_units > 65_536 {
        return Err(invalid("dynamic_cpu_units"));
    }
    if !(1..=3_600).contains(&scheduler.starvation_timeout_seconds) {
        return Err(invalid("starvation_timeout_seconds"));
    }
    if scheduler.max_bypass > 1_024 {
        return Err(invalid("max_bypass"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_scheduler_boundaries() {
        let mut artifacts = crate::config::ArtifactConfig::default();
        artifacts.import_export_scheduler.max_queued_jobs = 63;
        assert!(matches!(
            validate(&artifacts),
            Err(ConfigValidationError::InvalidImportExportSchedulerConfig {
                field: "max_queued_jobs"
            })
        ));

        let mut artifacts = crate::config::ArtifactConfig::default();
        artifacts.import_export_scheduler.manual_max_active_jobs = 0;
        assert!(matches!(
            validate(&artifacts),
            Err(ConfigValidationError::InvalidImportExportSchedulerConfig {
                field: "manual_max_active_jobs"
            })
        ));

        let mut artifacts = crate::config::ArtifactConfig::default();
        artifacts.import_export_scheduler.dynamic_max_active_jobs = 0;
        assert!(matches!(
            validate(&artifacts),
            Err(ConfigValidationError::InvalidImportExportSchedulerConfig {
                field: "dynamic_max_active_jobs"
            })
        ));

        let mut artifacts = crate::config::ArtifactConfig::default();
        artifacts.import_export_scheduler.dynamic_memory_budget_mib = 127;
        assert!(matches!(
            validate(&artifacts),
            Err(ConfigValidationError::InvalidImportExportSchedulerConfig {
                field: "dynamic_memory_budget_mib"
            })
        ));
    }
}
