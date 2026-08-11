use super::*;

pub(super) fn validate(
    artifacts: &crate::config::ArtifactConfig,
) -> Result<(), ConfigValidationError> {
    if !(1..=10_000).contains(&artifacts.max_artifacts_per_instance) {
        return Err(ConfigValidationError::InvalidImportUploadConfig {
            field: "max_artifacts_per_instance",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_default_artifact_policy() {
        validate(&crate::config::ArtifactConfig::default()).unwrap();
    }

    #[test]
    fn rejects_zero_or_excessive_per_instance_caps() {
        for maximum in [0, 10_001] {
            let artifacts = crate::config::ArtifactConfig {
                max_artifacts_per_instance: maximum,
                ..Default::default()
            };
            assert!(matches!(
                validate(&artifacts),
                Err(ConfigValidationError::InvalidImportUploadConfig {
                    field: "max_artifacts_per_instance"
                })
            ));
        }
    }
}
