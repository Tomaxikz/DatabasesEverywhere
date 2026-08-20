#[derive(Debug, thiserror::Error)]
pub enum IdError {
    #[error("id must not be empty")]
    Empty,
    #[error("id contains unsupported characters: {value}")]
    Unsafe { value: String },
}

pub fn validate_instance_id(value: &str) -> Result<(), IdError> {
    if value.is_empty() {
        return Err(IdError::Empty);
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        Ok(())
    } else {
        Err(IdError::Unsafe {
            value: value.to_string(),
        })
    }
}

pub fn sanitize_docker_suffix(value: &str) -> Result<String, IdError> {
    validate_instance_id(value)?;
    Ok(value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character
            } else {
                '-'
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_id_policy_rejects_paths_and_sanitizes_safe_suffixes() {
        let error = validate_instance_id("../root").unwrap_err();

        assert!(matches!(error, IdError::Unsafe { .. }));
        assert_eq!(sanitize_docker_suffix("inst_abc").unwrap(), "inst-abc");
    }
}
