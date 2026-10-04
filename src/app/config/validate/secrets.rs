use super::{ConfigValidationError, MIN_SECRET_LEN};

pub(super) fn validate_api_token(token: &str) -> Result<(), ConfigValidationError> {
    if token.trim().is_empty() {
        return Err(ConfigValidationError::EmptyApiToken);
    }
    if token.trim().len() < MIN_SECRET_LEN {
        return Err(ConfigValidationError::WeakApiToken);
    }
    if looks_like_placeholder(token) {
        return Err(ConfigValidationError::PlaceholderApiToken);
    }
    Ok(())
}

pub(super) fn validate_jwt_signing_key(
    key: &str,
    api_token: &str,
) -> Result<(), ConfigValidationError> {
    if key.trim().is_empty() {
        return Err(ConfigValidationError::EmptyJwtSigningKey);
    }
    if key.trim().len() < MIN_SECRET_LEN {
        return Err(ConfigValidationError::WeakJwtSigningKey);
    }
    if looks_like_placeholder(key) {
        return Err(ConfigValidationError::PlaceholderJwtSigningKey);
    }
    if key.as_bytes() == api_token.as_bytes() {
        return Err(ConfigValidationError::ReusedJwtSigningKey);
    }
    Ok(())
}

pub(super) fn looks_like_placeholder(secret: &str) -> bool {
    const PLACEHOLDER_MARKERS: [&str; 5] = [
        "change-me",
        "changeme",
        "replace_with",
        "replace-with",
        "generated-by-panel",
    ];
    let normalized = secret.trim().to_ascii_lowercase();
    let contains_marker = PLACEHOLDER_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker));
    let is_single_repeated_byte = normalized
        .as_bytes()
        .first()
        .is_some_and(|first| normalized.bytes().all(|byte| byte == *first));
    contains_marker || is_single_repeated_byte
}
