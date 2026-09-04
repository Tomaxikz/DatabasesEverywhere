use std::net::IpAddr;

use crate::config::Config;

use super::ConfigValidationError;

pub(super) fn validate_api_hosts(config: &Config) -> Result<(), ConfigValidationError> {
    if crate::config::url_origin(&config.remote).is_none() {
        return Err(ConfigValidationError::InvalidRemoteUrl);
    }

    for origin in &config.api.trusted_origins {
        if crate::config::normalize_http_origin(origin).is_none() {
            return Err(ConfigValidationError::InvalidApiOrigin {
                value: origin.to_string(),
            });
        }
    }

    Ok(())
}

pub(super) fn validate_api_host(host: &str) -> Result<(), ConfigValidationError> {
    let host = host.trim();
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if host.is_empty()
        || host.contains("://")
        || host.contains('/')
        || host.contains('\\')
        || host.contains(':')
    {
        return Err(ConfigValidationError::InvalidApiHost {
            value: host.to_string(),
        });
    }
    Ok(())
}
