use std::net::IpAddr;

use crate::config::{Config, path_policy::HostPathPolicy};

use super::ConfigValidationError;

/// Longest path that fits `sockaddr_un.sun_path` with its terminating NUL.
const MAX_SOCKET_PATH_BYTES: usize = 107;

pub(super) fn validate_api_hosts(config: &Config) -> Result<(), ConfigValidationError> {
    let remote = config.remote.trim();
    if !remote.is_empty() && crate::config::url_origin(remote).is_none() {
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

pub(super) fn validate_api_socket(socket_path: &str) -> Result<(), ConfigValidationError> {
    if socket_path.len() > MAX_SOCKET_PATH_BYTES {
        return Err(ConfigValidationError::ApiSocketPathTooLong {
            value: socket_path.to_string(),
            maximum: MAX_SOCKET_PATH_BYTES,
        });
    }
    HostPathPolicy::validate_api_socket(socket_path)?;
    Ok(())
}
