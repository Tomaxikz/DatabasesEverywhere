use std::net::IpAddr;

use crate::config::Config;

use super::ConfigValidationError;

pub(super) fn validate_api_hosts(config: &Config) -> Result<(), ConfigValidationError> {
    if crate::config::url_host(&config.remote).is_none() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_fqdn_is_accepted_but_has_no_effect() {
        let config = Config {
            remote: "https://panel.example.com".to_string(),
            api: crate::config::ApiConfig {
                host: "0.0.0.0".to_string(),
                fqdn: "this legacy value is deliberately not validated".to_string(),
                ..crate::config::ApiConfig::default()
            },
            ..Config::default()
        };

        validate_api_hosts(&config).unwrap();
        assert!(!serde_yaml::to_string(&config.api).unwrap().contains("fqdn"));
    }

    #[test]
    fn wildcard_and_concrete_binds_do_not_need_a_public_address() {
        validate_api_hosts(&Config {
            remote: "https://panel.example.com".to_string(),
            ..Config::default()
        })
        .unwrap();

        let config = Config {
            remote: "https://panel.example.com".to_string(),
            api: crate::config::ApiConfig {
                host: "0.0.0.0".to_string(),
                ..crate::config::ApiConfig::default()
            },
            ..Config::default()
        };

        validate_api_hosts(&config).unwrap();
    }
}
