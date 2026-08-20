use std::net::IpAddr;

use crate::config::Config;

use super::ConfigValidationError;

pub(super) fn validate_api_hosts(config: &Config) -> Result<(), ConfigValidationError> {
    if crate::config::url_host(&config.remote).is_none() {
        return Err(ConfigValidationError::InvalidRemoteUrl);
    }

    validate_api_fqdn(&config.api.fqdn)?;
    if matches!(config.api.host.trim(), "0.0.0.0" | "::" | "[::]") && config.api.fqdn().is_none() {
        return Err(ConfigValidationError::MissingApiFqdn);
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

fn validate_api_fqdn(fqdn: &str) -> Result<(), ConfigValidationError> {
    let fqdn = fqdn.trim();
    if fqdn.is_empty() {
        return Ok(());
    }

    let valid = fqdn.is_ascii()
        && fqdn.len() <= 253
        && fqdn.contains('.')
        && fqdn.parse::<IpAddr>().is_err()
        && fqdn.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        return Err(ConfigValidationError::InvalidApiFqdn {
            value: fqdn.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fqdn_is_automatically_allowed_as_a_request_host() {
        let config = Config {
            remote: "https://panel.example.com".to_string(),
            api: crate::config::ApiConfig {
                host: "0.0.0.0".to_string(),
                fqdn: "DB.Game-De-01.Example.com".to_string(),
                ..crate::config::ApiConfig::default()
            },
            ..Config::default()
        };

        validate_api_hosts(&config).unwrap();

        assert_eq!(
            config.request_allowed_hosts(),
            vec!["db.game-de-01.example.com"]
        );
    }

    #[test]
    fn fqdn_is_optional_for_concrete_binds_and_required_for_wildcards() {
        validate_api_fqdn("").unwrap();
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

        assert!(matches!(
            validate_api_hosts(&config),
            Err(ConfigValidationError::MissingApiFqdn)
        ));
    }

    #[test]
    fn public_url_keeps_the_configured_api_port() {
        let api = crate::config::ApiConfig {
            port: 8090,
            fqdn: "db.example.com".to_string(),
            ssl: crate::config::ApiSslConfig {
                enabled: true,
                ..crate::config::ApiSslConfig::default()
            },
            ..crate::config::ApiConfig::default()
        };

        assert_eq!(
            api.public_url().as_deref(),
            Some("https://db.example.com:8090")
        );
    }

    #[test]
    fn rejects_values_that_are_not_fully_qualified_dns_hosts() {
        for value in [
            "localhost",
            "127.0.0.1",
            "https://db.example.com",
            "db.example.com:8090",
            "*.example.com",
            ".example.com",
            "db.example.com.",
            "db_name.example.com",
            "-db.example.com",
            "db-.example.com",
        ] {
            assert!(
                matches!(
                    validate_api_fqdn(value),
                    Err(ConfigValidationError::InvalidApiFqdn { .. })
                ),
                "unexpectedly accepted {value}"
            );
        }
    }
}
