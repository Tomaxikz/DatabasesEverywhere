use super::*;

pub(super) fn validate_listener(
    name: &'static str,
    listener: &ListenerConfig,
    tls: &TlsConfig,
) -> Result<(), ConfigValidationError> {
    if listener.enabled {
        validate_bind(name, &listener.bind)?;
    }
    if listener.tls {
        validate_tls_pair(name, &tls.cert, &tls.key)?;
    }
    Ok(())
}

pub(super) fn validate_clickhouse(
    listener: &ClickhouseConfig,
    tls: &TlsConfig,
) -> Result<(), ConfigValidationError> {
    if listener.enabled {
        validate_bind("clickhouse", &listener.bind)?;
        validate_bind("clickhouse.http_bind", &listener.http_bind)?;
    }
    if listener.tls {
        validate_tls_pair("clickhouse", &tls.cert, &tls.key)?;
    }
    Ok(())
}

pub(super) fn validate_api_tls(ssl: &ApiSslConfig) -> Result<(), ConfigValidationError> {
    if ssl.enabled {
        validate_tls_pair("api.ssl", &ssl.cert, &ssl.key)?;
    }
    if ssl.require_client_cert {
        if !ssl.enabled {
            return Err(ConfigValidationError::ClientCertRequiresApiTls);
        }
        if ssl.client_ca.trim().is_empty() {
            return Err(ConfigValidationError::MissingClientCa);
        }
        if !Path::new(&ssl.client_ca).exists() {
            return Err(ConfigValidationError::MissingClientCaFile {
                path: ssl.client_ca.clone(),
            });
        }
    }
    Ok(())
}

pub(super) fn validate_security(
    security: &crate::config::SecurityConfig,
) -> Result<(), ConfigValidationError> {
    if security.self_upgrade_enabled {
        return Err(ConfigValidationError::UnsupportedSelfUpgrade);
    }
    for (field, invalid) in [
        ("api_body_limit_bytes", security.api_body_limit_bytes == 0),
        (
            "api_rate_limit_per_minute",
            security.api_rate_limit_per_minute == 0,
        ),
        (
            "db_connection_limit_per_minute",
            security.db_connection_limit_per_minute == 0,
        ),
    ] {
        if invalid {
            return Err(ConfigValidationError::InvalidSecurityLimit { field });
        }
    }
    if security.pids_limit <= 0 {
        return Err(ConfigValidationError::InvalidSecurityLimit {
            field: "pids_limit",
        });
    }
    for (field, value) in [
        ("pids_limits.postgres", security.pids_limits.postgres),
        ("pids_limits.redis", security.pids_limits.redis),
        ("pids_limits.valkey", security.pids_limits.valkey),
        ("pids_limits.mariadb", security.pids_limits.mariadb),
        ("pids_limits.mysql", security.pids_limits.mysql),
        ("pids_limits.mongodb", security.pids_limits.mongodb),
        ("pids_limits.clickhouse", security.pids_limits.clickhouse),
        ("pids_limits.qdrant", security.pids_limits.qdrant),
    ] {
        if value.is_some_and(|value| value <= 0) {
            return Err(ConfigValidationError::InvalidSecurityLimit { field });
        }
    }
    validate_remote_import_security(&security.remote_import)?;
    Ok(())
}

pub(super) fn validate_remote_import_security(
    remote: &crate::config::RemoteImportSecurityConfig,
) -> Result<(), ConfigValidationError> {
    for (field, value, maximum) in [
        (
            "max_concurrent_jobs",
            remote.max_concurrent_jobs as u64,
            MAX_REMOTE_IMPORT_JOBS as u64,
        ),
        (
            "connect_timeout_seconds",
            remote.connect_timeout_seconds,
            MAX_REMOTE_IMPORT_CONNECT_TIMEOUT_SECONDS,
        ),
        (
            "operation_timeout_seconds",
            remote.operation_timeout_seconds,
            MAX_REMOTE_IMPORT_OPERATION_TIMEOUT_SECONDS,
        ),
        (
            "max_staged_bytes",
            remote.max_staged_bytes,
            MAX_REMOTE_IMPORT_STAGED_BYTES,
        ),
    ] {
        if !(1..=maximum).contains(&value) {
            return Err(ConfigValidationError::InvalidRemoteImportLimit {
                field,
                minimum: 1,
                maximum,
            });
        }
    }
    if remote.operation_timeout_seconds < remote.connect_timeout_seconds {
        return Err(ConfigValidationError::InvalidRemoteImportTimeoutOrder);
    }
    for host in &remote.allowed_private_hosts {
        if super::super::normalize_remote_import_host(host).is_none() {
            return Err(ConfigValidationError::InvalidRemoteImportHost {
                value: host.clone(),
            });
        }
    }
    Ok(())
}

pub(super) fn validate_bind(field: &'static str, value: &str) -> Result<(), ConfigValidationError> {
    value
        .parse::<SocketAddr>()
        .map(|_| ())
        .map_err(|_| ConfigValidationError::InvalidBind {
            field,
            value: value.to_string(),
        })
}

pub(super) fn validate_tls_pair(
    field: &'static str,
    cert: &str,
    key: &str,
) -> Result<(), ConfigValidationError> {
    if cert.trim().is_empty() || key.trim().is_empty() {
        return Err(ConfigValidationError::IncompleteTls { field });
    }
    if !Path::new(cert).exists() {
        return Err(ConfigValidationError::MissingTlsCert {
            field,
            path: cert.to_string(),
        });
    }
    if !Path::new(key).exists() {
        return Err(ConfigValidationError::MissingTlsKey {
            field,
            path: key.to_string(),
        });
    }
    Ok(())
}

pub(super) fn validate_absolute_path(
    field: &'static str,
    value: &str,
) -> Result<(), ConfigValidationError> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(ConfigValidationError::RelativePath {
            field,
            value: value.to_string(),
        });
    }
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(ConfigValidationError::ParentPath {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}
