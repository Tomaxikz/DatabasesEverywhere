use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
};

use super::{ApiSslConfig, ClickhouseConfig, Config, DiskLimitMode, ListenerConfig, TlsConfig};
use crate::shared::images::has_sha256_digest;

#[derive(Debug, thiserror::Error)]
pub enum ConfigValidationError {
    #[error("uuid must not be empty")]
    EmptyUuid,
    #[error("token_id must not be empty")]
    EmptyTokenId,
    #[error("token must not be empty")]
    EmptyApiToken,
    #[error("token must contain at least 32 bytes of secret material")]
    WeakApiToken,
    #[error("token must be replaced with a randomly generated production secret")]
    PlaceholderApiToken,
    #[error("jwt_signing_key must not be empty")]
    EmptyJwtSigningKey,
    #[error("jwt_signing_key must contain at least 32 bytes of secret material")]
    WeakJwtSigningKey,
    #[error("jwt_signing_key must be replaced with a randomly generated production secret")]
    PlaceholderJwtSigningKey,
    #[error("jwt_signing_key must be different from token")]
    ReusedJwtSigningKey,
    #[error("remote must be a full URL such as https://panel.example.com")]
    InvalidRemoteUrl,
    #[error("api.host must be a host or IP address, not a URL/path: {value}")]
    InvalidApiHost { value: String },
    #[error("{field} bind address is invalid: {value}")]
    InvalidBind { field: &'static str, value: String },
    #[error(
        "{field} is exposed without TLS at {value}; enable TLS, bind to loopback, or set security.allow_insecure_public_listeners=true only for isolated development"
    )]
    InsecurePublicListener { field: &'static str, value: String },
    #[error(
        "api.host must be a literal loopback IP address in production; publish the API through a hardened local reverse proxy with connection, header, and idle timeouts (configured bind: {value})"
    )]
    DirectPublicApiUnsupported { value: String },
    #[error("daemon.network must not be empty")]
    EmptyDaemonNetwork,
    #[error("{field} must be a CIDR subnet: {value}")]
    InvalidCidr { field: &'static str, value: String },
    #[error("{field} must be an IP address: {value}")]
    InvalidIp { field: &'static str, value: String },
    #[error("daemon.ipam.gateway requires daemon.ipam.subnet")]
    GatewayRequiresSubnet,
    #[error("{field} must be an absolute path: {value}")]
    RelativePath { field: &'static str, value: String },
    #[error("{field} must not contain parent directory segments: {value}")]
    ParentPath { field: &'static str, value: String },
    #[error("{field} TLS requires both cert and key")]
    IncompleteTls { field: &'static str },
    #[error("{field} TLS cert does not exist: {path}")]
    MissingTlsCert { field: &'static str, path: String },
    #[error("{field} TLS key does not exist: {path}")]
    MissingTlsKey { field: &'static str, path: String },
    #[error("api.ssl.require_client_cert requires api.ssl.enabled=true")]
    ClientCertRequiresApiTls,
    #[error("api.ssl.require_client_cert requires api.ssl.client_ca")]
    MissingClientCa,
    #[error("api.ssl.client_ca does not exist: {path}")]
    MissingClientCaFile { path: String },
    #[error("security.{field} must be greater than zero")]
    InvalidSecurityLimit { field: &'static str },
    #[error(
        "security.self_upgrade_enabled is unsupported; deploy upgrades through a signed package or immutable container image"
    )]
    UnsupportedSelfUpgrade,
    #[error("disk.project_id_base must be greater than zero when disk.mode=project_quota")]
    InvalidProjectIdBase,
    #[error(
        "disk.fuse_quota_binary_sha256 must be the lowercase 64-character SHA-256 of the configured external helper"
    )]
    InvalidFuseQuotaBinarySha256,
    #[error("artifacts.retention_keep_latest must be greater than zero")]
    InvalidArtifactRetention,
    #[error("backups.interval_minutes must be greater than zero")]
    InvalidBackupInterval,
    #[error("backups.retention_keep_latest_per_instance must be greater than zero")]
    InvalidBackupRetentionKeepLatest,
    #[error("{field} must use an immutable sha256 digest: {image}")]
    InvalidImageReference { field: &'static str, image: String },
    #[error(
        "images.mongodb={image} is not compatible with Linux kernel {kernel}; MongoDB 8.0+ is affected by SERVER-121912 on kernel 6.19+"
    )]
    MongodbKernelIncompatible { image: String, kernel: String },
}

pub fn validate_config(config: &Config) -> Result<(), ConfigValidationError> {
    if config.uuid.trim().is_empty() {
        return Err(ConfigValidationError::EmptyUuid);
    }
    if config.token_id.trim().is_empty() {
        return Err(ConfigValidationError::EmptyTokenId);
    }
    validate_api_token(&config.token)?;
    validate_jwt_signing_key(&config.jwt_signing_key, &config.token)?;

    validate_api_host(&config.api.host)?;
    validate_api_hosts(config)?;
    validate_listener("postgres", &config.postgres, &config.tls)?;
    validate_listener("mariadb", &config.mariadb, &config.tls)?;
    validate_listener("redis", &config.redis, &config.tls)?;
    validate_listener("mongodb", &config.mongodb, &config.tls)?;
    validate_clickhouse(&config.clickhouse, &config.tls)?;
    validate_listener("qdrant", &config.qdrant, &config.tls)?;
    validate_api_tls(&config.api.ssl)?;
    validate_cleartext_exposure(config)?;
    validate_security(&config.security)?;
    validate_disk(&config.disk)?;
    if config.artifacts.retention_keep_latest == 0 {
        return Err(ConfigValidationError::InvalidArtifactRetention);
    }
    if config.backups.interval_minutes == 0 {
        return Err(ConfigValidationError::InvalidBackupInterval);
    }
    if config.backups.retention_keep_latest_per_instance == 0 {
        return Err(ConfigValidationError::InvalidBackupRetentionKeepLatest);
    }

    if config.daemon.network.trim().is_empty() {
        return Err(ConfigValidationError::EmptyDaemonNetwork);
    }
    if let Some(socket_path) = config.daemon.configured_socket_path() {
        validate_absolute_path("daemon.socket_path", socket_path)?;
    }
    validate_daemon_ipam(&config.daemon.ipam)?;

    validate_absolute_path("paths.data", &config.paths.data)?;
    validate_absolute_path("paths.metadata", &config.paths.metadata_root())?;
    validate_absolute_path("paths.volumes", &config.paths.volumes_root())?;
    validate_absolute_path("paths.backups", &config.paths.backups_root())?;
    validate_absolute_path("paths.sockets", &config.paths.sockets)?;
    validate_absolute_path("paths.locks", &config.paths.locks)?;
    validate_absolute_path("paths.logs", &config.paths.logs)?;
    validate_absolute_path("paths.artifacts", &config.paths.artifacts)?;
    validate_absolute_path("paths.exports", &config.paths.exports_root())?;
    validate_absolute_path("paths.imports", &config.paths.imports_root())?;
    validate_absolute_path("paths.fuse", &config.paths.fuse_root())?;
    validate_absolute_path("paths.tmp", &config.paths.tmp_root())?;
    validate_images(&config.images)?;
    validate_mongodb_kernel_compatibility(&config.images.mongodb)?;

    Ok(())
}

fn validate_api_token(token: &str) -> Result<(), ConfigValidationError> {
    if token.trim().is_empty() {
        return Err(ConfigValidationError::EmptyApiToken);
    }
    if token.trim().len() < 32 {
        return Err(ConfigValidationError::WeakApiToken);
    }
    if looks_like_placeholder(token) {
        return Err(ConfigValidationError::PlaceholderApiToken);
    }
    Ok(())
}

fn validate_jwt_signing_key(key: &str, api_token: &str) -> Result<(), ConfigValidationError> {
    if key.trim().is_empty() {
        return Err(ConfigValidationError::EmptyJwtSigningKey);
    }
    if key.trim().len() < 32 {
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

fn looks_like_placeholder(secret: &str) -> bool {
    let normalized = secret.trim().to_ascii_lowercase();
    normalized.contains("change-me")
        || normalized.contains("changeme")
        || normalized.contains("replace_with")
        || normalized.contains("replace-with")
        || normalized.contains("generated-by-panel")
        || normalized
            .as_bytes()
            .first()
            .is_some_and(|first| normalized.bytes().all(|byte| byte == *first))
}

fn validate_cleartext_exposure(config: &Config) -> Result<(), ConfigValidationError> {
    if config.security.allow_insecure_public_listeners {
        return Ok(());
    }

    validate_api_exposure(config)?;
    for (field, listener) in [
        ("postgres", &config.postgres),
        ("mariadb", &config.mariadb),
        ("redis", &config.redis),
        ("mongodb", &config.mongodb),
        ("qdrant", &config.qdrant),
    ] {
        if listener.enabled && !listener.tls {
            reject_non_loopback_bind(field, &listener.bind)?;
        }
    }
    if config.clickhouse.enabled && !config.clickhouse.tls {
        reject_non_loopback_bind("clickhouse", &config.clickhouse.bind)?;
        reject_non_loopback_bind("clickhouse.http_bind", &config.clickhouse.http_bind)?;
    }
    Ok(())
}

fn validate_api_exposure(config: &Config) -> Result<(), ConfigValidationError> {
    let host = config.api.host.trim();
    if host
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
    {
        return Ok(());
    }
    Err(ConfigValidationError::DirectPublicApiUnsupported {
        value: config.api.bind_addr(),
    })
}

fn reject_non_loopback_bind(field: &'static str, bind: &str) -> Result<(), ConfigValidationError> {
    let address = bind
        .parse::<SocketAddr>()
        .map_err(|_| ConfigValidationError::InvalidBind {
            field,
            value: bind.to_string(),
        })?;
    if address.ip().is_loopback() {
        return Ok(());
    }
    Err(ConfigValidationError::InsecurePublicListener {
        field,
        value: bind.to_string(),
    })
}

fn validate_images(images: &crate::config::ImageConfig) -> Result<(), ConfigValidationError> {
    for (field, image) in [
        ("images.postgres", images.postgres.as_str()),
        ("images.redis", images.redis.as_str()),
        ("images.mariadb", images.mariadb.as_str()),
        ("images.mongodb", images.mongodb.as_str()),
        ("images.clickhouse", images.clickhouse.as_str()),
        ("images.qdrant", images.qdrant.as_str()),
    ] {
        validate_image_reference(field, image)?;
    }
    for (field, allowed) in [
        (
            "images.allowed.postgres",
            images.allowed.postgres.as_slice(),
        ),
        ("images.allowed.redis", images.allowed.redis.as_slice()),
        ("images.allowed.mariadb", images.allowed.mariadb.as_slice()),
        ("images.allowed.mongodb", images.allowed.mongodb.as_slice()),
        (
            "images.allowed.clickhouse",
            images.allowed.clickhouse.as_slice(),
        ),
        ("images.allowed.qdrant", images.allowed.qdrant.as_slice()),
    ] {
        for image in allowed {
            validate_image_reference(field, image)?;
        }
    }
    Ok(())
}

fn validate_image_reference(field: &'static str, image: &str) -> Result<(), ConfigValidationError> {
    let image = image.trim();
    if image.is_empty() || image.chars().any(char::is_whitespace) {
        return Err(ConfigValidationError::InvalidImageReference {
            field,
            image: image.to_string(),
        });
    }
    if has_sha256_digest(image) {
        return Ok(());
    }
    Err(ConfigValidationError::InvalidImageReference {
        field,
        image: image.to_string(),
    })
}

fn validate_mongodb_kernel_compatibility(image: &str) -> Result<(), ConfigValidationError> {
    let Some(kernel) = linux_kernel_release() else {
        return Ok(());
    };
    if kernel_is_6_19_or_newer(&kernel) && mongodb_image_is_8_or_newer(image) {
        return Err(ConfigValidationError::MongodbKernelIncompatible {
            image: image.to_string(),
            kernel,
        });
    }
    Ok(())
}

fn linux_kernel_release() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn kernel_is_6_19_or_newer(release: &str) -> bool {
    let mut parts = release
        .split(|character: char| !character.is_ascii_digit())
        .filter(|part| !part.is_empty());
    let major = parts
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or_default();
    let minor = parts
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or_default();

    major > 6 || (major == 6 && minor >= 19)
}

fn mongodb_image_is_8_or_newer(image: &str) -> bool {
    let image = image.split_once('@').map_or(image, |(name, _)| name);
    let tag = image
        .rsplit_once(':')
        .filter(|(name, _)| !name.contains('/'))
        .map(|(_, tag)| tag)
        .or_else(|| {
            let (name, tag) = image.rsplit_once(':')?;
            if name.rsplit('/').next()?.contains(':') {
                None
            } else {
                Some(tag)
            }
        })
        .unwrap_or("latest");
    tag == "latest"
        || tag
            .split(|character: char| !character.is_ascii_digit())
            .next()
            .and_then(|major| major.parse::<u32>().ok())
            .is_some_and(|major| major >= 8)
}

fn validate_disk(disk: &crate::config::DiskConfig) -> Result<(), ConfigValidationError> {
    if disk.mode == DiskLimitMode::ProjectQuota && disk.project_id_base == 0 {
        return Err(ConfigValidationError::InvalidProjectIdBase);
    }
    let binary = disk.fuse_quota_binary();
    if !binary.eq_ignore_ascii_case("embedded") {
        validate_absolute_path("disk.fuse_quota_binary", binary)?;
        let digest = disk.fuse_quota_binary_sha256.trim();
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ConfigValidationError::InvalidFuseQuotaBinarySha256);
        }
    }
    Ok(())
}

fn validate_daemon_ipam(
    ipam: &crate::config::DaemonNetworkIpam,
) -> Result<(), ConfigValidationError> {
    if ipam.subnet.trim().is_empty() && !ipam.gateway.trim().is_empty() {
        return Err(ConfigValidationError::GatewayRequiresSubnet);
    }
    if !ipam.subnet.trim().is_empty() {
        validate_cidr("daemon.ipam.subnet", &ipam.subnet)?;
    }
    if !ipam.gateway.trim().is_empty() {
        ipam.gateway.parse::<IpAddr>().map(|_| ()).map_err(|_| {
            ConfigValidationError::InvalidIp {
                field: "daemon.ipam.gateway",
                value: ipam.gateway.clone(),
            }
        })?;
    }
    Ok(())
}

fn validate_listener(
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

fn validate_clickhouse(
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

fn validate_api_tls(ssl: &ApiSslConfig) -> Result<(), ConfigValidationError> {
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

fn validate_security(
    security: &crate::config::SecurityConfig,
) -> Result<(), ConfigValidationError> {
    if security.self_upgrade_enabled {
        return Err(ConfigValidationError::UnsupportedSelfUpgrade);
    }
    if security.api_body_limit_bytes == 0 {
        return Err(ConfigValidationError::InvalidSecurityLimit {
            field: "api_body_limit_bytes",
        });
    }
    if security.api_rate_limit_per_minute == 0 {
        return Err(ConfigValidationError::InvalidSecurityLimit {
            field: "api_rate_limit_per_minute",
        });
    }
    if security.db_connection_limit_per_minute == 0 {
        return Err(ConfigValidationError::InvalidSecurityLimit {
            field: "db_connection_limit_per_minute",
        });
    }
    if security.pids_limit <= 0 {
        return Err(ConfigValidationError::InvalidSecurityLimit {
            field: "pids_limit",
        });
    }
    for (field, value) in [
        ("pids_limits.postgres", security.pids_limits.postgres),
        ("pids_limits.redis", security.pids_limits.redis),
        ("pids_limits.mariadb", security.pids_limits.mariadb),
        ("pids_limits.mongodb", security.pids_limits.mongodb),
        ("pids_limits.clickhouse", security.pids_limits.clickhouse),
        ("pids_limits.qdrant", security.pids_limits.qdrant),
    ] {
        if value.is_some_and(|value| value <= 0) {
            return Err(ConfigValidationError::InvalidSecurityLimit { field });
        }
    }
    Ok(())
}

fn validate_bind(field: &'static str, value: &str) -> Result<(), ConfigValidationError> {
    value
        .parse::<SocketAddr>()
        .map(|_| ())
        .map_err(|_| ConfigValidationError::InvalidBind {
            field,
            value: value.to_string(),
        })
}

fn validate_cidr(field: &'static str, value: &str) -> Result<(), ConfigValidationError> {
    let Some((ip, prefix)) = value.split_once('/') else {
        return Err(ConfigValidationError::InvalidCidr {
            field,
            value: value.to_string(),
        });
    };
    let ip: IpAddr = ip.parse().map_err(|_| ConfigValidationError::InvalidCidr {
        field,
        value: value.to_string(),
    })?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| ConfigValidationError::InvalidCidr {
            field,
            value: value.to_string(),
        })?;
    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        return Err(ConfigValidationError::InvalidCidr {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn validate_api_hosts(config: &Config) -> Result<(), ConfigValidationError> {
    if super::url_host(&config.remote).is_none() {
        return Err(ConfigValidationError::InvalidRemoteUrl);
    }

    Ok(())
}

fn validate_api_host(host: &str) -> Result<(), ConfigValidationError> {
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

fn validate_tls_pair(
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

fn validate_absolute_path(field: &'static str, value: &str) -> Result<(), ConfigValidationError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn rejects_empty_api_token() {
        let config = Config::default();

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(error, ConfigValidationError::EmptyUuid));
    }

    #[test]
    fn rejects_relative_paths() {
        let mut config = valid_config();
        config.paths.data = "relative".to_string();

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(error, ConfigValidationError::RelativePath { .. }));
    }

    #[test]
    fn accepts_simple_valid_config() {
        validate_config(&valid_config()).unwrap();
    }

    #[test]
    fn rejects_invalid_pids_limits() {
        let mut config = valid_config();
        config.security.pids_limit = 0;

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(
            error,
            ConfigValidationError::InvalidSecurityLimit {
                field: "pids_limit"
            }
        ));

        let mut config = valid_config();
        config.security.pids_limits.clickhouse = Some(-1);

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(
            error,
            ConfigValidationError::InvalidSecurityLimit {
                field: "pids_limits.clickhouse"
            }
        ));
    }

    #[test]
    fn rejects_api_self_upgrade() {
        let mut config = valid_config();
        config.security.self_upgrade_enabled = true;

        assert!(matches!(
            validate_config(&config).unwrap_err(),
            ConfigValidationError::UnsupportedSelfUpgrade
        ));
    }

    #[test]
    fn rejects_missing_token() {
        let mut config = valid_config();
        config.token = String::new();

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(error, ConfigValidationError::EmptyApiToken));
    }

    #[test]
    fn rejects_weak_or_placeholder_secrets() {
        let mut config = valid_config();
        config.token = "short-token".to_string();
        assert!(matches!(
            validate_config(&config).unwrap_err(),
            ConfigValidationError::WeakApiToken
        ));

        let mut config = valid_config();
        config.token = "REPLACE_WITH_32_BYTE_RANDOM_API_TOKEN".to_string();
        assert!(matches!(
            validate_config(&config).unwrap_err(),
            ConfigValidationError::PlaceholderApiToken
        ));

        let mut config = valid_config();
        config.jwt_signing_key = "REPLACE_WITH_32_BYTE_RANDOM_JWT_SIGNING_KEY".to_string();
        assert!(matches!(
            validate_config(&config).unwrap_err(),
            ConfigValidationError::PlaceholderJwtSigningKey
        ));
    }

    #[test]
    fn rejects_reusing_api_token_as_jwt_signing_key() {
        let mut config = valid_config();
        config.jwt_signing_key = config.token.clone();

        assert!(matches!(
            validate_config(&config).unwrap_err(),
            ConfigValidationError::ReusedJwtSigningKey
        ));
    }

    #[test]
    fn rejects_exposed_cleartext_listeners_without_development_override() {
        let mut config = valid_config();
        config.postgres.bind = "0.0.0.0:5432".to_string();

        assert!(matches!(
            validate_config(&config).unwrap_err(),
            ConfigValidationError::InsecurePublicListener {
                field: "postgres",
                ..
            }
        ));

        config.security.allow_insecure_public_listeners = true;
        validate_config(&config).unwrap();
    }

    #[test]
    fn rejects_direct_public_api_without_development_override() {
        let mut config = valid_config();
        config.api.host = "0.0.0.0".to_string();

        assert!(matches!(
            validate_config(&config).unwrap_err(),
            ConfigValidationError::DirectPublicApiUnsupported { .. }
        ));

        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("certificate.pem");
        let private_key = directory.path().join("private-key.pem");
        std::fs::write(&certificate, b"test certificate").unwrap();
        std::fs::write(&private_key, b"test key").unwrap();
        config.api.ssl.enabled = true;
        config.api.ssl.cert = certificate.display().to_string();
        config.api.ssl.key = private_key.display().to_string();
        assert!(matches!(
            validate_config(&config).unwrap_err(),
            ConfigValidationError::DirectPublicApiUnsupported { .. }
        ));
    }

    #[test]
    fn rejects_hostname_api_bind_even_when_named_localhost() {
        for host in ["localhost", "dbe.internal"] {
            let mut config = valid_config();
            config.api.host = host.to_string();

            assert!(matches!(
                validate_config(&config).unwrap_err(),
                ConfigValidationError::DirectPublicApiUnsupported { .. }
            ));
        }
    }

    #[test]
    fn accepts_literal_ipv4_and_ipv6_loopback_api_binds() {
        for host in ["127.0.0.1", "::1"] {
            let mut config = valid_config();
            config.api.host = host.to_string();

            validate_config(&config).unwrap();
        }
    }

    #[test]
    fn accepts_exposed_listeners_when_tls_is_configured() {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("certificate.pem");
        let private_key = directory.path().join("private-key.pem");
        std::fs::write(&certificate, b"test certificate").unwrap();
        std::fs::write(&private_key, b"test key").unwrap();

        let mut config = valid_config();
        config.api.ssl.enabled = true;
        config.api.ssl.cert = certificate.display().to_string();
        config.api.ssl.key = private_key.display().to_string();
        config.postgres.bind = "0.0.0.0:5432".to_string();
        config.postgres.tls = true;
        config.tls.cert = certificate.display().to_string();
        config.tls.key = private_key.display().to_string();

        validate_config(&config).unwrap();
    }

    #[test]
    fn rejects_invalid_daemon_ipam() {
        let mut config = valid_config();
        config.daemon.ipam.subnet = "172.30.0.0".to_string();

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(error, ConfigValidationError::InvalidCidr { .. }));
    }

    #[test]
    fn rejects_daemon_gateway_without_subnet() {
        let mut config = valid_config();
        config.daemon.ipam.gateway = "172.30.0.1".to_string();

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(
            error,
            ConfigValidationError::GatewayRequiresSubnet
        ));
    }

    #[test]
    fn accepts_absolute_container_engine_socket_path() {
        let mut config = valid_config();
        config.daemon.socket_path = "/run/podman/podman.sock".to_string();

        validate_config(&config).unwrap();
    }

    #[test]
    fn rejects_relative_container_engine_socket_path() {
        let mut config = valid_config();
        config.daemon.socket_path = "podman.sock".to_string();

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(
            error,
            ConfigValidationError::RelativePath {
                field: "daemon.socket_path",
                ..
            }
        ));
    }

    #[test]
    fn identifies_kernels_affected_by_mongodb_8_incompatibility() {
        assert!(!kernel_is_6_19_or_newer("6.18.20"));
        assert!(kernel_is_6_19_or_newer("6.19.0"));
        assert!(kernel_is_6_19_or_newer("7.0.12-1-cachyos"));
    }

    #[test]
    fn identifies_mongodb_8_or_latest_images() {
        assert!(!mongodb_image_is_8_or_newer("mongo:7.0.37"));
        assert!(mongodb_image_is_8_or_newer("mongo:8.3.4"));
        assert!(mongodb_image_is_8_or_newer(
            "mongo:8.3.4@sha256:0f887198e29c093fd2b36c3e2eb43c7b98e47c081d89fbd5bc212da0cd43ec58"
        ));
        assert!(mongodb_image_is_8_or_newer("mongo:latest"));
        assert!(mongodb_image_is_8_or_newer("docker.io/library/mongo:8"));
    }

    #[test]
    fn rejects_unpinned_or_latest_runtime_images() {
        let mut config = valid_config();
        config.images.clickhouse = "clickhouse/clickhouse-server:26.4.4.38".to_string();

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(
            error,
            ConfigValidationError::InvalidImageReference {
                field: "images.clickhouse",
                ..
            }
        ));

        let mut config = valid_config();
        config.images.qdrant = "qdrant/qdrant".to_string();

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(
            error,
            ConfigValidationError::InvalidImageReference {
                field: "images.qdrant",
                ..
            }
        ));
    }

    #[test]
    fn rejects_unpinned_or_latest_allowed_images() {
        let mut config = valid_config();
        config.images.allowed.postgres = vec!["postgres:latest".to_string()];

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(
            error,
            ConfigValidationError::InvalidImageReference {
                field: "images.allowed.postgres",
                ..
            }
        ));
    }

    #[test]
    fn rejects_zero_project_id_base() {
        let mut config = valid_config();
        config.disk.mode = DiskLimitMode::ProjectQuota;
        config.disk.project_id_base = 0;

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(error, ConfigValidationError::InvalidProjectIdBase));
    }

    #[test]
    fn external_fuse_helper_requires_absolute_path_and_sha256() {
        let mut config = valid_config();
        config.disk.fuse_quota_binary = "bin/fusequota".to_string();
        config.disk.fuse_quota_binary_sha256 = "a".repeat(64);

        assert!(matches!(
            validate_config(&config).unwrap_err(),
            ConfigValidationError::RelativePath {
                field: "disk.fuse_quota_binary",
                ..
            }
        ));

        config.disk.fuse_quota_binary = "/usr/local/libexec/fusequota".to_string();
        config.disk.fuse_quota_binary_sha256 = "A".repeat(64);
        assert!(matches!(
            validate_config(&config).unwrap_err(),
            ConfigValidationError::InvalidFuseQuotaBinarySha256
        ));

        config.disk.fuse_quota_binary_sha256 = "a".repeat(64);
        validate_config(&config).unwrap();
    }

    #[test]
    fn accepts_remote_for_cors() {
        let mut config = valid_config();
        config.remote = "https://panel.example.com".to_string();
        config.api.host = "0.0.0.0".to_string();
        config.security.allow_insecure_public_listeners = true;

        validate_config(&config).unwrap();

        assert_eq!(config.api.bind_addr(), "0.0.0.0:8090");
        assert_eq!(config.cors_allowed_hosts(), vec!["panel.example.com"]);
    }

    #[test]
    fn rejects_url_shaped_api_host() {
        let mut config = valid_config();
        config.api.host = "https://dbe.example.com".to_string();

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(
            error,
            ConfigValidationError::InvalidApiHost { .. }
        ));
    }

    #[test]
    fn rejects_invalid_remote() {
        let mut config = valid_config();
        config.remote = "panel.example.com".to_string();

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(error, ConfigValidationError::InvalidRemoteUrl));
    }

    fn valid_config() -> Config {
        Config {
            uuid: "node-uuid".to_string(),
            token_id: "token-id".to_string(),
            token: "test-api-token-0123456789abcdef-01".to_string(),
            jwt_signing_key: "test-jwt-signing-key-0123456789abcdef-02".to_string(),
            remote: "https://panel.example.com".to_string(),
            ..Default::default()
        }
    }
}
