use super::*;

pub(in super::super) fn log_boot_config(config: &Config, config_path: &Path) {
    tracing::info!(
        config = %config_path.display(),
        data = %config.paths.data,
        metadata = %config.paths.metadata_root(),
        logs = %config.paths.logs,
        sockets = %config.paths.sockets,
        artifacts = %config.paths.artifacts,
        "configured paths"
    );
    tracing::info!(
        api_bind = %config.api.bind_addr(),
        api_host = %config.api.host,
        api_port = config.api.port,
        remote = %config.remote,
        cors_allowed_origins = ?config.cors_allowed_origins(),
        body_limit_bytes = config.security.api_body_limit_bytes,
        api_rate_limit_per_minute = config.security.api_rate_limit_per_minute,
        "api configuration"
    );
    if !config.api.fqdn.trim().is_empty() {
        tracing::warn!(
            "api.fqdn is a legacy setting and is ignored; configure the daemon's public IP or hostname in the panel"
        );
    }
    if !config.api.trusted_hosts.is_empty() {
        tracing::warn!(
            "api.trusted_hosts is retired and ignored; authenticate server clients with API tokens and restrict browser callers with api.trusted_origins"
        );
    }
    log_api_host_resolution(config);
    log_tls_config(config);
    tracing::info!(
        default_pids_limit = config.security.pids_limit,
        postgres = ?config.security.pids_limits.postgres,
        redis = ?config.security.pids_limits.redis,
        valkey = ?config.security.pids_limits.valkey,
        mariadb = ?config.security.pids_limits.mariadb,
        mysql = ?config.security.pids_limits.mysql,
        mongodb = ?config.security.pids_limits.mongodb,
        clickhouse = ?config.security.pids_limits.clickhouse,
        qdrant = ?config.security.pids_limits.qdrant,
        "container pid limits configured"
    );
    tracing::info!(
        postgres = %config.images.postgres,
        redis = %config.images.redis,
        valkey = %config.images.valkey,
        mariadb = %config.images.mariadb,
        mysql = %config.images.mysql,
        mongodb = %config.images.mongodb,
        clickhouse = %config.images.clickhouse,
        qdrant = %config.images.qdrant,
        "database images configured"
    );
    let mutable_images: Vec<&str> = [
        config.images.postgres.as_str(),
        config.images.redis.as_str(),
        config.images.valkey.as_str(),
        config.images.mariadb.as_str(),
        config.images.mysql.as_str(),
        config.images.mongodb.as_str(),
        config.images.clickhouse.as_str(),
        config.images.qdrant.as_str(),
    ]
    .into_iter()
    .filter(|image| !has_sha256_digest(image))
    .collect();
    if !mutable_images.is_empty() {
        tracing::warn!(
            images = ?mutable_images,
            "database image tags are mutable; version tags are accepted, while sha256 digests provide stronger reproducibility"
        );
    }
    tracing::info!(
        mode = %config.disk.mode.method(),
        enforced = config.disk.mode.enforced(),
        project_id_base = config.disk.project_id_base,
        fuse_quota_binary = %config.disk.fuse_quota_binary(),
        "disk limiter configured"
    );
    if config.security.remote_import.enabled {
        tracing::info!(
            allow_plaintext = config.security.remote_import.allow_plaintext,
            allowed_private_hosts = config.security.remote_import.allowed_private_hosts.len(),
            max_concurrent_jobs = config.security.remote_import.max_concurrent_jobs,
            "remote credential imports enabled by node policy; target database containers remain network-isolated"
        );
    } else {
        tracing::info!("remote credential imports disabled by node policy");
    }
}

pub(in super::super) fn log_api_host_resolution(config: &Config) {
    if config.api.host == "0.0.0.0" || config.api.host == "::" {
        tracing::info!(
            host = %config.api.host,
            port = config.api.port,
            "api binds all local interfaces; the panel controls the public connection address"
        );
        return;
    }
    if config.api.host.parse::<IpAddr>().is_ok() {
        tracing::info!(
            host = %config.api.host,
            port = config.api.port,
            "api binds explicit local IP"
        );
        return;
    }

    let target = config.api.bind_addr();
    match target.to_socket_addrs() {
        Ok(addrs) => {
            let resolved: Vec<String> = addrs.map(|addr| addr.to_string()).collect();
            tracing::warn!(
                host = %config.api.host,
                port = config.api.port,
                resolved = ?resolved,
                "api host is a DNS name; bind succeeds only if it resolves to an address assigned to this server"
            );
        }
        Err(error) => {
            tracing::warn!(
                host = %config.api.host,
                port = config.api.port,
                %error,
                "api host DNS resolution failed; use 0.0.0.0 when exposing the daemon by domain"
            );
        }
    }
}

pub(in super::super) fn log_tls_config(config: &Config) {
    if config.api.ssl.enabled {
        log_tls_file("api tls certificate", &config.api.ssl.cert);
        log_tls_file("api tls private key", &config.api.ssl.key);
        tracing::info!(
            require_client_cert = config.api.ssl.require_client_cert,
            client_ca = %empty_as_unset(&config.api.ssl.client_ca),
            "api tls enabled"
        );
        if config.api.ssl.require_client_cert {
            log_tls_file("api tls client ca", &config.api.ssl.client_ca);
        }
    } else {
        let host = config.api.host.trim();
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback());
        if loopback {
            tracing::info!(
                bind = %config.api.bind_addr(),
                "api tls disabled on loopback"
            );
        } else {
            tracing::warn!(
                bind = %config.api.bind_addr(),
                "api serves plaintext HTTP on a non-loopback interface; bearer tokens, credentials, requests, and responses are not protected from network interception"
            );
        }
    }

    if database_tls_enabled(config) {
        log_tls_file("database listener tls certificate", &config.tls.cert);
        log_tls_file("database listener tls private key", &config.tls.key);
        tracing::info!("database gateway tls enabled for at least one protocol");
    } else {
        tracing::info!("database gateway tls disabled for all protocols");
    }
}

pub(in super::super) fn log_tls_file(label: &'static str, path: &str) {
    if path.trim().is_empty() {
        tracing::warn!(label, "tls path is empty");
        return;
    }
    match fs::metadata(path) {
        Ok(metadata) => {
            tracing::info!(
                label,
                path,
                bytes = metadata.len(),
                readonly = metadata.permissions().readonly(),
                "tls file accessible"
            );
        }
        Err(error) => {
            tracing::error!(label, path, %error, "tls file is not accessible");
        }
    }
}

pub(in super::super) fn database_tls_enabled(config: &Config) -> bool {
    config.postgres.tls
        || config.redis.tls
        || config.valkey.tls
        || config.mariadb.tls
        || config.mysql.tls
        || config.mongodb.tls
        || config.clickhouse.tls
        || config.qdrant.tls
}

pub(in super::super) fn empty_as_unset(value: &str) -> &str {
    if value.trim().is_empty() {
        "<unset>"
    } else {
        value
    }
}

pub(in super::super) fn log_gateway_listeners(config: &Config) {
    log_listener(
        "postgres",
        &config.postgres.bind,
        config.postgres.enabled,
        config.postgres.tls,
    );
    log_listener(
        "redis",
        &config.redis.bind,
        config.redis.enabled,
        config.redis.tls,
    );
    log_listener(
        "valkey",
        &config.valkey.bind,
        config.valkey.enabled,
        config.valkey.tls,
    );
    log_listener(
        "mariadb",
        &config.mariadb.bind,
        config.mariadb.enabled,
        config.mariadb.tls,
    );
    log_listener(
        "mysql",
        &config.mysql.bind,
        config.mysql.enabled,
        config.mysql.tls,
    );
    log_listener(
        "mongodb",
        &config.mongodb.bind,
        config.mongodb.enabled,
        config.mongodb.tls,
    );
    log_listener(
        "clickhouse native",
        &config.clickhouse.bind,
        config.clickhouse.enabled,
        config.clickhouse.tls,
    );
    log_listener(
        "clickhouse http",
        &config.clickhouse.http_bind,
        config.clickhouse.enabled,
        config.clickhouse.tls,
    );
    log_listener(
        "qdrant",
        &config.qdrant.bind,
        config.qdrant.enabled,
        config.qdrant.tls,
    );
}

pub(in super::super) fn log_listener(protocol: &'static str, bind: &str, enabled: bool, tls: bool) {
    if enabled {
        let publicly_reachable = bind
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|address| !address.ip().is_loopback());
        if !tls && publicly_reachable {
            tracing::warn!(
                protocol,
                bind,
                "gateway listener accepts authenticated database traffic without transport encryption"
            );
        } else {
            tracing::info!(protocol, bind, tls, "gateway listener configured");
        }
    } else {
        tracing::info!(protocol, bind, "gateway listener disabled");
    }
}
