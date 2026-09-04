use http::HeaderValue;
use serde::Deserialize;

use crate::{
    api::http::{
        policy::{DestructiveActionConfirmation, DestructiveActionPolicy},
        response::ApiError,
    },
    config::Config,
    placement::DeploymentMode,
    shared::{
        ids::validate_instance_id,
        limits::{InstanceLimits, validate_runtime_limits},
        protocol::Protocol,
    },
};

pub(crate) const MAX_PASSWORD_CHARACTERS: usize = 4 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInstanceRequest {
    pub instance_id: String,
    pub protocol: Protocol,
    #[serde(default)]
    pub deployment_mode: DeploymentMode,
    pub database: String,
    pub username: String,
    pub password: String,
    pub public_host: String,
    pub public_port: Option<u16>,
    pub project_id: Option<String>,
    pub image: Option<String>,
    pub limits: Option<LimitsRequest>,
    #[serde(default)]
    pub purge_stale_resources: bool,
    pub purge_stale_resources_confirmation: Option<DestructiveActionConfirmation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsRequest {
    pub cpu_cores: f64,
    pub memory_mib: u64,
    pub disk_mib: u64,
}

pub fn validate_create_request(request: &CreateInstanceRequest) -> Result<(), ApiError> {
    validate_instance_id(&request.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    validate_database_name(&request.database)?;
    request
        .deployment_mode
        .check(request.protocol)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    if request.deployment_mode == DeploymentMode::Shared
        && is_reserved_shared_db(request.protocol, &request.database)
    {
        return Err(ApiError::BadRequest(
            "database uses a shared engine system database name".to_string(),
        ));
    }
    validate_username(&request.username)?;
    validate_database_password(request.protocol, &request.password)?;
    if request.public_host.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "public_host must not be empty".to_string(),
        ));
    }
    if let Some(limits) = &request.limits {
        validate_limits(limits)?;
        validate_protocol_limits(request.protocol, limits)?;
    }
    if request.purge_stale_resources {
        let confirmation = request
            .purge_stale_resources_confirmation
            .as_ref()
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "stale resource purge requires purge_stale_resources_confirmation".to_string(),
                )
            })?;
        DestructiveActionPolicy::authorize("stale resource purge", confirmation)?;
    }
    Ok(())
}

pub(crate) fn validate_create_config(
    config: &Config,
    request: &CreateInstanceRequest,
) -> Result<(), ApiError> {
    if config.protocol_enabled(request.protocol) {
        return Ok(());
    }
    Err(ApiError::BadRequest(format!(
        "{} is disabled on this node",
        request.protocol
    )))
}

pub(crate) fn validate_database_password(
    protocol: Protocol,
    password: &str,
) -> Result<(), ApiError> {
    if password.is_empty() {
        return Err(ApiError::BadRequest(
            "password must not be empty".to_string(),
        ));
    }
    if password.chars().count() > MAX_PASSWORD_CHARACTERS {
        return Err(ApiError::BadRequest(format!(
            "password must not exceed {MAX_PASSWORD_CHARACTERS} characters"
        )));
    }
    if password
        .bytes()
        .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    {
        return Err(ApiError::BadRequest(
            "password must contain no NUL bytes or line breaks".to_string(),
        ));
    }
    if protocol == Protocol::Qdrant && HeaderValue::from_str(password).is_err() {
        return Err(ApiError::BadRequest(
            "qdrant password contains characters that are invalid in an API-key header".to_string(),
        ));
    }
    Ok(())
}

fn validate_database_name(value: &str) -> Result<(), ApiError> {
    validate_database_identifier("database", value)?;
    if matches!(
        value.to_ascii_lowercase().as_str(),
        "postgres" | "template0" | "template1" | "mysql" | "information_schema" | "admin" | "local"
    ) {
        return Err(ApiError::BadRequest(
            "database uses a reserved name".to_string(),
        ));
    }
    Ok(())
}

fn validate_username(value: &str) -> Result<(), ApiError> {
    validate_database_identifier("username", value)?;
    if matches!(
        value.to_ascii_lowercase().as_str(),
        "root"
            | "admin"
            | "postgres"
            | "mysql"
            | "default"
            | crate::databases::postgres::docker::INTERNAL_ADMIN_USERNAME
            | "dbe_health"
    ) {
        return Err(ApiError::BadRequest(
            "username uses a reserved name".to_string(),
        ));
    }
    Ok(())
}

fn is_reserved_shared_db(protocol: Protocol, database: &str) -> bool {
    let database = database.to_ascii_lowercase();
    match protocol {
        Protocol::Postgres => database == crate::databases::postgres::docker::CONTROL_DATABASE,
        Protocol::Mysql | Protocol::Mariadb => {
            matches!(database.as_str(), "performance_schema" | "sys")
        }
        Protocol::Mongodb => database == "config",
        Protocol::Clickhouse => matches!(database.as_str(), "dbe_control" | "default" | "system"),
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => false,
    }
}

fn validate_database_identifier(kind: &str, value: &str) -> Result<(), ApiError> {
    if value.trim() != value || value.is_empty() || value.len() > 63 {
        return Err(ApiError::BadRequest(format!(
            "{kind} must be 1-63 characters with no surrounding whitespace"
        )));
    }
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(ApiError::BadRequest(format!("{kind} must not be empty")));
    };
    if !first.is_ascii_alphabetic() {
        return Err(ApiError::BadRequest(format!(
            "{kind} must start with an ascii letter"
        )));
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')) {
        return Err(ApiError::BadRequest(format!(
            "{kind} may only contain ascii letters, digits, underscore, or dash"
        )));
    }
    Ok(())
}

pub fn validate_limits(limits: &LimitsRequest) -> Result<(), ApiError> {
    validate_runtime_limits(limits.cpu_cores, limits.memory_mib)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    if limits.disk_mib == 0 {
        return Err(ApiError::BadRequest(
            "disk_mib must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_protocol_limits(
    protocol: Protocol,
    limits: &LimitsRequest,
) -> Result<(), ApiError> {
    if protocol == Protocol::Mongodb {
        if limits.memory_mib < 1024 {
            return Err(ApiError::BadRequest(
                "mongodb memory_mib must be at least 1024".to_string(),
            ));
        }
        if limits.disk_mib < 1024 {
            return Err(ApiError::BadRequest(
                "mongodb disk_mib must be at least 1024".to_string(),
            ));
        }
    }
    if protocol == Protocol::Clickhouse {
        if limits.memory_mib < 1024 {
            return Err(ApiError::BadRequest(
                "clickhouse memory_mib must be at least 1024".to_string(),
            ));
        }
        if limits.disk_mib < 1024 {
            return Err(ApiError::BadRequest(
                "clickhouse disk_mib must be at least 1024".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn limits_from_request(request: &LimitsRequest) -> InstanceLimits {
    InstanceLimits {
        cpu_cores: request.cpu_cores,
        memory_mib: request.memory_mib,
        disk_mib: request.disk_mib,
        disk_enforced: false,
        disk_enforcement_method: "not_supported".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(memory_mib: u64, disk_mib: u64) -> LimitsRequest {
        LimitsRequest {
            cpu_cores: 0.5,
            memory_mib,
            disk_mib,
        }
    }

    #[test]
    fn protocol_startup_resource_floors_are_enforced() {
        for protocol in [Protocol::Mongodb, Protocol::Clickhouse] {
            for (name, requested, field) in [
                ("low memory", limits(512, 1024), "memory_mib"),
                ("low disk", limits(1024, 768), "disk_mib"),
            ] {
                let error = validate_protocol_limits(protocol, &requested).unwrap_err();
                assert!(
                    error.to_string().contains(field),
                    "{protocol:?} {name} reported the wrong field: {error}"
                );
            }
            validate_protocol_limits(protocol, &limits(1024, 1024)).unwrap();
        }
    }

    #[test]
    fn database_and_username_identifier_policy_is_enforced() {
        for database in ["bad.name", "postgres"] {
            assert!(
                validate_database_name(database).is_err(),
                "accepted database name: {database}"
            );
        }
        for username in ["bad user", "-bad", "root", "dbe_admin", "dbe_health"] {
            assert!(
                validate_username(username).is_err(),
                "accepted username: {username}"
            );
        }
        validate_database_name("app_db-1").unwrap();
        validate_database_name("dbe_control").unwrap();
        validate_username("app_user-1").unwrap();
    }

    #[test]
    fn create_password_validation_rejects_unsafe_values_for_every_protocol() {
        for protocol in Protocol::ALL {
            assert!(validate_database_password(protocol, "").is_err());
            assert!(validate_database_password(protocol, "line\nbreak").is_err());
            assert!(validate_database_password(protocol, "nul\0byte").is_err());
            assert!(
                validate_database_password(protocol, &"x".repeat(MAX_PASSWORD_CHARACTERS + 1))
                    .is_err()
            );
        }
        assert!(validate_database_password(Protocol::Qdrant, "bad\u{7f}header").is_err());
        assert!(validate_database_password(Protocol::Postgres, "valid password").is_ok());
    }

    #[test]
    fn rejects_non_finite_cpu_limits() {
        for cpu_cores in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let error = validate_limits(&LimitsRequest {
                cpu_cores,
                memory_mib: 1024,
                disk_mib: 1024,
            })
            .unwrap_err();

            assert!(error.to_string().contains("finite"));
        }
    }

    #[test]
    fn rejects_memory_limit_that_would_overflow_docker_bytes() {
        let error = validate_limits(&LimitsRequest {
            cpu_cores: 1.0,
            memory_mib: 1_u64 << 44,
            disk_mib: 1024,
        })
        .unwrap_err();

        assert!(error.to_string().contains("memory_mib"));
    }

    #[test]
    fn stale_resource_purge_requires_central_confirmation() {
        let request: CreateInstanceRequest = serde_json::from_value(serde_json::json!({
            "instance_id": "inst_test_pg",
            "protocol": "postgres",
            "database": "test_db",
            "username": "test_user",
            "password": "secret",
            "public_host": "127.0.0.1",
            "purge_stale_resources": true
        }))
        .unwrap();

        assert!(validate_create_request(&request).is_err());
    }

    #[test]
    fn omitted_deployment_mode_keeps_dedicated_behavior() {
        let request: CreateInstanceRequest = serde_json::from_value(serde_json::json!({
            "instance_id": "inst_test_pg",
            "protocol": "postgres",
            "database": "test_db",
            "username": "test_user",
            "password": "secret",
            "public_host": "127.0.0.1"
        }))
        .unwrap();

        assert_eq!(request.deployment_mode, DeploymentMode::Dedicated);
        validate_create_request(&request).unwrap();
    }

    #[test]
    fn shared_create_policy_matches_protocol_capabilities() {
        for protocol in Protocol::ALL {
            let request: CreateInstanceRequest = serde_json::from_value(serde_json::json!({
                "instance_id": "inst_test_cache",
                "protocol": protocol,
                "deployment_mode": "shared",
                "database": "test_db",
                "username": "test_user",
                "password": "secret",
                "public_host": "127.0.0.1"
            }))
            .unwrap();

            let result = validate_create_request(&request);
            assert_eq!(
                result.is_ok(),
                DeploymentMode::Shared.supports(protocol),
                "unexpected shared create policy for {protocol}"
            );
            if let Err(error) = result {
                assert_eq!(error.status(), http::StatusCode::BAD_REQUEST);
                assert!(error.to_string().contains("cannot use shared deployment"));
            }
        }
    }

    #[test]
    fn disabled_protocol_rejects_dedicated_and_shared_create() {
        let mut config = Config::default();
        config.postgres.enabled = false;
        config.redis.enabled = false;
        config.valkey.enabled = false;
        config.mariadb.enabled = false;
        config.mysql.enabled = false;
        config.mongodb.enabled = false;
        config.clickhouse.enabled = false;
        config.qdrant.enabled = false;

        for protocol in Protocol::ALL {
            let request: CreateInstanceRequest = serde_json::from_value(serde_json::json!({
                "instance_id": "inst_test_mysql",
                "protocol": protocol,
                "deployment_mode": "dedicated",
                "database": "test_db",
                "username": "test_user",
                "password": "secret",
                "public_host": "127.0.0.1"
            }))
            .unwrap();

            validate_create_request(&request).unwrap();
            let error = validate_create_config(&config, &request).unwrap_err();
            assert_eq!(error.status(), http::StatusCode::BAD_REQUEST);
            assert!(
                error
                    .to_string()
                    .contains(&format!("{protocol} is disabled"))
            );

            match protocol {
                Protocol::Postgres => config.postgres.enabled = true,
                Protocol::Redis => config.redis.enabled = true,
                Protocol::Valkey => config.valkey.enabled = true,
                Protocol::Mariadb => config.mariadb.enabled = true,
                Protocol::Mysql => config.mysql.enabled = true,
                Protocol::Mongodb => config.mongodb.enabled = true,
                Protocol::Clickhouse => config.clickhouse.enabled = true,
                Protocol::Qdrant => config.qdrant.enabled = true,
            }
            validate_create_config(&config, &request).unwrap();
            for other in Protocol::ALL {
                assert_eq!(config.protocol_enabled(other), other == protocol);
            }
            match protocol {
                Protocol::Postgres => config.postgres.enabled = false,
                Protocol::Redis => config.redis.enabled = false,
                Protocol::Valkey => config.valkey.enabled = false,
                Protocol::Mariadb => config.mariadb.enabled = false,
                Protocol::Mysql => config.mysql.enabled = false,
                Protocol::Mongodb => config.mongodb.enabled = false,
                Protocol::Clickhouse => config.clickhouse.enabled = false,
                Protocol::Qdrant => config.qdrant.enabled = false,
            }
        }

        for protocol in Protocol::ALL
            .into_iter()
            .filter(|protocol| DeploymentMode::Shared.supports(*protocol))
        {
            let request: CreateInstanceRequest = serde_json::from_value(serde_json::json!({
                "instance_id": "inst_test_shared",
                "protocol": protocol,
                "deployment_mode": "shared",
                "database": "test_db",
                "username": "test_user",
                "password": "secret",
                "public_host": "127.0.0.1"
            }))
            .unwrap();
            validate_create_request(&request).unwrap();
            assert_eq!(
                validate_create_config(&config, &request)
                    .unwrap_err()
                    .status(),
                http::StatusCode::BAD_REQUEST
            );
        }
    }

    #[test]
    fn shared_engines_reserve_system_databases_without_affecting_dedicated() {
        for (protocol, deployment_mode, accepted) in [
            (Protocol::Postgres, DeploymentMode::Dedicated, true),
            (Protocol::Clickhouse, DeploymentMode::Dedicated, true),
            (Protocol::Postgres, DeploymentMode::Shared, false),
            (Protocol::Clickhouse, DeploymentMode::Shared, false),
            (Protocol::Mysql, DeploymentMode::Shared, true),
        ] {
            let request: CreateInstanceRequest = serde_json::from_value(serde_json::json!({
                "instance_id": "inst_test_control_name",
                "protocol": protocol,
                "deployment_mode": deployment_mode,
                "database": "dbe_control",
                "username": "test_user",
                "password": "secret",
                "public_host": "127.0.0.1"
            }))
            .unwrap();

            assert_eq!(validate_create_request(&request).is_ok(), accepted);
        }

        for (protocol, database) in [
            (Protocol::Mysql, "performance_schema"),
            (Protocol::Mariadb, "sys"),
            (Protocol::Mongodb, "config"),
            (Protocol::Clickhouse, "default"),
            (Protocol::Clickhouse, "system"),
        ] {
            let mut request: CreateInstanceRequest = serde_json::from_value(serde_json::json!({
                "instance_id": "inst_test_system_name",
                "protocol": protocol,
                "deployment_mode": "shared",
                "database": database,
                "username": "test_user",
                "password": "secret",
                "public_host": "127.0.0.1"
            }))
            .unwrap();

            assert!(
                validate_create_request(&request).is_err(),
                "{protocol}:{database}"
            );
            request.deployment_mode = DeploymentMode::Dedicated;
            assert!(
                validate_create_request(&request).is_ok(),
                "{protocol}:{database}"
            );
        }
    }
}
