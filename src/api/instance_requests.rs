use serde::Deserialize;

use crate::{
    api::handlers::ApiError,
    shared::{ids::validate_instance_id, limits::InstanceLimits, protocol::Protocol},
};

#[derive(Debug, Deserialize)]
pub struct CreateInstanceRequest {
    pub instance_id: String,
    pub protocol: Protocol,
    pub database: String,
    pub username: String,
    pub password: String,
    pub public_host: String,
    pub public_port: Option<u16>,
    pub project_id: Option<String>,
    pub image: Option<String>,
    pub limits: Option<LimitsRequest>,
}

#[derive(Debug, Deserialize)]
pub struct LimitsRequest {
    pub cpu_cores: f64,
    pub memory_mib: u64,
    pub disk_mib: u64,
}

pub fn validate_create_request(request: &CreateInstanceRequest) -> Result<(), ApiError> {
    validate_instance_id(&request.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    validate_database_name(&request.database)?;
    validate_username(&request.username)?;
    if request.password.is_empty() {
        return Err(ApiError::BadRequest(
            "password must not be empty".to_string(),
        ));
    }
    if request.public_host.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "public_host must not be empty".to_string(),
        ));
    }
    if let Some(limits) = &request.limits {
        validate_limits(limits)?;
        validate_protocol_limits(request.protocol, limits)?;
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
        "root" | "admin" | "postgres" | "mysql" | "default" | "dbe_health"
    ) {
        return Err(ApiError::BadRequest(
            "username uses a reserved name".to_string(),
        ));
    }
    Ok(())
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
    if limits.cpu_cores <= 0.0 {
        return Err(ApiError::BadRequest(
            "cpu_cores must be greater than zero".to_string(),
        ));
    }
    if limits.memory_mib == 0 {
        return Err(ApiError::BadRequest(
            "memory_mib must be greater than zero".to_string(),
        ));
    }
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
    fn mongodb_requires_startup_memory_floor() {
        let error = validate_protocol_limits(Protocol::Mongodb, &limits(512, 1024)).unwrap_err();

        assert!(error.to_string().contains("memory_mib"));
    }

    #[test]
    fn mongodb_requires_startup_disk_floor() {
        let error = validate_protocol_limits(Protocol::Mongodb, &limits(1024, 768)).unwrap_err();

        assert!(error.to_string().contains("disk_mib"));
    }

    #[test]
    fn mongodb_accepts_startup_resource_floor() {
        validate_protocol_limits(Protocol::Mongodb, &limits(1024, 1024)).unwrap();
    }

    #[test]
    fn clickhouse_requires_startup_resource_floor() {
        let memory_error =
            validate_protocol_limits(Protocol::Clickhouse, &limits(512, 1024)).unwrap_err();
        let disk_error =
            validate_protocol_limits(Protocol::Clickhouse, &limits(1024, 768)).unwrap_err();

        assert!(memory_error.to_string().contains("memory_mib"));
        assert!(disk_error.to_string().contains("disk_mib"));
    }

    #[test]
    fn rejects_database_and_username_metacharacters() {
        assert!(validate_database_name("bad.name").is_err());
        assert!(validate_username("bad user").is_err());
        assert!(validate_username("-bad").is_err());
    }

    #[test]
    fn rejects_reserved_database_and_usernames() {
        assert!(validate_database_name("postgres").is_err());
        assert!(validate_username("root").is_err());
        assert!(validate_username("dbe_health").is_err());
    }

    #[test]
    fn accepts_database_and_username_identifiers() {
        validate_database_name("app_db-1").unwrap();
        validate_username("app_user-1").unwrap();
    }
}
