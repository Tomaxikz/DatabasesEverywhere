use secrecy::SecretString;

use super::metadata::InstanceMetadata;
use crate::shared::protocol::Protocol;

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub(crate) struct CredentialUnavailable {
    message: String,
}

/// Short-lived environment values used by daemon-managed database clients.
///
/// These values come from encrypted metadata after it has been decrypted by
/// the repository. Container environment variables are deliberately not used
/// as an authority here because they are immutable and become stale after a
/// password rotation.
#[derive(Debug)]
pub(crate) struct SecretEnvironment {
    values: Vec<(&'static str, SecretString)>,
}

impl SecretEnvironment {
    fn empty() -> Self {
        Self { values: Vec::new() }
    }

    fn from_values(values: Vec<(&'static str, SecretString)>) -> Self {
        Self { values }
    }

    pub(crate) fn references(&self) -> Vec<(&'static str, &SecretString)> {
        self.values
            .iter()
            .map(|(name, value)| (*name, value))
            .collect()
    }
}

pub(crate) fn logical_export_environment(
    metadata: &InstanceMetadata,
) -> Result<SecretEnvironment, CredentialUnavailable> {
    match metadata.protocol {
        Protocol::Postgres => {
            tenant_environment(metadata, "DBE_POSTGRES_USER", "DBE_POSTGRES_PASSWORD")
        }
        Protocol::Mariadb => tenant_environment(metadata, "MARIADB_USER", "DBE_MARIADB_PASSWORD"),
        Protocol::Mysql => root_environment(metadata, "MYSQL_ROOT_PASSWORD"),
        Protocol::Mongodb => root_environment(metadata, "DBE_MONGO_ROOT_PASSWORD"),
        Protocol::Clickhouse => {
            tenant_environment(metadata, "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD")
        }
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => Ok(SecretEnvironment::empty()),
    }
}

pub(crate) fn logical_import_environment(
    metadata: &InstanceMetadata,
    database_definition_in_dump: bool,
) -> Result<SecretEnvironment, CredentialUnavailable> {
    match metadata.protocol {
        Protocol::Postgres => {
            tenant_environment(metadata, "DBE_POSTGRES_USER", "DBE_POSTGRES_PASSWORD")
        }
        Protocol::Mariadb if database_definition_in_dump => {
            root_environment(metadata, "DBE_MARIADB_ROOT_PASSWORD")
        }
        Protocol::Mariadb => tenant_environment(metadata, "MARIADB_USER", "DBE_MARIADB_PASSWORD"),
        Protocol::Mysql if database_definition_in_dump => {
            root_environment(metadata, "MYSQL_ROOT_PASSWORD")
        }
        Protocol::Mysql => tenant_environment(metadata, "DBE_IMPORT_USER", "DBE_IMPORT_PASSWORD"),
        Protocol::Mongodb => root_environment(metadata, "DBE_MONGO_ROOT_PASSWORD"),
        Protocol::Clickhouse => {
            tenant_environment(metadata, "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD")
        }
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => Ok(SecretEnvironment::empty()),
    }
}

fn tenant_environment(
    metadata: &InstanceMetadata,
    username_name: &'static str,
    password_name: &'static str,
) -> Result<SecretEnvironment, CredentialUnavailable> {
    let username = metadata.database.username.trim();
    if username.is_empty() {
        return Err(missing(metadata, "tenant username"));
    }
    let password = required_secret(
        metadata,
        metadata.tenant_password.as_deref(),
        "tenant password",
    )?;
    Ok(SecretEnvironment::from_values(vec![
        (username_name, SecretString::from(username.to_string())),
        (password_name, SecretString::from(password.to_string())),
    ]))
}

fn root_environment(
    metadata: &InstanceMetadata,
    password_name: &'static str,
) -> Result<SecretEnvironment, CredentialUnavailable> {
    let (value, description) = match metadata.protocol {
        Protocol::Mariadb => (
            metadata.mariadb_root_password.as_deref(),
            "MariaDB maintenance password",
        ),
        Protocol::Mysql => (
            metadata.mysql_root_password.as_deref(),
            "MySQL maintenance password",
        ),
        Protocol::Mongodb => (
            metadata.mongodb_root_password.as_deref(),
            "MongoDB maintenance password",
        ),
        _ => (None, "maintenance password"),
    };
    let password = required_secret(metadata, value, description)?;
    Ok(SecretEnvironment::from_values(vec![(
        password_name,
        SecretString::from(password.to_string()),
    )]))
}

fn required_secret<'a>(
    metadata: &InstanceMetadata,
    value: Option<&'a str>,
    description: &str,
) -> Result<&'a str, CredentialUnavailable> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| missing(metadata, description))
}

fn missing(metadata: &InstanceMetadata, description: &str) -> CredentialUnavailable {
    CredentialUnavailable {
        message: format!(
            "the current encrypted {description} is missing for {}; reset or repair this instance before running maintenance operations",
            metadata.protocol.as_str()
        ),
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;
    use crate::{
        instances::metadata::{
            DatabaseIdentity, DesiredInstanceState, InstanceStatus, PublicEndpoint, RuntimeKind,
            RuntimeMetadata, SCHEMA_VERSION,
        },
        shared::{backend::BackendEndpoint, limits::InstanceLimits},
    };

    fn metadata(protocol: Protocol) -> InstanceMetadata {
        InstanceMetadata {
            schema_version: SCHEMA_VERSION,
            instance_id: "inst_credentials".to_string(),
            protocol,
            status: InstanceStatus::Running,
            desired_state: DesiredInstanceState::Running,
            disk_limit_blocked: false,
            public: PublicEndpoint {
                host: "127.0.0.1".to_string(),
                port: 1,
            },
            backend: BackendEndpoint::DockerTcp {
                host: "127.0.0.1".to_string(),
                port: 2,
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: "container".to_string(),
                network_mode: "none".to_string(),
            },
            database: DatabaseIdentity {
                name: "database".to_string(),
                username: "latest_user".to_string(),
            },
            route_key_sha256: None,
            mariadb_native_password_sha1_stage2: None,
            mariadb_root_password: Some("maria-root".to_string()),
            mysql_native_password_sha1_stage2: None,
            mysql_root_password: Some("mysql-root".to_string()),
            mongodb_root_password: Some("mongo-root".to_string()),
            postgres_admin_password: Some("pg-admin".to_string()),
            tenant_password: Some("latest-tenant".to_string()),
            limits: InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "now".to_string(),
            updated_at: "now".to_string(),
        }
    }

    #[test]
    fn postgres_export_uses_the_current_protected_tenant_credential() {
        let environment = logical_export_environment(&metadata(Protocol::Postgres)).unwrap();
        let values = environment.references();

        assert_eq!(values[0].0, "DBE_POSTGRES_USER");
        assert_eq!(values[0].1.expose_secret(), "latest_user");
        assert_eq!(values[1].0, "DBE_POSTGRES_PASSWORD");
        assert_eq!(values[1].1.expose_secret(), "latest-tenant");
    }

    #[test]
    fn mysql_root_and_tenant_paths_use_different_current_credentials() {
        let export = logical_export_environment(&metadata(Protocol::Mysql)).unwrap();
        assert_eq!(export.references()[0].0, "MYSQL_ROOT_PASSWORD");
        assert_eq!(export.references()[0].1.expose_secret(), "mysql-root");

        let import = logical_import_environment(&metadata(Protocol::Mysql), false).unwrap();
        assert_eq!(import.references()[1].0, "DBE_IMPORT_PASSWORD");
        assert_eq!(import.references()[1].1.expose_secret(), "latest-tenant");
    }

    #[test]
    fn missing_current_secret_fails_instead_of_falling_back_to_container_state() {
        let mut metadata = metadata(Protocol::Postgres);
        metadata.tenant_password = None;

        let error = logical_export_environment(&metadata)
            .unwrap_err()
            .to_string();
        assert!(error.contains("current encrypted tenant password is missing"));
    }
}
