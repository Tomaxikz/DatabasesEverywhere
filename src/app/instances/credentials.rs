use secrecy::SecretString;

use super::metadata::InstanceMetadata;
use crate::{placement::DeploymentMode, shared::protocol::Protocol};

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

pub(crate) fn logical_export_env(
    metadata: &InstanceMetadata,
) -> Result<SecretEnvironment, CredentialUnavailable> {
    let environment = match metadata.protocol {
        Protocol::Postgres => {
            tenant_environment(metadata, "DBE_POSTGRES_USER", "DBE_POSTGRES_PASSWORD")
        }
        Protocol::Mariadb => tenant_environment(metadata, "MARIADB_USER", "DBE_MARIADB_PASSWORD"),
        Protocol::Mysql if metadata.deployment_mode == DeploymentMode::Shared => {
            tenant_environment(metadata, "MYSQL_USER", "DBE_MYSQL_PASSWORD")
        }
        Protocol::Mysql => root_environment(metadata, "MYSQL_ROOT_PASSWORD"),
        Protocol::Mongodb if metadata.deployment_mode == DeploymentMode::Shared => {
            tenant_environment(metadata, "DBE_MONGO_USER", "DBE_MONGO_PASSWORD")
        }
        Protocol::Mongodb => root_environment(metadata, "DBE_MONGO_ROOT_PASSWORD"),
        Protocol::Clickhouse => {
            tenant_environment(metadata, "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD")
        }
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => Ok(SecretEnvironment::empty()),
    }?;
    with_database(metadata, environment)
}

pub(crate) fn logical_import_env(
    metadata: &InstanceMetadata,
    database_definition_in_dump: bool,
) -> Result<SecretEnvironment, CredentialUnavailable> {
    if metadata.deployment_mode == DeploymentMode::Shared && database_definition_in_dump {
        return Err(CredentialUnavailable {
            message: "shared imports cannot use an administrator database-definition dump"
                .to_string(),
        });
    }
    let environment = match metadata.protocol {
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
        Protocol::Mongodb if metadata.deployment_mode == DeploymentMode::Shared => {
            tenant_environment(metadata, "DBE_MONGO_USER", "DBE_MONGO_PASSWORD")
        }
        Protocol::Mongodb => root_environment(metadata, "DBE_MONGO_ROOT_PASSWORD"),
        Protocol::Clickhouse => {
            tenant_environment(metadata, "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD")
        }
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => Ok(SecretEnvironment::empty()),
    }?;
    with_database(metadata, environment)
}

fn with_database(
    metadata: &InstanceMetadata,
    mut environment: SecretEnvironment,
) -> Result<SecretEnvironment, CredentialUnavailable> {
    let name = metadata.database.name.trim();
    if name.is_empty() {
        return Err(missing(metadata, "database name"));
    }
    let key = match metadata.protocol {
        Protocol::Postgres => "POSTGRES_DB",
        Protocol::Mariadb => "MARIADB_DATABASE",
        Protocol::Mysql => "MYSQL_DATABASE",
        Protocol::Mongodb => "DBE_MONGO_DATABASE",
        Protocol::Clickhouse => "CLICKHOUSE_DB",
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => return Ok(environment),
    };
    environment
        .values
        .push((key, SecretString::from(name.to_string())));
    Ok(environment)
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
    use crate::instances::test_support;

    fn metadata(protocol: Protocol) -> InstanceMetadata {
        let mut metadata = test_support::metadata("inst_credentials", protocol);
        metadata.database.username = "latest_user".to_string();
        metadata.mariadb_root_password = Some("maria-root".to_string());
        metadata.mysql_root_password = Some("mysql-root".to_string());
        metadata.mongodb_root_password = Some("mongo-root".to_string());
        metadata.postgres_admin_password = Some("pg-admin".to_string());
        metadata.tenant_password = Some("latest-tenant".to_string());
        metadata
    }

    #[test]
    fn postgres_export_uses_the_current_protected_tenant_credential() {
        let environment = logical_export_env(&metadata(Protocol::Postgres)).unwrap();
        let values = environment.references();

        assert_eq!(values[0].0, "DBE_POSTGRES_USER");
        assert_eq!(values[0].1.expose_secret(), "latest_user");
        assert_eq!(values[1].0, "DBE_POSTGRES_PASSWORD");
        assert_eq!(values[1].1.expose_secret(), "latest-tenant");
        assert_eq!(values[2].0, "POSTGRES_DB");
        assert_eq!(values[2].1.expose_secret(), "database");
    }

    #[test]
    fn mysql_root_and_tenant_paths_use_different_current_credentials() {
        let export = logical_export_env(&metadata(Protocol::Mysql)).unwrap();
        assert_eq!(export.references()[0].0, "MYSQL_ROOT_PASSWORD");
        assert_eq!(export.references()[0].1.expose_secret(), "mysql-root");

        let import = logical_import_env(&metadata(Protocol::Mysql), false).unwrap();
        assert_eq!(import.references()[1].0, "DBE_IMPORT_PASSWORD");
        assert_eq!(import.references()[1].1.expose_secret(), "latest-tenant");
    }

    #[test]
    fn missing_current_secret_fails_instead_of_falling_back_to_container_state() {
        let mut metadata = metadata(Protocol::Postgres);
        metadata.tenant_password = None;

        let error = logical_export_env(&metadata).unwrap_err().to_string();
        assert!(error.contains("current encrypted tenant password is missing"));
    }

    #[test]
    fn shared_mysql_and_mongodb_maintenance_uses_only_tenant_secrets() {
        let mut mysql = metadata(Protocol::Mysql);
        mysql.deployment_mode = DeploymentMode::Shared;
        mysql.runtime_id = "pool_mysql".to_string();
        let mysql_export = logical_export_env(&mysql).unwrap();
        assert_eq!(mysql_export.references()[0].0, "MYSQL_USER");
        assert_eq!(mysql_export.references()[1].0, "DBE_MYSQL_PASSWORD");
        assert_eq!(mysql_export.references()[2].0, "MYSQL_DATABASE");
        assert_eq!(mysql_export.references()[2].1.expose_secret(), "database");
        assert!(
            mysql_export
                .references()
                .iter()
                .all(|(name, _)| !name.contains("ROOT"))
        );
        assert!(logical_import_env(&mysql, true).is_err());

        let mut mongo = metadata(Protocol::Mongodb);
        mongo.deployment_mode = DeploymentMode::Shared;
        mongo.runtime_id = "pool_mongodb".to_string();
        let mongo_import = logical_import_env(&mongo, false).unwrap();
        assert_eq!(mongo_import.references()[0].0, "DBE_MONGO_USER");
        assert_eq!(mongo_import.references()[1].0, "DBE_MONGO_PASSWORD");
        assert_eq!(mongo_import.references()[2].0, "DBE_MONGO_DATABASE");
        assert_eq!(mongo_import.references()[2].1.expose_secret(), "database");
        assert!(
            mongo_import
                .references()
                .iter()
                .all(|(name, _)| !name.contains("ROOT"))
        );
    }

    #[test]
    fn every_shared_logical_environment_targets_the_tenant_database() {
        for (protocol, key) in [
            (Protocol::Postgres, "POSTGRES_DB"),
            (Protocol::Mariadb, "MARIADB_DATABASE"),
            (Protocol::Mysql, "MYSQL_DATABASE"),
            (Protocol::Mongodb, "DBE_MONGO_DATABASE"),
            (Protocol::Clickhouse, "CLICKHOUSE_DB"),
        ] {
            let mut metadata = metadata(protocol);
            metadata.deployment_mode = DeploymentMode::Shared;
            metadata.runtime_id = format!("pool_{}", protocol.as_str());

            for environment in [
                logical_export_env(&metadata).unwrap(),
                logical_import_env(&metadata, false).unwrap(),
            ] {
                let databases = environment
                    .references()
                    .into_iter()
                    .filter(|(name, _)| *name == key)
                    .collect::<Vec<_>>();
                assert_eq!(databases.len(), 1, "{protocol} database env count");
                assert_eq!(databases[0].1.expose_secret(), "database");
            }
        }
    }
}
