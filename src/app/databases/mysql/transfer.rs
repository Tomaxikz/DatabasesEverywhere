use crate::{
    databases::engine::{
        EngineInfo, EngineTransfer, ImportConnection, LogicalCredential, LogicalImportRequest,
        RemoteDumpFlow, SelectionUse, TransferError,
    },
    databases::protocol::Protocol,
    server::jobs::import_export::selection::{ImportExportSelection, SelectionMode},
    server::placement::DeploymentMode,
    server::{credentials::logical_import_env, metadata::InstanceMetadata},
    utils::shell::sh_quote,
};

use super::engine::Mysql;

impl EngineTransfer for Mysql {
    fn validate_selection_items(
        &self,
        selection: &ImportExportSelection,
        use_case: SelectionUse,
    ) -> Result<(), TransferError> {
        self.validate_sql_selection_items(selection, use_case)
    }

    fn logical_credential_for_export(&self, deployment_mode: DeploymentMode) -> LogicalCredential {
        if deployment_mode == DeploymentMode::Shared {
            LogicalCredential::Tenant {
                username: "MYSQL_USER",
                password: "DBE_MYSQL_PASSWORD",
            }
        } else {
            LogicalCredential::Root("MYSQL_ROOT_PASSWORD")
        }
    }

    fn logical_credential_for_import(
        &self,
        _deployment_mode: DeploymentMode,
        database_definition_in_dump: bool,
    ) -> LogicalCredential {
        if database_definition_in_dump {
            LogicalCredential::Root("MYSQL_ROOT_PASSWORD")
        } else {
            LogicalCredential::Tenant {
                username: "DBE_IMPORT_USER",
                password: "DBE_IMPORT_PASSWORD",
            }
        }
    }

    fn logical_export_script(
        &self,
        metadata: &InstanceMetadata,
        output_path: &str,
        selection: &ImportExportSelection,
        include_database_definition: bool,
    ) -> Result<String, TransferError> {
        let filters = mysql_family_dump_selection_args(selection, "MYSQL_DATABASE");
        let database_definition = if include_database_definition {
            " --databases"
        } else {
            ""
        };
        if metadata.deployment_mode == DeploymentMode::Shared {
            Ok(format!(
                r#"set -eu
MYSQL_PWD="$DBE_MYSQL_PASSWORD" mysqldump \
  --protocol=socket \
  --socket=/var/run/mysqld/mysqld.sock \
  -u "$MYSQL_USER" \
  --single-transaction --quick --skip-routines --skip-events --skip-triggers \
  --hex-blob --add-drop-table --no-tablespaces --set-gtid-purged=OFF{database_definition}{filters} \
  > {output_path}
"#
            ))
        } else {
            mysql_root_password(metadata)?;
            Ok(format!(
                r#"set -eu
MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqldump \
  --protocol=socket \
  --socket=/var/run/mysqld/mysqld.sock \
  -u root \
  --single-transaction --quick --routines --events --triggers \
  --hex-blob --add-drop-table --no-tablespaces --set-gtid-purged=OFF{database_definition}{filters} \
  > {output_path}
"#
            ))
        }
    }

    fn logical_wipe_script(
        &self,
        metadata: &InstanceMetadata,
        database_definition_in_dump: bool,
    ) -> Result<String, TransferError> {
        if database_definition_in_dump {
            mysql_root_password(metadata)?;
            Ok(r#"set -eu
MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql \
  --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u root \
  -e "DROP DATABASE IF EXISTS \`$MYSQL_DATABASE\`;"
"#
            .to_string())
        } else if metadata.deployment_mode == DeploymentMode::Shared {
            logical_import_env(metadata, false)
                .map_err(|error| TransferError::Conflict(error.to_string()))?;
            Ok(r#"set -eu
{
  printf '%s\n' 'SET FOREIGN_KEY_CHECKS=0;'
  MYSQL_PWD="$DBE_IMPORT_PASSWORD" mysql \
    --protocol=socket --socket=/var/run/mysqld/mysqld.sock \
    -u "$DBE_IMPORT_USER" --batch --skip-column-names "$MYSQL_DATABASE" \
    -e "SELECT CONCAT('DROP VIEW IF EXISTS `', REPLACE(TABLE_NAME, '`', '``'), '`;') FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'VIEW'; SELECT CONCAT('DROP TABLE IF EXISTS `', REPLACE(TABLE_NAME, '`', '``'), '`;') FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'; SELECT CONCAT('DROP PROCEDURE IF EXISTS `', REPLACE(ROUTINE_NAME, '`', '``'), '`;') FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = DATABASE() AND ROUTINE_TYPE = 'PROCEDURE'; SELECT CONCAT('DROP FUNCTION IF EXISTS `', REPLACE(ROUTINE_NAME, '`', '``'), '`;') FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = DATABASE() AND ROUTINE_TYPE = 'FUNCTION';"
  printf '%s\n' 'SET FOREIGN_KEY_CHECKS=1;'
} | MYSQL_PWD="$DBE_IMPORT_PASSWORD" mysql \
  --binary-mode --protocol=socket --socket=/var/run/mysqld/mysqld.sock \
  -u "$DBE_IMPORT_USER" "$MYSQL_DATABASE"
"#
            .to_string())
        } else {
            logical_import_env(metadata, false)
                .map_err(|error| TransferError::Conflict(error.to_string()))?;
            Ok(r#"set -eu
settings=$(MYSQL_PWD="$DBE_IMPORT_PASSWORD" mysql \
  --protocol=socket --socket=/var/run/mysqld/mysqld.sock \
  -u "$DBE_IMPORT_USER" \
  --batch --skip-column-names "$MYSQL_DATABASE" \
  -e 'SELECT @@character_set_database, @@collation_database')
set -- $settings
[ "$#" -eq 2 ] || {
  echo 'failed to read the target database charset and collation' >&2
  exit 43
}
case "$1" in ''|*[!A-Za-z0-9_]*)
  echo 'target database returned an invalid character set name' >&2
  exit 43
;; esac
case "$2" in ''|*[!A-Za-z0-9_]*)
  echo 'target database returned an invalid collation name' >&2
  exit 43
;; esac
MYSQL_PWD="$DBE_IMPORT_PASSWORD" mysql \
  --protocol=socket --socket=/var/run/mysqld/mysqld.sock \
  -u "$DBE_IMPORT_USER" \
  -e "DROP DATABASE IF EXISTS \`$MYSQL_DATABASE\`; CREATE DATABASE \`$MYSQL_DATABASE\` CHARACTER SET $1 COLLATE $2;"
"#
            .to_string())
        }
    }

    fn logical_import_script(
        &self,
        request: &LogicalImportRequest<'_>,
    ) -> Result<String, TransferError> {
        let input_path = request.input_path;
        let connection_args = mysql_connection_args(request.connection);
        if request.database_definition_in_dump {
            mysql_root_password(request.metadata)?;
            Ok(format!(
                r#"set -eu
MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql \
  --binary-mode \
  {connection_args} \
  -u root \
  < {input_path}
"#
            ))
        } else {
            logical_import_env(request.metadata, false)
                .map_err(|error| TransferError::Conflict(error.to_string()))?;
            Ok(format!(
                r#"set -eu
MYSQL_PWD="$DBE_IMPORT_PASSWORD" mysql \
  --binary-mode \
  {connection_args} \
  -u "$DBE_IMPORT_USER" \
  "$MYSQL_DATABASE" \
  < {input_path}
"#
            ))
        }
    }

    fn validate_remote_database_name(&self, database: Option<&str>) -> Result<(), TransferError> {
        validate_mysql_family_remote_database(self.protocol(), database)
    }

    fn remote_dump_flow(&self) -> RemoteDumpFlow {
        RemoteDumpFlow::Mysql
    }

    fn remote_dump_output_name(&self) -> Option<&'static str> {
        Some("source.mysql.sql")
    }
}

pub(crate) fn validate_mysql_family_remote_database(
    protocol: Protocol,
    database: Option<&str>,
) -> Result<(), TransferError> {
    if database.is_some_and(|database| !mysql_database_name(database)) {
        return Err(TransferError::BadRequest(format!(
            "{} source.database must contain at most 64 characters",
            protocol.as_str()
        )));
    }
    Ok(())
}

pub(crate) fn mysql_database_name(value: &str) -> bool {
    !value.is_empty() && value.chars().count() <= 64
}

fn mysql_root_password(metadata: &InstanceMetadata) -> Result<(), TransferError> {
    if metadata.mysql_root_password.is_none() {
        return Err(TransferError::BadRequest(
            "mysql internal root password is missing; recreate or repair this instance before exporting or importing"
                .to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn mysql_family_dump_selection_args(
    selection: &ImportExportSelection,
    database_variable: &str,
) -> String {
    let database_argument = format!(" -- \"${database_variable}\"");
    if selection.mode == SelectionMode::Full {
        return database_argument;
    }
    let mut args = String::new();
    for item in &selection.exclude {
        let table = unqualified_table_name(item);
        args.push_str(&format!(" --ignore-table=\"${database_variable}.{table}\""));
    }
    args.push_str(&database_argument);
    for item in &selection.include {
        args.push(' ');
        args.push_str(&sh_quote(unqualified_table_name(item)));
    }
    args
}

fn unqualified_table_name(item: &str) -> &str {
    item.rsplit_once('.')
        .map(|(_, table)| table)
        .unwrap_or(item)
}

fn mysql_connection_args(connection: ImportConnection) -> &'static str {
    match connection {
        ImportConnection::LocalSocket => {
            "--protocol=socket \\\n  --socket=/var/run/mysqld/mysqld.sock"
        }
        ImportConnection::PoolLoopback => "--protocol=TCP \\\n  --host=127.0.0.1",
    }
}
