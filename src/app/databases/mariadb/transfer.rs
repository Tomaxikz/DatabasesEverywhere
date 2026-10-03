use crate::{
    databases::{
        engine::{
            EngineInfo, EngineTransfer, ImportConnection, LogicalCredential, LogicalImportRequest,
            RemoteDumpFlow, SelectionUse, TransferError,
        },
        mysql::transfer::{
            mysql_family_dump_selection_args, validate_mysql_family_remote_database,
        },
    },
    instance::metadata::InstanceMetadata,
    instance::placement::DeploymentMode,
    subsystems::import_export::ImportExportSelection,
};

use super::engine::Mariadb;

impl EngineTransfer for Mariadb {
    fn validate_selection_items(
        &self,
        selection: &ImportExportSelection,
        use_case: SelectionUse,
    ) -> Result<(), TransferError> {
        self.validate_sql_selection_items(selection, use_case)
    }

    fn logical_credential_for_export(&self, _deployment_mode: DeploymentMode) -> LogicalCredential {
        LogicalCredential::Tenant {
            username: "MARIADB_USER",
            password: "DBE_MARIADB_PASSWORD",
        }
    }

    fn logical_credential_for_import(
        &self,
        _deployment_mode: DeploymentMode,
        database_definition_in_dump: bool,
    ) -> LogicalCredential {
        if database_definition_in_dump {
            LogicalCredential::Root("DBE_MARIADB_ROOT_PASSWORD")
        } else {
            LogicalCredential::Tenant {
                username: "MARIADB_USER",
                password: "DBE_MARIADB_PASSWORD",
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
        let filters = mysql_family_dump_selection_args(selection, "MARIADB_DATABASE");
        let database_definition = if include_database_definition {
            " --databases"
        } else {
            ""
        };
        let executable_objects = if metadata.deployment_mode == DeploymentMode::Shared {
            " --skip-routines --skip-events --skip-triggers"
        } else {
            " --routines --events --triggers"
        };
        Ok(format!(
            r#"set -eu
mariadb-dump \
  --protocol=socket \
  --socket=/run/mysqld/mysqld.sock \
  -u "$MARIADB_USER" \
  -p"$DBE_MARIADB_PASSWORD" \
  --single-transaction --quick{executable_objects} \
  --hex-blob --add-drop-table{database_definition}{filters} \
  > {output_path}
"#
        ))
    }

    fn logical_wipe_script(
        &self,
        metadata: &InstanceMetadata,
        database_definition_in_dump: bool,
    ) -> Result<String, TransferError> {
        let script = if database_definition_in_dump {
            r#"set -eu
mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock \
  -u root -p"$DBE_MARIADB_ROOT_PASSWORD" \
  -e "DROP DATABASE IF EXISTS \`$MARIADB_DATABASE\`;"
"#
        } else if metadata.deployment_mode == DeploymentMode::Shared {
            r#"set -eu
{
  printf '%s\n' 'SET FOREIGN_KEY_CHECKS=0;'
  MYSQL_PWD="$DBE_MARIADB_PASSWORD" mariadb \
    --protocol=socket --socket=/run/mysqld/mysqld.sock \
    -u "$MARIADB_USER" --batch --skip-column-names "$MARIADB_DATABASE" \
    -e "SELECT CONCAT('DROP VIEW IF EXISTS `', REPLACE(TABLE_NAME, '`', '``'), '`;') FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'VIEW'; SELECT CONCAT('DROP TABLE IF EXISTS `', REPLACE(TABLE_NAME, '`', '``'), '`;') FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'; SELECT CONCAT('DROP PROCEDURE IF EXISTS `', REPLACE(ROUTINE_NAME, '`', '``'), '`;') FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = DATABASE() AND ROUTINE_TYPE = 'PROCEDURE'; SELECT CONCAT('DROP FUNCTION IF EXISTS `', REPLACE(ROUTINE_NAME, '`', '``'), '`;') FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = DATABASE() AND ROUTINE_TYPE = 'FUNCTION';"
  printf '%s\n' 'SET FOREIGN_KEY_CHECKS=1;'
} | MYSQL_PWD="$DBE_MARIADB_PASSWORD" mariadb \
  --binary-mode --protocol=socket --socket=/run/mysqld/mysqld.sock \
  -u "$MARIADB_USER" "$MARIADB_DATABASE"
"#
        } else {
            r#"set -eu
settings=$(mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock \
  -u root -p"$DBE_MARIADB_ROOT_PASSWORD" \
  --batch --skip-column-names "$MARIADB_DATABASE" \
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
mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock \
  -u root -p"$DBE_MARIADB_ROOT_PASSWORD" \
  -e "DROP DATABASE IF EXISTS \`$MARIADB_DATABASE\`; CREATE DATABASE \`$MARIADB_DATABASE\` CHARACTER SET $1 COLLATE $2;"
"#
        };
        Ok(script.to_string())
    }

    fn logical_import_script(
        &self,
        request: &LogicalImportRequest<'_>,
    ) -> Result<String, TransferError> {
        let input_path = request.input_path;
        let connection_args = mariadb_connection_args(request.connection);
        if request.database_definition_in_dump {
            Ok(format!(
                r#"set -eu
mariadb \
  --binary-mode \
  {connection_args} \
  -u root \
  -p"$DBE_MARIADB_ROOT_PASSWORD" \
  < {input_path}
"#
            ))
        } else {
            Ok(format!(
                r#"set -eu
mariadb \
  --binary-mode \
  {connection_args} \
  -u "$MARIADB_USER" \
  -p"$DBE_MARIADB_PASSWORD" \
  "$MARIADB_DATABASE" \
  < {input_path}
"#
            ))
        }
    }

    fn validate_remote_database_name(&self, database: Option<&str>) -> Result<(), TransferError> {
        validate_mysql_family_remote_database(self.protocol(), database)
    }

    fn remote_dump_flow(&self) -> RemoteDumpFlow {
        RemoteDumpFlow::Mariadb
    }

    fn remote_dump_output_name(&self) -> Option<&'static str> {
        Some("source.mariadb.sql")
    }
}

fn mariadb_connection_args(connection: ImportConnection) -> &'static str {
    match connection {
        ImportConnection::LocalSocket => "--protocol=socket \\\n  --socket=/run/mysqld/mysqld.sock",
        ImportConnection::PoolLoopback => "--protocol=TCP \\\n  --host=127.0.0.1",
    }
}
