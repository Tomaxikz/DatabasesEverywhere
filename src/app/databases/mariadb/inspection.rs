use crate::{
    databases::{engine::EngineInspection, mysql::inspection as mysql},
    server::backup::catalog::BackupCatalogObject,
    server::metadata::InstanceMetadata,
};

use super::engine::Mariadb;

const SCHEMA_COMMAND: &str = "MYSQL_PWD=\"$DBE_MARIADB_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -u \"$MARIADB_USER\" --database=\"$MARIADB_DATABASE\"";
const PREVIEW_COMMAND: &str = "MYSQL_PWD=\"$DBE_MARIADB_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -u \"$MARIADB_USER\" \"$MARIADB_DATABASE\"";

impl EngineInspection for Mariadb {
    fn catalog_schema_script(
        &self,
        _metadata: &InstanceMetadata,
        max_objects: usize,
    ) -> Option<String> {
        Some(mysql::schema_script(SCHEMA_COMMAND, max_objects))
    }

    fn parse_catalog_schema(&self, output: &str) -> Result<Vec<BackupCatalogObject>, String> {
        mysql::parse_mysql_schema(output)
    }

    fn catalog_preview_script(
        &self,
        _metadata: &InstanceMetadata,
        object: &BackupCatalogObject,
        rows: usize,
        max_row_bytes: usize,
    ) -> Option<String> {
        mysql::preview_script(PREVIEW_COMMAND, object, rows, max_row_bytes)
    }
}
