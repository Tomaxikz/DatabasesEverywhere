use crate::{server::backup::catalog::BackupCatalogObject, server::metadata::InstanceMetadata};

use super::EngineInfo;

pub(crate) trait EngineInspection: EngineInfo {
    fn schema_less_catalog_kind(&self) -> Option<&'static str> {
        None
    }

    fn inspects_archive_catalogs(&self) -> bool {
        false
    }

    fn catalog_schema_script(
        &self,
        _metadata: &InstanceMetadata,
        _max_objects: usize,
    ) -> Option<String> {
        None
    }

    fn parse_catalog_schema(&self, _output: &str) -> Result<Vec<BackupCatalogObject>, String> {
        Ok(Vec::new())
    }

    fn catalog_preview_script(
        &self,
        _metadata: &InstanceMetadata,
        _object: &BackupCatalogObject,
        _rows: usize,
        _max_row_bytes: usize,
    ) -> Option<String> {
        None
    }

    fn preview_output_lines(&self, output: &str) -> Vec<String> {
        output.lines().map(str::to_string).collect()
    }

    fn infer_preview_columns(&self, _object: &mut BackupCatalogObject) {}
}
