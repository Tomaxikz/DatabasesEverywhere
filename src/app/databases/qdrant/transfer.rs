use secrecy::SecretString;

use crate::{
    databases::engine::{
        EngineTransfer, LogicalImportRequest, SelectionUse, TransferError,
        validate_header_safe_secret,
    },
    server::jobs::import_export::selection::ImportExportSelection,
    server::metadata::InstanceMetadata,
};

use super::engine::Qdrant;

impl EngineTransfer for Qdrant {
    fn validate_selection_items(
        &self,
        selection: &ImportExportSelection,
        _use_case: SelectionUse,
    ) -> Result<(), TransferError> {
        for item in selection.include.iter().chain(selection.exclude.iter()) {
            self.validate_simple_identifier("qdrant collection", item)?;
        }
        if !selection.fields.is_empty() {
            return Err(TransferError::NotImplemented(
                "qdrant field-level selection is not implemented; use collection-level selection"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn logical_export_script(
        &self,
        _metadata: &InstanceMetadata,
        _output_path: &str,
        _selection: &ImportExportSelection,
        _include_database_definition: bool,
    ) -> Result<String, TransferError> {
        Err(TransferError::NotImplemented(
            "qdrant snapshot export is not implemented yet".to_string(),
        ))
    }

    fn logical_import_script(
        &self,
        _request: &LogicalImportRequest<'_>,
    ) -> Result<String, TransferError> {
        Err(TransferError::NotImplemented(
            "qdrant snapshot import is not implemented yet".to_string(),
        ))
    }

    fn validate_remote_source_fields(
        &self,
        database: Option<&str>,
        username: Option<&str>,
        password: Option<&SecretString>,
        authentication_database: Option<&str>,
        database_index: Option<u32>,
        api_key: Option<&SecretString>,
    ) -> Result<(), TransferError> {
        if let Some(api_key) = api_key {
            validate_header_safe_secret("source.api_key", api_key)?;
        }
        if database.is_some()
            || username.is_some()
            || password.is_some()
            || authentication_database.is_some()
            || database_index.is_some()
        {
            return Err(TransferError::BadRequest(
                "qdrant remote import accepts source.api_key and endpoint fields only".to_string(),
            ));
        }
        Ok(())
    }
}
