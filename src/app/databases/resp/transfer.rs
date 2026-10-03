use secrecy::SecretString;

use crate::{
    databases::engine::{EngineInfo, EngineTransfer, SelectionUse, TransferError},
    databases::protocol::Protocol,
    server::jobs::import_export::selection::ImportExportSelection,
};

use super::engine::{Redis, Valkey};

impl EngineTransfer for Redis {
    fn validate_selection_items(
        &self,
        _selection: &ImportExportSelection,
        _use_case: SelectionUse,
    ) -> Result<(), TransferError> {
        resp_selection_unsupported(self.protocol())
    }

    fn validate_remote_source_fields(
        &self,
        database: Option<&str>,
        username: Option<&str>,
        password: Option<&SecretString>,
        authentication_database: Option<&str>,
        _database_index: Option<u32>,
        api_key: Option<&SecretString>,
    ) -> Result<(), TransferError> {
        validate_resp_remote_fields(
            self.protocol(),
            database,
            username,
            password,
            authentication_database,
            api_key,
        )
    }
}

impl EngineTransfer for Valkey {
    fn validate_selection_items(
        &self,
        _selection: &ImportExportSelection,
        _use_case: SelectionUse,
    ) -> Result<(), TransferError> {
        resp_selection_unsupported(self.protocol())
    }

    fn validate_remote_source_fields(
        &self,
        database: Option<&str>,
        username: Option<&str>,
        password: Option<&SecretString>,
        authentication_database: Option<&str>,
        _database_index: Option<u32>,
        api_key: Option<&SecretString>,
    ) -> Result<(), TransferError> {
        validate_resp_remote_fields(
            self.protocol(),
            database,
            username,
            password,
            authentication_database,
            api_key,
        )
    }
}

fn resp_selection_unsupported(protocol: Protocol) -> Result<(), TransferError> {
    Err(TransferError::NotImplemented(format!(
        "{} selective import/export requires a logical key dump format and is not implemented yet",
        protocol.as_str()
    )))
}

fn validate_resp_remote_fields(
    protocol: Protocol,
    database: Option<&str>,
    username: Option<&str>,
    password: Option<&SecretString>,
    authentication_database: Option<&str>,
    api_key: Option<&SecretString>,
) -> Result<(), TransferError> {
    if database.is_some() || authentication_database.is_some() || api_key.is_some() {
        return Err(TransferError::BadRequest(format!(
            "{} remote import accepts database_index instead of database",
            protocol.as_str()
        )));
    }
    if username.is_some() && password.is_none() {
        return Err(TransferError::BadRequest(format!(
            "{} source.username requires source.password",
            protocol.as_str()
        )));
    }
    Ok(())
}
