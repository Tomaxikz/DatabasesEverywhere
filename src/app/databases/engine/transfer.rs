use http::HeaderValue;
use secrecy::{ExposeSecret, SecretString};

use crate::{
    databases::protocol::Protocol,
    server::jobs::import_export::selection::{
        ImportExportSelection, MAX_SELECTION_FIELDS_PER_ITEM, MAX_SELECTION_ITEMS, SelectionMode,
    },
    server::metadata::InstanceMetadata,
    server::placement::DeploymentMode,
};

use super::EngineInfo;

const MAX_SIMPLE_IDENTIFIER_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum TransferError {
    #[error("{0}")]
    BadRequest(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("runtime error: {0}")]
    Runtime(String),
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum SelectionUse {
    Export,
    Import,
}

impl SelectionUse {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Export => "export",
            Self::Import => "import",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImportConnection {
    LocalSocket,
    PoolLoopback,
}

pub(crate) struct LogicalImportRequest<'a> {
    pub metadata: &'a InstanceMetadata,
    pub input_path: &'a str,
    pub source_database: Option<&'a str>,
    pub selection: &'a ImportExportSelection,
    pub database_definition_in_dump: bool,
    pub postgres_wrapper_lines: Option<(u64, u64)>,
    pub connection: ImportConnection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogicalCredential {
    Tenant {
        username: &'static str,
        password: &'static str,
    },
    Root(&'static str),
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteDumpFlow {
    Postgres,
    Mariadb,
    Mysql,
    Mongodb,
    Clickhouse,
    Unsupported,
}

fn validate_sql_object_name(protocol: Protocol, value: &str) -> Result<(), TransferError> {
    let parts: Vec<_> = value.split('.').collect();
    let family = protocol.engine().family();
    let valid = if family.is_postgres() || family.is_mysql() {
        (1..=2).contains(&parts.len())
    } else {
        false
    } && parts
        .iter()
        .all(|part| !part.is_empty() && simple_identifier(part));
    if valid {
        Ok(())
    } else {
        Err(TransferError::BadRequest(format!(
            "invalid {} object name {value}; use ascii identifiers like table or schema.table",
            protocol.as_str()
        )))
    }
}

fn simple_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SIMPLE_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(crate) trait EngineTransfer: EngineInfo {
    fn validate_selection(
        &self,
        selection: &ImportExportSelection,
        use_case: SelectionUse,
    ) -> Result<(), TransferError> {
        if selection.include.len() > MAX_SELECTION_ITEMS
            || selection.exclude.len() > MAX_SELECTION_ITEMS
        {
            return Err(TransferError::BadRequest(format!(
                "selection include/exclude may contain at most {MAX_SELECTION_ITEMS} items"
            )));
        }
        if selection.fields.len() > MAX_SELECTION_ITEMS {
            return Err(TransferError::BadRequest(format!(
                "selection fields may contain at most {MAX_SELECTION_ITEMS} objects"
            )));
        }
        for fields in selection.fields.values() {
            if fields.len() > MAX_SELECTION_FIELDS_PER_ITEM {
                return Err(TransferError::BadRequest(format!(
                    "selection fields for one object may contain at most {MAX_SELECTION_FIELDS_PER_ITEM} fields"
                )));
            }
        }

        if selection.mode == SelectionMode::Full {
            if !selection.include.is_empty()
                || !selection.exclude.is_empty()
                || !selection.fields.is_empty()
            {
                return Err(TransferError::BadRequest(
                    "selection.mode=full must not include include/exclude/fields".to_string(),
                ));
            }
            return Ok(());
        }

        if selection.include.is_empty() {
            return Err(TransferError::BadRequest(
                "selection.mode=selective requires at least one include item".to_string(),
            ));
        }
        if let Some(overlap) = selection
            .include
            .iter()
            .find(|item| selection.exclude.contains(*item))
        {
            return Err(TransferError::BadRequest(format!(
                "selection cannot both include and exclude {overlap}"
            )));
        }

        self.validate_selection_items(selection, use_case)
    }

    fn validate_selection_items(
        &self,
        selection: &ImportExportSelection,
        use_case: SelectionUse,
    ) -> Result<(), TransferError>;

    fn validate_sql_selection_items(
        &self,
        selection: &ImportExportSelection,
        use_case: SelectionUse,
    ) -> Result<(), TransferError> {
        for item in selection.include.iter().chain(selection.exclude.iter()) {
            validate_sql_object_name(self.protocol(), item)?;
        }
        if !selection.fields.is_empty() {
            return Err(TransferError::NotImplemented(format!(
                "{} column-level selective {} is not implemented yet; use table-level selection",
                self.protocol().as_str(),
                use_case.name()
            )));
        }
        Ok(())
    }

    fn validate_simple_identifier(&self, kind: &str, value: &str) -> Result<(), TransferError> {
        if simple_identifier(value) {
            Ok(())
        } else {
            Err(TransferError::BadRequest(format!(
                "invalid {kind} {value}; use ascii letters, digits, underscore, or dash"
            )))
        }
    }

    fn ensure_full_selection(
        &self,
        selection: &ImportExportSelection,
    ) -> Result<(), TransferError> {
        if selection.mode == SelectionMode::Full
            && selection.include.is_empty()
            && selection.exclude.is_empty()
            && selection.fields.is_empty()
        {
            return Ok(());
        }
        Err(TransferError::BadRequest(format!(
            "{} artifact import/export path only accepts selection.mode=full; create a selective export artifact or use remote selective import",
            self.protocol().as_str()
        )))
    }

    fn validate_artifact_selection(
        &self,
        selection: &ImportExportSelection,
    ) -> Result<(), TransferError> {
        self.ensure_full_selection(selection)
    }

    fn validate_upload_source_database(
        &self,
        source_database: Option<&str>,
    ) -> Result<(), TransferError> {
        match source_database {
            Some(_) => Err(TransferError::BadRequest(
                "source.source_database is supported only for mongodb upload imports".to_string(),
            )),
            None => Ok(()),
        }
    }

    fn native_gzip_logical_dump(&self) -> bool {
        false
    }

    fn logical_credential_for_export(&self, _deployment_mode: DeploymentMode) -> LogicalCredential {
        LogicalCredential::None
    }

    fn logical_credential_for_import(
        &self,
        _deployment_mode: DeploymentMode,
        _database_definition_in_dump: bool,
    ) -> LogicalCredential {
        LogicalCredential::None
    }

    fn logical_export_script(
        &self,
        _metadata: &InstanceMetadata,
        _output_path: &str,
        _selection: &ImportExportSelection,
        _include_database_definition: bool,
    ) -> Result<String, TransferError> {
        Err(TransferError::BadRequest(format!(
            "{} uses physical archive export",
            self.protocol().as_str()
        )))
    }

    fn logical_wipe_script(
        &self,
        _metadata: &InstanceMetadata,
        _database_definition_in_dump: bool,
    ) -> Result<String, TransferError> {
        Err(TransferError::BadRequest(format!(
            "{} does not use the logical wipe path",
            self.protocol().as_str()
        )))
    }

    fn logical_import_script(
        &self,
        _request: &LogicalImportRequest<'_>,
    ) -> Result<String, TransferError> {
        Err(TransferError::BadRequest(format!(
            "{} uses physical archive import",
            self.protocol().as_str()
        )))
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
        validate_sql_source(
            self.protocol(),
            database,
            username,
            password,
            authentication_database,
            database_index,
            api_key,
        )
    }

    fn validate_remote_database_name(&self, _database: Option<&str>) -> Result<(), TransferError> {
        Ok(())
    }

    fn remote_dump_flow(&self) -> RemoteDumpFlow {
        RemoteDumpFlow::Unsupported
    }

    fn remote_dump_output_name(&self) -> Option<&'static str> {
        None
    }
}

fn validate_sql_source(
    protocol: Protocol,
    database: Option<&str>,
    username: Option<&str>,
    password: Option<&SecretString>,
    authentication_database: Option<&str>,
    database_index: Option<u32>,
    api_key: Option<&SecretString>,
) -> Result<(), TransferError> {
    require_present("source.database", database)?;
    require_present("source.username", username)?;
    let password = password.ok_or_else(|| {
        TransferError::BadRequest("remote SQL import requires source.password".to_string())
    })?;
    validate_line_safe_secret("source.password", password)?;
    protocol.engine().validate_remote_database_name(database)?;
    if database_index.is_some() || api_key.is_some() || authentication_database.is_some() {
        return Err(TransferError::BadRequest(format!(
            "remote {} import contains credentials for a different database protocol",
            protocol.as_str()
        )));
    }
    Ok(())
}

fn require_present(field: &str, value: Option<&str>) -> Result<(), TransferError> {
    if value.is_some() {
        Ok(())
    } else {
        Err(TransferError::BadRequest(format!(
            "remote import requires {field}"
        )))
    }
}

pub(crate) fn validate_line_safe_secret(
    field: &str,
    value: &SecretString,
) -> Result<(), TransferError> {
    if value
        .expose_secret()
        .bytes()
        .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    {
        return Err(TransferError::BadRequest(format!(
            "{field} must contain no NUL bytes or line breaks"
        )));
    }
    Ok(())
}

pub(crate) fn validate_header_safe_secret(
    field: &str,
    value: &SecretString,
) -> Result<(), TransferError> {
    HeaderValue::from_bytes(value.expose_secret().as_bytes())
        .map(|_| ())
        .map_err(|_| {
            TransferError::BadRequest(format!(
                "{field} contains characters that are invalid in an HTTP header"
            ))
        })
}
