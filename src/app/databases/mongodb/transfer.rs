use std::collections::HashSet;

use secrecy::SecretString;

use crate::{
    databases::engine::{
        EngineTransfer, LogicalCredential, LogicalImportRequest, RemoteDumpFlow, SelectionUse,
        TransferError,
    },
    instance::metadata::InstanceMetadata,
    instance::placement::DeploymentMode,
    subsystems::import_export::{ImportExportSelection, SelectionMode},
    utils::shell::sh_quote,
};

use super::engine::Mongodb;

impl EngineTransfer for Mongodb {
    fn validate_selection_items(
        &self,
        selection: &ImportExportSelection,
        use_case: SelectionUse,
    ) -> Result<(), TransferError> {
        for item in selection.include.iter().chain(selection.exclude.iter()) {
            self.validate_simple_identifier("mongodb collection", item)?;
        }
        let mut included_collections = HashSet::with_capacity(selection.include.len());
        if let Some(duplicate) = selection
            .include
            .iter()
            .find(|collection| !included_collections.insert(collection.as_str()))
        {
            return Err(TransferError::BadRequest(format!(
                "mongodb selection includes collection {duplicate} more than once"
            )));
        }
        if matches!(use_case, SelectionUse::Export) && selection.include.len() != 1 {
            return Err(TransferError::NotImplemented(format!(
                "mongodb selective {} currently supports exactly one included collection",
                use_case.name()
            )));
        }
        if !selection.fields.is_empty() {
            return Err(TransferError::NotImplemented(
                "mongodb field projection is not implemented yet; use collection-level selection"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn validate_artifact_selection(
        &self,
        selection: &ImportExportSelection,
    ) -> Result<(), TransferError> {
        self.validate_selection(selection, SelectionUse::Import)
    }

    fn validate_upload_source_database(
        &self,
        source_database: Option<&str>,
    ) -> Result<(), TransferError> {
        match source_database {
            Some(source_database) => {
                validate_mongodb_database_name("source.source_database", source_database, false)
            }
            None => Ok(()),
        }
    }

    fn native_gzip_logical_dump(&self) -> bool {
        true
    }

    fn logical_credential_for_export(&self, deployment_mode: DeploymentMode) -> LogicalCredential {
        mongodb_credential(deployment_mode)
    }

    fn logical_credential_for_import(
        &self,
        deployment_mode: DeploymentMode,
        _database_definition_in_dump: bool,
    ) -> LogicalCredential {
        mongodb_credential(deployment_mode)
    }

    fn logical_export_script(
        &self,
        metadata: &InstanceMetadata,
        output_path: &str,
        selection: &ImportExportSelection,
        _include_database_definition: bool,
    ) -> Result<String, TransferError> {
        let filters = mongodb_dump_selection_args(selection)?;
        if metadata.deployment_mode == DeploymentMode::Shared {
            Ok(format!(
                r#"set -eu
mongodump \
  --host 127.0.0.1 \
  --username "$DBE_MONGO_USER" \
  --password "$DBE_MONGO_PASSWORD" \
  --authenticationDatabase "$DBE_MONGO_DATABASE" \
  --db "$DBE_MONGO_DATABASE" \
  {filters} \
  --archive={output_path} \
  --gzip
"#
            ))
        } else {
            mongodb_root_password(metadata)?;
            Ok(format!(
                r#"set -eu
mongodump \
  --host 127.0.0.1 \
  --username "$DBE_MONGO_ROOT_USER" \
  --password "$DBE_MONGO_ROOT_PASSWORD" \
  --authenticationDatabase "admin" \
  --db "$DBE_MONGO_DATABASE" \
  {filters} \
  --archive={output_path} \
  --gzip
"#
            ))
        }
    }

    fn logical_wipe_script(
        &self,
        metadata: &InstanceMetadata,
        _database_definition_in_dump: bool,
    ) -> Result<String, TransferError> {
        if metadata.deployment_mode == DeploymentMode::Shared {
            Ok(r#"set -eu
mongosh --quiet \
  --host 127.0.0.1 \
  --username "$DBE_MONGO_USER" \
  --password "$DBE_MONGO_PASSWORD" \
  --authenticationDatabase "$DBE_MONGO_DATABASE" \
  "$DBE_MONGO_DATABASE" \
  --eval 'for (const entry of db.getCollectionInfos({}, { nameOnly: true })) { if (entry.name.startsWith("system.")) { throw new Error("refusing to drop a system collection"); } db.getCollection(entry.name).drop(); }'
"#
            .to_string())
        } else {
            mongodb_root_password(metadata)?;
            Ok(r#"set -eu
mongosh --quiet \
  --host 127.0.0.1 \
  --username "$DBE_MONGO_ROOT_USER" \
  --password "$DBE_MONGO_ROOT_PASSWORD" \
  --authenticationDatabase admin \
  "$DBE_MONGO_DATABASE" \
  --eval 'db.dropDatabase()'
"#
            .to_string())
        }
    }

    fn logical_import_script(
        &self,
        request: &LogicalImportRequest<'_>,
    ) -> Result<String, TransferError> {
        let input_path = request.input_path;
        let namespaces =
            mongodb_restore_namespace_args(request.selection, request.source_database)?;
        if request.metadata.deployment_mode == DeploymentMode::Shared {
            Ok(format!(
                r#"set -eu
mongorestore \
  --host 127.0.0.1 \
  --username "$DBE_MONGO_USER" \
  --password "$DBE_MONGO_PASSWORD" \
  --authenticationDatabase "$DBE_MONGO_DATABASE" \
  --drop \
  {namespaces} \
  --archive={input_path} \
  --gzip
"#
            ))
        } else {
            mongodb_root_password(request.metadata)?;
            Ok(format!(
                r#"set -eu
mongorestore \
  --host 127.0.0.1 \
  --username "$DBE_MONGO_ROOT_USER" \
  --password "$DBE_MONGO_ROOT_PASSWORD" \
  --authenticationDatabase "admin" \
  --drop \
  {namespaces} \
  --archive={input_path} \
  --gzip
"#
            ))
        }
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
        let database = database.ok_or_else(|| {
            TransferError::BadRequest("remote import requires source.database".to_string())
        })?;
        validate_mongodb_database_name("source.database", database, false)?;
        if let Some(authentication_database) = authentication_database {
            validate_mongodb_database_name(
                "source.authentication_database",
                authentication_database,
                true,
            )?;
        }
        validate_mongodb_credentials(username, password, authentication_database)?;
        if database_index.is_some() || api_key.is_some() {
            return Err(TransferError::BadRequest(
                "mongodb remote import contains credentials for a different database protocol"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn remote_dump_flow(&self) -> RemoteDumpFlow {
        RemoteDumpFlow::Mongodb
    }
}

fn mongodb_credential(deployment_mode: DeploymentMode) -> LogicalCredential {
    if deployment_mode == DeploymentMode::Shared {
        LogicalCredential::Tenant {
            username: "DBE_MONGO_USER",
            password: "DBE_MONGO_PASSWORD",
        }
    } else {
        LogicalCredential::Root("DBE_MONGO_ROOT_PASSWORD")
    }
}

fn mongodb_root_password(metadata: &InstanceMetadata) -> Result<(), TransferError> {
    if metadata.mongodb_root_password.is_none() {
        return Err(TransferError::BadRequest(
            "mongodb internal root password is missing; this instance was created before DBE stored MongoDB maintenance credentials, so DBE cannot export/import protected internal collections such as time-series buckets. Recreate the instance or use a manual admin dump.".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn mongodb_dump_selection_args(
    selection: &ImportExportSelection,
) -> Result<String, TransferError> {
    if selection.mode == SelectionMode::Full {
        return Ok(String::new());
    }
    let mut args = String::new();
    let collection = selection.include.first().ok_or_else(|| {
        TransferError::BadRequest(
            "mongodb selective export requires one included collection".to_string(),
        )
    })?;
    args.push_str(" --collection=");
    args.push_str(&sh_quote(collection));
    Ok(args)
}

pub(crate) fn mongodb_database_pattern(database: &str) -> String {
    let mut pattern = String::with_capacity(database.len() + 2);
    for character in database.chars() {
        match character {
            '\\' => pattern.push_str(r"\\"),
            '*' => pattern.push_str(r"\*"),
            _ => pattern.push(character),
        }
    }
    pattern.push_str(".*");
    pattern
}

fn mongodb_collection_pattern(database: &str, collection: &str) -> String {
    let mut pattern = mongodb_database_pattern(database);
    pattern.pop();
    pattern.push_str(collection);
    pattern
}

pub(crate) fn mongodb_restore_namespace_args(
    selection: &ImportExportSelection,
    source_database: Option<&str>,
) -> Result<String, TransferError> {
    Mongodb.validate_selection(selection, SelectionUse::Import)?;

    let mut filters = Vec::new();
    match source_database {
        Some(source_database) => {
            if selection.mode == SelectionMode::Full {
                filters.push(format!(
                    "--nsInclude {}",
                    sh_quote(&mongodb_database_pattern(source_database))
                ));
            } else {
                for collection in &selection.include {
                    filters.push(format!(
                        "--nsInclude {}",
                        sh_quote(&mongodb_collection_pattern(source_database, collection))
                    ));
                }
                for collection in &selection.exclude {
                    filters.push(format!(
                        "--nsExclude {}",
                        sh_quote(&mongodb_collection_pattern(source_database, collection))
                    ));
                }
            }
            let source_pattern = mongodb_database_pattern(source_database);
            filters.push(format!("--nsFrom {}", sh_quote(&source_pattern)));
            filters.push("--nsTo \"$DBE_MONGO_DATABASE.*\"".to_string());
        }
        None if selection.mode == SelectionMode::Full => {
            filters.push("--nsInclude \"$DBE_MONGO_DATABASE.*\"".to_string());
        }
        None => {
            // Local archives have no trusted source database to remap. Collection filters
            // therefore apply only to namespaces already matching the target database.
            for collection in &selection.include {
                filters.push(format!(
                    "--nsInclude \"$DBE_MONGO_DATABASE\".{}",
                    sh_quote(collection)
                ));
            }
            for collection in &selection.exclude {
                filters.push(format!(
                    "--nsExclude \"$DBE_MONGO_DATABASE\".{}",
                    sh_quote(collection)
                ));
            }
        }
    }
    Ok(filters.join(" \\\n  "))
}

pub(crate) fn validate_mongodb_database_name(
    field: &str,
    value: &str,
    allow_external: bool,
) -> Result<(), TransferError> {
    if allow_external && value == "$external" {
        return Ok(());
    }
    let invalid_character = value
        .chars()
        .any(|character| matches!(character, '\0' | '/' | '\\' | '.' | ' ' | '"' | '$'));
    if value.is_empty() || value.len() > 63 || invalid_character {
        let external = if allow_external {
            "; source.authentication_database may alternatively be exactly $external"
        } else {
            ""
        };
        return Err(TransferError::BadRequest(format!(
            "{field} must be 1-63 UTF-8 bytes and cannot contain NUL, slash, backslash, dot, space, double quote, or dollar sign{external}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_mongodb_credentials(
    username: Option<&str>,
    password: Option<&SecretString>,
    authentication_database: Option<&str>,
) -> Result<(), TransferError> {
    if username.is_some() != password.is_some() {
        return Err(TransferError::BadRequest(
            "mongodb source.username and source.password must be supplied together".to_string(),
        ));
    }
    if authentication_database.is_some() && (username.is_none() || password.is_none()) {
        return Err(TransferError::BadRequest(
            "mongodb source.authentication_database requires source.username and source.password"
                .to_string(),
        ));
    }
    Ok(())
}
