use std::{path::Path, time::Duration};

use secrecy::ExposeSecret;

use serde::Serialize;

use crate::{
    databases::engine::RemoteDumpFlow,
    routes::http::response::ApiError,
    runtime::docker::{DockerError, ImportHelperNetwork, RemoteImportHelperSpec},
    subsystems::import_export::{
        CLICKHOUSE_ENGINE_AWK_PROGRAM, ImportExportSelection, SelectionMode,
    },
    utils::{
        ids::portable_identifier,
        protocol::{Protocol, xml_escape},
        shell::sh_quote,
    },
};

use super::{RemoteImportSource, write_private_file};

mod postgres;
use postgres::*;
mod mysql;
use mysql::*;
mod mongodb;
use mongodb::*;
mod clickhouse;
use clickhouse::*;

pub(super) async fn run_helper(
    state: &crate::routes::http::router::AppState,
    protocol: Protocol,
    source: &RemoteImportSource,
    selection: &ImportExportSelection,
    target_username: &str,
    work_dir: &Path,
    output_names: &[String],
) -> Result<(), ApiError> {
    let remote_import = &state.config.security.remote_import;
    let connect_timeout_seconds = remote_import.connect_timeout_seconds;
    let image = state
        .config
        .images
        .configured_for_protocol(protocol)
        .to_string();
    state
        .docker
        .prepare_import_image(&image)
        .await
        .map_err(|error| remote_helper_error(protocol, &error))?;

    let script = match protocol.engine().remote_dump_flow() {
        RemoteDumpFlow::Postgres => {
            prepare_postgres(source, selection, work_dir, connect_timeout_seconds).await?
        }
        RemoteDumpFlow::Mariadb => {
            prepare_mariadb(source, selection, work_dir, connect_timeout_seconds).await?
        }
        RemoteDumpFlow::Mysql => {
            prepare_mysql(
                source,
                selection,
                target_username,
                work_dir,
                connect_timeout_seconds,
            )
            .await?
        }
        RemoteDumpFlow::Mongodb => {
            prepare_mongodb(
                source,
                selection,
                work_dir,
                output_names,
                connect_timeout_seconds,
            )
            .await?
        }
        RemoteDumpFlow::Clickhouse => {
            prepare_clickhouse(source, selection, work_dir, connect_timeout_seconds).await?
        }
        RemoteDumpFlow::Unsupported => {
            return Err(ApiError::BadRequest(format!(
                "{} cannot be acquired as a logical dump",
                protocol.as_str()
            )));
        }
    };
    debug_assert!(
        output_names
            .iter()
            .all(|output_name| script.contains(output_name))
    );

    let spec = RemoteImportHelperSpec {
        image,
        work_dir: work_dir.to_path_buf(),
        script,
        extra_hosts: source.endpoint.helper_extra_hosts(),
        timeout: Duration::from_secs(remote_import.operation_timeout_seconds),
        max_output_bytes: remote_import.max_staged_bytes,
        network: ImportHelperNetwork::Outbound,
        input: None,
        environment: Vec::new(),
        read_only_work_dir: false,
    };
    state
        .docker
        .run_import_helper(&spec)
        .await
        .map(|_| ())
        .map_err(|error| remote_helper_error(protocol, &error))
}

pub(super) fn output_names(
    protocol: Protocol,
    selection: &ImportExportSelection,
) -> Result<Vec<String>, ApiError> {
    let engine = protocol.engine();
    let names = match engine.remote_dump_flow() {
        RemoteDumpFlow::Postgres
        | RemoteDumpFlow::Mariadb
        | RemoteDumpFlow::Mysql
        | RemoteDumpFlow::Clickhouse => engine
            .remote_dump_output_name()
            .map(|name| vec![name.to_string()])
            .unwrap_or_default(),
        RemoteDumpFlow::Mongodb => {
            let collection_count = mongodb_selected_collections(selection)?.len();
            if collection_count == 1 {
                vec!["source.mongodb.archive.gz".to_string()]
            } else {
                (0..collection_count)
                    .map(|index| format!("source.mongodb.{index:04}.archive.gz"))
                    .collect()
            }
        }
        RemoteDumpFlow::Unsupported => {
            return Err(ApiError::BadRequest(format!(
                "{} cannot be acquired as a logical dump",
                protocol.as_str()
            )));
        }
    };
    Ok(names)
}

fn remote_helper_error(protocol: Protocol, error: &DockerError) -> ApiError {
    tracing::warn!(
        protocol = protocol.as_str(),
        error_kind = ?std::mem::discriminant(error),
        "remote database dump helper failed"
    );
    ApiError::BadRequest(format!(
        "remote {} source acquisition failed; verify endpoint, TLS, credentials, permissions, and version compatibility",
        protocol.as_str()
    ))
}

fn required<'a>(value: Option<&'a str>, field: &str) -> Result<&'a str, ApiError> {
    value.ok_or_else(|| ApiError::BadRequest(format!("remote import requires {field}")))
}

fn required_secret<'a>(
    value: Option<&'a secrecy::SecretString>,
    field: &str,
) -> Result<&'a str, ApiError> {
    value
        .map(ExposeSecret::expose_secret)
        .ok_or_else(|| ApiError::BadRequest(format!("remote import requires {field}")))
}

fn contains_nul_or_line_break(value: &str) -> bool {
    value
        .bytes()
        .any(|byte| matches!(byte, b'\0' | b'\r' | b'\n'))
}

#[cfg(test)]
mod tests;
