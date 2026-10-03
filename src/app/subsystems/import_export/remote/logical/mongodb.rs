use super::*;

pub(super) async fn prepare_mongodb(
    source: &RemoteImportSource,
    selection: &ImportExportSelection,
    work_dir: &Path,
    output_names: &[String],
    connect_timeout_seconds: u64,
) -> Result<String, ApiError> {
    let database = required(source.database.as_deref(), "source.database")?;
    let collections = mongodb_selected_collections(selection)?;
    if collections.len() != output_names.len() {
        return Err(ApiError::Runtime(
            "mongodb remote import output plan did not match its collection selection".to_string(),
        ));
    }
    let host = if source.endpoint.host.contains(':') {
        format!("[{}]", source.endpoint.host)
    } else {
        source.endpoint.host.clone()
    };
    let tls = if source.endpoint.tls { "&tls=true" } else { "" };
    let connect_timeout_milliseconds = connect_timeout_seconds.saturating_mul(1_000);
    let config = MongoDumpConfig {
        uri: format!(
            "mongodb://{host}:{}/?directConnection=true&connectTimeoutMS={connect_timeout_milliseconds}&serverSelectionTimeoutMS={connect_timeout_milliseconds}{tls}",
            source.endpoint.port,
        ),
        password: source.password.as_ref().map(ExposeSecret::expose_secret),
    };
    let config = yaml_serde::to_string(&config).map_err(|error| {
        ApiError::Runtime(format!("failed to encode mongodb credentials: {error}"))
    })?;
    write_private_file(&work_dir.join("mongodump.yml"), config.as_bytes()).await?;

    let mut authentication = String::new();
    if let Some(username) = source.username.as_deref() {
        authentication.push_str(" --username ");
        authentication.push_str(&sh_quote(username));
        authentication.push_str(" --authenticationDatabase ");
        authentication.push_str(&sh_quote(
            source
                .authentication_database
                .as_deref()
                .unwrap_or(database),
        ));
    }
    let mut script = format!(
        "set -eu\numask 077\ndump_collection() {{\n  mongodump --config /work/mongodump.yml --db {}{authentication} \"$@\" --gzip\n}}\n",
        sh_quote(database),
    );
    for (collection, output_name) in collections.into_iter().zip(output_names) {
        let collection = collection
            .map(|collection| format!(" --collection={}", sh_quote(collection)))
            .unwrap_or_default();
        script.push_str(&format!(
            "dump_collection{collection} --archive={}\n",
            sh_quote(&format!("/work/{output_name}")),
        ));
    }
    Ok(script)
}

#[derive(Serialize)]
pub(super) struct MongoDumpConfig<'a> {
    pub(super) uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) password: Option<&'a str>,
}

pub(super) fn mongodb_selected_collections(
    selection: &ImportExportSelection,
) -> Result<Vec<Option<&str>>, ApiError> {
    if selection.mode == SelectionMode::Full {
        return Ok(vec![None]);
    }
    if selection.include.is_empty() {
        return Err(ApiError::BadRequest(
            "mongodb remote selective import requires at least one included collection".to_string(),
        ));
    }
    if let Some(overlap) = selection
        .include
        .iter()
        .find(|collection| selection.exclude.contains(*collection))
    {
        return Err(ApiError::BadRequest(format!(
            "mongodb remote selection cannot include and exclude the same collection: {overlap}"
        )));
    }
    Ok(selection
        .include
        .iter()
        .map(|collection| Some(collection.as_str()))
        .collect())
}
