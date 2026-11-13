use utoipa::{
    Modify, OpenApi, ToResponse,
    openapi::{
        self, ContentBuilder, HeaderBuilder, KnownFormat, Object, ObjectBuilder, RefOr, Response,
        ResponseBuilder, Schema, Type,
        schema::{AdditionalProperties, SchemaFormat, SchemaType},
        security::{Http, HttpAuthScheme, SecurityScheme},
    },
};

use crate::subsystems::system::API_VERSION;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "DatabasesEverywhere API",
        description = "API used by panels/addons to create, manage, monitor, back up, and restore hosted database instances."
    ),
    servers((url = "http://127.0.0.1:8090", description = "Local daemon API")),
    security(("bearerAuth" = [])),
    paths(
        crate::subsystems::system::system,
        crate::subsystems::system::scheduler_recommendation,
        crate::subsystems::system::config::patch_config,
        crate::subsystems::system::heartbeat,
        crate::subsystems::monitoring::metrics::metrics,
        crate::subsystems::instances::runtime_info::list_instances,
        crate::subsystems::instances::runtime_info::create_instance,
        crate::subsystems::instances::runtime_info::get_instance,
        crate::subsystems::instances::delete::delete_instance,
        crate::subsystems::instances::runtime_info::get_instance_status,
        crate::subsystems::instances::limits::update_instance_limits,
        crate::subsystems::instances::password::reset_instance_password,
        crate::subsystems::instances::deployment::list_deployment_migrations,
        crate::subsystems::instances::deployment::start_deployment_migration,
        crate::subsystems::instances::deployment::get_deployment_migration,
        crate::subsystems::instances::reconcile_instance,
        crate::subsystems::instances::power_instance,
        crate::subsystems::instances::image_update::update_instance_image,
        crate::subsystems::monitoring::resources::handlers::list_resources,
        crate::subsystems::monitoring::resources::handlers::node_resource_summary,
        crate::subsystems::monitoring::resources::pools::list_shared_pools,
        crate::subsystems::pools::operations::create,
        crate::subsystems::monitoring::resources::pools::get_shared_pool,
        crate::subsystems::pools::limits::resize_pool,
        crate::subsystems::pools::operations::delete,
        crate::subsystems::monitoring::resources::pools::list_pool_tenants,
        crate::subsystems::pools::operations::create_database,
        crate::subsystems::pools::operations::status,
        crate::subsystems::pools::operations::power,
        crate::subsystems::pools::image::update,
        crate::subsystems::pools::streams::logs,
        crate::subsystems::pools::streams::backups,
        crate::subsystems::pools::streams::monitoring,
        crate::subsystems::pools::streams::log_socket,
        crate::subsystems::monitoring::resources::handlers::instance_resources,
        crate::subsystems::monitoring::activity::current,
        crate::subsystems::monitoring::activity::history,
        crate::subsystems::instances::logs::instance_logs,
        crate::subsystems::import_export::jobs::export_instance,
        crate::subsystems::import_export::uploads::handlers::import_entry,
        crate::subsystems::import_export::uploads::handlers::list_import_uploads,
        crate::subsystems::import_export::uploads::handlers::get_import_upload,
        crate::subsystems::import_export::uploads::handlers::delete_import_upload,
        crate::subsystems::import_export::uploads::handlers::get_import_catalog,
        crate::subsystems::import_export::uploads::handlers::inspect_import_upload,
        crate::subsystems::import_export::jobs::list_import_export_jobs,
        crate::subsystems::import_export::jobs::get_import_export_job,
        crate::subsystems::backups::handlers::list_instance_backups,
        crate::subsystems::backups::handlers::run_instance_backup,
        crate::subsystems::backups::handlers::list_unsupported_backups,
        crate::subsystems::backups::handlers::backup_status,
        crate::subsystems::backups::handlers::run_all_backups,
        crate::subsystems::backups::handlers::delete_instance_backup,
        crate::subsystems::backups::handlers::browse_instance_backup,
        crate::subsystems::artifacts::handlers::download_backup,
        crate::subsystems::artifacts::handlers::create_backup_download,
        crate::subsystems::backups::handlers::restore_instance_backup,
        crate::subsystems::artifacts::handlers::list_instance_artifacts,
        crate::subsystems::artifacts::handlers::delete_artifact,
        crate::subsystems::artifacts::handlers::download_artifact,
        crate::subsystems::artifacts::handlers::create_artifact_download,
        crate::subsystems::artifacts::handlers::apply_retention,
        crate::subsystems::import_export::recovery::failed_jobs,
        crate::subsystems::import_export::recovery::retry_job,
        crate::subsystems::import_export::recovery::restore_artifact,
        crate::subsystems::monitoring::tokens::issue_ws_token,
        crate::subsystems::instances::images::pull_image,
        crate::subsystems::monitoring::websocket::monitoring::monitoring,
        crate::subsystems::monitoring::websocket::logs,
        crate::subsystems::monitoring::websocket::import_export,
    ),
    components(
        schemas(
            crate::routes::http::response::ErrorBody,
            crate::subsystems::pools::streams::PoolStats,
            crate::subsystems::monitoring::websocket::log_stream::PoolLogEvent,
            crate::subsystems::monitoring::websocket::monitoring::MonitoringBatch,
            crate::subsystems::monitoring::websocket::log_stream::InstanceLogEvent,
            crate::subsystems::monitoring::websocket::import_export::ImportExportSnapshot,
            crate::subsystems::monitoring::websocket::import_export::ImportExportJobEvent,
            crate::subsystems::monitoring::websocket::import_export::ImportExportLaggedEvent,
        ),
        responses(ApiError, Unauthorized, NotFound)
    ),
    modifiers(&Contract),
    tags(
        (name = "system", description = "Daemon status, configuration and metrics."),
        (name = "instances", description = "Database instance lifecycle."),
        (name = "import-export", description = "Imports, exports and their jobs."),
        (name = "backups", description = "Instance backups and restores."),
        (name = "artifacts", description = "Stored export artifacts and downloads."),
        (name = "pools", description = "Shared engine pools."),
        (name = "monitoring", description = "Resources, activity and live streams."),
        (name = "admin", description = "Node-wide administration."),
    )
)]
pub struct ApiDoc;

pub fn yaml() -> String {
    let mut document =
        yaml_serde::to_value(ApiDoc::openapi()).expect("the OpenAPI document must serialize");
    sort_extensions(&mut document);
    let yaml = yaml_serde::to_string(&document).expect("the OpenAPI document must serialize");
    format!(
        "# Generated from the code by `DBEV_WRITE_OPENAPI=1 cargo test --test openapi_contract`.\n{yaml}"
    )
}

fn sort_extensions(value: &mut yaml_serde::Value) {
    match value {
        yaml_serde::Value::Mapping(mapping) => {
            let mut extensions: Vec<_> = mapping
                .keys()
                .filter(|key| key.as_str().is_some_and(|key| key.starts_with("x-")))
                .cloned()
                .collect();
            extensions.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
            for key in extensions {
                if let Some(extension) = mapping.shift_remove(&key) {
                    mapping.insert(key, extension);
                }
            }
            mapping.values_mut().for_each(sort_extensions);
        }
        yaml_serde::Value::Sequence(sequence) => sequence.iter_mut().for_each(sort_extensions),
        _ => {}
    }
}

fn error_response(description: &str) -> ResponseBuilder {
    ResponseBuilder::new().description(description).content(
        "application/json",
        ContentBuilder::new()
            .schema(Some(RefOr::Ref(openapi::Ref::from_schema_name("Error"))))
            .build(),
    )
}

pub(crate) struct ApiError;

impl ToResponse<'_> for ApiError {
    fn response() -> (&'static str, RefOr<Response>) {
        let error_id = HeaderBuilder::new()
            .description(Some(
                "Opaque support identifier included for server-side failures.",
            ))
            .schema(Some(
                ObjectBuilder::new()
                    .schema_type(Type::String)
                    .format(Some(SchemaFormat::KnownFormat(KnownFormat::Uuid))),
            ))
            .build();
        let response = error_response("Request rejection or server-side failure. Internal details are logged under error_id and are never returned to clients.")
            .header("X-Error-Id", error_id)
            .build();
        ("ApiError", response.into())
    }
}

pub(crate) struct Unauthorized;

impl ToResponse<'_> for Unauthorized {
    fn response() -> (&'static str, RefOr<Response>) {
        let response = error_response("Missing, invalid, or insufficient bearer token.").build();
        ("Unauthorized", response.into())
    }
}

pub(crate) struct NotFound;

impl ToResponse<'_> for NotFound {
    fn response() -> (&'static str, RefOr<Response>) {
        (
            "NotFound",
            error_response("Resource not found.").build().into(),
        )
    }
}

struct Contract;

impl Modify for Contract {
    fn modify(&self, openapi: &mut openapi::OpenApi) {
        openapi.info.version = API_VERSION.into();
        openapi.info.license = None;
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearerAuth",
            SecurityScheme::Http(
                Http::builder()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("panel token")
                    .build(),
            ),
        );
        for schema in components.schemas.values_mut() {
            close_objects(schema);
        }
        for item in openapi.paths.paths.values_mut() {
            for operation in [
                &mut item.get,
                &mut item.put,
                &mut item.post,
                &mut item.delete,
                &mut item.patch,
            ]
            .into_iter()
            .flatten()
            {
                operation.responses.responses.insert(
                    "default".into(),
                    RefOr::Ref(openapi::Ref::from_response_name(ApiError::response().0)),
                );
                let bodies = operation
                    .request_body
                    .iter_mut()
                    .filter_map(|body| match body {
                        RefOr::T(body) => Some(body),
                        RefOr::Ref(_) => None,
                    })
                    .flat_map(|body| body.content.values_mut())
                    .chain(
                        operation
                            .responses
                            .responses
                            .values_mut()
                            .filter_map(|response| match response {
                                RefOr::T(response) => Some(response),
                                RefOr::Ref(_) => None,
                            })
                            .flat_map(|response| response.content.values_mut()),
                    );
                for content in bodies {
                    if let RefOr::T(content) = content
                        && let Some(schema) = content.schema.as_mut()
                    {
                        close_objects(schema);
                    }
                }
            }
        }
    }
}

fn close_objects(schema: &mut RefOr<Schema>) {
    let RefOr::T(schema) = schema else {
        return;
    };
    match schema {
        Schema::Object(object) => {
            if !object.properties.is_empty() && object.additional_properties.is_none() {
                object.additional_properties =
                    Some(Box::new(AdditionalProperties::FreeForm(false)));
            }
            object.properties.values_mut().for_each(close_objects);
        }
        Schema::Array(array) => {
            if let openapi::schema::ArrayItems::RefOrSchema(items) = &mut array.items {
                close_objects(items);
            }
        }
        Schema::OneOf(one_of) => one_of.items.iter_mut().for_each(close_objects),
        Schema::AnyOf(any_of) => any_of.items.iter_mut().for_each(close_objects),
        _ => {}
    }
}

pub(crate) fn literal(values: impl IntoIterator<Item = serde_json::Value>) -> Object {
    let values: Vec<serde_json::Value> = values.into_iter().collect();
    let schema_type = match values.iter().find(|value| !value.is_null()) {
        Some(serde_json::Value::Bool(_)) => Type::Boolean,
        Some(serde_json::Value::Number(_)) => Type::Integer,
        _ => Type::String,
    };
    let schema_type = if values.iter().any(serde_json::Value::is_null) {
        SchemaType::from_iter([schema_type, Type::Null])
    } else {
        SchemaType::Type(schema_type)
    };
    ObjectBuilder::new()
        .schema_type(schema_type)
        .enum_values(Some(values))
        .build()
}

macro_rules! literals {
    ($($name:ident = [$($value:expr),+]),* $(,)?) => {
        $(pub(crate) fn $name() -> Object {
            literal([$(serde_json::Value::from($value)),+])
        })*
    };
}

pub(crate) mod literals {
    use super::{Object, literal};

    literals! {
        bearer = ["Bearer"],
        credential_and_peer_ip = ["credential_and_peer_ip"],
        daemon_engine = ["docker", "podman"],
        databases_everywhere = ["databases-everywhere"],
        gateway_status = ["starting", "ready", "failed", "stopping"],
        action = ["import", "export"],
        none = ["none"],
        ok = ["ok"],
        ready = ["ready"],
        shared_pool_scope = ["server", serde_json::Value::Null],
        transfer_mode = ["merge", "wipe"],
        unix_socket = ["unix_socket"],
        yes = [true],
        backup_storage_driver = ["local", "s3", "kopia"],
        consistency_level = ["stopped_copy", "transactional_snapshot", "physical_recovery_point", "per_object", serde_json::Value::Null],
        dedicated_backup_mode = ["online", "offline"],
        pool_accepted_status = ["creating", "updating"],
        pool_stats = ["pool_stats"],
        stats = ["stats"],
        logs = ["logs"],
        log_event = ["reset", "append", "end"],
        enforcement_strength = ["hard", "soft", "none"],
        desired_state = ["running", "stopped"],
        connections_source = ["gateway_authenticated_exact", "unavailable"],
        network_source = ["gateway_route_exact"],
        operations_source = ["gateway_protocol_observed", "engine_query_log_observed", "unavailable"],
        engine_query_source = ["engine_query_observed", "unavailable"],
        bucket_seconds = [60],
        max_buckets = [1440],
        creating = ["creating"],
        install_action = ["create", "image_update", "major_upgrade"],
        export_archive_format = ["plain", "gzip", "bzip2", serde_json::Value::Null],
        import_archive_format = ["plain", "gzip", "bzip2", "tar", "tar.gz", "zip", serde_json::Value::Null],
        import_export_job_event = ["import_export_job"],
        import_export_lagged = ["import_export_lagged"],
        import_export_snapshot = ["import_export_snapshot"],
        upload_state = ["uploading", "uploaded", "processing", "ready", "failed", "importing", "consumed", "deleting"],
    }
}
