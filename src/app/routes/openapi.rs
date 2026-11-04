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
        crate::subsystems::monitoring::tokens::issue_ws_token,
    ),
    components(
        schemas(crate::routes::http::response::ErrorBody),
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
    }
}
