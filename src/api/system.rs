use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::api::{
    api_response::{ApiError, ApiQuery, ApiResponse, ApiResult},
    routes::AppState,
    security_policy::ApiRequestContext,
};
use crate::auth::scopes;

// API compatibility is versioned independently from the daemon binary release.
pub const API_VERSION: &str = "0.12.0";

#[derive(Debug, Serialize)]
pub struct SystemResponse {
    pub service: &'static str,
    pub version: &'static str,
    pub api_version: &'static str,
    pub api_readiness: &'static str,
    pub uuid: String,
    pub token_id: String,
    pub remote: String,
    pub api_host: String,
    pub api_port: u16,
    pub api_bind: String,
    pub api_ssl_enabled: bool,
    pub api_rate_limit_per_minute: u32,
    pub api_rate_limit_scope: &'static str,
    pub daemon_engine: &'static str,
    pub daemon_socket: String,
    pub database_container_network_mode: &'static str,
    pub database_backend_transport: &'static str,
    pub daemon_disk_limits_enforced: bool,
    pub disk_mode: &'static str,
    pub prevent_cpu_overallocation: bool,
    pub prevent_memory_overallocation: bool,
    pub prevent_disk_overallocation: bool,
    pub remote_import_enabled: bool,
    pub postgres_enabled: bool,
    pub redis_enabled: bool,
    pub valkey_enabled: bool,
    pub mariadb_enabled: bool,
    pub mysql_enabled: bool,
    pub mongodb_enabled: bool,
    pub clickhouse_enabled: bool,
    pub clickhouse_http_enabled: bool,
    pub clickhouse_http_bind: String,
    pub clickhouse_http_port: u16,
    pub qdrant_enabled: bool,
    pub gateways: crate::gateway::supervisor::GatewayReadinessSnapshot,
}

pub async fn system(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<SystemResponse> {
    auth.require_scope(scopes::SYSTEM_READ)?;
    Ok(ApiResponse::ok(SystemResponse {
        service: "databases-everywhere",
        version: env!("CARGO_PKG_VERSION"),
        api_version: API_VERSION,
        api_readiness: "ready",
        uuid: state.config.uuid.clone(),
        token_id: state.config.token_id.clone(),
        remote: state.config.remote.clone(),
        api_host: state.config.api.host.clone(),
        api_port: state.config.api.port,
        api_bind: state.config.api.bind_addr(),
        api_ssl_enabled: state.config.api.ssl.enabled,
        api_rate_limit_per_minute: state.config.security.api_rate_limit_per_minute,
        api_rate_limit_scope: "credential_and_peer_ip",
        daemon_engine: state.config.daemon.engine.as_str(),
        daemon_socket: state.docker.socket_path().to_string(),
        database_container_network_mode: "none",
        database_backend_transport: "unix_socket",
        daemon_disk_limits_enforced: state.config.disk.mode.enforced(),
        disk_mode: state.config.disk.mode.method(),
        prevent_cpu_overallocation: state.config.allocation.prevent_cpu_overallocation,
        prevent_memory_overallocation: state.config.allocation.prevent_memory_overallocation,
        prevent_disk_overallocation: state.config.allocation.prevent_disk_overallocation,
        remote_import_enabled: state.config.security.remote_import.enabled,
        postgres_enabled: state.config.postgres.enabled,
        redis_enabled: state.config.redis.enabled,
        valkey_enabled: state.config.valkey.enabled,
        mariadb_enabled: state.config.mariadb.enabled,
        mysql_enabled: state.config.mysql.enabled,
        mongodb_enabled: state.config.mongodb.enabled,
        clickhouse_enabled: state.config.clickhouse.enabled,
        clickhouse_http_enabled: state.config.clickhouse.enabled,
        clickhouse_http_bind: state.config.clickhouse.http_bind.clone(),
        clickhouse_http_port: clickhouse_http_port(&state.config.clickhouse.http_bind),
        qdrant_enabled: state.config.qdrant.enabled,
        gateways: state.gateway_supervisor.snapshot(),
    }))
}

fn clickhouse_http_port(bind: &str) -> u16 {
    bind.parse::<SocketAddr>()
        .map(|addr| addr.port())
        .unwrap_or_default()
}

#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    pub status: &'static str,
}

pub async fn heartbeat(auth: ApiRequestContext) -> ApiResult<HeartbeatResponse> {
    auth.require_scope(scopes::SYSTEM_READ)?;
    Ok(ApiResponse::ok(HeartbeatResponse { status: "ok" }))
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImportExportSchedulerEstimateQuery {
    pub protocol: Option<String>,
    pub action: Option<String>,
    pub size_bytes: Option<u64>,
    pub target_disk_mib: Option<u64>,
    pub mode: Option<String>,
    pub compressed: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ImportExportSchedulerRecommendationResponse {
    pub scheduler: crate::jobs::import_export::SchedulerSnapshot,
    pub estimate: crate::jobs::import_export::JobResourceCost,
    pub recommended_active_jobs: usize,
    pub admitted_jobs: usize,
    pub max_queued_jobs: usize,
    pub max_queued_jobs_per_instance: usize,
}

pub async fn import_export_scheduler_recommendation(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiQuery(query): ApiQuery<ImportExportSchedulerEstimateQuery>,
) -> ApiResult<ImportExportSchedulerRecommendationResponse> {
    auth.require_scope(scopes::SYSTEM_READ)?;
    let protocol = query
        .protocol
        .as_deref()
        .unwrap_or("postgres")
        .parse::<crate::shared::protocol::Protocol>()
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let export = match query.action.as_deref().unwrap_or("import") {
        "import" => false,
        "export" => true,
        _ => {
            return Err(ApiError::BadRequest(
                "action must be import or export".to_string(),
            ));
        }
    };
    let wipe = match query.mode.as_deref().unwrap_or("merge") {
        "merge" => false,
        "wipe" if !export => true,
        "wipe" => {
            return Err(ApiError::BadRequest(
                "mode=wipe is valid only for imports".to_string(),
            ));
        }
        _ => {
            return Err(ApiError::BadRequest(
                "mode must be merge or wipe".to_string(),
            ));
        }
    };
    let size_bytes = query
        .size_bytes
        .unwrap_or(state.config.artifacts.import_upload_max_bytes);
    if size_bytes == 0 || size_bytes > crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES {
        return Err(ApiError::BadRequest(format!(
            "size_bytes must be between 1 and {}",
            crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES
        )));
    }
    let compressed = query.compressed.unwrap_or(false)
        || crate::jobs::import_export::protocol_uses_native_compression(protocol);
    let target_disk_mib = query
        .target_disk_mib
        .unwrap_or_else(|| size_bytes.saturating_add(1024 * 1024 - 1) / (1024 * 1024));
    if target_disk_mib == 0 {
        return Err(ApiError::BadRequest(
            "target_disk_mib must be greater than zero".to_string(),
        ));
    }
    let estimated_input_size_bytes = if export {
        size_bytes
    } else {
        crate::jobs::import_export::conservative_import_input_bytes(
            protocol,
            size_bytes,
            state
                .config
                .artifacts
                .import_upload_max_bytes
                .min(crate::api::import_export::MAX_UNARCHIVED_BYTES),
            target_disk_mib,
            compressed,
        )
    };
    let rollback_size_bytes =
        if wipe && crate::jobs::import_export::protocol_uses_logical_dumps(protocol) {
            target_disk_mib
                .saturating_mul(1024 * 1024)
                .clamp(1, crate::api::import_export::MAX_UNARCHIVED_BYTES)
        } else {
            0
        };
    let estimate = crate::jobs::import_export::JobResourceCost::estimate(
        crate::jobs::import_export::JobEstimateInput {
            protocol,
            input_size_bytes: estimated_input_size_bytes,
            rollback_size_bytes,
            wipe,
            compressed,
            export,
        },
    );
    let scheduler = state.import_export_jobs.scheduler_snapshot();
    let config = &state.config.artifacts.import_export_scheduler;
    Ok(ApiResponse::ok(
        ImportExportSchedulerRecommendationResponse {
            recommended_active_jobs: scheduler
                .capacity
                .model_recommended_active_jobs(estimate, config.dynamic_max_active_jobs),
            admitted_jobs: state.import_export_jobs.active_count(),
            scheduler,
            estimate,
            max_queued_jobs: config.max_queued_jobs,
            max_queued_jobs_per_instance: config.max_queued_jobs_per_instance,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml::Value;

    #[test]
    fn openapi_advertises_remote_import_capability_and_discriminator() {
        let document: Value =
            serde_yaml::from_str(include_str!("../../openapi.yml")).expect("valid OpenAPI YAML");
        assert_eq!(document["info"]["version"].as_str(), Some(API_VERSION));

        let schemas = &document["components"]["schemas"];
        let system = &schemas["SystemResponse"];
        assert!(system["properties"]["remote_import_enabled"].is_mapping());
        assert!(system["properties"]["valkey_enabled"].is_mapping());
        for field in [
            "prevent_cpu_overallocation",
            "prevent_memory_overallocation",
            "prevent_disk_overallocation",
        ] {
            assert!(system["properties"][field].is_mapping());
            assert!(
                system["required"]
                    .as_sequence()
                    .expect("SystemResponse required array")
                    .iter()
                    .any(|required| required.as_str() == Some(field))
            );
        }
        assert!(
            system["required"]
                .as_sequence()
                .expect("SystemResponse required array")
                .iter()
                .any(|field| field.as_str() == Some("remote_import_enabled"))
        );

        let discriminator = &schemas["ImportRequest"]["properties"]["source"]["discriminator"];
        assert_eq!(discriminator["propertyName"].as_str(), Some("type"));
        assert_eq!(
            discriminator["mapping"]["artifact"].as_str(),
            Some("#/components/schemas/ArtifactImportSource")
        );
        assert_eq!(
            discriminator["mapping"]["remote"].as_str(),
            Some("#/components/schemas/RemoteImportSource")
        );
    }

    #[test]
    fn openapi_remote_source_constraints_match_request_validation() {
        let document: Value =
            serde_yaml::from_str(include_str!("../../openapi.yml")).expect("valid OpenAPI YAML");
        let properties = &document["components"]["schemas"]["RemoteImportSource"]["properties"];

        assert_eq!(properties["host"]["minLength"].as_i64(), Some(1));
        assert_eq!(properties["host"]["maxLength"].as_i64(), Some(253));
        for field in ["database", "username", "authentication_database"] {
            assert_eq!(properties[field]["minLength"].as_i64(), Some(1));
            assert_eq!(properties[field]["maxLength"].as_i64(), Some(256));
            assert_eq!(
                properties[field]["pattern"].as_str(),
                Some(r"^[^\u0000-\u001F\u007F-\u009F]+$")
            );
        }
        assert_eq!(properties["password"]["writeOnly"].as_bool(), Some(true));
        assert_eq!(properties["api_key"]["writeOnly"].as_bool(), Some(true));
        let password_description = properties["password"]["description"]
            .as_str()
            .expect("password description");
        assert!(password_description.contains("durable job records or metadata"));
        assert!(password_description.contains("mode-0600"));

        let artifact_formats = document["components"]["schemas"]["ArtifactImportSource"]
            ["properties"]["archive_format"]["enum"]
            .as_sequence()
            .expect("artifact archive format enum");
        assert!(
            !artifact_formats
                .iter()
                .any(|format| format.as_str() == Some("rar"))
        );
    }

    #[test]
    fn openapi_advertises_backup_storage_and_catalog_browsing() {
        let document: Value =
            serde_yaml::from_str(include_str!("../../openapi.yml")).expect("valid OpenAPI YAML");
        let status = &document["components"]["schemas"]["BackupStatusResponse"];
        assert_eq!(
            status["properties"]["storage_driver"]["enum"]
                .as_sequence()
                .expect("storage driver enum")
                .len(),
            3
        );
        let browse =
            &document["paths"]["/api/instances/{instance_id}/backups/{backup_id}/contents"]["get"];
        assert_eq!(browse["x-required-scope"].as_str(), Some("backups:read"));
        assert_eq!(
            browse["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].as_str(),
            Some("#/components/schemas/BackupContentsResponse")
        );
    }

    #[test]
    fn openapi_advertises_password_reset_without_response_credentials() {
        let document: Value =
            serde_yaml::from_str(include_str!("../../openapi.yml")).expect("valid OpenAPI YAML");
        let operation = &document["paths"]["/api/instances/{instance_id}/password"]["patch"];
        assert_eq!(
            operation["x-required-scope"].as_str(),
            Some(crate::auth::scopes::INSTANCES_WRITE)
        );
        assert_eq!(
            document["components"]["schemas"]["ResetInstancePasswordRequest"]["properties"]
                ["password"]["writeOnly"]
                .as_bool(),
            Some(true)
        );
        let response_properties =
            document["components"]["schemas"]["ResetInstancePasswordResponse"]["properties"]
                .as_mapping()
                .expect("password-reset response properties");
        assert_eq!(response_properties.len(), 2);
        assert!(response_properties.contains_key(Value::String("instance".to_string())));
        assert!(response_properties.contains_key(Value::String("restarted".to_string())));
    }

    #[test]
    fn example_config_includes_valid_backup_driver_settings() {
        let config: crate::config::Config =
            serde_yaml::from_str(include_str!("../../config.example.yml"))
                .expect("valid example config YAML");
        assert_eq!(
            config.backups.storage.driver,
            crate::config::BackupStorageDriver::Local
        );
        assert!(config.backups.browsing.enabled);
        assert!(config.allocation.prevent_cpu_overallocation);
        assert!(config.allocation.prevent_memory_overallocation);
        assert!(config.allocation.prevent_disk_overallocation);
    }

    #[test]
    fn scheduler_recommendation_distinguishes_admission_from_execution_waiters() {
        let jobs = crate::jobs::import_export::ImportExportJobs::default();
        let _admitted = jobs.try_admit("inst-waiting-on-lock").unwrap();
        let scheduler = jobs.scheduler_snapshot();
        let estimate = crate::jobs::import_export::JobResourceCost::estimate(
            crate::jobs::import_export::JobEstimateInput {
                protocol: crate::shared::protocol::Protocol::Postgres,
                input_size_bytes: 1024,
                rollback_size_bytes: 0,
                wipe: false,
                compressed: false,
                export: false,
            },
        );
        let response = ImportExportSchedulerRecommendationResponse {
            scheduler,
            estimate,
            recommended_active_jobs: 1,
            admitted_jobs: jobs.active_count(),
            max_queued_jobs: 1024,
            max_queued_jobs_per_instance: 32,
        };
        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["admitted_jobs"].as_u64(), Some(1));
        assert_eq!(json["scheduler"]["active_jobs"].as_u64(), Some(0));
        assert_eq!(json["scheduler"]["waiting_jobs"].as_u64(), Some(0));
    }
}
