pub mod config;

use axum::extract::State;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::api::http::{
    policy::ApiRequestContext,
    response::{ApiError, ApiQuery, ApiResponse, ApiResult},
    router::AppState,
};
use crate::auth::scopes;
use crate::{
    placement::DeploymentMode,
    shared::{
        limits::{bytes_to_mib_ceil, mib_to_bytes},
        protocol::Protocol,
    },
};

// API compatibility is versioned independently from the daemon binary release.
pub const API_VERSION: &str = "0.14.0";

#[derive(Debug, Serialize)]
pub struct DeploymentCapability {
    pub protocol: Protocol,
    pub enabled: bool,
    pub modes: Vec<DeploymentMode>,
}

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
    pub deployment_capabilities: Vec<DeploymentCapability>,
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
        postgres_enabled: state.config.protocol_enabled(Protocol::Postgres),
        redis_enabled: state.config.protocol_enabled(Protocol::Redis),
        valkey_enabled: state.config.protocol_enabled(Protocol::Valkey),
        mariadb_enabled: state.config.protocol_enabled(Protocol::Mariadb),
        mysql_enabled: state.config.protocol_enabled(Protocol::Mysql),
        mongodb_enabled: state.config.protocol_enabled(Protocol::Mongodb),
        clickhouse_enabled: state.config.protocol_enabled(Protocol::Clickhouse),
        clickhouse_http_enabled: state.config.protocol_enabled(Protocol::Clickhouse),
        clickhouse_http_bind: state.config.clickhouse.http_bind.clone(),
        clickhouse_http_port: clickhouse_http_port(&state.config.clickhouse.http_bind),
        qdrant_enabled: state.config.protocol_enabled(Protocol::Qdrant),
        deployment_capabilities: deployment_capabilities(&state.config),
        gateways: state.gateway_supervisor.snapshot(),
    }))
}

fn deployment_capabilities(config: &crate::config::Config) -> Vec<DeploymentCapability> {
    Protocol::ALL
        .into_iter()
        .map(|protocol| {
            let mut modes = vec![DeploymentMode::Dedicated];
            if DeploymentMode::Shared.supports(protocol) {
                modes.push(DeploymentMode::Shared);
            }
            DeploymentCapability {
                protocol,
                enabled: config.protocol_enabled(protocol),
                modes,
            }
        })
        .collect()
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

pub async fn scheduler_recommendation(
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
        .unwrap_or_else(|| bytes_to_mib_ceil(size_bytes));
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
            mib_to_bytes(target_disk_mib).clamp(1, crate::api::import_export::MAX_UNARCHIVED_BYTES)
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

    const OPENAPI_YAML: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/api/openapi.yml"));
    const EXAMPLE_CONFIG_YAML: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/example.yml"));

    #[test]
    fn openapi_advertises_remote_import_capability_and_discriminator() {
        let document: Value = serde_yaml::from_str(OPENAPI_YAML).expect("valid OpenAPI YAML");
        assert_eq!(document["info"]["version"].as_str(), Some(API_VERSION));

        let schemas = &document["components"]["schemas"];
        let system = &schemas["SystemResponse"];
        assert!(system["properties"]["remote_import_enabled"].is_mapping());
        assert!(system["properties"]["valkey_enabled"].is_mapping());
        assert!(system["properties"]["deployment_capabilities"].is_mapping());
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
        assert!(
            system["required"]
                .as_sequence()
                .expect("SystemResponse required array")
                .iter()
                .any(|field| field.as_str() == Some("deployment_capabilities"))
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
    fn deployment_capabilities_match_protocol_policy() {
        let config = crate::config::Config::default();
        let capabilities = deployment_capabilities(&config);
        assert_eq!(capabilities.len(), Protocol::ALL.len());
        for (capability, protocol) in capabilities.into_iter().zip(Protocol::ALL) {
            assert_eq!(capability.protocol, protocol);
            assert_eq!(capability.enabled, config.protocol_enabled(protocol));
            assert_eq!(capability.modes.first(), Some(&DeploymentMode::Dedicated));
            assert_eq!(
                capability.modes.contains(&DeploymentMode::Shared),
                DeploymentMode::Shared.supports(capability.protocol)
            );
        }
    }

    #[test]
    fn openapi_shared_deployment_contract_matches_wire_policy() {
        let document: Value = serde_yaml::from_str(OPENAPI_YAML).expect("valid OpenAPI YAML");
        let schemas = &document["components"]["schemas"];

        let protocols = schemas["Protocol"]["enum"]
            .as_sequence()
            .expect("Protocol enum")
            .iter()
            .map(|value| value.as_str().expect("protocol string"))
            .collect::<Vec<_>>();
        assert_eq!(
            protocols,
            Protocol::ALL
                .iter()
                .map(|protocol| protocol.as_str())
                .collect::<Vec<_>>()
        );
        let modes = schemas["DeploymentMode"]["enum"]
            .as_sequence()
            .expect("DeploymentMode enum")
            .iter()
            .map(|value| value.as_str().expect("deployment mode string"))
            .collect::<Vec<_>>();
        assert_eq!(modes, ["dedicated", "shared"]);

        let create = &schemas["CreateInstanceRequest"];
        assert_eq!(
            create["properties"]["deployment_mode"]["default"].as_str(),
            Some("dedicated")
        );
        assert!(
            !create["required"]
                .as_sequence()
                .expect("CreateInstanceRequest required array")
                .iter()
                .any(|field| field.as_str() == Some("deployment_mode"))
        );

        let instance = &schemas["Instance"];
        assert_eq!(instance["additionalProperties"].as_bool(), Some(false));
        for field in ["deployment_mode", "runtime_id"] {
            assert!(
                instance["required"]
                    .as_sequence()
                    .expect("Instance required array")
                    .iter()
                    .any(|required| required.as_str() == Some(field))
            );
        }

        // Limits returned by the daemon add two enforcement fields to the
        // three request fields. Referencing LimitsRequest through allOf would
        // make its additionalProperties=false reject those response fields.
        let instance_limits = &schemas["InstanceLimits"];
        assert!(instance_limits["allOf"].is_null());
        assert_eq!(
            instance_limits["additionalProperties"].as_bool(),
            Some(false)
        );
        let limit_fields = instance_limits["required"]
            .as_sequence()
            .expect("InstanceLimits required array")
            .iter()
            .map(|field| field.as_str().expect("limit field name"))
            .collect::<Vec<_>>();
        assert_eq!(
            limit_fields,
            [
                "cpu_cores",
                "memory_mib",
                "disk_mib",
                "disk_enforced",
                "disk_enforcement_method"
            ]
        );

        let create_responses = &document["paths"]["/api/instances"]["post"]["responses"];
        assert_eq!(
            create_responses["400"]["content"]["application/json"]["schema"]["$ref"].as_str(),
            Some("#/components/schemas/Error")
        );
        assert_eq!(
            create_responses["422"]["content"]["application/json"]["schema"]["$ref"].as_str(),
            Some("#/components/schemas/Error")
        );
        assert_eq!(
            schemas["SystemResponse"]["properties"]["deployment_capabilities"]["items"]["$ref"]
                .as_str(),
            Some("#/components/schemas/DeploymentCapability")
        );

        let pool = &schemas["ResourceReport"]["properties"]["pool"];
        let required = pool["required"]
            .as_sequence()
            .expect("ResourceReport pool required array")
            .iter()
            .map(|field| field.as_str().expect("pool field name"))
            .collect::<Vec<_>>();
        assert_eq!(
            required,
            [
                "runtime_id",
                "cpu_limit_cores",
                "cpu_usage_percent",
                "memory_limit_bytes",
                "memory_usage_bytes"
            ]
        );
        assert_eq!(
            pool["properties"]["cpu_limit_cores"]["type"].as_str(),
            Some("number")
        );
        assert_eq!(
            pool["properties"]["memory_limit_bytes"]["type"].as_str(),
            Some("integer")
        );
        let monitoring = document["paths"]["/ws/monitoring"]["get"]["description"]
            .as_str()
            .expect("monitoring contract description");
        for field in ["runtime_id", "deployment_mode", "resource_scope"] {
            assert!(monitoring.contains(field), "monitoring docs omit {field}");
        }
        for private_pool_field in [
            "pool_cpu_limit_cores",
            "pool_cpu_usage_percent",
            "pool_memory_limit_bytes",
            "pool_memory_usage_bytes",
        ] {
            assert!(
                !monitoring.contains(private_pool_field),
                "tenant monitoring docs leak {private_pool_field}"
            );
        }
    }

    #[test]
    fn openapi_deployment_migration_contract_matches_wire_types() {
        let document: Value = serde_yaml::from_str(OPENAPI_YAML).expect("valid OpenAPI YAML");
        let schemas = &document["components"]["schemas"];
        let migration = &schemas["DeploymentMigration"];

        assert_eq!(migration["additionalProperties"].as_bool(), Some(false));
        let required = migration["required"]
            .as_sequence()
            .expect("DeploymentMigration required array")
            .iter()
            .map(|field| field.as_str().expect("migration field name"))
            .collect::<Vec<_>>();
        assert_eq!(
            required,
            [
                "migration_id",
                "instance_id",
                "protocol",
                "source_mode",
                "target_mode",
                "source_runtime_id",
                "stage",
                "revision",
                "source_fenced",
                "cutover_committed",
                "created_at",
                "updated_at"
            ]
        );

        let stages = schemas["DeploymentMigrationStage"]["enum"]
            .as_sequence()
            .expect("DeploymentMigrationStage enum")
            .iter()
            .map(|stage| stage.as_str().expect("migration stage"))
            .collect::<Vec<_>>();
        let expected_stages = [
            crate::placement::MigrationStage::Requested,
            crate::placement::MigrationStage::Preflight,
            crate::placement::MigrationStage::TargetPreparing,
            crate::placement::MigrationStage::TargetPrepared,
            crate::placement::MigrationStage::SourceFencing,
            crate::placement::MigrationStage::SourceFenced,
            crate::placement::MigrationStage::Exporting,
            crate::placement::MigrationStage::Exported,
            crate::placement::MigrationStage::Importing,
            crate::placement::MigrationStage::Imported,
            crate::placement::MigrationStage::Validating,
            crate::placement::MigrationStage::CutoverPending,
            crate::placement::MigrationStage::CutoverCommitted,
            crate::placement::MigrationStage::VerifyingCutover,
            crate::placement::MigrationStage::CleaningSource,
            crate::placement::MigrationStage::RollingBack,
            crate::placement::MigrationStage::CleanupPending,
            crate::placement::MigrationStage::ManualIntervention,
            crate::placement::MigrationStage::Completed,
            crate::placement::MigrationStage::Failed,
            crate::placement::MigrationStage::Cancelled,
        ];
        assert_eq!(
            stages,
            expected_stages
                .iter()
                .map(|stage| stage.as_str())
                .collect::<Vec<_>>()
        );

        for field in ["failure_code", "failure_message"] {
            let description = migration["properties"][field]["description"]
                .as_str()
                .expect("failure field safety contract");
            let description = description.to_ascii_lowercase();
            assert!(description.contains("stable"));
            assert!(description.contains("sanitized"));
        }
        let failure_codes = migration["properties"]["failure_code"]["enum"]
            .as_sequence()
            .expect("stable migration failure codes")
            .iter()
            .map(|code| code.as_str().expect("failure code"))
            .collect::<Vec<_>>();
        assert_eq!(
            failure_codes,
            [
                "preflight_failed",
                "pre_cutover_failure",
                "structural_validation_timed_out",
                "post_cutover_failure",
                "rolled_back_before_cutover",
                "target_verification_failed",
                "daemon_restarted_before_mutation",
                "daemon_restarted_before_cutover",
                "daemon_restarted_after_cutover"
            ]
        );

        let collection = &document["paths"]["/api/instances/{instance_id}/deployment-migrations"];
        let start = &collection["post"];
        assert_eq!(start["x-required-scope"].as_str(), Some("instances:write"));
        assert!(start["responses"]["501"].is_null());
        assert_eq!(
            start["responses"]["202"]["content"]["application/json"]["schema"]["$ref"].as_str(),
            Some("#/components/schemas/DeploymentMigration")
        );
        assert_eq!(
            start["responses"]["202"]["headers"]["Location"]["schema"]["type"].as_str(),
            Some("string")
        );
        for status in ["400", "404", "409", "422", "429", "503"] {
            assert!(
                !start["responses"][status].is_null(),
                "deployment migration start omits {status}"
            );
        }
        let start_description = start["description"].as_str().expect("start semantics");
        assert!(start_description.contains("asynchronously"));
        assert!(start_description.contains("both directions"));

        assert_eq!(
            collection["get"]["x-required-scope"].as_str(),
            Some("instances:read")
        );
        assert_eq!(
            collection["get"]["responses"]["200"]["content"]["application/json"]["schema"]["items"]
                ["$ref"]
                .as_str(),
            Some("#/components/schemas/DeploymentMigration")
        );
        assert!(!collection["get"]["responses"]["404"].is_null());
        let item = &document["paths"]["/api/instances/{instance_id}/deployment-migrations/{migration_id}"]
            ["get"];
        assert_eq!(item["x-required-scope"].as_str(), Some("instances:read"));
        assert_eq!(
            item["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].as_str(),
            Some("#/components/schemas/DeploymentMigration")
        );
        assert!(!item["responses"]["404"].is_null());
    }

    #[test]
    fn openapi_remote_source_constraints_match_request_validation() {
        let document: Value = serde_yaml::from_str(OPENAPI_YAML).expect("valid OpenAPI YAML");
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
        let document: Value = serde_yaml::from_str(OPENAPI_YAML).expect("valid OpenAPI YAML");
        let info = &document["components"]["schemas"]["BackupInfo"];
        let info_required = info["required"]
            .as_sequence()
            .expect("BackupInfo required array");
        for field in ["protocol", "layout"] {
            assert!(
                info_required
                    .iter()
                    .any(|required| required.as_str() == Some(field)),
                "BackupInfo omits restore-compatibility field {field}"
            );
        }
        assert_eq!(
            info["properties"]["layout"]["$ref"].as_str(),
            Some("#/components/schemas/BackupLayout")
        );
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
        let restore =
            &document["paths"]["/api/instances/{instance_id}/backups/{backup_id}/restore"]["post"];
        assert_eq!(
            restore["responses"]["409"]["content"]["application/json"]["schema"]["$ref"].as_str(),
            Some("#/components/schemas/Error")
        );
        assert!(
            restore["description"]
                .as_str()
                .expect("restore layout contract")
                .contains("restore returns 409")
        );
    }

    #[test]
    fn openapi_advertises_password_reset_without_response_credentials() {
        let document: Value = serde_yaml::from_str(OPENAPI_YAML).expect("valid OpenAPI YAML");
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
            serde_yaml::from_str(EXAMPLE_CONFIG_YAML).expect("valid example config YAML");
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
