use std::collections::HashSet;

use databases_everywhere::{api::system::API_VERSION, auth::scopes};
use yaml_serde::Value;

const INSTANCE_PATHS: &[&str] = &[
    "/api/instances/{instance_id}/activity",
    "/api/instances/{instance_id}/activity/history",
    "/api/instances/{instance_id}/artifacts",
    "/api/instances/{instance_id}/artifacts/{artifact_id}",
    "/api/instances/{instance_id}/artifacts/{artifact_id}/download",
    "/api/instances/{instance_id}/backups",
    "/api/instances/{instance_id}/backups/{backup_id}",
    "/api/instances/{instance_id}/backups/{backup_id}/download",
    "/api/instances/{instance_id}/backups/{backup_id}/restore",
    "/api/instances/{instance_id}/import-export/jobs",
    "/api/instances/{instance_id}/import-export/jobs/{job_id}",
    "/api/instances/{instance_id}/recovery/jobs/{job_id}/retry",
    "/api/instances/{instance_id}/recovery/restore",
    "/ws/instances/{instance_id}/import-export",
    "/ws/instances/{instance_id}/logs",
];

const ADMIN_PATHS: &[&str] = &[
    "/api/admin/backups/run",
    "/api/admin/backups/status",
    "/api/admin/images/pull",
    "/api/admin/recovery/failed-jobs",
    "/api/admin/resources",
    "/api/admin/resources/summary",
    "/api/pools",
    "/api/pools/{runtime_id}",
    "/api/pools/{runtime_id}/instances",
    "/api/pools/{runtime_id}/status",
    "/api/pools/{runtime_id}/power",
    "/api/pools/{runtime_id}/image",
    "/api/pools/{runtime_id}/logs",
    "/api/pools/{runtime_id}/backups",
    "/ws/pools/{runtime_id}/logs",
    "/ws/pools/{runtime_id}/monitoring",
];

const RETIRED_PATHS: &[&str] = &[
    "/api/admin/shared-pools",
    "/api/admin/shared-pools/{runtime_id}",
    "/api/admin/shared-pools/{runtime_id}/instances",
    "/api/artifacts",
    "/api/backups",
    "/api/import-export/jobs",
    "/api/recovery/failed-jobs",
    "/api/resources",
    "/api/runtime-instances",
    "/api/admin/runtime-instances",
    "/ws/import-export",
    "/ws/logs",
    "/ws/recovery",
    "/api/instances/{instance_id}/start",
    "/api/instances/{instance_id}/stop",
    "/api/instances/{instance_id}/restart",
    "/api/instances/{instance_id}/artifacts/{artifact_id}/download-token",
    "/api/instances/{instance_id}/backups/{backup_id}/download-token",
    "/api/artifacts/download-signed",
    "/api/backups/download-signed",
];

const METHODS: &[&str] = &["get", "post", "patch", "delete"];
const ROUTE_SOURCES: &[&str] = &[include_str!("../src/app/api/http/router.rs")];

fn router_paths(source: &str) -> HashSet<&str> {
    source
        .split(".route(")
        .skip(1)
        .map(|route| {
            let start = route.find('"').expect("route must contain a string path") + 1;
            let remainder = &route[start..];
            let end = remainder
                .find('"')
                .expect("route path string must terminate");
            &remainder[..end]
        })
        .collect()
}

fn router_operations(source: &str) -> HashSet<String> {
    source
        .split(".route(")
        .skip(1)
        .flat_map(|route| {
            let path_start = route.find('"').expect("route must contain a string path") + 1;
            let path_remainder = &route[path_start..];
            let path_end = path_remainder
                .find('"')
                .expect("route path string must terminate");
            let path = &path_remainder[..path_end];
            let mut depth = 1_usize;
            let mut route_end = route.len();
            for (index, character) in route.char_indices() {
                match character {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            route_end = index;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let route_call = &route[..route_end];
            METHODS
                .iter()
                .filter(move |method| route_call.contains(&format!("{method}(")))
                .map(move |method| format!("{method} {path}"))
        })
        .collect()
}

fn property_names(schema: &Value) -> HashSet<&str> {
    schema["properties"]
        .as_mapping()
        .expect("schema must contain properties")
        .keys()
        .map(|key| key.as_str().expect("property names must be strings"))
        .collect()
}

#[test]
fn openapi_and_router_use_only_the_scoped_contract() {
    let source = include_str!("../docs/api/openapi.yml");
    let document: Value = yaml_serde::from_str(source).expect("openapi.yml must be valid YAML");
    let paths = document["paths"]
        .as_mapping()
        .expect("OpenAPI document must contain a paths mapping");
    let documented: HashSet<&str> = paths
        .keys()
        .map(|key| key.as_str().expect("OpenAPI path keys must be strings"))
        .collect();
    let routed: HashSet<&str> = ROUTE_SOURCES
        .iter()
        .flat_map(|source| router_paths(source))
        .collect();
    let documented_operations: HashSet<String> = paths
        .iter()
        .flat_map(|(path, item)| {
            let path = path.as_str().expect("OpenAPI path keys must be strings");
            METHODS
                .iter()
                .filter(move |method| item[**method].is_mapping())
                .map(move |method| format!("{method} {path}"))
        })
        .collect();
    let routed_operations: HashSet<String> = ROUTE_SOURCES
        .iter()
        .flat_map(|source| router_operations(source))
        .collect();

    assert_eq!(
        documented, routed,
        "every router path must be documented exactly once in OpenAPI"
    );
    assert_eq!(
        documented_operations, routed_operations,
        "every routed path and HTTP method must exactly match OpenAPI"
    );

    for path in INSTANCE_PATHS.iter().chain(ADMIN_PATHS) {
        assert!(documented.contains(path), "OpenAPI is missing {path}");
        assert!(routed.contains(path), "router is missing {path}");
    }

    for path in RETIRED_PATHS {
        assert!(
            !documented.contains(path),
            "retired OpenAPI path remains: {path}"
        );
        assert!(
            !routed.contains(path),
            "retired router path remains: {path}"
        );
    }

    assert!(!source.contains("artifact_path"));
    assert!(!source.contains("export_artifact_path"));
    assert!(!source.contains("old_volume_backup_path"));
    assert!(!source.contains("nullable:"));

    assert!(document["paths"]["/api/heartbeat"]["get"].is_mapping());
    assert!(document["paths"]["/api/heartbeat"]["post"].is_null());
    assert!(
        document["paths"]["/api/heartbeat"]["get"]["responses"]["503"].is_null(),
        "heartbeat must not depend on instance or gateway readiness"
    );
    assert!(document["paths"]["/api/instances/{instance_id}/power"]["post"].is_mapping());
    for (path, scope) in [
        (
            "/api/instances/{instance_id}/artifacts/{artifact_id}/download",
            scopes::ARTIFACTS_READ,
        ),
        (
            "/api/instances/{instance_id}/backups/{backup_id}/download",
            scopes::BACKUPS_READ,
        ),
    ] {
        let download = &document["paths"][path];
        assert!(download["get"].is_mapping(), "{path} must support GET");
        assert!(download["post"].is_mapping(), "{path} must support POST");
        assert_eq!(download["post"]["x-required-scope"].as_str(), Some(scope));
        assert_eq!(
            download["get"]["security"].as_sequence().map(Vec::len),
            Some(0),
            "temporary download GET must authenticate with its URL capability"
        );
    }

    for (path, item) in paths {
        let path = path.as_str().expect("OpenAPI path keys must be strings");
        for method in METHODS {
            let operation = &item[*method];
            if operation.is_null() {
                continue;
            }
            assert_eq!(
                operation["responses"]["default"]["$ref"].as_str(),
                Some("#/components/responses/ApiError"),
                "{method} {path} must use the centralized API error response"
            );
            if method == &"get" && path.ends_with("/download") {
                continue;
            }
            let scope = operation["x-required-scope"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} is missing x-required-scope"));
            assert!(
                scopes::is_known(scope),
                "{method} {path} documents unknown scope {scope}"
            );
        }
    }
}

#[test]
fn openapi_describes_the_current_response_contract() {
    let source = include_str!("../docs/api/openapi.yml");
    let document: Value = yaml_serde::from_str(source).expect("openapi.yml must be valid YAML");
    let schemas = &document["components"]["schemas"];

    assert_eq!(document["info"]["version"].as_str(), Some(API_VERSION));

    let import_properties = property_names(&schemas["ImportRequest"]);
    assert_eq!(
        import_properties,
        HashSet::from(["source", "mode", "selection"]),
        "import mode belongs at request level; archive settings belong inside artifact sources"
    );
    let artifact_source_properties = property_names(&schemas["ArtifactImportSource"]);
    assert_eq!(
        artifact_source_properties,
        HashSet::from(["type", "artifact_id", "archive_format"])
    );
    assert_eq!(
        property_names(&schemas["RemoteImportSource"]),
        HashSet::from([
            "type",
            "host",
            "port",
            "tls",
            "database",
            "username",
            "password",
            "authentication_database",
            "database_index",
            "api_key",
        ])
    );
    assert_eq!(
        schemas["RemoteImportSource"]["properties"]["password"]["writeOnly"].as_bool(),
        Some(true)
    );
    assert_eq!(
        schemas["RemoteImportSource"]["properties"]["api_key"]["writeOnly"].as_bool(),
        Some(true)
    );
    assert_eq!(
        property_names(&schemas["ExportRequest"]),
        HashSet::from(["selection", "archive_format"])
    );

    assert!(document["paths"]["/api/instances"]["post"]["responses"]["202"].is_mapping());
    assert!(document["paths"]["/api/instances"]["post"]["responses"]["200"].is_null());
    for path in [
        "/api/instances/{instance_id}/export",
        "/api/instances/{instance_id}/import",
        "/api/instances/{instance_id}/recovery/jobs/{job_id}/retry",
        "/api/instances/{instance_id}/recovery/restore",
    ] {
        let responses = &document["paths"][path]["post"]["responses"];
        assert!(responses["202"].is_mapping(), "{path} must return 202");
        assert!(responses["200"].is_null(), "{path} must not return 200");
        assert!(
            responses["202"]["headers"]["Location"].is_mapping(),
            "{path} must advertise its job status URL"
        );
    }

    assert_eq!(
        document["paths"]["/api/instances/{instance_id}/backups/{backup_id}/restore"]
            ["post"]["x-required-scope"]
            .as_str(),
        Some(scopes::RECOVERY_ADMIN)
    );
    assert!(
        document["paths"]["/api/instances/{instance_id}/backups/{backup_id}/restore"]
            ["post"]["requestBody"]
            .is_mapping()
    );

    assert_eq!(
        property_names(&schemas["Error"]),
        HashSet::from(["error", "code", "error_id"])
    );
    let progress_actions: HashSet<&str> =
        schemas["InstallProgress"]["properties"]["action"]["enum"]
            .as_sequence()
            .expect("InstallProgress action must be an enum")
            .iter()
            .map(|action| action.as_str().expect("action must be a string"))
            .collect();
    assert_eq!(
        progress_actions,
        HashSet::from(["create", "image_update", "major_upgrade"])
    );

    assert_eq!(
        property_names(&schemas["DownloadUrlResponse"]),
        HashSet::from(["url", "expires_at_unix", "single_use"])
    );

    assert_eq!(
        property_names(&schemas["NodeResourceSummary"]),
        HashSet::from([
            "node_uuid",
            "sampled_at",
            "cpu",
            "memory",
            "disk",
            "instances"
        ])
    );
    assert_eq!(
        document["paths"]["/api/admin/resources/summary"]["get"]["x-required-scope"].as_str(),
        Some(scopes::RESOURCES_ADMIN)
    );

    let system_properties = property_names(&schemas["SystemResponse"]);
    assert!(system_properties.contains("api_version"));
    assert!(system_properties.contains("api_readiness"));
    assert!(system_properties.contains("mysql_enabled"));
    assert!(system_properties.contains("daemon_engine"));
    assert!(system_properties.contains("disk_mode"));
    assert!(!system_properties.contains("runtime"));
    assert!(!system_properties.contains("daemon_disk_enforcement_method"));
    assert!(system_properties.contains("gateways"));
    assert_eq!(
        schemas["SystemResponse"]["properties"]["api_readiness"]["const"].as_str(),
        Some("ready")
    );
    assert_eq!(
        property_names(&schemas["HeartbeatResponse"]),
        HashSet::from(["status"])
    );
    let scheduler_path =
        &document["paths"]["/api/system/import-export-scheduler/recommendation"]["get"];
    assert_eq!(
        scheduler_path["x-required-scope"].as_str(),
        Some(scopes::SYSTEM_READ)
    );
    assert_eq!(
        scheduler_path["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
            .as_str(),
        Some("#/components/schemas/ImportExportSchedulerRecommendation")
    );
    assert_eq!(
        property_names(&schemas["ImportExportSchedulerRecommendation"]),
        HashSet::from([
            "scheduler",
            "estimate",
            "recommended_active_jobs",
            "admitted_jobs",
            "max_queued_jobs",
            "max_queued_jobs_per_instance",
        ])
    );
    assert_eq!(
        schemas["UploadImportSource"]["required"]
            .as_sequence()
            .expect("upload source required fields")
            .iter()
            .filter_map(Value::as_str)
            .collect::<HashSet<_>>(),
        HashSet::from(["type", "upload_id"]),
        "MongoDB source_database remains optional when one complete catalog candidate can be inferred"
    );
    let protocols: HashSet<&str> = schemas["Protocol"]["enum"]
        .as_sequence()
        .expect("Protocol must be an enum")
        .iter()
        .map(|protocol| protocol.as_str().expect("protocol must be a string"))
        .collect();
    assert!(protocols.contains("mysql"));
    assert_eq!(
        schemas["HeartbeatResponse"]["properties"]["status"]["const"].as_str(),
        Some("ok")
    );
    let instance_statuses: HashSet<&str> = schemas["Instance"]["properties"]["status"]["enum"]
        .as_sequence()
        .expect("Instance status must be an enum")
        .iter()
        .map(|status| status.as_str().expect("status must be a string"))
        .collect();
    assert_eq!(
        instance_statuses,
        HashSet::from([
            "creating",
            "booting",
            "running",
            "stopped",
            "failed",
            "quarantined",
            "deleting",
        ])
    );

    assert_eq!(
        property_names(&schemas["RunBackupsResponse"]),
        HashSet::from(["backups", "skipped", "failed"])
    );
    assert!(schemas.get("SkippedBackup").is_none());
    assert_eq!(
        property_names(&schemas["BackupIssue"]),
        HashSet::from(["instance_id", "protocol", "reason"])
    );
    assert_eq!(
        property_names(&schemas["RestoreBackupResponse"]),
        HashSet::from(["instance_id", "backup_id", "restored"])
    );

    let ws_scope_values: HashSet<&str> = schemas["WsTokenRequest"]["properties"]["scopes"]["items"]
        ["enum"]
        .as_sequence()
        .expect("WsTokenRequest scopes must be an enum")
        .iter()
        .map(|scope| scope.as_str().expect("scope enum values must be strings"))
        .collect();
    assert_eq!(
        ws_scope_values,
        HashSet::from([
            "monitor:read",
            "logs:read",
            "import-export:read",
            "pools:monitor",
            "pools:logs"
        ])
    );
}

#[test]
fn lean_stream_and_catalog_schemas_match_the_current_payloads() {
    let document: Value = yaml_serde::from_str(include_str!("../docs/api/openapi.yml")).unwrap();
    let schemas = &document["components"]["schemas"];
    assert_eq!(
        property_names(&schemas["MonitoringResources"]),
        HashSet::from(["cpu", "memory", "disk"])
    );
    assert!(!property_names(&schemas["MonitoringActivity"]).contains("instance_id"));
    assert!(property_names(&schemas["MonitoringBatch"]).contains("progress_reset"));
    assert!(property_names(&schemas["MonitoringBatch"]).contains("install_progress_removed"));
    let logs = property_names(&schemas["LogEvent"]);
    assert!(logs.contains("event") && logs.contains("stream") && logs.contains("data"));
    assert!(!logs.contains("stdout") && !logs.contains("stderr"));
    let summary = property_names(&schemas["ImportUpload"]);
    assert!(summary.contains("catalog_available") && !summary.contains("catalog"));
    let path =
        &document["paths"]["/api/instances/{instance_id}/import/uploads/{upload_id}/catalog"];
    for method in ["get", "post"] {
        assert_eq!(
            path[method]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
                .as_str(),
            Some("#/components/schemas/DumpInspection")
        );
    }
    assert_eq!(
        path["get"]["x-required-scope"].as_str(),
        Some("import-export:read")
    );
    assert_eq!(
        path["post"]["x-required-scope"].as_str(),
        Some("import-export:write")
    );
    assert!(property_names(&schemas["BackupObjectSummary"]).contains("column_count"));
    assert!(!property_names(&schemas["BackupObjectSummary"]).contains("columns"));
    assert!(property_names(&schemas["BackupObjectSelection"]).contains("columns"));
}
