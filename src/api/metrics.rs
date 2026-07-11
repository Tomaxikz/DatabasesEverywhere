use axum::{
    extract::State,
    http::header,
    response::{IntoResponse, Response},
};

use crate::{
    api::{api_response::ApiError, routes::AppState, security_policy::ApiRequestContext},
    auth::scopes,
    jobs::import_export::ImportExportStatus,
    shared::protocol::Protocol,
};

pub async fn metrics(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> Result<Response, ApiError> {
    auth.require_scope(scopes::METRICS_READ)?;
    let instances = state.instances.list().await;
    let jobs_by_status = state
        .import_export_jobs
        .count_by_status()
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let mut out = String::new();
    out.push_str("# HELP dbe_instances_total Managed instances by protocol and status\n");
    out.push_str("# TYPE dbe_instances_total gauge\n");
    for protocol in Protocol::ALL {
        for status in [
            "creating",
            "booting",
            "running",
            "stopped",
            "failed",
            "quarantined",
            "deleting",
        ] {
            let count = instances
                .iter()
                .filter(|instance| instance.protocol == protocol)
                .filter(|instance| instance.status.as_str() == status)
                .count();
            let protocol = protocol.as_str();
            out.push_str(&format!(
                "dbe_instances_total{{protocol=\"{protocol}\",status=\"{status}\"}} {count}\n"
            ));
        }
    }
    out.push_str("# HELP dbe_import_export_jobs_total Import/export jobs by status\n");
    out.push_str("# TYPE dbe_import_export_jobs_total gauge\n");
    for status in [
        ImportExportStatus::Queued,
        ImportExportStatus::Running,
        ImportExportStatus::Succeeded,
        ImportExportStatus::Failed,
    ] {
        let count = jobs_by_status.get(&status).copied().unwrap_or(0);
        out.push_str(&format!(
            "dbe_import_export_jobs_total{{status=\"{}\"}} {count}\n",
            status.as_str()
        ));
    }
    out.push_str("# HELP dbe_daemon_disk_limits_enforced Disk limits strict mode\n");
    out.push_str("# TYPE dbe_daemon_disk_limits_enforced gauge\n");
    out.push_str(&format!(
        "dbe_daemon_disk_limits_enforced {}\n",
        u8::from(state.config.disk.mode.enforced())
    ));
    Ok(([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], out).into_response())
}
