use axum::{Router, routing::get};

use crate::state::AppState;

pub(crate) fn router() -> Router<AppState> {
    Router::new().route(
        "/api/instances/{instance_id}/import/uploads/{upload_id}/catalog",
        get(crate::subsystems::import_export::get_import_catalog)
            .post(crate::subsystems::import_export::inspect_import_upload),
    )
}
