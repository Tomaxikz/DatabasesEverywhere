use axum::{Router, routing::get};

use crate::state::AppState;

mod catalog;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/api/instances/{instance_id}/import/uploads/{upload_id}",
            get(crate::subsystems::import_export::get_import_upload)
                .delete(crate::subsystems::import_export::delete_import_upload),
        )
        .merge(catalog::router())
}
