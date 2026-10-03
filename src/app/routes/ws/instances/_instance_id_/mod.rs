use axum::Router;

use crate::state::AppState;

mod import_export;
mod logs;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .merge(import_export::router())
        .merge(logs::router())
}
