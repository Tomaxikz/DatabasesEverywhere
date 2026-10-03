use axum::Router;

use crate::state::AppState;

mod logs;
mod monitoring;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .merge(logs::router())
        .merge(monitoring::router())
}
