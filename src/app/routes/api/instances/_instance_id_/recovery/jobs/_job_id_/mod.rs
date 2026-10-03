use axum::Router;

use crate::state::AppState;

mod retry;

pub(crate) fn router() -> Router<AppState> {
    Router::new().merge(retry::router())
}
