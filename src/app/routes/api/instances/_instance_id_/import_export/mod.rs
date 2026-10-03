use axum::Router;

use crate::state::AppState;

mod jobs;

pub(crate) fn router() -> Router<AppState> {
    Router::new().merge(jobs::router())
}
