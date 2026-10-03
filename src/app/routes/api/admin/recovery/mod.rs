use axum::Router;

use crate::state::AppState;

mod failed_jobs;

pub(crate) fn router() -> Router<AppState> {
    Router::new().merge(failed_jobs::router())
}
