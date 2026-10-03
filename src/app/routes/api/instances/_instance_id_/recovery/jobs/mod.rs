use axum::Router;

use crate::state::AppState;

mod _job_id_;

pub(crate) fn router() -> Router<AppState> {
    Router::new().merge(_job_id_::router())
}
