use axum::Router;

use crate::state::AppState;

mod _runtime_id_;

pub(crate) fn router() -> Router<AppState> {
    Router::new().merge(_runtime_id_::router())
}
