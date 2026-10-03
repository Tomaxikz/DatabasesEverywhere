use axum::Router;

use crate::state::AppState;

mod _instance_id_;

pub(crate) fn router() -> Router<AppState> {
    Router::new().merge(_instance_id_::router())
}
