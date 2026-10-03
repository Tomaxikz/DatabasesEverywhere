use axum::Router;

use crate::state::AppState;

mod admin;
mod heartbeat;
mod instances;
mod pools;
mod system;
mod ws_token;

pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .merge(admin::router())
        .merge(heartbeat::router())
        .merge(instances::router())
        .merge(pools::router())
        .merge(system::router())
        .merge(ws_token::router())
}
