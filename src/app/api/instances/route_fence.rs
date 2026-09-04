use crate::api::http::router::AppState;

pub(crate) async fn fence(state: &AppState, instance_id: &str) {
    let sessions = state.gateway_supervisor.tenant_sessions();
    crate::instances::sessions::fence(&state.instances, &sessions, instance_id).await;
}

pub(crate) async fn pin(state: &AppState, instance_id: &str) {
    if state.instances.pin_routes_fenced(instance_id).await {
        state
            .gateway_supervisor
            .tenant_sessions()
            .cancel(instance_id);
    }
}
