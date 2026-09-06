use crate::{
    api::{
        http::{
            policy::ApiRequestContext,
            response::{ApiError, ApiJson, ApiPath},
        },
        monitoring::tokens::{IssueWsTokenRequest, issue_ws_token},
        test_support,
    },
    auth::{jwt, scopes},
    config::Config,
    placement::{EngineRuntimeStatus, test_support::runtime},
    shared::protocol::Protocol,
};
use axum::{
    extract::{FromRequestParts, State},
    http::Request,
};
use tokio::time::{Duration, timeout};

async fn auth(state: &crate::api::http::router::AppState) -> ApiRequestContext {
    let (mut parts, _) = Request::builder()
        .header("Authorization", "Bearer secret")
        .body(())
        .unwrap()
        .into_parts();
    ApiRequestContext::from_request_parts(&mut parts, state)
        .await
        .unwrap()
}

#[tokio::test]
async fn issued_pool_tokens_bind_owner_generation_and_scope() {
    let (state, _dir) = test_support::database(Config {
        token_id: "test-panel".into(),
        ..Default::default()
    })
    .await;
    let mut pool = runtime("server-a", Protocol::Postgres, "postgres:18.4");
    pool.owner.as_mut().unwrap().panel_id = state.config.token_id.clone();
    state.placements.save(&pool).await.unwrap();
    let body = serde_json::json!({"subject":"test-user", "server_id":"server-a", "pools":[pool.runtime_id],
        "scopes":["pools:monitor","pools:logs"], "ttl_seconds":60});
    let token = issue_ws_token(
        State(state.clone()),
        auth(&state).await,
        ApiJson(serde_json::from_value(body.clone()).unwrap()),
    )
    .await
    .unwrap()
    .into_body();
    let claims = jwt::validate_ws_token(
        &token.token,
        state.config.websocket_jwt_secret(),
        scopes::POOLS_MONITOR,
        None,
    )
    .unwrap();
    assert!(claims.pools[0].matches(&pool));
    assert!(!claims.allows_instance("any-database"));
    assert!(
        jwt::validate_ws_token(
            &token.token,
            state.config.websocket_jwt_secret(),
            scopes::MONITOR_READ,
            None
        )
        .is_err()
    );
    let mut replacement = pool.clone();
    replacement.created_at = "different-generation".into();
    assert!(!claims.pools[0].matches(&replacement));

    for (field, value, expected) in [
        ("server_id", serde_json::json!("another-server"), 403),
        ("pools", serde_json::json!(["missing-pool"]), 404),
        ("instances", serde_json::json!(["db"]), 400),
        ("all_instances", serde_json::json!(true), 400),
        ("scopes", serde_json::json!(["monitor:read"]), 400),
        ("scopes", serde_json::json!(["pools:write"]), 400),
    ] {
        let mut bad = body.clone();
        bad[field] = value;
        let request: IssueWsTokenRequest = serde_json::from_value(bad).unwrap();
        let error = issue_ws_token(State(state.clone()), auth(&state).await, ApiJson(request))
            .await
            .unwrap_err();
        assert_eq!(error.status().as_u16(), expected, "{field}: {error}");
    }
}

#[tokio::test]
async fn pool_lock_wait_does_not_hold_node_admission() {
    let (state, _dir) = test_support::database(Config::default()).await;
    let pool = runtime("server-a", Protocol::Mysql, "mysql:8.4");
    state.placements.save(&pool).await.unwrap();
    let held = state.instance_locks.lock(&pool.runtime_id).await;
    let worker = tokio::spawn({
        let state = state.clone();
        let id = pool.runtime_id.clone();
        async move { super::power::PoolGuard::acquire(&state, &id).await }
    });
    tokio::task::yield_now().await;
    let admission = timeout(Duration::from_secs(1), state.instance_locks.lock_creation())
        .await
        .unwrap();
    drop(admission);
    drop(held);
    let (_, guard) = timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(guard);
}

#[tokio::test]
async fn power_rejects_unfinished_image_work_before_touching_docker() {
    let (state, _dir) = test_support::database(Config::default()).await;
    let mut pool = runtime("server-a", Protocol::Mysql, "mysql:8.4");
    for (status, pending) in [
        (EngineRuntimeStatus::Creating, None),
        (EngineRuntimeStatus::Quarantined, None),
        (EngineRuntimeStatus::Running, Some("sha256:pending".into())),
    ] {
        pool.status = status;
        pool.pending_image = pending;
        state.placements.save(&pool).await.unwrap();
        let error = super::power::change(
            &state,
            &pool.runtime_id,
            crate::api::instances::LifecycleAction::Start,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ApiError::Conflict(_)));
    }
}

#[tokio::test]
async fn pool_status_and_child_request_are_distinct_resources() {
    let (state, _dir) = test_support::database(Config::default()).await;
    let pool = runtime("server-a", Protocol::Postgres, "postgres:18.4");
    state.placements.save(&pool).await.unwrap();
    let response = super::status(
        State(state.clone()),
        auth(&state).await,
        ApiPath(pool.runtime_id.clone()),
    )
    .await
    .unwrap()
    .into_body();
    let json = serde_json::to_value(response).unwrap();
    assert_eq!(json["runtime_id"], pool.runtime_id);
    assert_eq!(json["status"], "running");
    assert!(json.get("data").is_none() && json.get("instance_id").is_none());
    let old = serde_json::json!({
        "server_id":"server-a","protocol":"mysql","database":"db",
        "limits":{"cpu_cores":1,"memory_mib":1024,"disk_mib":4096,"max_tenants":8}
    });
    assert!(serde_json::from_value::<super::operations::CreatePool>(old).is_err());
}

#[tokio::test]
async fn pending_images_and_stopped_intent_survive_storage_and_block_route_recovery() {
    use crate::instances::metadata::DesiredInstanceState;
    let (state, _dir) = test_support::database(Config::default()).await;
    let mut pool = runtime("pending-pool", Protocol::Mysql, "mysql:8.4");
    pool.pending_image = Some("sha256:attested-image".into());
    pool.desired_state = DesiredInstanceState::Stopped;
    state.placements.save(&pool).await.unwrap();
    let stored = state
        .placements
        .get(&pool.runtime_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.pending_image, pool.pending_image);
    assert_eq!(stored.desired_state, DesiredInstanceState::Stopped);
    // Offline runtime deliberately cannot execute commands. Recovery must
    // return before probing or opening anything for either of these states.
    for (pending, desired) in [
        (
            Some("sha256:attested-image".into()),
            DesiredInstanceState::Running,
        ),
        (None, DesiredInstanceState::Stopped),
    ] {
        pool.pending_image = pending;
        pool.desired_state = desired;
        let result =
            crate::placement::tenant::recovery::reconcile_runtime_tenants_locked(&state, &pool)
                .await
                .unwrap();
        assert_eq!(result.checked, 0);
    }
}

#[tokio::test]
async fn pool_mutations_reject_durable_migrations_even_before_target_provisioning() {
    let (state, _dir) = test_support::database(Config::default()).await;
    let pool = runtime("destination", Protocol::Mysql, "mysql:8.4");
    state.placements.save(&pool).await.unwrap();
    let mut source = crate::instances::test_support::metadata("source", Protocol::Mysql);
    source.owner = pool.owner.clone();
    state.manager.upsert(source.clone()).await.unwrap();
    state
        .placements
        .migrations()
        .start(
            &source,
            crate::placement::DeploymentMode::Shared,
            Some(&pool.runtime_id),
            None,
        )
        .await
        .unwrap();
    let result = super::power::PoolGuard::acquire(&state, &pool.runtime_id).await;
    assert!(
        matches!(result, Err(ApiError::Conflict(message)) if message.contains("active database migration"))
    );
}
