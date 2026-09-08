use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::body::Body;
use http_body_util::BodyExt;
use hyper::{Response, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::net::UnixListener;

use super::*;
use crate::{
    config::{DaemonConfig, DaemonEngine},
    constants::docker::{INSTANCE_LABEL, MANAGED_LABEL, NODE_LABEL, PROTOCOL_LABEL},
    placement::{PlacementRepository, test_support},
    storage::{repositories::InstanceRepository, sqlite, test_support::seed_dedicated_instance},
};

const ID: &str = "inst_guard";

async fn seed(pool: &sqlx::SqlitePool) {
    seed_dedicated_instance(pool, ID, "2026-09-08T00:00:00Z").await;
    PlacementRepository::new(pool.clone())
        .save(&test_support::runtime(
            "pool_guard",
            Protocol::Clickhouse,
            "clickhouse:26.4",
        ))
        .await
        .unwrap();
}

#[tokio::test]
async fn startup_budget_survives_boots_and_unrelated_metadata_writes() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    seed(&pool).await;
    let runtime = DockerRuntime::offline_for_tests(&DaemonConfig::default(), false)
        .with_startup_history(pool.clone());
    for id in [ID, "pool_guard"] {
        runtime.check_autostart(id).await.unwrap();
        runtime.note_start(id, true).await.unwrap();
        runtime.check_autostart(id).await.unwrap();
        runtime.note_start(id, true).await.unwrap();
        assert!(matches!(
            runtime.check_autostart(id).await,
            Err(DockerError::AutostartBlocked(_))
        ));
    }
    let repository = InstanceRepository::new(pool.clone());
    let metadata = repository.get(ID).await.unwrap().unwrap();
    repository.upsert(&metadata).await.unwrap();
    let placements = PlacementRepository::new(pool.clone());
    let shared = placements.get("pool_guard").await.unwrap().unwrap();
    placements.save(&shared).await.unwrap();
    // Reconciliation and secret/placement persistence cannot reset the budget.
    assert!(runtime.check_autostart(ID).await.is_err());
    assert!(runtime.check_autostart("pool_guard").await.is_err());
    pool.close().await;
    let reopened = sqlite::connect(dir.path()).await.unwrap();
    let runtime = DockerRuntime::offline_for_tests(&DaemonConfig::default(), false)
        .with_startup_history(reopened.clone());
    assert!(runtime.check_autostart(ID).await.is_err());
    assert!(runtime.note_start(ID, true).await.is_err());
    // An explicit repair/start is allowed; it does not clear history until ready.
    runtime.note_start(ID, false).await.unwrap();
    assert!(runtime.check_autostart(ID).await.is_err());
    runtime.startup_ready(ID).await.unwrap();
    runtime.check_autostart(ID).await.unwrap();
    assert!(runtime.check_autostart("pool_guard").await.is_err());
    // Missing/deleted runtimes cannot be admitted for automatic recovery.
    assert!(runtime.note_start("deleted", true).await.is_err());
    reopened.close().await;
}

#[tokio::test]
async fn automatic_recovery_admission_is_atomic_and_database_errors_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    seed(&pool).await;
    let runtime = DockerRuntime::offline_for_tests(&DaemonConfig::default(), false)
        .with_startup_history(pool.clone());
    let outcomes = futures::future::join_all((0..12).map(|_| runtime.note_start(ID, true))).await;
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 2);
    assert!(runtime.check_autostart(ID).await.is_err());
    runtime.check_autostart("pool_guard").await.unwrap();
    pool.close().await;
    assert!(matches!(
        runtime.check_autostart(ID).await,
        Err(DockerError::StartupHistory(_))
    ));
    assert!(runtime.note_start(ID, false).await.is_err());
    assert!(runtime.startup_ready(ID).await.is_err());
}

#[derive(Default)]
struct Engine {
    running: bool,
    start_succeeds: bool,
    restart_policy_fixed: bool,
    ignore_policy_update: bool,
    missing: bool,
    foreign: bool,
    hang_probe: bool,
    unknown_exit: bool,
    starts: usize,
    updates: usize,
    probes: usize,
    kills: usize,
}

async fn serve(
    mut request: hyper::Request<hyper::body::Incoming>,
    engine: Arc<Mutex<Engine>>,
) -> Result<Response<Body>, Infallible> {
    let path = request.uri().path().to_owned();
    if path.ends_with("/update") {
        let body = request.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["RestartPolicy"]["Name"], "no");
        assert_eq!(body["RestartPolicy"]["MaximumRetryCount"], 0);
        let mut state = engine.lock().unwrap();
        state.updates += 1;
        if !state.ignore_policy_update {
            state.restart_policy_fixed = true;
        }
        return Ok(Response::new(Body::from("{\"Warnings\":[]}")));
    }
    let mut state = engine.lock().unwrap();
    let (status, value) = if state.missing {
        (404, serde_json::json!({"message":"no such container"}))
    } else if path.contains("/exec/") && path.ends_with("/start") {
        state.probes += 1;
        let hang = state.hang_probe;
        let upgrade = hyper::upgrade::on(&mut request);
        tokio::spawn(async move {
            let stream = upgrade.await.unwrap();
            if hang {
                use tokio::io::AsyncReadExt;
                let mut stream = TokioIo::new(stream);
                let mut byte = [0];
                let _ = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await;
            }
        });
        return Ok(Response::builder()
            .status(101)
            .header("Connection", "Upgrade")
            .header("Upgrade", "tcp")
            .body(Body::empty())
            .unwrap());
    } else if path.contains("/exec/") {
        (
            200,
            serde_json::json!({"Running":state.unknown_exit,"ExitCode": if state.unknown_exit {None} else {Some(0)}}),
        )
    } else if path.ends_with("/exec") {
        (201, serde_json::json!({"Id":"probe"}))
    } else if path.ends_with("/json") {
        let labels = std::collections::HashMap::from([
            (MANAGED_LABEL, "true"),
            (INSTANCE_LABEL, ID),
            (PROTOCOL_LABEL, "postgres"),
            (
                NODE_LABEL,
                if state.foreign {
                    "another-node"
                } else {
                    "test-node"
                },
            ),
        ]);
        (
            200,
            serde_json::json!({
                "Id":"a".repeat(64), "Config":{"Labels":labels},
                "State":{"Running":state.running,"Status":if state.running {"running"} else {"exited"},"ExitCode":1},
                "HostConfig":{"NetworkMode":"none", "RestartPolicy":{"Name":if state.restart_policy_fixed {"no"} else {"always"},"MaximumRetryCount":0}},
            }),
        )
    } else if path.ends_with("/start") {
        state.starts += 1;
        if state.start_succeeds {
            state.running = true;
            return Ok(Response::builder().status(204).body(Body::empty()).unwrap());
        }
        (500, serde_json::json!({"message":"startup failed"}))
    } else if path.ends_with("/kill") {
        state.kills += 1;
        state.running = false;
        return Ok(Response::builder().status(204).body(Body::empty()).unwrap());
    } else {
        panic!("unexpected runtime request: {path}");
    };
    Ok(Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(value.to_string()))
        .unwrap())
}

#[tokio::test]
async fn real_runtime_paths_count_starts_but_never_restart_a_readiness_probe() {
    for daemon_engine in [DaemonEngine::Docker, DaemonEngine::Podman] {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        seed(&pool).await;
        let socket = dir.path().join("docker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let state = Arc::new(Mutex::new(Engine::default()));
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let state = server_state.clone();
                        connections.spawn(async move {
                            let _ = http1::Builder::new().serve_connection(TokioIo::new(stream),
                                service_fn(move |request| serve(request, state.clone()))).with_upgrades().await;
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        let runtime = DockerRuntime::new(
            &DaemonConfig {
                engine: daemon_engine,
                socket_path: socket.display().to_string(),
                ..Default::default()
            },
            false,
        )
        .unwrap()
        .with_node_id("test-node")
        .with_startup_history(pool.clone());
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            for _ in 0..2 {
                runtime.check_autostart(ID).await.unwrap();
                assert!(runtime.start(Protocol::Postgres, ID).await.is_err());
            }
            assert!(runtime.check_autostart(ID).await.is_err());
            assert_eq!(state.lock().unwrap().starts, 2);
            assert_eq!(state.lock().unwrap().updates, 1);
            state.lock().unwrap().start_succeeds = true;
            runtime.start(Protocol::Postgres, ID).await.unwrap();
            // Idempotent start of an already running engine consumes no attempt.
            runtime.start(Protocol::Postgres, ID).await.unwrap();
            assert_eq!(state.lock().unwrap().starts, 3);
            assert!(runtime.check_autostart(ID).await.is_err());
            runtime
                .wait_until_ready(Protocol::Postgres, ID, Duration::from_secs(1))
                .await
                .unwrap();
            runtime.check_autostart(ID).await.unwrap();
            runtime.note_start(ID, true).await.unwrap();
            state.lock().unwrap().unknown_exit = true;
            assert!(
                runtime
                    .exec_readiness_probe(Protocol::Postgres, ID, "SELECT 1")
                    .await
                    .is_err()
            );
            state.lock().unwrap().unknown_exit = false;
            state.lock().unwrap().hang_probe = true;
            let before = state.lock().unwrap().probes;
            assert!(
                runtime
                    .wait_until_ready(Protocol::Postgres, ID, Duration::from_millis(60))
                    .await
                    .is_err()
            );
            assert_eq!(state.lock().unwrap().probes, before + 1);
            assert!(
                runtime
                    .exec_secret_readiness_probe(
                        Protocol::Postgres,
                        ID,
                        "SELECT 1",
                        &[],
                        Duration::from_millis(60)
                    )
                    .await
                    .is_err()
            );
            assert_eq!(state.lock().unwrap().starts, 3);
            assert_eq!(state.lock().unwrap().kills, 0);
            // Readiness failures did not clear the previous pending attempt.
            runtime.note_start(ID, true).await.unwrap();
            assert!(runtime.check_autostart(ID).await.is_err());
            // Exec recovery must still kill the uncertain process, but may
            // not bypass the cutoff through its low-level start_container call.
            assert!(
                runtime
                    .recover_interrupted_exec(
                        Protocol::Postgres,
                        ID,
                        &"a".repeat(64),
                        "probe cleanup",
                        Duration::from_secs(1)
                    )
                    .await
                    .is_err()
            );
            assert_eq!(state.lock().unwrap().kills, 1);
            assert_eq!(state.lock().unwrap().starts, 3);
            state.lock().unwrap().foreign = true;
            assert!(
                runtime
                    .disable_restarts(Protocol::Postgres, ID)
                    .await
                    .is_err()
            );
            assert_eq!(state.lock().unwrap().updates, 1);
            state.lock().unwrap().foreign = false;
            state.lock().unwrap().restart_policy_fixed = false;
            state.lock().unwrap().ignore_policy_update = true;
            assert!(matches!(
                runtime.disable_restarts(Protocol::Postgres, ID).await,
                Err(DockerError::RestartPolicyNotDisabled(_))
            ));
            state.lock().unwrap().missing = true;
            runtime
                .disable_restarts(Protocol::Postgres, ID)
                .await
                .unwrap();
            assert!(runtime.start(Protocol::Postgres, ID).await.is_err());
            assert_eq!(state.lock().unwrap().starts, 3);
        })
        .await;
        server.abort();
        let _ = server.await;
        result.unwrap();
        pool.close().await;
    }
}
