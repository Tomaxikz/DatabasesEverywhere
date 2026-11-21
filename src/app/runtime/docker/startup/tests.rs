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
    server::placement::{PlacementRepository, test_support},
    storage::{repositories::InstanceRepository, sqlite, test_support::seed_dedicated_instance},
    utils::constants::docker::{INSTANCE_LABEL, MANAGED_LABEL, NODE_LABEL, PROTOCOL_LABEL},
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
        .expect("runtime should succeed");
}

#[tokio::test]
async fn startup_budget_survives_boots_and_unrelated_metadata_writes() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    seed(&pool).await;
    let runtime = DockerRuntime::offline_for_tests(&DaemonConfig::default(), false)
        .with_startup_history(pool.clone());
    for id in [ID, "pool_guard"] {
        runtime.check_autostart(id).await?;
        runtime.note_start(id, true).await?;
        runtime.check_autostart(id).await?;
        runtime.note_start(id, true).await?;
        assert!(matches!(
            runtime.check_autostart(id).await,
            Err(DockerError::AutostartBlocked(_))
        ));
    }
    let repository = InstanceRepository::new(pool.clone());
    let metadata = repository
        .get(ID)
        .await?
        .context("get should provide a value")?;
    repository.upsert(&metadata).await?;
    let placements = PlacementRepository::new(pool.clone());
    let shared = placements
        .get("pool_guard")
        .await?
        .context("get should provide a value")?;
    placements.save(&shared).await?;
    // Reconciliation and secret/placement persistence cannot reset the budget.
    assert!(runtime.check_autostart(ID).await.is_err());
    assert!(runtime.check_autostart("pool_guard").await.is_err());
    pool.close().await;
    let reopened = sqlite::connect(dir.path()).await?;
    let runtime = DockerRuntime::offline_for_tests(&DaemonConfig::default(), false)
        .with_startup_history(reopened.clone());
    assert!(runtime.check_autostart(ID).await.is_err());
    assert!(runtime.note_start(ID, true).await.is_err());
    // An explicit repair/start is allowed; it does not clear history until ready.
    runtime.note_start(ID, false).await?;
    assert!(runtime.check_autostart(ID).await.is_err());
    runtime.startup_ready(ID).await?;
    runtime.check_autostart(ID).await?;
    assert!(runtime.check_autostart("pool_guard").await.is_err());
    assert!(runtime.note_start("deleted", true).await.is_err());
    reopened.close().await;

    Ok(())
}

#[tokio::test]
async fn automatic_recovery_admission_is_atomic_and_database_errors_fail_closed()
-> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let pool = sqlite::connect(dir.path()).await?;
    seed(&pool).await;
    let runtime = DockerRuntime::offline_for_tests(&DaemonConfig::default(), false)
        .with_startup_history(pool.clone());
    let outcomes = futures::future::join_all((0..12).map(|_| runtime.note_start(ID, true))).await;
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 2);
    assert!(runtime.check_autostart(ID).await.is_err());
    runtime.check_autostart("pool_guard").await?;
    pool.close().await;
    assert!(matches!(
        runtime.check_autostart(ID).await,
        Err(DockerError::StartupHistory(_))
    ));
    assert!(runtime.note_start(ID, false).await.is_err());
    assert!(runtime.startup_ready(ID).await.is_err());

    Ok(())
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
        let body = request
            .into_body()
            .collect()
            .await
            .expect("collect should succeed")
            .to_bytes();
        let body: serde_json::Value =
            serde_json::from_slice(&body).expect("from slice should succeed");
        assert_eq!(body["RestartPolicy"]["Name"], "no");
        assert_eq!(body["RestartPolicy"]["MaximumRetryCount"], 0);
        let mut state = engine.lock().expect("lock should succeed");
        state.updates += 1;
        if !state.ignore_policy_update {
            state.restart_policy_fixed = true;
        }
        return Ok(Response::new(Body::from("{\"Warnings\":[]}")));
    }
    let mut state = engine.lock().expect("lock should succeed");
    let (status, value) = if state.missing {
        (404, serde_json::json!({"message":"no such container"}))
    } else if path.contains("/exec/") && path.ends_with("/start") {
        state.probes += 1;
        let hang = state.hang_probe;
        let upgrade = hyper::upgrade::on(&mut request);
        tokio::spawn(async move {
            let stream = upgrade.await.expect("serve should succeed");
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
            .expect("empty should succeed"));
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
            return Ok(Response::builder()
                .status(204)
                .body(Body::empty())
                .expect("empty should succeed"));
        }
        (500, serde_json::json!({"message":"startup failed"}))
    } else if path.ends_with("/kill") {
        state.kills += 1;
        state.running = false;
        return Ok(Response::builder()
            .status(204)
            .body(Body::empty())
            .expect("empty should succeed"));
    } else {
        panic!("unexpected runtime request: {path}");
    };
    Ok(Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(value.to_string()))
        .expect("to string should succeed"))
}

#[tokio::test]
async fn real_runtime_paths_count_starts_but_never_restart_a_readiness_probe() -> anyhow::Result<()>
{
    for daemon_engine in [DaemonEngine::Docker, DaemonEngine::Podman] {
        let dir = tempfile::tempdir()?;
        let pool = sqlite::connect(dir.path()).await?;
        seed(&pool).await;
        let socket = dir.path().join("docker.sock");
        let listener = UnixListener::bind(&socket)?;
        let state = Arc::new(Mutex::new(Engine::default()));
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.expect("real runtime paths count starts but never restart a readiness probe should succeed");
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
        )?
        .with_node_id("test-node")
        .with_startup_history(pool.clone());
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            for _ in 0..2 {
                runtime
                    .check_autostart(ID)
                    .await
                    .expect("check autostart should succeed");
                assert!(runtime.start(Protocol::Postgres, ID).await.is_err());
            }
            assert!(runtime.check_autostart(ID).await.is_err());
            assert_eq!(state.lock().expect("lock should succeed").starts, 2);
            assert_eq!(state.lock().expect("lock should succeed").updates, 1);
            state.lock().expect("lock should succeed").start_succeeds = true;
            runtime
                .start(Protocol::Postgres, ID)
                .await
                .expect("start should succeed");
            runtime
                .start(Protocol::Postgres, ID)
                .await
                .expect("start should succeed");
            assert_eq!(state.lock().expect("lock should succeed").starts, 3);
            assert!(runtime.check_autostart(ID).await.is_err());
            runtime
                .wait_until_ready(Protocol::Postgres, ID, Duration::from_secs(1))
                .await
                .expect("from secs should succeed");
            runtime
                .check_autostart(ID)
                .await
                .expect("check autostart should succeed");
            runtime
                .note_start(ID, true)
                .await
                .expect("note start should succeed");
            state.lock().expect("lock should succeed").unknown_exit = true;
            assert!(
                runtime
                    .exec_readiness_probe(Protocol::Postgres, ID, "SELECT 1")
                    .await
                    .is_err()
            );
            state.lock().expect("lock should succeed").unknown_exit = false;
            state.lock().expect("lock should succeed").hang_probe = true;
            let before = state.lock().expect("lock should succeed").probes;
            assert!(
                runtime
                    .wait_until_ready(Protocol::Postgres, ID, Duration::from_millis(60))
                    .await
                    .is_err()
            );
            assert_eq!(
                state.lock().expect("lock should succeed").probes,
                before + 1
            );
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
            assert_eq!(state.lock().expect("lock should succeed").starts, 3);
            assert_eq!(state.lock().expect("lock should succeed").kills, 0);
            // Readiness failures did not clear the previous pending attempt.
            runtime
                .note_start(ID, true)
                .await
                .expect("note start should succeed");
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
            assert_eq!(state.lock().expect("lock should succeed").kills, 1);
            assert_eq!(state.lock().expect("lock should succeed").starts, 3);
            state.lock().expect("lock should succeed").foreign = true;
            assert!(
                runtime
                    .disable_restarts(Protocol::Postgres, ID)
                    .await
                    .is_err()
            );
            assert_eq!(state.lock().expect("lock should succeed").updates, 1);
            state.lock().expect("lock should succeed").foreign = false;
            state
                .lock()
                .expect("lock should succeed")
                .restart_policy_fixed = false;
            state
                .lock()
                .expect("lock should succeed")
                .ignore_policy_update = true;
            assert!(matches!(
                runtime.disable_restarts(Protocol::Postgres, ID).await,
                Err(DockerError::RestartPolicyNotDisabled(_))
            ));
            state.lock().expect("lock should succeed").missing = true;
            runtime
                .disable_restarts(Protocol::Postgres, ID)
                .await
                .expect("disable restarts should succeed");
            assert!(runtime.start(Protocol::Postgres, ID).await.is_err());
            assert_eq!(state.lock().expect("lock should succeed").starts, 3);
        })
        .await;
        server.abort();
        let _ = server.await;
        result?;
        pool.close().await;
    }

    Ok(())
}
