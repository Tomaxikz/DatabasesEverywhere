use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
};

use axum::body::Body;
use hyper::{Response, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::net::UnixListener;

use super::*;
use crate::{
    config::{Config, DaemonConfig},
    constants::docker::{INSTANCE_LABEL, MANAGED_LABEL, NODE_LABEL, PROTOCOL_LABEL},
    instances::metadata::InstanceStatus,
    placement::{DeploymentMode, ReserveTenant},
    runtime::docker::DockerRuntime,
    shared::{backend::BackendEndpoint, protocol::Protocol},
};

const ID: &str = "pool_failure";

fn readiness_error() -> anyhow::Error {
    DockerError::ContainerNotReady {
        instance_id: ID.into(),
        status: "exited".into(),
        health: None,
        readiness_error: None,
    }
    .into()
}

#[test]
fn ordinary_startup_errors_keep_down_but_integrity_failures_quarantine() {
    assert_eq!(
        decide(Phase::Readiness, &readiness_error()),
        Decision::KeepDown
    );
    let api: anyhow::Error = DockerError::Api(bollard::errors::Error::DockerResponseServerError {
        status_code: 500,
        message: "cannot start".into(),
    })
    .into();
    for phase in [
        Phase::EngineStart,
        Phase::Readiness,
        Phase::SocketDirectory,
        Phase::Isolation,
    ] {
        assert_eq!(decide(phase, &api), Decision::KeepDown);
    }
    for phase in [Phase::Metadata, Phase::PoolSecurity, Phase::TenantSecurity] {
        assert_eq!(decide(phase, &api), Decision::Quarantine);
    }
    let mismatch: anyhow::Error = DockerError::DiskBindSourceMismatch {
        instance_id: ID.into(),
        destination: "/data".into(),
        expected_source: "/expected".into(),
        actual_source: "/other".into(),
    }
    .into();
    assert_eq!(
        decide(Phase::StorageBoundary, &mismatch),
        Decision::Quarantine
    );
    let foreign: anyhow::Error = DockerError::UntrustedContainerNameCollision {
        container: "foreign".into(),
        instance_id: ID.into(),
        protocol: "postgres".into(),
    }
    .into();
    assert_eq!(decide(Phase::EngineStart, &foreign), Decision::Quarantine);
    let capacity = anyhow::anyhow!("measurement unavailable").context(CapacityUnavailable);
    assert_eq!(
        decide(Phase::StorageBoundary, &capacity),
        Decision::KeepDown
    );
    assert_eq!(
        decide(Phase::Readiness, &EngineExited.into()),
        Decision::KeepDown
    );
    assert_eq!(
        decide(Phase::EngineStart, &anyhow::anyhow!("unknown")),
        Decision::Quarantine
    );
    assert_eq!(
        decide(Phase::Isolation, &anyhow::anyhow!("network changed")),
        Decision::Quarantine
    );
}

#[test]
fn missing_or_unwritable_socket_paths_are_not_confused_with_unsafe_paths() {
    for errno in [
        libc::ENOENT,
        libc::EACCES,
        libc::ENOSPC,
        libc::EDQUOT,
        libc::EROFS,
    ] {
        let error = anyhow::Error::from(std::io::Error::from_raw_os_error(errno))
            .context("prepare sockets");
        assert_eq!(decide(Phase::SocketDirectory, &error), Decision::KeepDown);
        assert_eq!(decide(Phase::StorageBoundary, &error), Decision::Quarantine);
    }
    for errno in [rustix::io::Errno::LOOP, rustix::io::Errno::NOTDIR] {
        assert_eq!(
            decide(Phase::SocketDirectory, &errno.into()),
            Decision::Quarantine
        );
    }
    assert_eq!(
        decide(Phase::SocketDirectory, &rustix::io::Errno::NOENT.into()),
        Decision::KeepDown
    );
}

#[derive(Default)]
struct Engine {
    running: bool,
    refuses_stop: bool,
    stops: usize,
    kills: usize,
}

async fn serve(
    request: hyper::Request<hyper::body::Incoming>,
    engine: Arc<Mutex<Engine>>,
) -> Result<Response<Body>, Infallible> {
    let path = request.uri().path();
    let mut engine = engine.lock().unwrap();
    if path.ends_with("/stop") || path.ends_with("/kill") {
        if path.ends_with("/stop") {
            engine.stops += 1;
        } else {
            engine.kills += 1;
        }
        if engine.refuses_stop {
            return Ok(Response::builder()
                .status(500)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"message":"engine unavailable"}"#))
                .unwrap());
        }
        engine.running = false;
        return Ok(Response::builder().status(204).body(Body::empty()).unwrap());
    }
    assert!(path.ends_with("/json"), "unexpected request {path}");
    let labels = std::collections::HashMap::from([
        (MANAGED_LABEL, "true"),
        (INSTANCE_LABEL, ID),
        (PROTOCOL_LABEL, "postgres"),
        (NODE_LABEL, "test-node"),
    ]);
    let value = serde_json::json!({"Id": "a".repeat(64), "Config": {"Labels": labels},
        "State": {"Running": engine.running, "Status": if engine.running {"running"} else {"exited"}, "ExitCode": 1},
        "HostConfig": {"NetworkMode": "none"}});
    Ok(Response::builder()
        .header("Content-Type", "application/json")
        .body(Body::from(value.to_string()))
        .unwrap())
}

struct Fixture {
    state: AppState,
    runtime: EngineRuntime,
    engine: Arc<Mutex<Engine>>,
    db: sqlx::SqlitePool,
    server: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn fixture(refuses_stop: bool) -> Fixture {
    let (state, dir) = crate::api::test_support::database(Config::default()).await;
    let db = crate::storage::sqlite::connect(dir.path()).await.unwrap();
    let mut runtime =
        crate::placement::test_support::runtime(ID, Protocol::Postgres, "postgres:18.4");
    runtime.limits.disk_mib = 64 * 1024;
    runtime.backend = BackendEndpoint::UnixSocket {
        socket_path: "/run/dbev/pool_failure/postgres.sock".into(),
    };
    state.placements.save(&runtime).await.unwrap();
    let mut metadata =
        crate::instances::test_support::metadata("tenant_failure", Protocol::Postgres);
    metadata.owner = runtime.owner.clone();
    metadata.deployment_mode = DeploymentMode::Shared;
    metadata.runtime_id = ID.into();
    metadata.backend = runtime.backend.clone();
    state
        .placements
        .reserve(ReserveTenant {
            owner: runtime.owner.clone().unwrap(),
            instance_id: &metadata.instance_id,
            runtime_id: ID,
            database: &metadata.database.name,
            username: &metadata.database.username,
            limits: &metadata.limits,
        })
        .await
        .unwrap();
    state
        .placements
        .mark_provisioned(&metadata.instance_id)
        .await
        .unwrap();
    state.manager.upsert(metadata).await.unwrap();
    runtime = state.placements.get(ID).await.unwrap().unwrap();
    let socket = dir.path().join("engine.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let engine = Arc::new(Mutex::new(Engine {
        running: true,
        refuses_stop,
        ..Default::default()
    }));
    let server_engine = engine.clone();
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = accepted.unwrap();
                    let engine = server_engine.clone();
                    connections.spawn(async move {
                        let _ = http1::Builder::new().serve_connection(TokioIo::new(stream), service_fn(move |r| serve(r, engine.clone()))).await;
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    let mut data = (*state).clone();
    data.docker = DockerRuntime::new(
        &DaemonConfig {
            socket_path: socket.to_string_lossy().into_owned(),
            ..Default::default()
        },
        false,
    )
    .unwrap()
    .with_node_id("test-node");
    Fixture {
        state: AppState::new(data),
        runtime,
        engine,
        db,
        server,
        _dir: dir,
    }
}

#[tokio::test]
async fn confirmed_start_failure_stays_down_until_explicit_or_boot_recovery() {
    let mut f = fixture(false).await;
    handle(
        &f.state,
        &mut f.runtime,
        Phase::Readiness,
        &readiness_error(),
    )
    .await
    .unwrap();
    let stored = f.state.placements.get(ID).await.unwrap().unwrap();
    assert!(
        crate::storage::quarantine::list(&f.db, None, true, None, 100)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(stored.status, EngineRuntimeStatus::Failed);
    assert_eq!(stored.desired_state, DesiredInstanceState::Stopped);
    assert!(!f.engine.lock().unwrap().running);
    let tenant = f
        .state
        .manager
        .get_persisted("tenant_failure")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tenant.status, InstanceStatus::Failed);
    assert_eq!(tenant.desired_state, DesiredInstanceState::Running);
    assert!(f.state.instances.routes_fenced("tenant_failure").await);
    assert_eq!(f.state.placements.reservations(ID).await.unwrap().len(), 1);
    // A later stop event or boot reconciliation preserves the failure label.
    assert!(
        super::super::honor_stop(&f.state, &mut f.runtime)
            .await
            .unwrap()
    );
    assert_eq!(f.runtime.status, EngineRuntimeStatus::Failed);
    assert!(super::super::shared_boot_action(f.runtime.status, f.runtime.desired_state).is_none());
}

#[tokio::test]
async fn uncertain_stop_escalates_to_quarantine_instead_of_claiming_stopped() {
    let mut f = fixture(true).await;
    assert!(
        handle(
            &f.state,
            &mut f.runtime,
            Phase::Readiness,
            &readiness_error()
        )
        .await
        .is_err()
    );
    assert_eq!(
        f.state.placements.get(ID).await.unwrap().unwrap().status,
        EngineRuntimeStatus::Quarantined
    );
    assert_eq!(
        f.state
            .manager
            .get_persisted("tenant_failure")
            .await
            .unwrap()
            .unwrap()
            .status,
        InstanceStatus::Quarantined
    );
    assert!(f.state.instances.routes_fenced("tenant_failure").await);
    assert!(f.engine.lock().unwrap().kills > 0);
    let causes = crate::storage::quarantine::list(&f.db, None, false, None, 100)
        .await
        .unwrap();
    assert_eq!(causes.len(), 2);
    assert!(
        causes
            .iter()
            .all(|cause| cause.code == "shutdown_unconfirmed"
                && cause.recovery_class == "validated_retry")
    );
}

#[tokio::test]
async fn credential_or_incomplete_image_failures_remain_quarantined() {
    let mut f = fixture(false).await;
    handle(
        &f.state,
        &mut f.runtime,
        Phase::PoolSecurity,
        &anyhow::anyhow!("credentials unverified"),
    )
    .await
    .unwrap();
    assert_eq!(
        f.state.placements.get(ID).await.unwrap().unwrap().status,
        EngineRuntimeStatus::Quarantined
    );
    let mut f = fixture(false).await;
    f.runtime.pending_image = Some("new-image".into());
    f.state.placements.save(&f.runtime).await.unwrap();
    handle(
        &f.state,
        &mut f.runtime,
        Phase::Readiness,
        &readiness_error(),
    )
    .await
    .unwrap();
    assert_eq!(
        f.state.placements.get(ID).await.unwrap().unwrap().status,
        EngineRuntimeStatus::Quarantined
    );
}

#[tokio::test]
async fn failure_to_persist_failed_state_escalates_without_deleting_metadata() {
    let mut f = fixture(false).await;
    sqlx::query(
        "CREATE TRIGGER reject_failed BEFORE UPDATE ON engine_runtimes WHEN NEW.status = 'failed'
        BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END",
    )
    .execute(&f.db)
    .await
    .unwrap();
    handle(
        &f.state,
        &mut f.runtime,
        Phase::Readiness,
        &readiness_error(),
    )
    .await
    .unwrap();
    assert_eq!(
        f.state.placements.get(ID).await.unwrap().unwrap().status,
        EngineRuntimeStatus::Quarantined
    );
    assert!(
        f.state
            .manager
            .get_persisted("tenant_failure")
            .await
            .unwrap()
            .is_some()
    );
}
