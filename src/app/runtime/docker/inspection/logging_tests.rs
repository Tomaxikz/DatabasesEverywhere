use super::*;
use crate::{
    config::{DaemonConfig, DaemonEngine},
    utils::constants::docker::{INSTANCE_LABEL, MANAGED_LABEL, NODE_LABEL, PROTOCOL_LABEL},
};

#[test]
fn log_policy_upgrade_is_idempotent_and_rejects_unbounded_or_legacy_layouts() {
    for engine in [DaemonEngine::Docker, DaemonEngine::Podman] {
        let mut value = serde_json::json!({
            "Config":{"Labels":{"dbev.console-policy":"1"}},
            "HostConfig":{"LogConfig":super::super::container_config::log_config(engine)},
            "Mounts":[]
        });
        let matches = |value: &serde_json::Value| {
            log_policy_matches(&serde_json::from_value(value.clone()).unwrap(), engine)
        };
        assert!(matches(&value));
        if engine == DaemonEngine::Podman {
            value["HostConfig"]["LogConfig"] =
                serde_json::json!({"Type":"json-file","Config":null});
            assert!(
                matches(&value),
                "native Podman size is omitted from Docker-compatible inspect"
            );
        }
        let valid = value.clone();
        value["Config"]["Labels"] = serde_json::json!({});
        assert!(!matches(&value));
        value = valid.clone();
        value["HostConfig"]["LogConfig"] = serde_json::json!({"Type":"json-file","Config":{}});
        if engine == DaemonEngine::Docker {
            assert!(!matches(&value));
        }
        value = valid.clone();
        value["HostConfig"]["LogConfig"]["Config"] = serde_json::json!({"max-size":"-1"});
        assert!(!matches(&value));
        value = valid;
        value["Mounts"] = serde_json::json!([{"Type":"bind","Destination":"/var/log/clickhouse-server","Source":"/logs/legacy"}]);
        assert!(!matches(&value));
    }
}

#[tokio::test]
async fn history_is_bounded_and_dropping_a_live_reader_closes_the_stream() {
    use axum::body::Body;
    use bytes::Bytes;
    use hyper::{Response, server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    use std::{
        convert::Infallible,
        sync::{Arc, Mutex},
    };
    use tokio::{net::UnixListener, sync::oneshot};

    struct StreamDropped(Option<oneshot::Sender<()>>);
    impl Drop for StreamDropped {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }
    fn frame(channel: u8, contents: &[u8]) -> Bytes {
        let mut bytes = vec![channel, 0, 0, 0];
        bytes.extend_from_slice(&(contents.len() as u32).to_be_bytes());
        bytes.extend_from_slice(contents);
        Bytes::from(bytes)
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("docker.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let config = DaemonConfig {
        socket_path: path.display().to_string(),
        ..Default::default()
    };
    let runtime = DockerRuntime::new(&config, false)
        .unwrap()
        .with_node_id("test-node");
    let labels = std::collections::HashMap::from([
        (MANAGED_LABEL, "true"),
        (INSTANCE_LABEL, "inst_abc"),
        (PROTOCOL_LABEL, "postgres"),
        (NODE_LABEL, "test-node"),
    ]);
    let inspection =
        serde_json::json!({"Id":"a".repeat(64),"Config":{"Labels":labels}}).to_string();
    let (dropped, finished) = oneshot::channel();
    let dropped = Arc::new(Mutex::new(Some(dropped)));
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let inspection = inspection.clone();
            let dropped = dropped.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let inspection = inspection.clone();
                    let dropped = dropped.clone();
                    async move {
                        let body = if request.uri().path().ends_with("/json") {
                            Body::from(inspection)
                        } else {
                            assert!(request.uri().path().ends_with("/logs"));
                            let query = request.uri().query().unwrap();
                            assert!(query.contains("tail="));
                            if query.contains("follow=true") {
                                let guard = StreamDropped(dropped.lock().unwrap().take());
                                Body::from_stream(futures::stream::unfold(
                                    (guard, 0),
                                    |(guard, index)| async move {
                                        let bytes = match index {
                                            0 => frame(1, b"recent tail\n"),
                                            1 => frame(2, b"live output\n"),
                                            _ => futures::future::pending().await,
                                        };
                                        Some((Ok::<_, Infallible>(bytes), (guard, index + 1)))
                                    },
                                ))
                            } else {
                                let mut history = "old line\n".repeat(160_000);
                                history.push_str("PASSWORD=\"hidden-secret\"\nimportant tail\n");
                                Body::from(frame(1, history.as_bytes()))
                            }
                        };
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("Content-Type", "application/vnd.docker.raw-stream")
                                .body(body)
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let history = runtime
            .logs(Protocol::Postgres, "inst_abc", Some(2000))
            .await
            .unwrap();
        assert!(
            history
                .stdout
                .starts_with(super::super::EXEC_OUTPUT_TRUNCATION_MARKER)
        );
        assert!(history.stdout.ends_with("important tail\n"));
        assert!(!history.stdout.contains("hidden-secret"));
        assert!(
            history.stdout.len()
                <= super::super::MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL
                    + super::super::EXEC_OUTPUT_TRUNCATION_MARKER.len()
        );
        let mut live = runtime
            .follow_logs(Protocol::Postgres, "inst_abc", None)
            .await
            .unwrap();
        assert_eq!(live.next().await.unwrap().unwrap().stdout, "recent tail\n");
        assert_eq!(live.next().await.unwrap().unwrap().stderr, "live output\n");
        drop(live);
        finished.await.unwrap();
        assert!(
            runtime
                .logs(Protocol::Postgres, "another_instance", None)
                .await
                .is_err()
        );
    })
    .await;
    server.abort();
    result.unwrap();
}
