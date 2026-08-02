use std::{path::PathBuf, time::Duration};

use anyhow::{Context, ensure};
use futures::StreamExt;
use secrecy::SecretString;

use super::{
    DockerContainerStatus, DockerEnv, DockerInstanceSpec, DockerRuntime, ManagedContainerAction,
};
use crate::{config::DaemonEngine, shared::protocol::Protocol};

const DEFAULT_SMOKE_IMAGE: &str = "docker.io/library/alpine:3.21";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires DBE_PODMAN_SOCKET pointing to a live rootless Podman API socket"]
async fn rootless_podman_compatibility_smoke() -> anyhow::Result<()> {
    let socket = std::env::var("DBE_PODMAN_SOCKET")
        .context("DBE_PODMAN_SOCKET must point to the rootless Podman Unix socket")?;
    let image =
        std::env::var("DBE_PODMAN_SMOKE_IMAGE").unwrap_or_else(|_| DEFAULT_SMOKE_IMAGE.to_string());
    let daemon = crate::config::DaemonConfig {
        engine: DaemonEngine::Podman,
        socket_path: socket,
        ..Default::default()
    };
    let mut runtime = DockerRuntime::new(&daemon, false)?;
    runtime.refresh_engine_info().await?;
    ensure!(runtime.uses_rootless_podman());
    ensure!(!runtime.ping().await?.trim().is_empty());

    let temporary = tempfile::tempdir()?;
    let instance_id = format!("inst_podman_smoke_{}", uuid::Uuid::new_v4().simple());
    let data_path = temporary.path().join("data");
    let logs_path = temporary.path().join("logs");
    let upload_path = temporary.path().join("upload.txt");
    let download_path = temporary.path().join("download.txt");
    let payload = b"dbev-podman-file-transfer\n";
    tokio::fs::write(&upload_path, payload).await?;

    let spec = smoke_spec(&instance_id, &image, data_path, logs_path);
    let mut created = false;
    let operation = async {
        runtime.create(&spec).await?;
        created = true;
        ensure!(
            runtime
                .verified_managed_container_name(Protocol::Redis, &instance_id)
                .await?
                .is_some()
        );

        let mut events = runtime.managed_container_events();
        let started_event = async {
            loop {
                let event = events
                    .next()
                    .await
                    .context("Podman event stream ended before the start event")??;
                if event.instance_id == instance_id
                    && event.action == ManagedContainerAction::Started
                {
                    return Ok::<_, anyhow::Error>(event);
                }
            }
        };
        let start = async {
            tokio::time::sleep(Duration::from_millis(250)).await;
            runtime.start(Protocol::Redis, &instance_id).await
        };
        let (event, start) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(20), started_event),
            start
        );
        start?;
        event.context("Podman did not publish a managed start event")??;

        let inspection = runtime
            .inspect_instance(Protocol::Redis, &instance_id)
            .await?;
        ensure!(inspection.status == DockerContainerStatus::Running);
        ensure!(inspection.network_mode.as_deref() == Some("none"));

        let output = runtime
            .exec_shell(Protocol::Redis, &instance_id, "printf dbev-podman-exec")
            .await?;
        ensure!(output.stdout == "dbev-podman-exec");

        runtime
            .upload_file(
                Protocol::Redis,
                &instance_id,
                &upload_path,
                "/tmp/dbev-upload.txt",
            )
            .await?;
        let output = runtime
            .exec_shell(Protocol::Redis, &instance_id, "cat /tmp/dbev-upload.txt")
            .await?;
        ensure!(output.stdout.as_bytes() == payload);
        runtime
            .download_file(
                Protocol::Redis,
                &instance_id,
                "/tmp/dbev-upload.txt",
                &download_path,
            )
            .await?;
        ensure!(tokio::fs::read(&download_path).await? == payload);

        runtime
            .update_limits(Protocol::Redis, &instance_id, 0.5, 96)
            .await?;
        runtime.stats(Protocol::Redis, &instance_id).await?;
        let logs = runtime
            .logs(Protocol::Redis, &instance_id, Some(20))
            .await?;
        ensure!(logs.stdout.contains("dbev-podman-smoke-ready"));

        runtime.restart(Protocol::Redis, &instance_id).await?;
        ensure!(
            runtime
                .inspect_instance(Protocol::Redis, &instance_id)
                .await?
                .status
                == DockerContainerStatus::Running
        );
        runtime.stop(Protocol::Redis, &instance_id).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;

    let cleanup = if created {
        runtime.delete(Protocol::Redis, &instance_id).await
    } else {
        Ok(super::CommandOutput::empty())
    };
    if let Err(error) = operation {
        if let Err(cleanup_error) = cleanup {
            return Err(error.context(format!(
                "Podman smoke cleanup also failed for {instance_id}: {cleanup_error}"
            )));
        }
        return Err(error);
    }
    cleanup.context("failed to remove the Podman smoke container")?;
    Ok(())
}

fn smoke_spec(
    instance_id: &str,
    image: &str,
    data_path: PathBuf,
    logs_path: PathBuf,
) -> DockerInstanceSpec {
    DockerInstanceSpec {
        instance_id: instance_id.to_string(),
        protocol: Protocol::Redis,
        image: image.to_string(),
        project_id: Some("podman-ci".to_string()),
        user: Some("0:0".to_string()),
        working_dir: None,
        entrypoint: None,
        cpu_cores: 0.75,
        memory_mib: 128,
        disk_mib: 128,
        pids_limit: Some(64),
        data_path,
        data_target: "/data".to_string(),
        logs_path,
        logs_target: "/logs".to_string(),
        extra_mounts: Vec::new(),
        socket_bridges: Vec::new(),
        env: vec![DockerEnv {
            key: "DBEV_PODMAN_SMOKE".to_string(),
            value: SecretString::from("true"),
        }],
        command: vec![
            "sh".to_string(),
            "-c".to_string(),
            "echo dbev-podman-smoke-ready; trap 'exit 0' TERM INT; while :; do sleep 1; done"
                .to_string(),
        ],
    }
}
