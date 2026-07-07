use std::{collections::HashMap, path::Path};

use bollard::{
    container::LogOutput,
    errors::Error as BollardError,
    models::{ContainerCreateBody, HostConfig},
    query_parameters::{
        CreateContainerOptionsBuilder, LogsOptionsBuilder, RemoveContainerOptions,
        StartContainerOptions, WaitContainerOptions,
    },
};
use futures::{StreamExt, TryStreamExt};

use super::{container_config::bind_mount, storage_opt};
use crate::{
    constants::docker::MANAGED_LABEL,
    runtime::docker::{DockerError, DockerRuntime},
};

impl DockerRuntime {
    pub async fn verify_disk_limit_support(
        &self,
        probe_image: &str,
        probe_parent: &Path,
    ) -> Result<(), DockerError> {
        let id = uuid::Uuid::new_v4();
        let name = format!("dbe-disk-quota-probe-{id}");
        let probe_dir = probe_parent.join(format!(".dbe-disk-quota-probe-{id}"));
        std::fs::create_dir_all(&probe_dir).map_err(DockerError::DiskLimitProbeIo)?;
        let body = ContainerCreateBody {
            image: Some(probe_image.to_string()),
            cmd: Some(vec![
                "sh".to_string(),
                "-c".to_string(),
                "dd if=/dev/zero of=/data/probe.bin bs=1M count=96 status=none".to_string(),
            ]),
            labels: Some(HashMap::from([(
                MANAGED_LABEL.to_string(),
                "true".to_string(),
            )])),
            host_config: Some(HostConfig {
                network_mode: Some(self.network.clone()),
                mounts: Some(vec![bind_mount(&probe_dir, "/data", false)]),
                storage_opt: storage_opt(true, 64),
                ..Default::default()
            }),
            ..Default::default()
        };

        if let Err(error) = self
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::default().name(&name).build()),
                body,
            )
            .await
        {
            remove_probe_dir(&probe_dir)?;
            return Err(DockerError::DiskLimitUnsupported {
                image: probe_image.to_string(),
                source: Box::new(error),
            });
        }

        if let Err(error) = self
            .docker
            .start_container(&name, None::<StartContainerOptions>)
            .await
        {
            self.remove_probe_container_and_dir(&name, &probe_dir)
                .await?;
            return Err(DockerError::DiskLimitUnsupported {
                image: probe_image.to_string(),
                source: Box::new(error),
            });
        }

        let result = self.evaluate_disk_probe_result(&name, probe_image).await;
        self.remove_probe_container_and_dir(&name, &probe_dir)
            .await?;
        result
    }

    async fn evaluate_disk_probe_result(
        &self,
        name: &str,
        probe_image: &str,
    ) -> Result<(), DockerError> {
        let mut wait = self
            .docker
            .wait_container(name, None::<WaitContainerOptions>);
        let wait_result = wait.next().await;
        drop(wait);

        match wait_result {
            Some(Ok(response)) if response.status_code == 0 => {
                Err(DockerError::DiskLimitNotEnforced)
            }
            Some(Ok(_)) => self.evaluate_nonzero_probe_exit(name, probe_image).await,
            Some(Err(BollardError::DockerContainerWaitError { .. })) => {
                self.evaluate_nonzero_probe_exit(name, probe_image).await
            }
            Some(Err(error)) => Err(DockerError::DiskLimitUnsupported {
                image: probe_image.to_string(),
                source: Box::new(error),
            }),
            None => Err(DockerError::DiskLimitProbeFailed(
                "docker wait stream ended without a result".to_string(),
            )),
        }
    }

    async fn evaluate_nonzero_probe_exit(
        &self,
        name: &str,
        probe_image: &str,
    ) -> Result<(), DockerError> {
        let logs = self.container_logs_by_name(name).await?;
        if logs.contains("No space left on device") || logs.contains("Disk quota exceeded") {
            Ok(())
        } else {
            Err(DockerError::DiskLimitProbeFailed(format!(
                "probe image {probe_image} exited non-zero without a quota error: {logs}"
            )))
        }
    }

    async fn container_logs_by_name(&self, name: &str) -> Result<String, DockerError> {
        let mut logs = String::new();
        let mut stream = self.docker.logs(
            name,
            Some(
                LogsOptionsBuilder::default()
                    .stdout(true)
                    .stderr(true)
                    .tail("50")
                    .build(),
            ),
        );
        while let Some(chunk) = stream.try_next().await? {
            match chunk {
                LogOutput::StdErr { message }
                | LogOutput::StdOut { message }
                | LogOutput::Console { message } => {
                    logs.push_str(&String::from_utf8_lossy(&message));
                }
                LogOutput::StdIn { .. } => {}
            }
        }
        Ok(logs)
    }

    async fn remove_probe_container_and_dir(
        &self,
        name: &str,
        probe_dir: &Path,
    ) -> Result<(), DockerError> {
        self.docker
            .remove_container(
                name,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await?;
        remove_probe_dir(probe_dir)
    }
}

fn remove_probe_dir(path: &Path) -> Result<(), DockerError> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DockerError::DiskLimitProbeIo(error)),
    }
}
