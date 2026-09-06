use super::*;
use bollard::query_parameters::{LogsOptionsBuilder, WaitContainerOptions};
use futures::TryStreamExt;

impl DockerRuntime {
    /// Called once before API startup, when this daemon owns no live probes.
    pub(crate) async fn cleanup_version_probes(&self) -> Result<usize, String> {
        let node = self
            .node_id
            .as_deref()
            .ok_or("node identity is unavailable")?;
        tokio::time::timeout(Duration::from_secs(30), async {
            let filters: HashMap<String, Vec<String>> = HashMap::from([(
                "label".into(),
                vec![
                    "dbev.image-version-probe=true".into(),
                    format!("{NODE_LABEL}={node}"),
                ],
            )]);
            let containers = self
                .docker
                .list_containers(Some(
                    ListContainersOptionsBuilder::default()
                        .all(true)
                        .filters(&filters)
                        .build(),
                ))
                .await
                .map_err(|error| error.to_string())?;
            let mut removed = 0;
            for container in containers {
                let labels = container.labels.unwrap_or_default();
                if labels.get("dbev.image-version-probe").map(String::as_str) != Some("true")
                    || labels.get(NODE_LABEL).map(String::as_str) != Some(node)
                    || !container.names.as_ref().is_some_and(|names| {
                        names.iter().any(|name| {
                            name.trim_start_matches('/')
                                .strip_prefix("dbev-version-")
                                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
                        })
                    })
                {
                    continue;
                }
                if let Some(id) = container.id {
                    self.docker
                        .remove_container(
                            &id,
                            Some(RemoveContainerOptions {
                                force: true,
                                v: true,
                                ..Default::default()
                            }),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                    removed += 1;
                }
            }
            Ok(removed)
        })
        .await
        .map_err(|_| "version probe cleanup timed out".to_string())?
    }

    /// Runs only the version command in a disposable, networkless container
    /// with no host/database mounts. Resolve the tag once and return that ID.
    pub(crate) async fn probe_image_version(
        &self,
        protocol: Protocol,
        image: &str,
    ) -> Result<(String, String), String> {
        let image_id = self
            .docker
            .inspect_image(image)
            .await
            .map_err(|error| error.to_string())?
            .id
            .ok_or("image has no immutable identity")?;
        let name = format!("dbev-version-{}", uuid::Uuid::new_v4().simple());
        let body = probe_body(protocol, &image_id, &self.security, self.node_id.as_deref());
        let created = self
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::default().name(&name).build()),
                body,
            )
            .await
            .map_err(|error| error.to_string())?;
        let id = created.id;
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            self.docker
                .start_container(&id, None::<StartContainerOptions>)
                .await
                .map_err(|error| error.to_string())?;
            self.docker
                .wait_container(&id, None::<WaitContainerOptions>)
                .try_next()
                .await
                .map_err(|error| error.to_string())?
                .ok_or("version probe returned no exit status")?;
            let mut logs = self.docker.logs(
                &id,
                Some(
                    LogsOptionsBuilder::default()
                        .stdout(true)
                        .stderr(true)
                        .build(),
                ),
            );
            let mut output = String::new();
            while let Some(chunk) = logs.try_next().await.map_err(|error| error.to_string())? {
                let chunk = chunk.to_string();
                if output.len().saturating_add(chunk.len()) > 64 * 1024 {
                    return Err("version output exceeded its limit".into());
                }
                output.push_str(&chunk);
            }
            let version = crate::compatibility::normalize_database_version(protocol, &output)
                .ok_or("image version could not be parsed")?;
            crate::compatibility::compatibility_profile(protocol, &version)
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(version)
        })
        .await
        .map_err(|_| "image version probe timed out".to_string())
        .and_then(|result| result);
        let cleanup = tokio::time::timeout(
            Duration::from_secs(15),
            self.docker.remove_container(
                &id,
                Some(RemoveContainerOptions {
                    force: true,
                    v: true,
                    ..Default::default()
                }),
            ),
        )
        .await
        .map_err(|_| "version probe cleanup timed out".to_string())?;
        if let Err(error) = cleanup {
            return Err(format!("version probe cleanup failed: {error}"));
        }
        result.map(|version| (image_id, version))
    }
}

fn probe_body(
    protocol: Protocol,
    image: &str,
    security: &DockerSecurityPolicy,
    node_id: Option<&str>,
) -> ContainerCreateBody {
    let mut policy = security.clone();
    policy.read_only_rootfs = true;
    policy.drop_all_capabilities = true;
    policy.no_new_privileges = true;
    policy.pids_limit = 32;
    ContainerCreateBody {
        image: Some(image.into()),
        entrypoint: Some(vec!["sh".into(), "-c".into()]),
        cmd: Some(vec![
            crate::compatibility::database_version_script(protocol).into(),
        ]),
        labels: Some(HashMap::from([
            ("dbev.image-version-probe".into(), "true".into()),
            (NODE_LABEL.into(), node_id.unwrap_or("").into()),
        ])),
        host_config: Some({
            let mut host = HostConfig {
                network_mode: Some("none".into()),
                readonly_rootfs: Some(true),
                cap_drop: Some(vec!["ALL".into()]),
                security_opt: Some(vec!["no-new-privileges".into()]),
                memory: Some(256 * 1024 * 1024),
                memory_swap: Some(256 * 1024 * 1024),
                nano_cpus: Some(250_000_000),
                pids_limit: Some(32),
                ..Default::default()
            };
            policy.apply(&mut host);
            host
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_probes_never_mount_customer_or_host_data() {
        for protocol in Protocol::ALL {
            let body = probe_body(
                protocol,
                "sha256:test",
                &DockerSecurityPolicy::default(),
                Some("test-node"),
            );
            let host = body.host_config.unwrap();
            assert_eq!(host.network_mode.as_deref(), Some("none"));
            assert_eq!(host.readonly_rootfs, Some(true));
            assert!(host.mounts.is_none() && host.binds.is_none());
            assert_eq!(host.pids_limit, Some(32));
        }
    }
}
