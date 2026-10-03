use super::*;
use bollard::query_parameters::{LogsOptionsBuilder, WaitContainerOptions};
use futures::TryStreamExt;

const PROBE_LABEL: &str = "dbev.image-version-probe";
const PROBE_NAME_PREFIX: &str = "dbev-version-";
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_REMOVAL_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PROBE_OUTPUT_BYTES: usize = 64 * 1024;
const PROBE_MEMORY_BYTES: i64 = 256 * 1024 * 1024;
const PROBE_NANO_CPUS: i64 = 250_000_000;
const PROBE_PIDS_LIMIT: i64 = 32;

impl DockerRuntime {
    /// Called once before API startup, when this daemon owns no live probes.
    pub(crate) async fn cleanup_version_probes(&self) -> Result<usize, String> {
        let node = self
            .node_id
            .as_deref()
            .ok_or("node identity is unavailable")?;
        tokio::time::timeout(PROBE_TIMEOUT, async {
            let filters: HashMap<String, Vec<String>> = HashMap::from([(
                "label".into(),
                vec![
                    format!("{PROBE_LABEL}=true"),
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
                if !is_owned_version_probe(&labels, container.names.as_deref(), node) {
                    continue;
                }
                let Some(id) = container.id else {
                    continue;
                };
                self.docker
                    .remove_container(&id, Some(probe_removal_options()))
                    .await
                    .map_err(|error| error.to_string())?;
                removed += 1;
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
        let name = format!("{PROBE_NAME_PREFIX}{}", uuid::Uuid::new_v4().simple());
        let body = probe_body(
            protocol,
            &image_id,
            &self.security,
            self.engine,
            self.node_id.as_deref(),
        );
        let created = self
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::default().name(&name).build()),
                body,
            )
            .await
            .map_err(|error| error.to_string())?;
        let id = created.id;
        let result = tokio::time::timeout(PROBE_TIMEOUT, async {
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
                if output.len().saturating_add(chunk.len()) > MAX_PROBE_OUTPUT_BYTES {
                    return Err("version output exceeded its limit".into());
                }
                output.push_str(&chunk);
            }
            let version =
                crate::server::compatibility::normalize_database_version(protocol, &output)
                    .ok_or("image version could not be parsed")?;
            crate::server::compatibility::compatibility_profile(protocol, &version)
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(version)
        })
        .await
        .map_err(|_| "image version probe timed out".to_string())
        .and_then(|result| result);
        let cleanup = tokio::time::timeout(
            PROBE_REMOVAL_TIMEOUT,
            self.docker
                .remove_container(&id, Some(probe_removal_options())),
        )
        .await
        .map_err(|_| "version probe cleanup timed out".to_string())?;
        if let Err(error) = cleanup {
            return Err(format!("version probe cleanup failed: {error}"));
        }
        result.map(|version| (image_id, version))
    }
}

fn is_owned_version_probe(
    labels: &HashMap<String, String>,
    names: Option<&[String]>,
    node: &str,
) -> bool {
    labels.get(PROBE_LABEL).map(String::as_str) == Some("true")
        && labels.get(NODE_LABEL).map(String::as_str) == Some(node)
        && names.is_some_and(|names| names.iter().any(|name| is_version_probe_name(name)))
}

fn is_version_probe_name(name: &str) -> bool {
    name.trim_start_matches('/')
        .strip_prefix(PROBE_NAME_PREFIX)
        .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
}

fn probe_removal_options() -> RemoveContainerOptions {
    RemoveContainerOptions {
        force: true,
        v: true,
        ..Default::default()
    }
}

fn probe_body(
    protocol: Protocol,
    image: &str,
    security: &DockerSecurityPolicy,
    engine: crate::config::DaemonEngine,
    node_id: Option<&str>,
) -> ContainerCreateBody {
    let mut policy = security.clone();
    policy.read_only_rootfs = true;
    policy.drop_all_capabilities = true;
    policy.no_new_privileges = true;
    policy.pids_limit = PROBE_PIDS_LIMIT;
    let mut host_config = HostConfig {
        log_config: Some(super::container_config::log_config(engine)),
        network_mode: Some("none".into()),
        readonly_rootfs: Some(true),
        cap_drop: Some(vec!["ALL".into()]),
        security_opt: Some(vec!["no-new-privileges".into()]),
        memory: Some(PROBE_MEMORY_BYTES),
        memory_swap: Some(PROBE_MEMORY_BYTES),
        nano_cpus: Some(PROBE_NANO_CPUS),
        pids_limit: Some(PROBE_PIDS_LIMIT),
        ..Default::default()
    };
    policy.apply(&mut host_config);
    ContainerCreateBody {
        image: Some(image.into()),
        entrypoint: Some(vec!["sh".into(), "-c".into()]),
        cmd: Some(vec![
            crate::server::compatibility::database_version_script(protocol).into(),
        ]),
        labels: Some(HashMap::from([
            (PROBE_LABEL.into(), "true".into()),
            (NODE_LABEL.into(), node_id.unwrap_or("").into()),
        ])),
        host_config: Some(host_config),
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
                crate::config::DaemonEngine::Docker,
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
