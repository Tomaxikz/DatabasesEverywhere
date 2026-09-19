use std::path::PathBuf;

use bollard::{models::MountPoint, query_parameters::ListContainersOptionsBuilder};

use super::DockerRuntime;

impl DockerRuntime {
    /// Include stopped and foreign containers: their mounts must survive too.
    /// An incomplete inventory must never authorize host mount cleanup.
    pub(crate) async fn all_container_mount_sources(&self) -> anyhow::Result<Vec<PathBuf>> {
        let containers = self
            .docker
            .list_containers(Some(
                ListContainersOptionsBuilder::default().all(true).build(),
            ))
            .await?;
        anyhow::ensure!(
            containers.len() <= 4096,
            "container mount inventory limit exceeded"
        );
        let mut sources = Vec::new();
        for container in containers {
            let id = container
                .id
                .ok_or_else(|| anyhow::anyhow!("container inventory has no identity"))?;
            let inspection = self.docker.inspect_container(&id, None).await?;
            let mounts = inspection
                .mounts
                .ok_or_else(|| anyhow::anyhow!("container mount inventory is unavailable"))?;
            for mount in mounts {
                if let Some(source) = mount_source(mount)? {
                    sources.push(source);
                }
            }
        }
        Ok(sources)
    }
}

fn mount_source(mount: MountPoint) -> anyhow::Result<Option<PathBuf>> {
    match mount.source.filter(|source| !source.is_empty()) {
        Some(source) => {
            let source = PathBuf::from(source);
            anyhow::ensure!(
                source.is_absolute(),
                "container mount source is not absolute"
            );
            Ok(Some(source))
        }
        None if mount.typ.as_deref() == Some("tmpfs") => Ok(None),
        None => anyhow::bail!("container mount has an unknown host source"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_bind_or_volume_sources_never_authorize_cleanup() {
        for kind in [None, Some("bind"), Some("volume")] {
            assert!(
                mount_source(MountPoint {
                    typ: kind.map(str::to_owned),
                    ..Default::default()
                })
                .is_err()
            );
        }
        assert_eq!(
            mount_source(MountPoint {
                typ: Some("tmpfs".into()),
                ..Default::default()
            })
            .unwrap(),
            None
        );
        assert_eq!(
            mount_source(MountPoint {
                source: Some("/host/mount".into()),
                ..Default::default()
            })
            .unwrap(),
            Some(PathBuf::from("/host/mount"))
        );
        assert!(
            mount_source(MountPoint {
                source: Some("relative".into()),
                ..Default::default()
            })
            .is_err()
        );
    }
}
