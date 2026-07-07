use std::path::{Path, PathBuf};

use super::{DiskLimitError, privileged_command};

pub(super) async fn verify_startup() -> Result<(), DiskLimitError> {
    list_datasets().await.map(|_| ())
}

pub(super) async fn apply(
    instance_id: &str,
    data_path: &Path,
    disk_mib: u64,
) -> Result<String, DiskLimitError> {
    let dataset = ensure_dataset(instance_id, data_path).await?;
    set_refquota(&dataset.name, disk_mib).await?;
    Ok("host_zfs_refquota".to_string())
}

pub(super) async fn destroy(data_path: &Path) -> Result<(), DiskLimitError> {
    let datasets = list_datasets().await?;
    let Some(dataset) = dataset_for_exact_mount(data_path, &datasets) else {
        return Ok(());
    };
    run_zfs(
        &["destroy", "-r", &dataset.name],
        format!("zfs destroy -r {}", dataset.name),
    )
    .await
}

async fn ensure_dataset(instance_id: &str, data_path: &Path) -> Result<ZfsDataset, DiskLimitError> {
    let datasets = list_datasets().await?;
    if let Some(dataset) = dataset_for_exact_mount(data_path, &datasets) {
        return Ok(dataset);
    }

    ensure_empty_mountpoint(data_path).await?;
    let parent = parent_dataset_for_path(data_path, &datasets)
        .ok_or_else(|| DiskLimitError::MountpointNotFound(data_path.to_path_buf()))?;
    let dataset = ZfsDataset {
        name: format!("{}/dbe_{}", parent.name, dataset_suffix(instance_id)),
        mountpoint: data_path.to_path_buf(),
    };

    run_zfs(
        &[
            "create",
            "-o",
            &format!("mountpoint={}", data_path.display()),
            &dataset.name,
        ],
        format!(
            "zfs create -o mountpoint={} {}",
            data_path.display(),
            dataset.name
        ),
    )
    .await?;
    Ok(dataset)
}

async fn ensure_empty_mountpoint(path: &Path) -> Result<(), DiskLimitError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        if path.exists() {
            let mut entries =
                std::fs::read_dir(&path).map_err(|source| DiskLimitError::PathIo {
                    path: path.display().to_string(),
                    source,
                })?;
            if entries
                .next()
                .transpose()
                .map_err(|source| DiskLimitError::PathIo {
                    path: path.display().to_string(),
                    source,
                })?
                .is_some()
            {
                return Err(DiskLimitError::DataPathNotEmpty(path));
            }
            std::fs::remove_dir(&path).map_err(|source| DiskLimitError::PathIo {
                path: path.display().to_string(),
                source,
            })?;
        }
        Ok(())
    })
    .await
    .map_err(|error| DiskLimitError::Task(error.to_string()))?
}

async fn set_refquota(dataset: &str, disk_mib: u64) -> Result<(), DiskLimitError> {
    let quota = if disk_mib == 0 {
        "none".to_string()
    } else {
        format!("{disk_mib}M")
    };
    run_zfs(
        &["set", &format!("refquota={quota}"), dataset],
        format!("zfs set refquota={quota} {dataset}"),
    )
    .await
}

async fn list_datasets() -> Result<Vec<ZfsDataset>, DiskLimitError> {
    let output = privileged_command("zfs")
        .arg("list")
        .arg("-H")
        .arg("-o")
        .arg("name,mountpoint")
        .arg("-t")
        .arg("filesystem")
        .output()
        .await
        .map_err(|source| DiskLimitError::CommandIo {
            command: "zfs",
            source,
        })?;
    if !output.status.success() {
        return Err(DiskLimitError::CommandFailed {
            command: "zfs list -H -o name,mountpoint -t filesystem".to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(parse_zfs_datasets(&String::from_utf8_lossy(&output.stdout)))
}

fn parse_zfs_datasets(output: &str) -> Vec<ZfsDataset> {
    output
        .lines()
        .filter_map(|line| {
            let (name, mountpoint) = line.split_once('\t')?;
            if mountpoint == "-" || mountpoint == "legacy" || mountpoint == "none" {
                return None;
            }
            Some(ZfsDataset {
                name: name.to_string(),
                mountpoint: PathBuf::from(mountpoint),
            })
        })
        .collect()
}

fn dataset_for_exact_mount(path: &Path, datasets: &[ZfsDataset]) -> Option<ZfsDataset> {
    datasets
        .iter()
        .find(|dataset| dataset.mountpoint == path)
        .cloned()
}

fn parent_dataset_for_path(path: &Path, datasets: &[ZfsDataset]) -> Option<ZfsDataset> {
    datasets
        .iter()
        .filter(|dataset| path.starts_with(&dataset.mountpoint))
        .max_by_key(|dataset| dataset.mountpoint.as_os_str().len())
        .cloned()
}

async fn run_zfs(args: &[&str], command: String) -> Result<(), DiskLimitError> {
    let output = privileged_command("zfs")
        .args(args)
        .output()
        .await
        .map_err(|source| DiskLimitError::CommandIo {
            command: "zfs",
            source,
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(DiskLimitError::CommandFailed {
            command,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn dataset_suffix(instance_id: &str) -> String {
    instance_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ZfsDataset {
    name: String,
    mountpoint: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_zfs_dataset_list() {
        let datasets = parse_zfs_datasets("tank/root\t/tank/root\ntank/off\t-\n");

        assert_eq!(
            datasets,
            vec![ZfsDataset {
                name: "tank/root".to_string(),
                mountpoint: PathBuf::from("/tank/root"),
            }]
        );
    }

    #[test]
    fn picks_nearest_parent_dataset() {
        let datasets = vec![
            ZfsDataset {
                name: "tank".to_string(),
                mountpoint: PathBuf::from("/tank"),
            },
            ZfsDataset {
                name: "tank/data".to_string(),
                mountpoint: PathBuf::from("/tank/data"),
            },
        ];

        let dataset = parent_dataset_for_path(Path::new("/tank/data/db/inst_1"), &datasets)
            .expect("parent dataset");

        assert_eq!(dataset.name, "tank/data");
    }
}
