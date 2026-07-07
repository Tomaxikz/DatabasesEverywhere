use std::{hash::Hasher, path::Path};

use super::{DiskLimitError, displayed_privileged_command, privileged_command};

pub(super) async fn verify_startup(
    data_root: &Path,
    mount: &Path,
    source: &str,
    fstype: &str,
    options: &[String],
) -> Result<(), DiskLimitError> {
    require_project_quota_mount_option(data_root, mount, source, fstype, options)?;
    require_command("quotaon").await?;
    require_command("setquota").await?;
    require_command("chattr").await?;
    run_quotaon_state(mount).await
}

pub(super) async fn apply(
    instance_id: &str,
    data_path: &Path,
    disk_mib: u64,
    project_id_base: u32,
    mount: &Path,
) -> Result<String, DiskLimitError> {
    let project_id = project_id(instance_id, project_id_base);
    set_project_id(data_path, project_id).await?;
    set_project_quota(mount, project_id, disk_mib).await?;
    Ok("host_linux_project_quota".to_string())
}

async fn require_command(command: &'static str) -> Result<(), DiskLimitError> {
    privileged_command(command)
        .output()
        .await
        .map(|_| ())
        .map_err(|source| DiskLimitError::CommandIo { command, source })
}

fn require_project_quota_mount_option(
    data_root: &Path,
    mount: &Path,
    source: &str,
    fstype: &str,
    options: &[String],
) -> Result<(), DiskLimitError> {
    let enabled = options
        .iter()
        .any(|option| matches!(option.as_str(), "prjquota" | "pquota"));
    if enabled {
        return Ok(());
    }

    Err(DiskLimitError::ProjectQuotaNotEnabled {
        data_root: data_root.to_path_buf(),
        mountpoint: mount.to_path_buf(),
        device: source.to_string(),
        fstype: fstype.to_string(),
        options: if options.is_empty() {
            "-".to_string()
        } else {
            options.join(",")
        },
    })
}

async fn run_quotaon_state(mount: &Path) -> Result<(), DiskLimitError> {
    let output = privileged_command("quotaon")
        .arg("-P")
        .arg("-p")
        .arg(mount)
        .output()
        .await
        .map_err(|source| DiskLimitError::CommandIo {
            command: "quotaon",
            source,
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(DiskLimitError::CommandFailed {
            command: displayed_privileged_command("quotaon", format!("-P -p {}", mount.display())),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

async fn set_project_id(path: &Path, project_id: u32) -> Result<(), DiskLimitError> {
    let output = privileged_command("chattr")
        .arg("-p")
        .arg(project_id.to_string())
        .arg("+P")
        .arg(path)
        .output()
        .await
        .map_err(|source| DiskLimitError::CommandIo {
            command: "chattr",
            source,
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(DiskLimitError::CommandFailed {
            command: displayed_privileged_command(
                "chattr",
                format!("-p {project_id} +P {}", path.display()),
            ),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

async fn set_project_quota(
    mount: &Path,
    project_id: u32,
    disk_mib: u64,
) -> Result<(), DiskLimitError> {
    let blocks_1k = disk_mib.saturating_mul(1024);
    let output = privileged_command("setquota")
        .arg("-P")
        .arg(project_id.to_string())
        .arg(blocks_1k.to_string())
        .arg(blocks_1k.to_string())
        .arg("0")
        .arg("0")
        .arg(mount)
        .output()
        .await
        .map_err(|source| DiskLimitError::CommandIo {
            command: "setquota",
            source,
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(DiskLimitError::CommandFailed {
            command: displayed_privileged_command(
                "setquota",
                format!(
                    "-P {project_id} {blocks_1k} {blocks_1k} 0 0 {}",
                    mount.display()
                ),
            ),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn project_id(instance_id: &str, base: u32) -> u32 {
    let mut hasher = Fnv1a32::default();
    hasher.write(instance_id.as_bytes());
    base.saturating_add((hasher.finish() as u32) % 1_000_000_000)
}

#[derive(Default)]
struct Fnv1a32(u32);

impl Hasher for Fnv1a32 {
    fn write(&mut self, bytes: &[u8]) {
        let mut hash = if self.0 == 0 { 0x811c_9dc5 } else { self.0 };
        for byte in bytes {
            hash ^= u32::from(*byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
        self.0 = hash;
    }

    fn finish(&self) -> u64 {
        u64::from(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_ids_are_stable() {
        assert_eq!(
            project_id("inst_abc", 200_000),
            project_id("inst_abc", 200_000)
        );
    }

    #[test]
    fn rejects_mount_without_project_quota_option() {
        let error = require_project_quota_mount_option(
            Path::new("/var/lib/databases-everywhere"),
            Path::new("/"),
            "/dev/vda3",
            "ext4",
            &["rw".to_string(), "errors=remount-ro".to_string()],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            DiskLimitError::ProjectQuotaNotEnabled { .. }
        ));
    }

    #[test]
    fn accepts_project_quota_mount_option_aliases() {
        require_project_quota_mount_option(
            Path::new("/var/lib/databases-everywhere"),
            Path::new("/"),
            "/dev/vda3",
            "ext4",
            &["rw".to_string(), "prjquota".to_string()],
        )
        .unwrap();
        require_project_quota_mount_option(
            Path::new("/var/lib/databases-everywhere"),
            Path::new("/"),
            "/dev/vda3",
            "f2fs",
            &["rw".to_string(), "pquota".to_string()],
        )
        .unwrap();
    }
}
