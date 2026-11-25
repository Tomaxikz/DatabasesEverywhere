use std::path::Path;

use super::{DiskLimitError, run};

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Disabled,
    Simple,
    Full,
    Unknown(String),
}

impl Mode {
    fn enabled(name: &str) -> Self {
        match name {
            "squota" => Self::Simple,
            "qgroup" => Self::Full,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

pub(in crate::server::disk) async fn verify_startup(
    root: &Path,
    allow_enable: bool,
) -> Result<(), DiskLimitError> {
    match quota_mode(root).await? {
        Mode::Simple => {}
        Mode::Full => tracing::warn!(
            path = %root.display(),
            "Btrfs full quotas are active. Large snapshot or subvolume deletions can stall writers. Switching quota modes discards filesystem-wide qgroups and limits and requires operator planning."
        ),
        Mode::Unknown(mode) => {
            tracing::warn!(path = %root.display(), %mode, "unrecognized active Btrfs quota mode")
        }
        Mode::Disabled => {
            if !allow_enable {
                return Err(quota_error(
                    root,
                    "quotas are disabled. Enable simple quotas on the volumes filesystem or set disk.btrfs_allow_enable_simple_quotas",
                ));
            }
            run(
                root,
                &["quota", "enable", "--simple"],
                "btrfs quota enable --simple",
            )
            .await?;
            if quota_mode(root).await? != Mode::Simple {
                return Err(quota_error(
                    root,
                    "simple quotas could not be confirmed after enable",
                ));
            }
            tracing::info!(path = %root.display(), "enabled Btrfs simple quotas");
        }
    }
    Ok(())
}

fn quota_error(root: &Path, reason: impl ToString) -> DiskLimitError {
    DiskLimitError::BtrfsQuota {
        path: root.into(),
        reason: reason.to_string(),
    }
}

fn parse_status(text: &str) -> Option<Mode> {
    let field = |name| {
        text.lines()
            .find_map(|line| line.trim().strip_prefix(name))
            .map(str::trim)
    };
    match field("Enabled:")? {
        "yes" => field("Mode:")?.split_whitespace().next().map(Mode::enabled),
        "no" if field("Mode:").is_none() => Some(Mode::Disabled),
        _ => None,
    }
}

async fn quota_mode(root: &Path) -> Result<Mode, DiskLimitError> {
    let output = tokio::process::Command::new("btrfs")
        .args(["quota", "status"])
        .arg(root)
        .env("LC_ALL", "C")
        .output()
        .await
        .map_err(|source| DiskLimitError::CommandIo {
            command: "btrfs",
            source,
        })?;
    if output.status.success() {
        let mode = parse_status(&String::from_utf8_lossy(&output.stdout))
            .ok_or_else(|| quota_error(root, "incomplete btrfs quota status output"))?;
        // btrfs-progs also prints "Enabled: no" when sysfs is inaccessible.
        if mode != Mode::Disabled {
            return Ok(mode);
        }
    } else if !String::from_utf8_lossy(&output.stderr).contains("unknown token 'status'") {
        return Err(quota_error(
            root,
            String::from_utf8_lossy(&output.stderr).trim(),
        ));
    }

    #[cfg(target_os = "linux")]
    {
        let path = root.to_owned();
        tokio::task::spawn_blocking(move || mode_from_sysfs(&path))
            .await
            .map_err(|error| DiskLimitError::Task(error.to_string()))?
            .map_err(|error| quota_error(root, error))
    }
    #[cfg(not(target_os = "linux"))]
    Err(quota_error(
        root,
        "Btrfs quota detection requires Linux sysfs",
    ))
}

// btrfs-progs 6.6 (Ubuntu 24.04) supports --simple but lacks quota status.
#[cfg(target_os = "linux")]
fn mode_from_sysfs(root: &Path) -> std::io::Result<Mode> {
    use linux_raw_sys::{btrfs::btrfs_ioctl_fs_info_args, ioctl::BTRFS_IOC_FS_INFO};
    use std::{fs, io, os::fd::AsRawFd};

    let dir = fs::File::open(root)?;
    // SAFETY: the Linux UAPI structure contains only integers and byte arrays.
    // Zeroed input flags request the basic FSID from this directory's mount.
    let mut info: btrfs_ioctl_fs_info_args = unsafe { std::mem::zeroed() };
    // SAFETY: dir is live and info is writable and matches this ioctl's ABI.
    if unsafe { libc::ioctl(dir.as_raw_fd(), BTRFS_IOC_FS_INFO as _, &mut info) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let fs_dir = Path::new("/sys/fs/btrfs").join(uuid::Uuid::from_bytes(info.fsid).to_string());
    fs::metadata(&fs_dir)?;
    let groups = fs_dir.join("qgroups");
    if !groups.try_exists()? {
        return Ok(Mode::Disabled);
    }
    match fs::read_to_string(groups.join("mode")) {
        Ok(mode) => Ok(Mode::enabled(mode.trim())),
        // Kernels before 6.7 only have full accounting.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Mode::Full),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_requires_explicit_fields() {
        assert_eq!(
            parse_status("Quotas on /no:\n  Enabled: no\n"),
            Some(Mode::Disabled)
        );
        assert_eq!(
            parse_status("Enabled: yes\nMode: squota (simplified accounting)"),
            Some(Mode::Simple)
        );
        assert_eq!(
            parse_status("Enabled: yes\nMode: qgroup (full accounting)\nInconsistent: no"),
            Some(Mode::Full)
        );
        assert_eq!(
            parse_status("Enabled: yes\nMode: future"),
            Some(Mode::Unknown("future".into()))
        );
        for incomplete in [
            "",
            "Enabled: yes",
            "Mode: squota",
            "Enabled: no\nMode: qgroup",
        ] {
            assert_eq!(parse_status(incomplete), None);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[tokio::test]
#[ignore = "requires DBE_BTRFS_TEST_ROOT on a disposable loop-mounted Btrfs filesystem"]
async fn loopback_quota_and_volume_lifecycle() -> anyhow::Result<()> {
    use std::{fs, io::Write, process::Command};

    let root = fs::canonicalize(std::env::var("DBE_BTRFS_TEST_ROOT")?)?;
    let mount = crate::server::disk::mounts::find_mount(&root)?;
    anyhow::ensure!(
        mount.mountpoint == root
            && mount.fstype == "btrfs"
            && mount.source.starts_with("/dev/loop")
    );
    let initial = quota_mode(&root).await?;
    match initial {
        Mode::Full => {
            verify_startup(&root, true).await?;
            assert_eq!(quota_mode(&root).await?, Mode::Full);
        }
        Mode::Disabled => {
            assert!(verify_startup(&root, false).await.is_err());
            assert_eq!(quota_mode(&root).await?, Mode::Disabled);
            verify_startup(&root, true).await?;
            assert_eq!(quota_mode(&root).await?, Mode::Simple);
        }
        other => anyhow::bail!("expected a fresh or full-quota test filesystem, got {other:?}"),
    }
    verify_startup(&root, false).await?;
    let work = tempfile::tempdir_in(&root)?;
    let volume = work.path().join("data");
    fs::create_dir(&volume)?;
    super::apply(&volume, 16).await?;
    let file = volume.join("payload");
    let block = vec![0xab; 1024 * 1024];
    let mut writer = fs::File::create(&file)?;
    let attrs = Command::new("lsattr").arg(&file).output()?;
    assert!(attrs.status.success());
    assert!(
        String::from_utf8_lossy(&attrs.stdout)
            .split_whitespace()
            .next()
            .is_some_and(|flags| flags.contains('C'))
    );
    let fill = |writer: &mut fs::File| -> std::io::Result<()> {
        for _ in 0..24 {
            writer.write_all(&block)?;
            writer.sync_data()?;
        }
        Ok(())
    };
    assert_eq!(
        fill(&mut writer)
            .expect_err("16 MiB hard limit")
            .raw_os_error(),
        Some(libc::EDQUOT)
    );
    super::apply(&volume, 64).await?;
    writer.write_all(&block)?;
    writer.sync_data()?;
    drop(writer);
    let snap = work.path().join("backup");
    assert!(
        Command::new("btrfs")
            .args(["subvolume", "snapshot", "-r"])
            .arg(&volume)
            .arg(&snap)
            .status()?
            .success()
    super::destroy(&volume).await?;
    assert!(!volume.exists());
    assert!(snap.join("payload").is_file());
    super::destroy(&snap).await?;
    assert!(!snap.exists());
    Ok(())
}
