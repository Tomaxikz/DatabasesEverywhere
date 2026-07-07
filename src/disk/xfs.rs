use std::{
    fs::OpenOptions,
    hash::Hasher,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use super::{DiskLimitError, displayed_privileged_command, privileged_command};

pub(super) async fn verify_startup(mount: &Path) -> Result<(), DiskLimitError> {
    run_quota(mount, "state").await?;
    verify_project_files_writable().await
}

pub(super) async fn apply(
    instance_id: &str,
    data_path: &Path,
    disk_mib: u64,
    project_id_base: u32,
    mount: &Path,
) -> Result<String, DiskLimitError> {
    let project = ProjectQuota {
        id: project_id(instance_id, project_id_base),
        name: project_name(instance_id),
        path: data_path.to_path_buf(),
    };

    ensure_project_files(project.clone()).await?;
    run_quota(mount, &format!("project -s {}", project.name)).await?;
    run_quota(
        mount,
        &format!("limit -p bhard={}m {}", disk_mib, project.name),
    )
    .await?;
    Ok("host_xfs_project_quota".to_string())
}

#[derive(Debug, Clone)]
struct ProjectQuota {
    id: u32,
    name: String,
    path: PathBuf,
}

async fn verify_project_files_writable() -> Result<(), DiskLimitError> {
    tokio::task::spawn_blocking(|| {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("/etc/projects")
            .map_err(|source| DiskLimitError::ProjectFile {
                path: "/etc/projects",
                source,
            })?;
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("/etc/projid")
            .map_err(|source| DiskLimitError::ProjectFile {
                path: "/etc/projid",
                source,
            })?;
        Ok(())
    })
    .await
    .map_err(|error| DiskLimitError::Task(error.to_string()))?
}

async fn ensure_project_files(project: ProjectQuota) -> Result<(), DiskLimitError> {
    tokio::task::spawn_blocking(move || {
        upsert_project_file_line(
            "/etc/projects",
            &format!("{}:", project.id),
            &format!("{}:{}", project.id, project.path.display()),
        )?;
        upsert_project_file_line(
            "/etc/projid",
            &format!("{}:", project.name),
            &format!("{}:{}", project.name, project.id),
        )
    })
    .await
    .map_err(|error| DiskLimitError::Task(error.to_string()))?
}

fn upsert_project_file_line(
    path: &'static str,
    key: &str,
    line: &str,
) -> Result<(), DiskLimitError> {
    let mut contents = String::new();
    match OpenOptions::new().read(true).open(path) {
        Ok(mut file) => {
            file.read_to_string(&mut contents)
                .map_err(|source| DiskLimitError::ProjectFile { path, source })?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(DiskLimitError::ProjectFile { path, source }),
    }

    let mut found = false;
    let mut lines = Vec::new();
    for existing in contents.lines() {
        if existing.starts_with(key) {
            lines.push(line.to_string());
            found = true;
        } else {
            lines.push(existing.to_string());
        }
    }
    if !found {
        lines.push(line.to_string());
    }

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|source| DiskLimitError::ProjectFile { path, source })?;
    file.write_all(lines.join("\n").as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|source| DiskLimitError::ProjectFile { path, source })
}

async fn run_quota(mount: &Path, command: &str) -> Result<(), DiskLimitError> {
    let output = privileged_command("xfs_quota")
        .arg("-x")
        .arg("-c")
        .arg(command)
        .arg(mount)
        .output()
        .await
        .map_err(|source| DiskLimitError::CommandIo {
            command: "xfs_quota",
            source,
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(DiskLimitError::CommandFailed {
            command: displayed_privileged_command(
                "xfs_quota",
                format!("-x -c '{command}' {}", mount.display()),
            ),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn project_name(instance_id: &str) -> String {
    let sanitized: String = instance_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    format!("dbe_{sanitized}")
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
    fn project_names_are_safe() {
        assert_eq!(project_name("inst-abc.1"), "dbe_inst_abc_1");
    }

    #[test]
    fn project_ids_are_stable() {
        assert_eq!(
            project_id("inst_abc", 200_000),
            project_id("inst_abc", 200_000)
        );
    }
}
