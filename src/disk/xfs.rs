use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use super::{DiskLimitError, displayed_privileged_command, privileged_command, project_id};

const PROJECTS_FILE: &str = "/etc/projects";
const PROJID_FILE: &str = "/etc/projid";
const PROJECT_FILES_LOCK: &str = "/etc/.dbe-project-quota.lock";
const MAX_PROJECT_FILE_BYTES: u64 = 8 * 1024 * 1024;

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
    let id = project_id::allocate(instance_id, data_path, project_id_base).await?;
    let project = ProjectQuota {
        id,
        name: project_name(id),
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
        let _lock = lock_project_files()?;
        verify_regular_file_writable(PROJECTS_FILE)?;
        verify_regular_file_writable(PROJID_FILE)?;
        Ok(())
    })
    .await
    .map_err(|error| DiskLimitError::Task(error.to_string()))?
}

async fn ensure_project_files(project: ProjectQuota) -> Result<(), DiskLimitError> {
    tokio::task::spawn_blocking(move || ensure_project_files_blocking(&project))
        .await
        .map_err(|error| DiskLimitError::Task(error.to_string()))?
}

fn ensure_project_files_blocking(project: &ProjectQuota) -> Result<(), DiskLimitError> {
    validate_project_path(project).map_err(|source| DiskLimitError::ProjectFile {
        path: PROJECTS_FILE,
        source,
    })?;
    let _lock = lock_project_files()?;
    let projects = read_project_file(PROJECTS_FILE)?;
    let projid = read_project_file(PROJID_FILE)?;

    // Plan and validate both updates before replacing either file. This makes a
    // conflicting external allocation fail closed without modifying the other
    // registry file.
    let projects_update =
        updated_projects(&projects, project).map_err(|source| DiskLimitError::ProjectFile {
            path: PROJECTS_FILE,
            source,
        })?;
    let projid_update =
        updated_projid(&projid, project).map_err(|source| DiskLimitError::ProjectFile {
            path: PROJID_FILE,
            source,
        })?;

    if let Some(contents) = projects_update {
        atomic_replace_project_file(Path::new(PROJECTS_FILE), &contents).map_err(|source| {
            DiskLimitError::ProjectFile {
                path: PROJECTS_FILE,
                source,
            }
        })?;
    }
    if let Some(contents) = projid_update {
        atomic_replace_project_file(Path::new(PROJID_FILE), &contents).map_err(|source| {
            DiskLimitError::ProjectFile {
                path: PROJID_FILE,
                source,
            }
        })?;
    }
    Ok(())
}

fn lock_project_files() -> Result<File, DiskLimitError> {
    acquire_exclusive_lock(Path::new(PROJECT_FILES_LOCK)).map_err(|source| {
        DiskLimitError::ProjectFile {
            path: PROJECT_FILES_LOCK,
            source,
        }
    })
}

fn acquire_exclusive_lock(path: &Path) -> Result<File, std::io::Error> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }

    let lock = options.open(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "project file lock must be a real regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
            .map_err(std::io::Error::from)?;
    }
    Ok(lock)
}

fn verify_regular_file_writable(path: &'static str) -> Result<(), DiskLimitError> {
    let path_ref = Path::new(path);
    match std::fs::symlink_metadata(path_ref) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(DiskLimitError::ProjectFile {
                    path,
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "project registry must be a real regular file",
                    ),
                });
            }
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(path_ref)
                .map_err(|source| DiskLimitError::ProjectFile { path, source })?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;

                options.mode(0o644);
            }
            options
                .open(path_ref)
                .map_err(|source| DiskLimitError::ProjectFile { path, source })?;
        }
        Err(source) => return Err(DiskLimitError::ProjectFile { path, source }),
    }
    Ok(())
}

fn read_project_file(path: &'static str) -> Result<String, DiskLimitError> {
    read_regular_file(Path::new(path))
        .map_err(|source| DiskLimitError::ProjectFile { path, source })
}

fn read_regular_file(path: &Path) -> Result<String, std::io::Error> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "project registry must be a real regular file",
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(error),
    }

    let mut contents = String::new();
    File::open(path)?
        .take(MAX_PROJECT_FILE_BYTES + 1)
        .read_to_string(&mut contents)?;
    if contents.len() as u64 > MAX_PROJECT_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "project registry exceeds the 8 MiB safety limit",
        ));
    }
    Ok(contents)
}

fn validate_project_path(project: &ProjectQuota) -> Result<(), std::io::Error> {
    let path = project.path.to_string_lossy();
    if path.bytes().any(|byte| matches!(byte, b'\n' | b'\r')) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "project path must not contain line breaks",
        ));
    }
    Ok(())
}

fn updated_projects(
    contents: &str,
    project: &ProjectQuota,
) -> Result<Option<String>, std::io::Error> {
    let desired_path = project.path.to_string_lossy();
    let mut found = false;
    for line in registry_data_lines(contents) {
        let Some((id, path)) = parse_projects_entry(line) else {
            continue;
        };
        if id == project.id {
            if path != desired_path {
                return Err(project_conflict(format!(
                    "project id {} is already assigned to {path}",
                    project.id
                )));
            }
            found = true;
        } else if path == desired_path {
            return Err(project_conflict(format!(
                "project path {desired_path} is already assigned to project id {id}"
            )));
        }
    }

    if found {
        Ok(None)
    } else {
        Ok(Some(append_registry_line(
            contents,
            &format!("{}:{desired_path}", project.id),
        )))
    }
}

fn updated_projid(
    contents: &str,
    project: &ProjectQuota,
) -> Result<Option<String>, std::io::Error> {
    let mut found = false;
    for line in registry_data_lines(contents) {
        let Some((name, raw_id)) = line.split_once(':') else {
            continue;
        };
        let parsed_id = raw_id.trim().parse::<u32>().ok();
        if name == project.name {
            if parsed_id != Some(project.id) {
                return Err(project_conflict(format!(
                    "project name {} is already assigned to an invalid or different id",
                    project.name
                )));
            }
            found = true;
        } else if parsed_id == Some(project.id) {
            return Err(project_conflict(format!(
                "project id {} is already assigned to project name {name}",
                project.id
            )));
        }
    }

    if found {
        Ok(None)
    } else {
        Ok(Some(append_registry_line(
            contents,
            &format!("{}:{}", project.name, project.id),
        )))
    }
}

fn registry_data_lines(contents: &str) -> impl Iterator<Item = &str> {
    contents
        .lines()
        .map(str::trim_start)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

fn parse_projects_entry(line: &str) -> Option<(u32, &str)> {
    let (raw_id, path) = line.split_once(':')?;
    Some((raw_id.trim().parse().ok()?, path))
}

fn append_registry_line(contents: &str, line: &str) -> String {
    let mut updated = contents.to_string();
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(line);
    updated.push('\n');
    updated
}

fn project_conflict(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::AlreadyExists, message)
}

fn atomic_replace_project_file(path: &Path, contents: &str) -> Result<(), std::io::Error> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "project registry path has no parent directory",
        )
    })?;
    let existing_metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "project registry must be a real regular file",
                ));
            }
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "project registry filename is not valid UTF-8",
            )
        })?;
    let temporary_path = parent.join(format!(".{file_name}.dbe-{}.tmp", uuid::Uuid::new_v4()));

    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            let mode = existing_metadata
                .as_ref()
                .map_or(0o644, |metadata| metadata.permissions().mode() & 0o7777);
            options.mode(mode);
        }
        let mut file = options.open(&temporary_path)?;

        #[cfg(unix)]
        if let Some(metadata) = existing_metadata.as_ref() {
            preserve_file_owner(&file, metadata)?;
            file.set_permissions(metadata.permissions())?;
        }

        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&temporary_path, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result
}

#[cfg(unix)]
fn preserve_file_owner(file: &File, metadata: &std::fs::Metadata) -> Result<(), std::io::Error> {
    use std::os::unix::fs::MetadataExt;

    let temporary_metadata = file.metadata()?;
    if temporary_metadata.uid() != metadata.uid() || temporary_metadata.gid() != metadata.gid() {
        rustix::fs::fchown(
            file,
            Some(rustix::process::Uid::from_raw(metadata.uid())),
            Some(rustix::process::Gid::from_raw(metadata.gid())),
        )
        .map_err(std::io::Error::from)?;
    }
    Ok(())
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

fn project_name(project_id: u32) -> String {
    format!("dbe_{project_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> ProjectQuota {
        ProjectQuota {
            id: 200_123,
            name: "dbe_200123".to_string(),
            path: PathBuf::from("/srv/dbe/instances/one"),
        }
    }

    #[test]
    fn project_names_are_safe() {
        assert_eq!(project_name(200_123), "dbe_200123");
    }

    #[test]
    fn registry_updates_are_idempotent() {
        let project = project();

        assert!(
            updated_projects("200123:/srv/dbe/instances/one\n", &project)
                .unwrap()
                .is_none()
        );
        assert!(
            updated_projid("dbe_200123:200123\n", &project)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            updated_projects("# managed projects\n", &project).unwrap(),
            Some("# managed projects\n200123:/srv/dbe/instances/one\n".to_string())
        );
        assert_eq!(
            updated_projid("# managed projects", &project).unwrap(),
            Some("# managed projects\ndbe_200123:200123\n".to_string())
        );
    }

    #[test]
    fn projects_registry_rejects_id_and_path_conflicts() {
        let project = project();

        let id_conflict = updated_projects("200123:/srv/external\n", &project).unwrap_err();
        let path_conflict = updated_projects("42:/srv/dbe/instances/one\n", &project).unwrap_err();

        assert_eq!(id_conflict.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(path_conflict.kind(), std::io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn projid_registry_rejects_id_and_name_conflicts() {
        let project = project();

        let id_conflict = updated_projid("external:200123\n", &project).unwrap_err();
        let name_conflict = updated_projid("dbe_200123:42\n", &project).unwrap_err();

        assert_eq!(id_conflict.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(name_conflict.kind(), std::io::ErrorKind::AlreadyExists);
    }

    #[cfg(unix)]
    #[test]
    fn project_file_updates_use_atomic_replacement_and_preserve_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("projects");
        std::fs::write(&path, "before\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let original_inode = std::fs::metadata(&path).unwrap().ino();

        atomic_replace_project_file(&path, "after\n").unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "after\n");
        assert_ne!(metadata.ino(), original_inode);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
    }

    #[cfg(unix)]
    #[test]
    fn advisory_lock_is_private_and_exclusive() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("project-files.lock");
        let lock = acquire_exclusive_lock(&path).unwrap();
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        assert_eq!(lock.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert!(
            rustix::fs::flock(
                &contender,
                rustix::fs::FlockOperation::NonBlockingLockExclusive,
            )
            .is_err()
        );
    }
}
