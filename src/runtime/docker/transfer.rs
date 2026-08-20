use std::{
    collections::VecDeque,
    io::{Error as IoError, ErrorKind, Read, Write},
    path::{Component, Path},
    time::Instant,
};

use bollard::{
    body_try_stream,
    query_parameters::{DownloadFromContainerOptionsBuilder, UploadToContainerOptionsBuilder},
};
use bytes::Bytes;
use futures::{Stream, StreamExt, TryStreamExt, stream};
use tokio_util::io::{ReaderStream, StreamReader, SyncIoBridge};

use super::{
    DockerError, DockerInstanceSpec, DockerRuntime, EXEC_OUTPUT_TRUNCATION_MARKER,
    FILE_TRANSFER_TIMEOUT, MAX_CONTAINER_TRANSFER_BYTES, MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL,
};
use crate::{runtime::docker::container_config::bind_mount, shared::protocol::Protocol};

impl DockerRuntime {
    pub async fn upload_file(
        &self,
        protocol: Protocol,
        instance_id: &str,
        host_path: &Path,
        container_path: &str,
    ) -> Result<(), DockerError> {
        let container = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let (container_parent, container_file_name) = container_file_parts(container_path)?;
        let metadata = tokio::fs::symlink_metadata(host_path)
            .await
            .map_err(|source| DockerError::FileTransferIo {
                path: host_path.display().to_string(),
                source,
            })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(DockerError::InvalidTransferSource {
                path: host_path.display().to_string(),
            });
        }
        if metadata.len() > MAX_CONTAINER_TRANSFER_BYTES {
            return Err(DockerError::FileTransferTooLarge {
                path: host_path.display().to_string(),
                size: metadata.len(),
                max_bytes: MAX_CONTAINER_TRANSFER_BYTES,
            });
        }

        let (uid, gid) = self
            .configured_container_user(protocol, instance_id)
            .await?
            .as_deref()
            .and_then(numeric_container_user)
            .unwrap_or((0, 0));

        let file = tokio::fs::File::open(host_path).await.map_err(|source| {
            DockerError::FileTransferIo {
                path: host_path.display().to_string(),
                source,
            }
        })?;
        let header = transfer_tar_header(&container_file_name, metadata.len(), uid, gid)?;
        let trailer_len = tar_padding(metadata.len()) + 1024;
        let stream = stream::once(async move { Ok::<Bytes, IoError>(header) })
            .chain(ReaderStream::new(tokio::io::AsyncReadExt::take(
                file,
                metadata.len(),
            )))
            .chain(stream::once(async move {
                Ok::<Bytes, IoError>(Bytes::from(vec![0_u8; trailer_len]))
            }));

        match tokio::time::timeout(
            FILE_TRANSFER_TIMEOUT,
            self.docker.upload_to_container(
                &container,
                Some(
                    UploadToContainerOptionsBuilder::default()
                        .path(&container_parent)
                        .no_overwrite_dir_non_dir("true")
                        .copy_uidgid("true")
                        .build(),
                ),
                body_try_stream(stream),
            ),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                return Err(DockerError::FileTransferTimedOut {
                    direction: "upload",
                    path: host_path.display().to_string(),
                    timeout_seconds: FILE_TRANSFER_TIMEOUT.as_secs(),
                });
            }
        }
        Ok(())
    }

    pub async fn download_file(
        &self,
        protocol: Protocol,
        instance_id: &str,
        container_path: &str,
        host_path: &Path,
    ) -> Result<(), DockerError> {
        self.download_file_bounded(
            protocol,
            instance_id,
            container_path,
            host_path,
            MAX_CONTAINER_TRANSFER_BYTES,
        )
        .await
    }

    pub async fn download_file_bounded(
        &self,
        protocol: Protocol,
        instance_id: &str,
        container_path: &str,
        host_path: &Path,
        max_bytes: u64,
    ) -> Result<(), DockerError> {
        let max_bytes = max_bytes.min(MAX_CONTAINER_TRANSFER_BYTES);
        let container = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let (_, expected_file_name) = container_file_parts(container_path)?;
        let async_deadline = tokio::time::Instant::now() + FILE_TRANSFER_TIMEOUT;
        let blocking_deadline = Instant::now() + FILE_TRANSFER_TIMEOUT;
        let stream = self
            .docker
            .download_from_container(
                &container,
                Some(
                    DownloadFromContainerOptionsBuilder::default()
                        .path(container_path)
                        .build(),
                ),
            )
            .map_err(IoError::other);
        let stream = stream_with_deadline(stream, async_deadline).boxed();
        let reader = StreamReader::new(stream);
        let bridge = SyncIoBridge::new(reader);
        let host_path = host_path.to_path_buf();
        let error_path = host_path.display().to_string();

        let result = tokio::task::spawn_blocking(move || {
            extract_single_regular_file_with_constraints(
                bridge,
                &expected_file_name,
                &host_path,
                max_bytes,
                blocking_deadline,
            )
        })
        .await
        .map_err(|error| DockerError::FileTransferTask(error.to_string()))?;
        match result {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == ErrorKind::TimedOut => {
                Err(DockerError::FileTransferTimedOut {
                    direction: "download",
                    path: error_path,
                    timeout_seconds: FILE_TRANSFER_TIMEOUT.as_secs(),
                })
            }
            Err(source) => Err(DockerError::FileTransferIo {
                path: error_path,
                source,
            }),
        }
    }
}

pub(super) fn container_mounts(spec: &DockerInstanceSpec) -> Vec<bollard::models::Mount> {
    let mut mounts = vec![
        bind_mount(&spec.data_path, &spec.data_target, false),
        bind_mount(&spec.logs_path, &spec.logs_target, false),
    ];
    mounts.extend(
        spec.extra_mounts
            .iter()
            .map(|mount| bind_mount(&mount.source, &mount.target, mount.read_only)),
    );
    mounts
}

pub(super) async fn ensure_bind_mount_sources(
    spec: &DockerInstanceSpec,
) -> Result<(), DockerError> {
    ensure_bind_mount_dir(&spec.data_path).await?;
    ensure_bind_mount_dir(&spec.logs_path).await?;
    for mount in &spec.extra_mounts {
        if mount.read_only {
            ensure_bind_mount_file(&mount.source).await?;
        } else {
            ensure_bind_mount_dir(&mount.source).await?;
        }
    }
    Ok(())
}

pub(super) async fn ensure_bind_mount_dir(path: &std::path::Path) -> Result<(), DockerError> {
    tokio::fs::create_dir_all(path)
        .await
        .map_err(|source| DockerError::MountSourceIo {
            path: path.display().to_string(),
            source,
        })?;
    let metadata =
        tokio::fs::symlink_metadata(path)
            .await
            .map_err(|source| DockerError::MountSourceIo {
                path: path.display().to_string(),
                source,
            })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DockerError::InvalidMountSource {
            path: path.display().to_string(),
            reason: "expected a real directory".to_string(),
        });
    }
    Ok(())
}

pub(super) async fn ensure_bind_mount_file(path: &std::path::Path) -> Result<(), DockerError> {
    let metadata =
        tokio::fs::symlink_metadata(path)
            .await
            .map_err(|source| DockerError::MountSourceIo {
                path: path.display().to_string(),
                source,
            })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DockerError::InvalidMountSource {
            path: path.display().to_string(),
            reason: "expected a real file".to_string(),
        });
    }
    Ok(())
}

pub(super) fn container_file_parts(container_path: &str) -> Result<(String, String), DockerError> {
    let path = Path::new(container_path);
    let valid = path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    let parent = path.parent().and_then(Path::to_str);
    let file_name = path.file_name().and_then(|value| value.to_str());
    match (valid, parent, file_name) {
        (true, Some(parent), Some(file_name)) if !file_name.is_empty() => {
            Ok((parent.to_string(), file_name.to_string()))
        }
        _ => Err(DockerError::InvalidContainerTransferPath {
            path: container_path.to_string(),
        }),
    }
}

pub(super) fn numeric_container_user(user: &str) -> Option<(u64, u64)> {
    let (uid, gid) = user.trim().split_once(':').unwrap_or((user.trim(), ""));
    let uid = uid.parse::<u64>().ok()?;
    let gid = if gid.is_empty() {
        uid
    } else {
        gid.parse::<u64>().ok()?
    };
    Some((uid, gid))
}

pub(super) fn transfer_tar_header(
    file_name: &str,
    size: u64,
    uid: u64,
    gid: u64,
) -> Result<Bytes, DockerError> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o600);
    header.set_uid(uid);
    header.set_gid(gid);
    header.set_mtime(0);
    header.set_size(size);
    header
        .set_path(file_name)
        .map_err(|source| DockerError::FileTransferIo {
            path: file_name.to_string(),
            source,
        })?;
    header.set_cksum();
    Ok(Bytes::copy_from_slice(header.as_bytes()))
}

pub(super) fn tar_padding(size: u64) -> usize {
    ((512 - (size % 512)) % 512) as usize
}

pub(super) fn stream_with_deadline<S>(
    source: S,
    deadline: tokio::time::Instant,
) -> impl Stream<Item = Result<Bytes, IoError>>
where
    S: Stream<Item = Result<Bytes, IoError>> + Unpin,
{
    stream::unfold((source, false), move |(mut source, finished)| async move {
        if finished {
            return None;
        }
        match tokio::time::timeout_at(deadline, source.next()).await {
            Ok(Some(Ok(bytes))) => Some((Ok(bytes), (source, false))),
            Ok(Some(Err(error))) => Some((Err(error), (source, true))),
            Ok(None) => None,
            Err(_) => Some((
                Err(IoError::new(
                    ErrorKind::TimedOut,
                    "container file transfer exceeded time limit",
                )),
                (source, true),
            )),
        }
    })
}

#[cfg(test)]
pub(super) fn extract_single_regular_file<R: Read>(
    reader: R,
    expected_file_name: &str,
    host_path: &Path,
) -> Result<(), IoError> {
    extract_single_regular_file_with_limit(
        reader,
        expected_file_name,
        host_path,
        MAX_CONTAINER_TRANSFER_BYTES,
    )
}

#[cfg(test)]
pub(super) fn extract_single_regular_file_with_limit<R: Read>(
    reader: R,
    expected_file_name: &str,
    host_path: &Path,
    max_bytes: u64,
) -> Result<(), IoError> {
    extract_single_regular_file_with_constraints(
        reader,
        expected_file_name,
        host_path,
        max_bytes,
        Instant::now() + FILE_TRANSFER_TIMEOUT,
    )
}

pub(super) fn extract_single_regular_file_with_constraints<R: Read>(
    reader: R,
    expected_file_name: &str,
    host_path: &Path,
    max_bytes: u64,
    deadline: Instant,
) -> Result<(), IoError> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let parent = host_path
        .parent()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "download target has no parent"))?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "download target parent must be a real directory",
        ));
    }

    let mut created_path = false;
    let result = (|| {
        let mut archive = tar::Archive::new(reader);
        let mut extracted = false;
        for entry in archive.entries()? {
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "container download contained a non-file entry",
                ));
            }
            let entry_path = entry.path()?;
            let safe_path = entry_path
                .components()
                .all(|component| matches!(component, Component::CurDir | Component::Normal(_)));
            if !safe_path
                || entry_path.file_name().and_then(|value| value.to_str())
                    != Some(expected_file_name)
                || extracted
            {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "container download contained an unexpected archive path",
                ));
            }

            let expected_size = entry.header().size()?;
            if expected_size > max_bytes {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    format!("container download exceeds the configured {max_bytes}-byte limit"),
                ));
            }
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut output = options.open(host_path)?;
            created_path = true;
            let copied = copy_download_entry(&mut entry, &mut output, max_bytes, deadline)?;
            if copied != expected_size {
                return Err(IoError::new(
                    ErrorKind::UnexpectedEof,
                    "container download ended before the declared file size",
                ));
            }
            ensure_file_transfer_deadline(deadline)?;
            output.flush()?;
            output.sync_all()?;
            ensure_file_transfer_deadline(deadline)?;
            extracted = true;
        }
        if !extracted {
            return Err(IoError::new(
                ErrorKind::NotFound,
                "container download did not contain the requested file",
            ));
        }
        Ok(())
    })();

    if result.is_err() && created_path {
        let _ = std::fs::remove_file(host_path);
    }
    result
}

pub(super) fn copy_download_entry<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    max_bytes: u64,
    deadline: Instant,
) -> Result<u64, IoError> {
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        ensure_file_transfer_deadline(deadline)?;
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(copied);
        }
        copied = copied.checked_add(read as u64).ok_or_else(|| {
            IoError::new(ErrorKind::InvalidData, "container download size overflow")
        })?;
        if copied > max_bytes {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!("container download exceeds the configured {max_bytes}-byte limit"),
            ));
        }
        writer.write_all(&buffer[..read])?;
    }
}

pub(super) fn ensure_file_transfer_deadline(deadline: Instant) -> Result<(), IoError> {
    if Instant::now() >= deadline {
        return Err(IoError::new(
            ErrorKind::TimedOut,
            "container file transfer exceeded time limit",
        ));
    }
    Ok(())
}

#[derive(Default)]
pub(super) struct CappedExecOutput {
    bytes: VecDeque<u8>,
    truncated: bool,
}

impl CappedExecOutput {
    pub(super) fn append(&mut self, chunk: &[u8]) {
        if chunk.len() >= MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL {
            let discarded_output = self.truncated
                || !self.bytes.is_empty()
                || chunk.len() > MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL;
            self.bytes.clear();
            self.bytes.extend(
                chunk[chunk.len() - MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL..]
                    .iter()
                    .copied(),
            );
            self.truncated = discarded_output;
            return;
        }

        let overflow = self
            .bytes
            .len()
            .saturating_add(chunk.len())
            .saturating_sub(MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL);
        if overflow > 0 {
            self.bytes.drain(..overflow);
            self.truncated = true;
        }
        self.bytes.extend(chunk.iter().copied());
    }

    pub(super) fn into_string(self) -> String {
        let bytes: Vec<u8> = self.bytes.into_iter().collect();
        let retained = String::from_utf8_lossy(&bytes);
        if self.truncated {
            format!("{EXEC_OUTPUT_TRUNCATION_MARKER}{retained}")
        } else {
            retained.into_owned()
        }
    }
}
