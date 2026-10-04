use std::path::{Path, PathBuf};

use secrecy::ExposeSecret;

use crate::runtime::docker::{
    engine::is_rootless_podman_socket,
    error::DockerError,
    remote_import::{
        ImportHelperInput, ImportHelperNetwork, MAX_EXTRA_HOST_BYTES, MAX_EXTRA_HOSTS,
        MAX_HELPER_ENVIRONMENT_BYTES, MAX_HELPER_ENVIRONMENT_ENTRIES, MAX_HELPER_SCRIPT_BYTES,
        RemoteImportHelperSpec, output::invalid_helper_spec,
    },
    stream_exec::{encode_secrets, open_private_input, verify_private_input},
};

pub(super) async fn validate_helper_spec(
    spec: &RemoteImportHelperSpec,
) -> Result<PathBuf, DockerError> {
    if spec.image.trim().is_empty() {
        return Err(invalid_helper_spec("image must not be empty"));
    }
    if spec.script.trim().is_empty() {
        return Err(invalid_helper_spec("script must not be empty"));
    }
    if spec.script.len() > MAX_HELPER_SCRIPT_BYTES {
        return Err(invalid_helper_spec(format!(
            "script exceeds {MAX_HELPER_SCRIPT_BYTES} bytes"
        )));
    }
    if spec.script.contains('\0') {
        return Err(invalid_helper_spec("script must not contain NUL"));
    }
    if spec.timeout.is_zero() {
        return Err(invalid_helper_spec("timeout must be greater than zero"));
    }
    if spec.max_output_bytes == 0 {
        return Err(invalid_helper_spec(
            "max_output_bytes must be greater than zero",
        ));
    }
    if spec.extra_hosts.len() > MAX_EXTRA_HOSTS {
        return Err(invalid_helper_spec(format!(
            "extra_hosts may contain at most {MAX_EXTRA_HOSTS} entries"
        )));
    }
    if !spec
        .extra_hosts
        .iter()
        .all(|entry| is_valid_extra_host(entry))
    {
        return Err(invalid_helper_spec("extra_hosts contains an invalid entry"));
    }
    match &spec.network {
        ImportHelperNetwork::Outbound => {}
        ImportHelperNetwork::ManagedRuntime { runtime_id, .. } => {
            if runtime_id.trim().is_empty() {
                return Err(invalid_helper_spec("managed runtime id must not be empty"));
            }
            if !spec.extra_hosts.is_empty() {
                return Err(invalid_helper_spec(
                    "managed-runtime helpers cannot inject extra hosts",
                ));
            }
        }
    }
    if !spec.work_dir.is_absolute() {
        return Err(invalid_helper_spec("work_dir must be absolute"));
    }
    if has_parent_component(&spec.work_dir) {
        return Err(invalid_helper_spec(
            "work_dir must not contain parent components",
        ));
    }

    let metadata = tokio::fs::symlink_metadata(&spec.work_dir)
        .await
        .map_err(|source| DockerError::RemoteImportHelperIo {
            path: spec.work_dir.display().to_string(),
            source,
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid_helper_spec(
            "work_dir must be a real existing directory",
        ));
    }
    let canonical = tokio::fs::canonicalize(&spec.work_dir)
        .await
        .map_err(|source| DockerError::RemoteImportHelperIo {
            path: spec.work_dir.display().to_string(),
            source,
        })?;
    if forbidden_helper_mount(&canonical) {
        return Err(invalid_helper_spec(format!(
            "work_dir {} is too broad or security-sensitive",
            canonical.display()
        )));
    }
    Ok(canonical)
}

pub(super) fn is_valid_extra_host(entry: &str) -> bool {
    !entry.is_empty()
        && entry.len() <= MAX_EXTRA_HOST_BYTES
        && !entry.chars().any(char::is_control)
        && (entry.contains(':') || entry.contains('='))
}

pub(super) fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
}

pub(super) fn validate_helper_environment(
    spec: &RemoteImportHelperSpec,
) -> Result<(Vec<String>, Vec<String>), DockerError> {
    if spec.environment.len() > MAX_HELPER_ENVIRONMENT_ENTRIES {
        return Err(invalid_helper_spec(format!(
            "helper environment may contain at most {MAX_HELPER_ENVIRONMENT_ENTRIES} entries"
        )));
    }
    if spec.environment.iter().any(|entry| entry.key == "HOME") {
        return Err(invalid_helper_spec(
            "helper environment must not replace HOME",
        ));
    }
    let references = spec
        .environment
        .iter()
        .map(|entry| (entry.key.as_str(), &entry.value))
        .collect::<Vec<_>>();
    let encoded = encode_secrets(&references)?;
    let encoded_bytes = encoded
        .iter()
        .try_fold(0_usize, |total, value| total.checked_add(value.len() + 1));
    if encoded_bytes.is_none_or(|bytes| bytes > MAX_HELPER_ENVIRONMENT_BYTES) {
        return Err(invalid_helper_spec(format!(
            "helper environment exceeds {MAX_HELPER_ENVIRONMENT_BYTES} bytes"
        )));
    }
    let mut secret_values = spec
        .environment
        .iter()
        .map(|entry| entry.value.expose_secret().to_string())
        .collect::<Vec<_>>();
    if secret_values.iter().any(String::is_empty) {
        return Err(invalid_helper_spec(
            "helper environment values must not be empty",
        ));
    }
    if secret_values
        .iter()
        .any(|secret| spec.script.contains(secret))
    {
        return Err(invalid_helper_spec(
            "helper script must not contain environment secrets",
        ));
    }
    secret_values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    secret_values.dedup();
    Ok((encoded, secret_values))
}

pub(super) async fn validate_helper_input(
    input: Option<&ImportHelperInput>,
) -> Result<Option<PathBuf>, DockerError> {
    let Some(input) = input else {
        return Ok(None);
    };
    if !input.path.is_absolute() || has_parent_component(&input.path) {
        return Err(invalid_helper_spec(
            "helper input must be an absolute path without parent components",
        ));
    }
    let canonical = tokio::fs::canonicalize(&input.path)
        .await
        .map_err(|source| DockerError::RemoteImportHelperIo {
            path: input.path.display().to_string(),
            source,
        })?;
    if forbidden_helper_mount(&canonical) {
        return Err(invalid_helper_spec(format!(
            "helper input {} is security-sensitive",
            canonical.display()
        )));
    }
    let (mut file, bytes) = open_private_input(&canonical, input.size_bytes)?;
    if bytes != input.size_bytes {
        return Err(invalid_helper_spec(
            "helper input size changed after inspection",
        ));
    }
    verify_private_input(&mut file, bytes, input.size_bytes, input.sha256)
        .await
        .map_err(|source| DockerError::RemoteImportHelperIo {
            path: canonical.display().to_string(),
            source,
        })?;
    Ok(Some(canonical))
}

pub(super) fn forbidden_helper_mount(path: &Path) -> bool {
    if path.parent().is_none() {
        return true;
    }
    [
        "/etc",
        "/proc",
        "/sys",
        "/dev",
        "/root",
        "/run/docker.sock",
        "/var/run/docker.sock",
        "/run/podman/podman.sock",
        "/var/run/podman/podman.sock",
    ]
    .iter()
    .any(|forbidden| path == Path::new(forbidden) || path.starts_with(forbidden))
        || is_rootless_podman_socket(path)
}
