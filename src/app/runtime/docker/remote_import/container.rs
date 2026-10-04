use crate::{
    runtime::docker::{
        container_config::{bind_mount, cpu_to_nano, disabled_healthcheck, mib_to_bytes},
        error::DockerError,
        remote_import::{
            HELPER_CLEANUP_TIMEOUT, HELPER_CPU_CORES, HELPER_LABEL, HELPER_MEMORY_MIB,
            HELPER_NAME_PREFIX, HELPER_NAME_SUFFIX_LEN, HELPER_PIDS_LIMIT,
            HELPER_STOP_TIMEOUT_SECONDS, HELPER_TMPFS, HELPER_WORK_DIR, IMPORT_HELPER_INPUT_PATH,
            RemoteImportHelperSpec, ResolvedHelperNetwork, cancellation::HelperCancellation,
        },
        security::DockerSecurityPolicy,
    },
    utils::constants::docker::{MANAGED_LABEL, NODE_LABEL},
};
use bollard::{
    Docker,
    errors::Error as BollardError,
    models::{ContainerCreateBody, HostConfig, HostConfigLogConfig},
    query_parameters::RemoveContainerOptions,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

pub(super) async fn run_unless_cancelled<T>(
    cancellation: &HelperCancellation,
    operation: impl Future<Output = Result<T, DockerError>>,
) -> Result<T, DockerError> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(DockerError::RemoteImportHelperCancelled),
        result = operation => result,
    }
}

pub(super) async fn chown_work_directory(
    work_dir: PathBuf,
    uid: u32,
    gid: u32,
) -> Result<(), DockerError> {
    tokio::task::spawn_blocking(move || {
        crate::io::ownership::chown_recursive(
            &work_dir,
            crate::io::ownership::HostOwner { uid, gid },
        )
        .map_err(|source| DockerError::RemoteImportHelperIo {
            path: work_dir.display().to_string(),
            source,
        })
    })
    .await
    .map_err(|error| DockerError::RemoteImportHelperTask(error.to_string()))?
}

pub(super) fn ensure_output_within_limit(size: u64, max_bytes: u64) -> Result<(), DockerError> {
    if size > max_bytes {
        return Err(DockerError::RemoteImportHelperOutputTooLarge { size, max_bytes });
    }
    Ok(())
}

pub(super) async fn remove_import_helper(
    docker: &Docker,
    name_or_id: &str,
) -> Result<(), DockerError> {
    let remove = docker.remove_container(
        name_or_id,
        Some(RemoveContainerOptions {
            v: true,
            force: true,
            ..Default::default()
        }),
    );
    match tokio::time::timeout(HELPER_CLEANUP_TIMEOUT, remove).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(BollardError::DockerResponseServerError {
            status_code: 404, ..
        })) => Ok(()),
        Ok(Err(source)) => Err(DockerError::RemoteImportHelperCleanupFailed {
            container: name_or_id.to_string(),
            source,
        }),
        Err(_) => Err(DockerError::RemoteImportHelperCleanupTimedOut {
            container: name_or_id.to_string(),
            timeout_seconds: HELPER_CLEANUP_TIMEOUT.as_secs(),
        }),
    }
}

pub(super) fn is_owned_import_helper(
    labels: Option<&HashMap<String, String>>,
    names: Option<&[String]>,
    expected_node_id: &str,
) -> bool {
    labels.and_then(|labels| labels.get(HELPER_LABEL).map(String::as_str)) == Some("true")
        && labels.and_then(|labels| labels.get(NODE_LABEL).map(String::as_str))
            == Some(expected_node_id)
        && names.is_some_and(|names| names.iter().any(|name| is_import_helper_name(name)))
}

pub(super) fn is_import_helper_name(name: &str) -> bool {
    let normalized = name.strip_prefix('/').unwrap_or(name);
    let Some(suffix) = normalized.strip_prefix(HELPER_NAME_PREFIX) else {
        return false;
    };
    suffix.len() == HELPER_NAME_SUFFIX_LEN
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) struct ImportHelperCreateOptions<'a> {
    pub(super) spec: &'a RemoteImportHelperSpec,
    pub(super) work_dir: &'a Path,
    pub(super) input_path: Option<&'a Path>,
    pub(super) network: &'a ResolvedHelperNetwork,
    pub(super) environment: Vec<String>,
    pub(super) security: &'a DockerSecurityPolicy,
    pub(super) rootless_podman: bool,
    pub(super) node_id: &'a str,
}

pub(super) fn import_helper_body(options: ImportHelperCreateOptions<'_>) -> ContainerCreateBody {
    let ImportHelperCreateOptions {
        spec,
        work_dir,
        input_path,
        network,
        environment,
        security,
        rootless_podman,
        node_id,
    } = options;
    let mut mounts = vec![bind_mount(
        work_dir,
        HELPER_WORK_DIR,
        spec.read_only_work_dir,
    )];
    if let Some(input_path) = input_path {
        mounts.push(bind_mount(input_path, IMPORT_HELPER_INPUT_PATH, true));
    }
    let mut host_config = HostConfig {
        network_mode: Some(network.mode.clone()),
        nano_cpus: cpu_to_nano(HELPER_CPU_CORES),
        memory: mib_to_bytes(HELPER_MEMORY_MIB),
        memory_swap: mib_to_bytes(HELPER_MEMORY_MIB),
        pids_limit: Some(HELPER_PIDS_LIMIT),
        mounts: Some(mounts.clone()),
        tmpfs: Some(HashMap::from([(
            "/tmp".to_string(),
            HELPER_TMPFS.to_string(),
        )])),
        extra_hosts: (!spec.extra_hosts.is_empty()).then(|| spec.extra_hosts.clone()),
        log_config: Some(HostConfigLogConfig {
            typ: Some("none".to_string()),
            config: None,
        }),
        auto_remove: Some(true),
        port_bindings: None,
        ..Default::default()
    };
    security.apply(&mut host_config);
    if rootless_podman {
        // The helper runs as container uid/gid 0 while its private work
        // directory is owned by the rootless Podman service account.
        host_config.userns_mode = Some("host".to_string());
    }

    // These helper-specific limits are deliberately stricter than configurable
    // managed-database defaults.
    host_config.network_mode = Some(network.mode.clone());
    host_config.nano_cpus = cpu_to_nano(HELPER_CPU_CORES);
    host_config.memory = mib_to_bytes(HELPER_MEMORY_MIB);
    host_config.memory_swap = mib_to_bytes(HELPER_MEMORY_MIB);
    host_config.pids_limit = Some(HELPER_PIDS_LIMIT);
    host_config.readonly_rootfs = Some(true);
    host_config.mounts = Some(mounts);
    host_config.tmpfs = Some(HashMap::from([(
        "/tmp".to_string(),
        HELPER_TMPFS.to_string(),
    )]));
    host_config.extra_hosts = (!spec.extra_hosts.is_empty()).then(|| spec.extra_hosts.clone());
    host_config.log_config = Some(HostConfigLogConfig {
        typ: Some("none".to_string()),
        config: None,
    });
    host_config.auto_remove = Some(true);
    host_config.port_bindings = None;
    host_config.privileged = Some(false);
    host_config.cap_add = None;
    host_config.cap_drop = Some(vec!["ALL".to_string()]);
    host_config.devices = Some(Vec::new());
    let security_opts = host_config.security_opt.get_or_insert_default();
    if !security_opts
        .iter()
        .any(|option| option == "no-new-privileges")
    {
        security_opts.push("no-new-privileges".to_string());
    }

    ContainerCreateBody {
        image: Some(spec.image.clone()),
        user: Some("0:0".to_string()),
        working_dir: Some(HELPER_WORK_DIR.to_string()),
        entrypoint: Some(vec!["/bin/sh".to_string()]),
        cmd: Some(vec!["-c".to_string(), spec.script.clone()]),
        env: Some(
            std::iter::once("HOME=/tmp".to_string())
                .chain(environment)
                .collect(),
        ),
        labels: Some(HashMap::from([
            (HELPER_LABEL.to_string(), "true".to_string()),
            (MANAGED_LABEL.to_string(), "false".to_string()),
            (NODE_LABEL.to_string(), node_id.to_string()),
        ])),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        attach_stdin: Some(false),
        open_stdin: Some(false),
        stdin_once: Some(false),
        tty: Some(false),
        stop_timeout: Some(HELPER_STOP_TIMEOUT_SECONDS),
        healthcheck: Some(disabled_healthcheck()),
        host_config: Some(host_config),
        exposed_ports: None,
        ..Default::default()
    }
}
