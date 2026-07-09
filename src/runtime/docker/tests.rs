use std::path::PathBuf;

use secrecy::SecretString;

use super::*;

#[test]
fn create_body_does_not_publish_backend_ports_by_default() {
    let runtime = test_runtime(false);
    let body = runtime.create_body(&postgres_spec()).unwrap();
    let host_config = body.host_config.unwrap();

    assert!(host_config.port_bindings.is_none());
    assert!(body.exposed_ports.is_none());
    assert_eq!(
        host_config.network_mode,
        Some("databases-everywhere".to_string())
    );
}

#[test]
fn create_body_includes_limits_labels_and_security() {
    let runtime = test_runtime(false);
    let body = runtime.create_body(&postgres_spec()).unwrap();
    let host_config = body.host_config.unwrap();
    let labels = body.labels.unwrap();

    assert_eq!(host_config.nano_cpus, Some(1_000_000_000));
    assert_eq!(host_config.memory, Some(512 * 1024 * 1024));
    assert_eq!(
        host_config
            .storage_opt
            .as_ref()
            .and_then(|opts| opts.get("size")),
        Some(&"10240m".to_string())
    );
    assert_eq!(
        labels.get("databases-everywhere.managed"),
        Some(&"true".to_string())
    );
    assert_eq!(host_config.privileged, Some(false));
    assert_eq!(host_config.cap_drop, Some(vec!["ALL".to_string()]));
    assert_eq!(
        host_config.security_opt,
        Some(vec!["no-new-privileges".to_string()])
    );
}

#[test]
fn existing_network_must_match_internal_setting() {
    let runtime = test_runtime(false);
    let error = runtime
        .validate_existing_network(&NetworkInspect {
            internal: Some(false),
            ..Default::default()
        })
        .unwrap_err();

    assert!(matches!(error, DockerError::InvalidNetworkSecurity { .. }));
}

#[test]
fn existing_network_without_internal_flag_defaults_to_non_internal() {
    let runtime = DockerRuntime::with_client(
        Docker::connect_with_local_defaults().unwrap(),
        crate::config::DaemonEngine::Docker,
        "auto",
        "databases-everywhere",
        false,
        Default::default(),
        false,
        true,
        DockerSecurityPolicy::default(),
    );

    runtime
        .validate_existing_network(&NetworkInspect {
            internal: None,
            ..Default::default()
        })
        .unwrap();
}

#[test]
fn create_body_allows_database_specific_pids_limit() {
    let runtime = test_runtime(false);
    let mut spec = postgres_spec();
    spec.pids_limit = Some(4096);
    let body = runtime.create_body(&spec).unwrap();

    assert_eq!(body.host_config.unwrap().pids_limit, Some(4096));
}

#[test]
fn create_body_uses_database_specific_mount_target() {
    let runtime = test_runtime(false);
    let body = runtime.create_body(&postgres_spec()).unwrap();
    let mounts = body.host_config.unwrap().mounts.unwrap();

    assert!(mounts.iter().any(|mount| {
        mount.target.as_deref() == Some("/var/lib/postgresql")
            && mount
                .source
                .as_deref()
                .unwrap_or_default()
                .ends_with("/data")
    }));
}

#[test]
fn podman_create_body_omits_docker_healthcheck() {
    let runtime = test_runtime_with_engine(
        crate::config::DaemonEngine::Podman,
        "/run/user/1000/podman/podman.sock",
        false,
    );
    let body = runtime.create_body(&postgres_spec()).unwrap();

    assert!(body.healthcheck.is_none());
}

#[tokio::test]
async fn create_preflight_creates_missing_managed_mount_dirs() {
    let temp = tempfile::tempdir().unwrap();
    let mut spec = postgres_spec();
    spec.data_path = temp.path().join("volumes").join("inst_abc");
    spec.logs_path = temp.path().join("logs").join("instances").join("inst_abc");

    ensure_bind_mount_sources(&spec).await.unwrap();

    assert!(spec.data_path.is_dir());
    assert!(spec.logs_path.is_dir());
}

#[tokio::test]
async fn create_preflight_rejects_missing_read_only_file_mount() {
    let temp = tempfile::tempdir().unwrap();
    let mut spec = postgres_spec();
    spec.data_path = temp.path().join("volumes").join("inst_abc");
    spec.logs_path = temp.path().join("logs").join("instances").join("inst_abc");
    spec.extra_mounts.push(DockerMount {
        source: temp.path().join("missing-config.xml"),
        target: "/etc/service/config.xml".to_string(),
        read_only: true,
    });

    let error = ensure_bind_mount_sources(&spec).await.unwrap_err();

    assert!(matches!(error, DockerError::MountSourceIo { .. }));
}

#[test]
fn rootless_podman_is_detected_from_user_socket() {
    let runtime = test_runtime_with_engine(
        crate::config::DaemonEngine::Podman,
        "/run/user/1000/podman/podman.sock",
        false,
    );
    let rootful = test_runtime_with_engine(
        crate::config::DaemonEngine::Podman,
        "/run/podman/podman.sock",
        false,
    );

    assert!(runtime.uses_rootless_podman());
    assert!(!rootful.uses_rootless_podman());
}

#[test]
fn rootless_podman_uses_protocol_specific_users() {
    let runtime = test_runtime_with_engine(
        crate::config::DaemonEngine::Podman,
        "/run/user/1000/podman/podman.sock",
        false,
    );

    assert_eq!(
        runtime.rootless_podman_container_user(Protocol::Postgres),
        Some("999:999")
    );
    assert_eq!(
        runtime.rootless_podman_container_user(Protocol::Mariadb),
        Some("999:999")
    );
    assert_eq!(
        runtime.rootless_podman_container_user(Protocol::Mongodb),
        Some("999:999")
    );
    assert_eq!(
        runtime.rootless_podman_container_user(Protocol::Redis),
        Some("0:0")
    );
}

#[test]
fn rootless_podman_publishes_private_backend_port() {
    let runtime = test_runtime_with_engine(
        crate::config::DaemonEngine::Podman,
        "/run/user/1000/podman/podman.sock",
        false,
    );
    let mut spec = postgres_spec();
    spec.public_backend_port = Some(29123);
    let body = runtime.create_body(&spec).unwrap();
    let host_config = body.host_config.unwrap();
    let bindings = host_config.port_bindings.unwrap();
    let binding = bindings
        .get("5432/tcp")
        .and_then(|bindings| bindings.as_ref())
        .and_then(|bindings| bindings.first())
        .unwrap();

    assert_eq!(binding.host_ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(binding.host_port.as_deref(), Some("29123"));
}

#[test]
fn rootless_podman_sets_keep_id_for_postgres_like_images() {
    let runtime = test_runtime_with_engine(
        crate::config::DaemonEngine::Podman,
        "/run/user/1000/podman/podman.sock",
        false,
    );
    let body = runtime.create_body(&postgres_spec()).unwrap();

    assert_eq!(
        body.host_config.unwrap().userns_mode.as_deref(),
        Some("keep-id:uid=999,gid=999")
    );
}

#[test]
fn unsafe_instance_id_is_rejected() {
    let runtime = test_runtime(false);
    let mut spec = postgres_spec();
    spec.instance_id = "../bad".to_string();

    let error = runtime
        .container_name(spec.protocol, &spec.instance_id)
        .unwrap_err();

    assert!(matches!(error, DockerError::InvalidId(_)));
}

#[test]
fn update_limits_body_uses_docker_api_units() {
    let body = DockerRuntime::update_limits_body(2.0, 2048).unwrap();

    assert_eq!(body.nano_cpus, Some(2_000_000_000));
    assert_eq!(body.memory, Some(2048 * 1024 * 1024));
    assert_eq!(body.memory_swap, body.memory);
}

#[test]
fn docker_limit_conversion_rejects_overflow_and_non_finite_cpu() {
    assert_eq!(mib_to_bytes(1_u64 << 44), None);
    assert_eq!(cpu_to_nano(f64::NAN), None);
    assert_eq!(cpu_to_nano(f64::INFINITY), None);

    let memory_error = DockerRuntime::update_limits_body(1.0, 1_u64 << 44).unwrap_err();
    assert!(matches!(memory_error, DockerError::ResourceLimit(_)));

    let cpu_error = DockerRuntime::update_limits_body(f64::INFINITY, 1024).unwrap_err();
    assert!(matches!(cpu_error, DockerError::ResourceLimit(_)));
}

#[test]
fn docker_byte_conversion_checks_i64_boundary() {
    const BYTES_PER_MIB: u64 = 1024 * 1024;
    let largest_mib = (i64::MAX as u64) / BYTES_PER_MIB;

    assert_eq!(
        mib_to_bytes(largest_mib),
        Some((largest_mib * BYTES_PER_MIB) as i64)
    );
    assert_eq!(mib_to_bytes(largest_mib + 1), None);
}

#[test]
fn transfer_archive_preserves_private_numeric_ownership() {
    let bytes = transfer_tar_header("dump.sql", 12, 1001, 1002).unwrap();
    let header = tar::Header::from_byte_slice(&bytes);

    assert_eq!(header.path().unwrap(), std::path::Path::new("dump.sql"));
    assert_eq!(header.size().unwrap(), 12);
    assert_eq!(header.mode().unwrap(), 0o600);
    assert_eq!(header.uid().unwrap(), 1001);
    assert_eq!(header.gid().unwrap(), 1002);
    assert_eq!(numeric_container_user("1001:1002"), Some((1001, 1002)));
    assert_eq!(numeric_container_user("1001"), Some((1001, 1001)));
    assert_eq!(numeric_container_user("postgres"), None);
}

#[test]
fn managed_container_verification_requires_the_exact_ownership_tuple() {
    let container = "dbe-postgres-inst_test";
    let mut labels = HashMap::from([
        (MANAGED_LABEL.to_string(), "true".to_string()),
        (INSTANCE_LABEL.to_string(), "inst_test".to_string()),
        (PROTOCOL_LABEL.to_string(), "postgres".to_string()),
    ]);

    verify_managed_instance_labels(&labels, container, Protocol::Postgres, "inst_test").unwrap();

    labels.insert(PROTOCOL_LABEL.to_string(), "redis".to_string());
    let error = verify_managed_instance_labels(&labels, container, Protocol::Postgres, "inst_test")
        .unwrap_err();
    assert!(matches!(
        error,
        DockerError::UntrustedContainerNameCollision { .. }
    ));

    labels.remove(MANAGED_LABEL);
    assert!(
        verify_managed_instance_labels(&labels, container, Protocol::Postgres, "inst_test")
            .is_err()
    );
}

#[test]
fn container_download_does_not_delete_an_existing_target() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("dump.sql");
    std::fs::write(&target, b"existing").unwrap();
    let archive = single_file_archive("dump.sql", b"replacement");

    assert!(
        extract_single_regular_file(std::io::Cursor::new(archive), "dump.sql", &target).is_err()
    );
    assert_eq!(std::fs::read(target).unwrap(), b"existing");
}

#[cfg(unix)]
#[test]
fn container_download_creates_a_private_regular_file() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("dump.sql");
    let archive = single_file_archive("dump.sql", b"contents");

    extract_single_regular_file(std::io::Cursor::new(archive), "dump.sql", &target).unwrap();

    assert_eq!(std::fs::read(&target).unwrap(), b"contents");
    assert_eq!(
        std::fs::metadata(target).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn container_download_rejects_entries_over_the_byte_limit_without_partial_output() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("dump.sql");
    let archive = single_file_archive("dump.sql", b"too-large");

    let error = extract_single_regular_file_with_limit(
        std::io::Cursor::new(archive),
        "dump.sql",
        &target,
        4,
    )
    .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("4-byte limit"));
    assert!(!target.exists());
}

#[test]
fn container_download_deadline_removes_partial_output() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("dump.sql");
    let archive = single_file_archive("dump.sql", b"contents");

    let error = extract_single_regular_file_with_constraints(
        std::io::Cursor::new(archive),
        "dump.sql",
        &target,
        MAX_CONTAINER_TRANSFER_BYTES,
        Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
    )
    .unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(!target.exists());
}

#[tokio::test]
async fn container_download_stream_emits_timeout_at_deadline() {
    let source = futures::stream::pending::<Result<Bytes, IoError>>();
    let mut stream = Box::pin(stream_with_deadline(source, tokio::time::Instant::now()));

    let error = stream.next().await.unwrap().unwrap_err();

    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert!(stream.next().await.is_none());
}

#[test]
fn docker_exec_output_retains_a_bounded_marked_tail() {
    let mut output = CappedExecOutput::default();
    let full_buffer = vec![b'a'; MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL];
    output.append(&full_buffer);
    output.append(b"important-tail");

    let output = output.into_string();

    assert!(output.starts_with(EXEC_OUTPUT_TRUNCATION_MARKER));
    assert!(output.ends_with("important-tail"));
    assert_eq!(
        output.len(),
        EXEC_OUTPUT_TRUNCATION_MARKER.len() + MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL
    );
}

fn single_file_archive(path: &str, contents: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut archive = tar::Builder::new(&mut bytes);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o600);
        header.set_size(contents.len() as u64);
        header.set_cksum();
        archive.append_data(&mut header, path, contents).unwrap();
        archive.finish().unwrap();
    }
    bytes
}

fn test_runtime(allow_public_backend_ports: bool) -> DockerRuntime {
    test_runtime_with_engine(
        crate::config::DaemonEngine::Docker,
        "auto",
        allow_public_backend_ports,
    )
}

fn test_runtime_with_engine(
    engine: crate::config::DaemonEngine,
    socket_path: &str,
    allow_public_backend_ports: bool,
) -> DockerRuntime {
    DockerRuntime::with_client(
        Docker::connect_with_local_defaults().unwrap(),
        engine,
        socket_path,
        "databases-everywhere",
        true,
        Default::default(),
        allow_public_backend_ports,
        true,
        DockerSecurityPolicy::default(),
    )
}

fn postgres_spec() -> DockerInstanceSpec {
    DockerInstanceSpec {
        instance_id: "inst_abc".to_string(),
        protocol: Protocol::Postgres,
        image: "postgres:18.4".to_string(),
        project_id: Some("project_1".to_string()),
        user: None,
        working_dir: None,
        entrypoint: None,
        cpu_cores: 1.0,
        memory_mib: 512,
        disk_mib: 10240,
        pids_limit: None,
        container_port: 5432,
        public_backend_port: None,
        data_path: PathBuf::from("/var/lib/databases-everywhere/instances/inst_abc/data"),
        data_target: "/var/lib/postgresql".to_string(),
        logs_path: PathBuf::from("/var/log/databases-everywhere/instances/inst_abc"),
        logs_target: "/logs".to_string(),
        extra_mounts: Vec::new(),
        env: vec![DockerEnv {
            key: "POSTGRES_PASSWORD".to_string(),
            value: SecretString::from("super-secret"),
        }],
        command: Vec::new(),
    }
}
