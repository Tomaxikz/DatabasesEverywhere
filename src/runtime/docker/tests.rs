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
    let body = DockerRuntime::update_limits_body(2.0, 2048);

    assert_eq!(body.nano_cpus, Some(2_000_000_000));
    assert_eq!(body.memory, Some(2048 * 1024 * 1024));
    assert_eq!(body.memory_swap, body.memory);
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
