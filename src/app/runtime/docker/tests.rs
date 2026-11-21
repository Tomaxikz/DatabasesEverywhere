use std::{
    collections::HashMap,
    io::{Error as IoError, ErrorKind},
    path::PathBuf,
    time::Instant,
};

use bytes::Bytes;
use futures::StreamExt;

use super::{
    transfer::{
        ensure_bind_mount_sources, extract_one_file, extract_one_file_until,
        extract_one_file_with_limit, numeric_container_user, stream_with_deadline,
        transfer_tar_header,
    },
    *,
};
use crate::{
    runtime::docker::{
        container_config::{cpu_to_nano, mib_to_bytes},
        helpers::{
            is_owned_managed_container, managed_container_filters, verify_managed_instance_labels,
        },
    },
    utils::constants::docker::{INSTANCE_LABEL, MANAGED_LABEL, NODE_LABEL, PROTOCOL_LABEL},
};

#[test]
fn create_body_does_not_publish_backend_ports_by_default() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let rootless_podman = test_runtime_with_engine(
        crate::config::DaemonEngine::Podman,
        "/run/user/1000/podman/podman.sock",
    );
    for runtime in [test_runtime(), rootless_podman] {
        let body = runtime.create_body(&postgres_spec())?;
        let host_config = body.host_config.context(
            "create body does not publish backend ports by default should provide a value",
        )?;

        assert!(host_config.port_bindings.is_none());
        assert!(body.exposed_ports.is_none());
        assert_eq!(host_config.network_mode, Some("none".to_string()));
        assert_eq!(body.stop_timeout, Some(30));
    }

    Ok(())
}

#[test]
fn every_database_uses_one_bounded_console_history_without_log_binds() -> anyhow::Result<()> {
    use anyhow::Context as _;

    use crate::config::DaemonEngine;
    for engine in [DaemonEngine::Docker, DaemonEngine::Podman] {
        let runtime = test_runtime_with_engine(engine, "auto");
        for protocol in Protocol::ALL {
            let mut spec = postgres_spec();
            spec.protocol = protocol;
            let body = runtime.create_body(&spec)?;
            let host = body.host_config.context("expected body.host config")?;
            assert_eq!(host.restart_policy, Some(startup::no_restarts()));
            let logs = host.log_config.context("expected host.log config")?;
            assert_eq!(
                logs.typ.as_deref(),
                Some(if engine == DaemonEngine::Docker {
                    "local"
                } else {
                    "k8s-file"
                })
            );
            let options = logs.config.context("expected logs.config")?;
            assert_eq!(options.get("max-size").map(String::as_str), Some("5m"));
            if engine == DaemonEngine::Docker {
                assert_eq!(options.get("max-file").map(String::as_str), Some("1"));
                assert_eq!(options.get("compress").map(String::as_str), Some("false"));
            }
            assert_eq!(
                body.labels
                    .context("every database uses one bounded console history without log binds should provide a value")?
                    .get("dbev.console-policy")
                    .map(String::as_str),
                Some("1")
            );
            assert!(!host.mounts.expect("every database uses one bounded console history without log binds should provide a value").iter().any(|mount| matches!(
                mount.target.as_deref(),
                Some("/logs" | "/var/log/clickhouse-server")
            )));
        }
    }

    Ok(())
}

#[test]
fn clickhouse_uses_a_loopback_resolvable_hostname_with_network_disabled() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let runtime = test_runtime();
    let mut spec = postgres_spec();
    spec.protocol = Protocol::Clickhouse;

    let body = runtime.create_body(&spec)?;

    assert_eq!(body.hostname.as_deref(), Some("localhost"));
    assert_eq!(
        body.host_config.context("clickhouse uses a loopback resolvable hostname with network disabled should provide a value")?.network_mode.as_deref(),
        Some("none")
    );

    Ok(())
}

#[test]
fn create_body_includes_limits_labels_and_security() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let runtime = test_runtime().with_node_id("node-test");
    let mut spec = postgres_spec();
    spec.pids_limit = Some(4096);
    let body = runtime.create_body(&spec)?;
    let host_config = body
        .host_config
        .context("create body includes limits labels and security should provide a value")?;
    let labels = body
        .labels
        .context("create body includes limits labels and security should provide a value")?;

    assert_eq!(host_config.pids_limit, Some(4096));
    assert!(
        host_config
            .mounts
            .as_ref()
            .expect("create body includes limits labels and security should provide a value")
            .iter()
            .any(|mount| {
                mount.target.as_deref() == Some("/var/lib/postgresql")
                    && mount
                        .source
                        .as_deref()
                        .unwrap_or_default()
                        .ends_with("/data")
            })
    );
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
    assert_eq!(labels.get(NODE_LABEL), Some(&"node-test".to_string()));
    assert_eq!(host_config.privileged, Some(false));
    assert_eq!(host_config.cap_drop, Some(vec!["ALL".to_string()]));
    assert_eq!(
        host_config.security_opt,
        Some(vec!["no-new-privileges".to_string()])
    );

    Ok(())
}

#[test]
fn create_body_disables_permanent_healthchecks_for_every_engine() -> anyhow::Result<()> {
    let docker = test_runtime();
    let runtime = test_runtime_with_engine(
        crate::config::DaemonEngine::Podman,
        "/run/user/1000/podman/podman.sock",
    );

    for body in [
        docker.create_body(&postgres_spec())?,
        runtime.create_body(&postgres_spec())?,
    ] {
        assert_eq!(
            body.healthcheck.and_then(|healthcheck| healthcheck.test),
            Some(vec!["NONE".to_string()])
        );
    }

    Ok(())
}

#[tokio::test]
async fn create_preflight_creates_missing_managed_mount_dirs() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let mut spec = postgres_spec();
    spec.data_path = temp.path().join("volumes").join("inst_abc");

    ensure_bind_mount_sources(&spec).await?;

    assert!(spec.data_path.is_dir());
    assert!(!temp.path().join("logs").exists());

    Ok(())
}

#[tokio::test]
async fn create_preflight_rejects_missing_read_only_file_mount() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let mut spec = postgres_spec();
    spec.data_path = temp.path().join("volumes").join("inst_abc");
    spec.extra_mounts.push(DockerMount {
        source: temp.path().join("missing-config.xml"),
        target: "/etc/service/config.xml".to_string(),
        read_only: true,
    });

    let error = ensure_bind_mount_sources(&spec)
        .await
        .expect_err("ensure bind mount sources should return an error");

    assert!(matches!(error, DockerError::MountSourceIo { .. }));

    Ok(())
}

#[test]
fn rootless_podman_sets_user_and_keep_id_per_protocol() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let runtime = test_runtime_with_engine(
        crate::config::DaemonEngine::Podman,
        "/run/user/1000/podman/podman.sock",
    );
    for protocol in [
        Protocol::Postgres,
        Protocol::Mariadb,
        Protocol::Mysql,
        Protocol::Mongodb,
    ] {
        assert_eq!(
            runtime.rootless_podman_container_user(protocol),
            Some("999:999")
        );
        let mut spec = postgres_spec();
        spec.protocol = protocol;
        let body = runtime.create_body(&spec)?;
        assert_eq!(
            body.host_config
                .context(
                    "rootless podman sets user and keep id per protocol should provide a value"
                )?
                .userns_mode
                .as_deref(),
            Some("keep-id:uid=999,gid=999")
        );
    }

    for protocol in [
        Protocol::Redis,
        Protocol::Valkey,
        Protocol::Clickhouse,
        Protocol::Qdrant,
    ] {
        assert_eq!(
            runtime.rootless_podman_container_user(protocol),
            Some("0:0")
        );
        let mut spec = postgres_spec();
        spec.protocol = protocol;
        let body = runtime.create_body(&spec)?;
        assert_eq!(
            body.host_config
                .context(
                    "rootless podman sets user and keep id per protocol should provide a value"
                )?
                .userns_mode
                .as_deref(),
            Some("host")
        );
    }

    Ok(())
}

#[test]
fn unsafe_instance_id_is_rejected() {
    let runtime = test_runtime();
    let mut spec = postgres_spec();
    spec.instance_id = "../bad".to_string();

    let error = runtime
        .container_name(spec.protocol, &spec.instance_id)
        .expect_err("container name should return an error");

    assert!(matches!(error, DockerError::InvalidId(_)));
}

#[test]
fn limit_conversion_uses_docker_api_units_and_rejects_overflow() -> anyhow::Result<()> {
    let body = DockerRuntime::update_limits_body(2.0, 2048)?;

    assert_eq!(body.nano_cpus, Some(2_000_000_000));
    assert_eq!(body.memory, Some(2048 * 1024 * 1024));
    assert_eq!(body.memory_swap, body.memory);

    assert_eq!(mib_to_bytes(1_u64 << 44), None);
    assert_eq!(cpu_to_nano(f64::NAN), None);
    assert_eq!(cpu_to_nano(f64::INFINITY), None);

    let memory_error = DockerRuntime::update_limits_body(1.0, 1_u64 << 44)
        .expect_err("update limits body should return an error");
    assert!(matches!(memory_error, DockerError::ResourceLimit(_)));

    let cpu_error = DockerRuntime::update_limits_body(f64::INFINITY, 1024)
        .expect_err("update limits body should return an error");
    assert!(matches!(cpu_error, DockerError::ResourceLimit(_)));

    const BYTES_PER_MIB: u64 = 1024 * 1024;
    let largest_mib = (i64::MAX as u64) / BYTES_PER_MIB;

    assert_eq!(
        mib_to_bytes(largest_mib),
        Some((largest_mib * BYTES_PER_MIB) as i64)
    );
    assert_eq!(mib_to_bytes(largest_mib + 1), None);

    Ok(())
}

#[test]
fn transfer_archive_preserves_private_numeric_ownership() -> anyhow::Result<()> {
    let bytes = transfer_tar_header("dump.sql", 12, 1001, 1002)?;
    let header = tar::Header::from_byte_slice(&bytes);

    assert_eq!(header.path()?, std::path::Path::new("dump.sql"));
    assert_eq!(header.size()?, 12);
    assert_eq!(header.mode()?, 0o600);
    assert_eq!(header.uid()?, 1001);
    assert_eq!(header.gid()?, 1002);
    assert_eq!(numeric_container_user("1001:1002"), Some((1001, 1002)));
    assert_eq!(numeric_container_user("1001"), Some((1001, 1001)));
    assert_eq!(numeric_container_user("postgres"), None);

    Ok(())
}

#[test]
fn managed_container_verification_requires_the_exact_ownership_tuple() -> anyhow::Result<()> {
    let container = "dbe-postgres-inst_test";
    let mut labels = HashMap::from([
        (MANAGED_LABEL.to_string(), "true".to_string()),
        (INSTANCE_LABEL.to_string(), "inst_test".to_string()),
        (PROTOCOL_LABEL.to_string(), "postgres".to_string()),
    ]);

    verify_managed_instance_labels(
        &labels,
        container,
        Protocol::Postgres,
        "inst_test",
        Some("node-a"),
    )?;

    labels.insert(PROTOCOL_LABEL.to_string(), "redis".to_string());
    let error =
        verify_managed_instance_labels(&labels, container, Protocol::Postgres, "inst_test", None)
            .expect_err("verify managed instance labels should return an error");
    assert!(matches!(
        error,
        DockerError::UntrustedContainerNameCollision { .. }
    ));

    labels.remove(MANAGED_LABEL);
    assert!(
        verify_managed_instance_labels(&labels, container, Protocol::Postgres, "inst_test", None,)
            .is_err()
    );

    let labels = HashMap::from([
        (MANAGED_LABEL.to_string(), "true".to_string()),
        (INSTANCE_LABEL.to_string(), "inst_test".to_string()),
        (PROTOCOL_LABEL.to_string(), "postgres".to_string()),
        (NODE_LABEL.to_string(), "node-b".to_string()),
    ]);

    let error = verify_managed_instance_labels(
        &labels,
        "dbe-postgres-inst_test",
        Protocol::Postgres,
        "inst_test",
        Some("node-a"),
    )
    .expect_err("verify managed instance labels should return an error");

    assert!(matches!(
        error,
        DockerError::UntrustedContainerNameCollision { .. }
    ));

    Ok(())
}

#[test]
fn destructive_managed_container_selection_is_scoped_to_one_node() {
    let owned = HashMap::from([
        (MANAGED_LABEL.to_string(), "true".to_string()),
        (NODE_LABEL.to_string(), "node-a".to_string()),
    ]);
    let other_node = HashMap::from([
        (MANAGED_LABEL.to_string(), "true".to_string()),
        (NODE_LABEL.to_string(), "node-b".to_string()),
    ]);
    let filters = managed_container_filters("node-a");

    assert_eq!(
        filters.get("label"),
        Some(&vec![
            format!("{MANAGED_LABEL}=true"),
            format!("{NODE_LABEL}=node-a"),
        ])
    );
    assert!(is_owned_managed_container(Some(&owned), "node-a"));
    assert!(!is_owned_managed_container(Some(&other_node), "node-a"));
    assert!(!is_owned_managed_container(None, "node-a"));
}

#[test]
fn container_download_does_not_delete_an_existing_target() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let target = temp.path().join("dump.sql");
    std::fs::write(&target, b"existing")?;
    let archive = single_file_archive("dump.sql", b"replacement");

    assert!(extract_one_file(std::io::Cursor::new(archive), "dump.sql", &target).is_err());
    assert_eq!(std::fs::read(target)?, b"existing");

    Ok(())
}

#[test]
fn container_download_creates_a_private_regular_file() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let target = temp.path().join("dump.sql");
    let archive = single_file_archive("dump.sql", b"contents");

    extract_one_file(std::io::Cursor::new(archive), "dump.sql", &target)?;

    assert_eq!(std::fs::read(&target)?, b"contents");
    assert_eq!(
        std::fs::metadata(target)?.permissions().mode() & 0o777,
        0o600
    );

    Ok(())
}

#[test]
fn container_download_rejects_entries_over_the_byte_limit_without_partial_output()
-> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let target = temp.path().join("dump.sql");
    let archive = single_file_archive("dump.sql", b"too-large");

    let error = extract_one_file_with_limit(std::io::Cursor::new(archive), "dump.sql", &target, 4)
        .expect_err("extract one file with limit should return an error");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("4-byte limit"));
    assert!(!target.exists());

    Ok(())
}

#[test]
fn container_download_deadline_removes_partial_output() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let temp = tempfile::tempdir()?;
    let target = temp.path().join("dump.sql");
    let archive = single_file_archive("dump.sql", b"contents");

    let error = extract_one_file_until(
        std::io::Cursor::new(archive),
        "dump.sql",
        &target,
        MAX_CONTAINER_TRANSFER_BYTES,
        Instant::now()
            .checked_sub(Duration::from_secs(1))
            .context("expected a value from checked_sub")?,
    )
    .expect_err("from secs should return an error");

    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(!target.exists());

    Ok(())
}

#[tokio::test]
async fn container_download_stream_emits_timeout_at_deadline() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let source = futures::stream::pending::<Result<Bytes, IoError>>();
    let mut stream = Box::pin(stream_with_deadline(source, tokio::time::Instant::now()));

    let error = stream
        .next()
        .await
        .context("expected a value from next")?
        .expect_err("next should return an error");

    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert!(stream.next().await.is_none());

    Ok(())
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
        archive
            .append_data(&mut header, path, contents)
            .expect("append data should succeed");
        archive.finish().expect("finish should succeed");
    }
    bytes
}

fn test_runtime() -> DockerRuntime {
    test_runtime_with_engine(crate::config::DaemonEngine::Docker, "auto")
}

fn test_runtime_with_engine(
    engine: crate::config::DaemonEngine,
    socket_path: &str,
) -> DockerRuntime {
    let mut config = crate::config::DaemonConfig {
        engine,
        ..Default::default()
    };
    if socket_path != "auto" {
        config.socket_path = socket_path.to_string();
    }
    DockerRuntime::offline_for_tests(&config, true)
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
        data_path: PathBuf::from("/var/lib/databases-everywhere/instances/inst_abc/data"),
        data_target: "/var/lib/postgresql".to_string(),
        extra_mounts: Vec::new(),
        socket_bridges: Vec::new(),
        env: vec![DockerEnv::plain("POSTGRES_PASSWORD", "super-secret")],
        command: Vec::new(),
    }
}

#[test]
fn a_missing_podman_socket_is_reported_with_the_unit_that_provides_it() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let expect_unit = |socket_path: String, unit: &str| {
        let config = crate::config::DaemonConfig {
            engine: crate::config::DaemonEngine::Podman,
            socket_path: socket_path.clone(),
            ..Default::default()
        };
        match DockerRuntime::new(&config, false) {
            Err(DockerError::PodmanSocketMissing { path, unit: named }) => {
                assert_eq!(path, socket_path);
                assert!(named.contains(unit), "{named}");
            }
            other => panic!("expected a missing-socket error, got {:?}", other.err()),
        }
    };
    expect_unit(
        directory.path().join("podman.sock").display().to_string(),
        "externally managed",
    );
    expect_unit(
        "/run/user/4294967294/podman/podman.sock".to_string(),
        "user manager for uid 4294967294",
    );

    // Docker keeps bollard's own error for a missing socket.
    let docker = crate::config::DaemonConfig {
        socket_path: directory.path().join("docker.sock").display().to_string(),
        ..Default::default()
    };
    assert!(!matches!(
        DockerRuntime::new(&docker, false),
        Err(DockerError::PodmanSocketMissing { .. })
    ));

    Ok(())
}
