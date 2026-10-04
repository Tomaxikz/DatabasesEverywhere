use std::{collections::HashMap, sync::Arc};

use secrecy::SecretString;
use sha2::{Digest, Sha256};

use super::*;
use crate::{
    runtime::docker::{
        DockerError, DockerSecurityPolicy,
        remote_import::{
            cancellation::{CancelHelperOnDrop, HelperCancellation},
            container::{ImportHelperCreateOptions, import_helper_body, is_owned_import_helper},
            output::redact_helper_output,
            validation::{validate_helper_environment, validate_helper_input},
        },
    },
    utils::constants::docker::{MANAGED_LABEL, NODE_LABEL},
};

#[test]
fn helper_body_has_only_the_work_mount_and_strict_sandboxing() {
    let spec = RemoteImportHelperSpec {
        image: "postgres:18.4".to_string(),
        work_dir: PathBuf::from("/var/lib/dbev/tmp/import-job"),
        script: "pg_dump --file=/work/source.sql".to_string(),
        extra_hosts: vec!["db.example.com:203.0.113.10".to_string()],
        timeout: Duration::from_secs(900),
        max_output_bytes: 8 * 1024 * 1024 * 1024,
        network: ImportHelperNetwork::Outbound,
        input: None,
        environment: Vec::new(),
        read_only_work_dir: false,
    };
    let network = ResolvedHelperNetwork {
        mode: "bridge".to_string(),
    };
    let body = import_helper_body(ImportHelperCreateOptions {
        spec: &spec,
        work_dir: &spec.work_dir,
        input_path: None,
        network: &network,
        environment: Vec::new(),
        security: &DockerSecurityPolicy::default(),
        rootless_podman: false,
        node_id: "node-test",
    });
    let labels = body.labels.as_ref().unwrap();
    let host = body.host_config.as_ref().unwrap();
    let mounts = host.mounts.as_ref().unwrap();

    assert_eq!(body.image.as_deref(), Some("postgres:18.4"));
    assert_eq!(body.user.as_deref(), Some("0:0"));
    assert_eq!(body.working_dir.as_deref(), Some(HELPER_WORK_DIR));
    assert_eq!(
        body.entrypoint.as_deref(),
        Some(&["/bin/sh".to_string()][..])
    );
    assert_eq!(body.env.as_deref(), Some(&["HOME=/tmp".to_string()][..]));
    assert_eq!(body.attach_stdin, Some(false));
    assert_eq!(body.open_stdin, Some(false));
    assert!(body.exposed_ports.is_none());
    assert_eq!(
        body.healthcheck
            .as_ref()
            .and_then(|healthcheck| healthcheck.test.as_deref()),
        Some(&["NONE".to_string()][..])
    );

    assert_eq!(labels.get(HELPER_LABEL).map(String::as_str), Some("true"));
    assert_eq!(labels.get(MANAGED_LABEL).map(String::as_str), Some("false"));
    assert_eq!(
        labels.get(NODE_LABEL).map(String::as_str),
        Some("node-test")
    );
    assert_eq!(host.network_mode.as_deref(), Some("bridge"));
    assert_ne!(host.network_mode.as_deref(), Some("host"));
    assert_eq!(host.nano_cpus, Some(1_000_000_000));
    assert_eq!(host.memory, Some(1024 * 1024 * 1024));
    assert_eq!(host.memory_swap, host.memory);
    assert_eq!(host.pids_limit, Some(HELPER_PIDS_LIMIT));
    assert_eq!(host.readonly_rootfs, Some(true));
    assert_eq!(host.privileged, Some(false));
    assert_eq!(host.cap_drop, Some(vec!["ALL".to_string()]));
    assert!(
        host.security_opt
            .as_ref()
            .is_some_and(|options| options.iter().any(|option| option == "no-new-privileges"))
    );
    assert_eq!(host.devices, Some(Vec::new()));
    assert!(host.port_bindings.is_none());
    assert_eq!(
        host.extra_hosts.as_deref(),
        Some(&["db.example.com:203.0.113.10".to_string()][..])
    );
    assert_eq!(
        host.log_config
            .as_ref()
            .and_then(|config| config.typ.as_deref()),
        Some("none")
    );
    assert_eq!(host.auto_remove, Some(true));
    assert_eq!(
        host.tmpfs
            .as_ref()
            .and_then(|tmpfs| tmpfs.get("/tmp"))
            .map(String::as_str),
        Some(HELPER_TMPFS)
    );
    assert_eq!(mounts.len(), 1);
    assert_eq!(
        mounts[0].source.as_deref(),
        Some("/var/lib/dbev/tmp/import-job")
    );
    assert_eq!(mounts[0].target.as_deref(), Some(HELPER_WORK_DIR));
    assert_eq!(mounts[0].read_only, Some(false));
}

#[test]
fn rootless_podman_helper_overrides_incompatible_user_namespaces() {
    let spec = RemoteImportHelperSpec {
        image: "postgres:18.4".to_string(),
        work_dir: PathBuf::from("/var/lib/dbev/tmp/import-job"),
        script: "pg_dump --file=/work/source.sql".to_string(),
        extra_hosts: Vec::new(),
        timeout: Duration::from_secs(900),
        max_output_bytes: 8 * 1024 * 1024 * 1024,
        network: ImportHelperNetwork::Outbound,
        input: None,
        environment: Vec::new(),
        read_only_work_dir: false,
    };
    let security = DockerSecurityPolicy {
        userns_mode: Some("keep-id".to_string()),
        ..DockerSecurityPolicy::default()
    };

    let body = import_helper_body(ImportHelperCreateOptions {
        spec: &spec,
        work_dir: &spec.work_dir,
        input_path: None,
        network: &ResolvedHelperNetwork {
            mode: "bridge".to_string(),
        },
        environment: Vec::new(),
        security: &security,
        rootless_podman: true,
        node_id: "node-test",
    });

    assert_eq!(
        body.host_config.unwrap().userns_mode.as_deref(),
        Some("host")
    );
}

#[test]
fn shared_restore_body_has_only_read_only_input_and_work_mounts() {
    let secret = SecretString::from("tenant-password".to_string());
    let spec = RemoteImportHelperSpec {
        image: "sha256:pinned-image".to_string(),
        work_dir: PathBuf::from("/var/lib/dbev/tmp/shared-restore"),
        script: format!("mysql < {IMPORT_HELPER_INPUT_PATH}"),
        extra_hosts: Vec::new(),
        timeout: Duration::from_secs(90),
        max_output_bytes: 512,
        network: ImportHelperNetwork::ManagedRuntime {
            protocol: Protocol::Mysql,
            runtime_id: "pool-mysql".to_string(),
        },
        input: Some(ImportHelperInput {
            path: PathBuf::from("/var/lib/dbev/tmp/shared-restore/input"),
            size_bytes: 512,
            sha256: [7; 32],
        }),
        environment: vec![DockerEnv {
            key: "DBE_IMPORT_PASSWORD".to_string(),
            value: secret,
        }],
        read_only_work_dir: true,
    };
    let (environment, _) = validate_helper_environment(&spec).unwrap();
    let body = import_helper_body(ImportHelperCreateOptions {
        spec: &spec,
        work_dir: &spec.work_dir,
        input_path: spec.input.as_ref().map(|input| input.path.as_path()),
        network: &ResolvedHelperNetwork {
            mode: "container:verified-pool-id".to_string(),
        },
        environment,
        security: &DockerSecurityPolicy::default(),
        rootless_podman: false,
        node_id: "node-test",
    });
    let host = body.host_config.unwrap();
    let mounts = host.mounts.unwrap();

    assert_eq!(
        host.network_mode.as_deref(),
        Some("container:verified-pool-id")
    );
    assert!(host.extra_hosts.is_none());
    assert_eq!(mounts.len(), 2);
    assert!(mounts.iter().all(|mount| mount.read_only == Some(true)));
    assert_eq!(mounts[0].target.as_deref(), Some(HELPER_WORK_DIR));
    assert_eq!(mounts[1].target.as_deref(), Some(IMPORT_HELPER_INPUT_PATH));
    assert_eq!(host.readonly_rootfs, Some(true));
    assert_eq!(host.cap_drop, Some(vec!["ALL".to_string()]));
    assert_eq!(host.pids_limit, Some(HELPER_PIDS_LIMIT));
    assert!(body.cmd.as_ref().is_some_and(|command| {
        command
            .iter()
            .all(|value| !value.contains("tenant-password"))
    }));
    assert!(body.env.as_ref().is_some_and(|environment| {
        environment.contains(&"DBE_IMPORT_PASSWORD=tenant-password".to_string())
    }));
}

#[test]
fn helper_output_and_validation_never_expose_environment_secrets() {
    let secret = SecretString::from("correct-horse-battery-staple".to_string());
    let mut spec = RemoteImportHelperSpec {
        image: "postgres:18.4".to_string(),
        work_dir: PathBuf::from("/var/lib/dbev/tmp/import-job"),
        script: "printf failure".to_string(),
        extra_hosts: Vec::new(),
        timeout: Duration::from_secs(30),
        max_output_bytes: 1,
        network: ImportHelperNetwork::Outbound,
        input: None,
        environment: vec![DockerEnv {
            key: "PGPASSWORD".to_string(),
            value: secret,
        }],
        read_only_work_dir: false,
    };
    let (_, secrets) = validate_helper_environment(&spec).unwrap();
    let redacted = redact_helper_output("password=correct-horse-battery-staple", &secrets);
    assert!(!redacted.contains("correct-horse-battery-staple"));
    assert!(redacted.contains("[redacted]"));

    spec.script = "echo correct-horse-battery-staple".to_string();
    let error = validate_helper_environment(&spec).unwrap_err().to_string();
    assert!(!error.contains("correct-horse-battery-staple"));
}

#[tokio::test]
async fn helper_input_rejects_digest_changes_before_container_creation() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("dump.sql");
    std::fs::write(&input, b"unsafe").unwrap();
    let expected: [u8; 32] = Sha256::digest(b"safe!!").into();
    let error = validate_helper_input(Some(&ImportHelperInput {
        path: input,
        size_bytes: 6,
        sha256: expected,
    }))
    .await
    .unwrap_err();
    assert!(!error.to_string().contains("unsafe"));
}

#[test]
fn reconciliation_requires_the_exact_label_and_generated_name_shape() {
    let labels = HashMap::from([
        (HELPER_LABEL.to_string(), "true".to_string()),
        (NODE_LABEL.to_string(), "node-a".to_string()),
    ]);
    let valid_names = vec!["/dbe-remote-import-0123456789abcdef0123456789abcdef".to_string()];

    assert!(is_owned_import_helper(
        Some(&labels),
        Some(&valid_names),
        "node-a",
    ));
    assert!(!is_owned_import_helper(None, Some(&valid_names), "node-a"));
    assert!(!is_owned_import_helper(
        Some(&HashMap::from([(
            HELPER_LABEL.to_string(),
            "false".to_string()
        )])),
        Some(&valid_names),
        "node-a",
    ));
    assert!(!is_owned_import_helper(
        Some(&labels),
        Some(&["/dbe-remote-import-not-a-uuid".to_string()]),
        "node-a",
    ));
    assert!(!is_owned_import_helper(
        Some(&labels),
        Some(&["/dbe-remote-import-0123456789ABCDEF0123456789ABCDEF".to_string()]),
        "node-a",
    ));
    assert!(!is_owned_import_helper(
        Some(&labels),
        Some(&["/unrelated-0123456789abcdef0123456789abcdef".to_string()]),
        "node-a",
    ));
    assert!(!is_owned_import_helper(
        Some(&labels),
        Some(&valid_names),
        "node-b",
    ));
}

#[test]
fn cleanup_uncertainty_is_typed_for_fail_closed_callers() {
    let uncertain = DockerError::RemoteImportHelperStateUncertain {
        reason: "supervisor ended".to_string(),
    };
    let timed_out = DockerError::RemoteImportHelperCleanupTimedOut {
        container: "helper".to_string(),
        timeout_seconds: 30,
    };
    let ordinary = DockerError::RemoteImportHelperFailed {
        exit_code: 1,
        failure_output: "restore failed".to_string(),
    };

    assert!(uncertain.import_helper_state_uncertain());
    assert!(timed_out.import_helper_state_uncertain());
    assert!(!ordinary.import_helper_state_uncertain());
}

#[tokio::test]
async fn dropping_the_cancellation_guard_notifies_the_supervisor() {
    let cancellation = Arc::new(HelperCancellation::default());
    {
        let _guard = CancelHelperOnDrop::new(cancellation.clone());
    }

    tokio::time::timeout(Duration::from_millis(100), cancellation.cancelled())
        .await
        .expect("cancellation must be observable without a missed notification");
}

#[tokio::test]
async fn concurrent_cancellation_notifications_are_not_lost() {
    for iteration in 0..256 {
        let cancellation = Arc::new(HelperCancellation::default());
        let waiter_cancellation = cancellation.clone();
        let waiter = tokio::spawn(async move {
            waiter_cancellation.cancelled().await;
        });
        if iteration % 2 == 0 {
            tokio::task::yield_now().await;
        }
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("cancellation waiter must not miss a notification")
            .expect("cancellation waiter task must complete");
    }
}
