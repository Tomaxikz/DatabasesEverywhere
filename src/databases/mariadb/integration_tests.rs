use std::{
    io::Write,
    process::{Command, Output, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use super::provision::tenant_user_sql;
use crate::{
    databases::mysql_wire_integration::{
        run_jdbc_smoke, run_mariadb_cli, start_gateway, test_tls_acceptor,
    },
    instances::{
        metadata::{
            DatabaseIdentity, InstanceMetadata, InstanceStatus, PublicEndpoint, RuntimeKind,
            RuntimeMetadata, SCHEMA_VERSION,
        },
        state::InstanceStore,
    },
    protocols::mariadb::native_password_sha1_stage2_hex,
    shared::{backend::BackendEndpoint, limits::InstanceLimits, protocol::Protocol},
};

const DEFAULT_IMAGE: &str = "mariadb:12.3";
const DATABASE: &str = "integration_db";
const TENANT: &str = "integration_user";
const TENANT_PASSWORD: &str = "integration-tenant-password";
const ROOT_PASSWORD: &str = "integration-root-password";

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker, supported MariaDB images, Maven, Java, and OpenSSL"]
async fn mariadb_supported_version_routes_real_cli_jdbc_tls_and_hikari() {
    let image =
        std::env::var("DBE_MARIADB_TEST_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_string());
    let name = format!("dbev-mariadb-test-{}", uuid::Uuid::new_v4().simple());
    let socket_root = tempfile::tempdir().unwrap();
    let container = TestContainer::start(&name, socket_root.path(), &image);
    wait_until_ready(&name);

    let verifier = native_password_sha1_stage2_hex(TENANT_PASSWORD);
    let provision_sql = tenant_user_sql(DATABASE, TENANT, &verifier).unwrap();
    assert_success(
        &exec_with_input(&name, ROOT_PASSWORD, provision_sql.as_bytes()),
        "MariaDB tenant provisioning",
    );
    assert_success(
        &exec_mariadb(
            &name,
            TENANT_PASSWORD,
            TENANT,
            DATABASE,
            "CREATE TABLE restore_test (id INT PRIMARY KEY, value VARCHAR(32)); INSERT INTO restore_test VALUES (1, 'before')",
        ),
        "MariaDB tenant table creation",
    );
    let version = query_mariadb(&name, ROOT_PASSWORD, "root", "mysql", "SELECT VERSION()");
    crate::compatibility::compatibility_profile(Protocol::Mariadb, &version).unwrap_or_else(
        |error| panic!("{image} reported unsupported live version {version}: {error}"),
    );

    let store = InstanceStore::default();
    store
        .upsert(InstanceMetadata {
            schema_version: SCHEMA_VERSION,
            instance_id: "inst_mariadb_integration".to_string(),
            protocol: Protocol::Mariadb,
            status: InstanceStatus::Running,
            desired_state: crate::instances::metadata::DesiredInstanceState::Running,
            disk_limit_blocked: false,
            public: PublicEndpoint {
                host: "127.0.0.1".to_string(),
                port: 0,
            },
            backend: BackendEndpoint::UnixSocket {
                socket_path: socket_root.path().join("mysqld.sock").display().to_string(),
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: name.clone(),
                network_mode: "none".to_string(),
            },
            database: DatabaseIdentity {
                name: DATABASE.to_string(),
                username: TENANT.to_string(),
            },
            route_key_sha256: None,
            mariadb_native_password_sha1_stage2: Some(verifier),
            mariadb_root_password: Some(ROOT_PASSWORD.to_string()),
            mysql_native_password_sha1_stage2: None,
            mysql_root_password: None,
            mongodb_root_password: None,
            postgres_admin_password: None,
            tenant_password: Some(TENANT_PASSWORD.to_string()),
            limits: InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        })
        .await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (address, gateway) =
        start_gateway(Protocol::Mariadb, store.clone(), None, shutdown_rx.clone()).await;
    let tls_directory = tempfile::tempdir().unwrap();
    let tls = test_tls_acceptor(tls_directory.path());
    let (tls_address, tls_gateway) =
        start_gateway(Protocol::Mariadb, store, Some(tls), shutdown_rx).await;

    let routed = host_mariadb(
        address.port(),
        TENANT_PASSWORD,
        "SELECT value FROM restore_test WHERE id = 1",
    );
    assert_success(&routed, "gateway-routed MariaDB CLI query");
    assert_eq!(String::from_utf8_lossy(&routed.stdout).trim(), "before");
    run_jdbc_smoke(
        address.port(),
        tls_address.port(),
        DATABASE,
        TENANT,
        TENANT_PASSWORD,
    );
    assert!(
        !host_mariadb(address.port(), "wrong-password", "SELECT 1")
            .status
            .success(),
        "MariaDB gateway accepted a wrong password"
    );

    shutdown_tx.send(true).unwrap();
    gateway.await.unwrap().unwrap();
    tls_gateway.await.unwrap().unwrap();
    drop(container);
}

struct TestContainer(String);

impl TestContainer {
    fn start(name: &str, socket_root: &std::path::Path, image: &str) -> Self {
        let output = Command::new("docker")
            .args([
                "run",
                "--detach",
                "--rm",
                "--name",
                name,
                "--volume",
                &format!("{}:/run/mysqld", socket_root.display()),
                "--env",
                &format!("MARIADB_ROOT_PASSWORD={ROOT_PASSWORD}"),
                "--env",
                &format!("MARIADB_DATABASE={DATABASE}"),
                image,
                "--skip-networking=ON",
                "--skip-name-resolve",
                "--skip-log-bin",
                "--wsrep-on=OFF",
            ])
            .output()
            .expect("start MariaDB test container");
        assert_success(&output, "start MariaDB test container");
        Self(name.to_string())
    }
}

impl Drop for TestContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "--force", &self.0])
            .output();
    }
}

fn wait_until_ready(name: &str) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if Command::new("docker")
            .args([
                "exec",
                "-e",
                &format!("MARIADB_ROOT_PASSWORD={ROOT_PASSWORD}"),
                name,
                "sh",
                "-c",
                crate::runtime::docker::startup_readiness_script(Protocol::Mariadb),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run MariaDB final-server readiness probe")
            .success()
        {
            return;
        }
        sleep(Duration::from_millis(250));
    }
    panic!("MariaDB test container did not become ready");
}

fn exec_mariadb(name: &str, password: &str, user: &str, database: &str, sql: &str) -> Output {
    Command::new("docker")
        .args([
            "exec",
            "-e",
            &format!("MYSQL_PWD={password}"),
            name,
            "mariadb",
            "--protocol=socket",
            "--socket=/run/mysqld/mysqld.sock",
            "-u",
            user,
            "-N",
            "-B",
            database,
            "-e",
            sql,
        ])
        .output()
        .expect("run MariaDB query")
}

fn query_mariadb(name: &str, password: &str, user: &str, database: &str, sql: &str) -> String {
    let output = exec_mariadb(name, password, user, database, sql);
    assert_success(&output, "MariaDB query");
    String::from_utf8(output.stdout)
        .expect("MariaDB query output is UTF-8")
        .trim()
        .to_string()
}

fn exec_with_input(name: &str, password: &str, input: &[u8]) -> Output {
    let mut child = Command::new("docker")
        .args([
            "exec",
            "-i",
            "-e",
            &format!("MYSQL_PWD={password}"),
            name,
            "mariadb",
            "--protocol=socket",
            "--socket=/run/mysqld/mysqld.sock",
            "-uroot",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start MariaDB command");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input)
        .expect("write MariaDB input");
    child.wait_with_output().expect("wait for MariaDB command")
}

fn host_mariadb(port: u16, password: &str, sql: &str) -> Output {
    run_mariadb_cli(port, DATABASE, TENANT, password, sql)
}

fn assert_success(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
