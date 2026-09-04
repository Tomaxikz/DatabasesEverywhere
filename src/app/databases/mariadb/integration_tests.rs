use std::{
    io::Write,
    process::{Command, Output, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use super::provision::shared_tenant_user_sql;
use crate::{
    databases::{
        mysql_wire_integration::{
            assert_engine_tenant_rows, run_jdbc_smoke, run_mariadb_cli, start_gateway,
            test_tls_acceptor,
        },
        test_support::DockerContainer,
    },
    instances::{state::InstanceStore, test_support},
    protocols::mariadb::native_password_sha1_stage2_hex,
    shared::{backend::BackendEndpoint, protocol::Protocol},
};

const DEFAULT_IMAGE: &str = "mariadb:12.3";
const DATABASE: &str = "integration_db";
const TENANT: &str = "integration_user";
const TENANT_PASSWORD: &str = "integration-tenant-password";
const NEIGHBOR_DATABASE: &str = "integration_neighbor_db";
const NEIGHBOR: &str = "integration_neighbor";
const NEIGHBOR_PASSWORD: &str = "integration-neighbor-password";
const ROOT_PASSWORD: &str = "integration-root-password";

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker, supported MariaDB images, Maven, Java, and OpenSSL"]
async fn mariadb_supported_version_routes_real_cli_jdbc_tls_and_hikari() {
    let image =
        std::env::var("DBE_MARIADB_TEST_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_string());
    let name = format!("dbev-mariadb-test-{}", uuid::Uuid::new_v4().simple());
    let socket_root = tempfile::tempdir().unwrap();
    let container = start_container(&name, socket_root.path(), &image);
    wait_until_ready(&name);

    let verifier = native_password_sha1_stage2_hex(TENANT_PASSWORD);
    let provision_sql = shared_tenant_user_sql(DATABASE, TENANT, &verifier).unwrap();
    assert_success(
        &exec_with_input(&name, ROOT_PASSWORD, provision_sql.as_bytes()),
        "MariaDB tenant provisioning",
    );
    let neighbor_verifier = native_password_sha1_stage2_hex(NEIGHBOR_PASSWORD);
    let neighbor_sql =
        shared_tenant_user_sql(NEIGHBOR_DATABASE, NEIGHBOR, &neighbor_verifier).unwrap();
    assert_success(
        &exec_with_input(&name, ROOT_PASSWORD, neighbor_sql.as_bytes()),
        "MariaDB neighbor tenant provisioning",
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
    assert_mariadb_engine_telemetry(&name);
    let version = query_mariadb(&name, ROOT_PASSWORD, "root", "mysql", "SELECT VERSION()");
    crate::compatibility::compatibility_profile(Protocol::Mariadb, &version).unwrap_or_else(
        |error| panic!("{image} reported unsupported live version {version}: {error}"),
    );

    let store = InstanceStore::default();
    let mut metadata = test_support::metadata("inst_mariadb_integration", Protocol::Mariadb);
    metadata.public.host = "127.0.0.1".to_string();
    metadata.public.port = 0;
    metadata.backend = BackendEndpoint::UnixSocket {
        socket_path: socket_root.path().join("mysqld.sock").display().to_string(),
    };
    metadata.runtime.container_name = name.clone();
    metadata.database.name = DATABASE.to_string();
    metadata.database.username = TENANT.to_string();
    metadata.mariadb_native_password_sha1_stage2 = Some(verifier);
    metadata.mariadb_root_password = Some(ROOT_PASSWORD.to_string());
    metadata.tenant_password = Some(TENANT_PASSWORD.to_string());
    store.upsert(metadata).await;

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

fn assert_mariadb_engine_telemetry(name: &str) {
    let prepare = exec_mariadb(
        name,
        ROOT_PASSWORD,
        "root",
        "mysql",
        crate::monitoring::mariadb_prepare_sql(),
    );
    assert_success(&prepare, "prepare canonical MariaDB engine telemetry");
    let prepare_output =
        String::from_utf8(prepare.stdout).expect("MariaDB telemetry output is UTF-8");
    crate::monitoring::parse_mariadb_ready(&prepare_output)
        .expect("confirm MariaDB telemetry accounting is ready");

    for (database, username, password) in [
        (DATABASE, TENANT, TENANT_PASSWORD),
        (NEIGHBOR_DATABASE, NEIGHBOR, NEIGHBOR_PASSWORD),
    ] {
        assert_success(
            &exec_mariadb(name, password, username, database, "SELECT 1"),
            "tenant telemetry probe query",
        );
    }

    let collect = exec_mariadb(
        name,
        ROOT_PASSWORD,
        "root",
        "mysql",
        crate::monitoring::mariadb_collect_sql(),
    );
    assert_success(&collect, "collect canonical MariaDB engine telemetry");
    let collect_output =
        String::from_utf8(collect.stdout).expect("MariaDB telemetry output is UTF-8");
    let rows = crate::monitoring::parse_mariadb_rows(&collect_output)
        .expect("parse canonical MariaDB engine telemetry");
    assert_engine_tenant_rows(rows, &[TENANT, NEIGHBOR]);
}

fn start_container(name: &str, socket_root: &std::path::Path, image: &str) -> DockerContainer {
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
    DockerContainer::started(name)
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
