use std::{
    io::Write,
    process::{Command, Output, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use base64::Engine;

use super::provision::{reset_tenant_password_sql, shared_tenant_user_sql};
use crate::databases::{
    mysql_wire_integration::{
        assert_engine_tenant_rows, run_jdbc_smoke, run_mariadb_cli, start_gateway,
        test_tls_acceptor,
    },
    test_support::DockerContainer,
};
use crate::{
    instances::{state::InstanceStore, test_support},
    protocols::mariadb::native_password_sha1_stage2_hex,
    shared::{backend::BackendEndpoint, protocol::Protocol},
};

const DEFAULT_IMAGE: &str = "mysql:8.4";
const DATABASE: &str = "integration_db";
const TENANT: &str = "integration_user";
const TENANT_PASSWORD: &str = "integration-tenant-password";
const NEIGHBOR_DATABASE: &str = "integration_neighbor_db";
const NEIGHBOR: &str = "integration_neighbor";
const NEIGHBOR_PASSWORD: &str = "integration-neighbor-password";
const ROTATED_TENANT_PASSWORD: &str = "integration-rotated-password";
const ROOT_PASSWORD: &str = "integration-root-password";

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker, supported MySQL/MariaDB images, Maven, Java, and OpenSSL"]
async fn mysql_supported_version_provisions_routes_and_round_trips_dump() {
    let image = std::env::var("DBE_MYSQL_TEST_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_string());
    let name = format!("dbev-mysql-test-{}", uuid::Uuid::new_v4().simple());
    let socket_root = tempfile::tempdir().unwrap();
    let container = start_container(&name, socket_root.path(), &image);
    wait_until_ready(&name);
    let version = query_mysql(&name, ROOT_PASSWORD, "root", "mysql", "SELECT VERSION()");
    crate::compatibility::compatibility_profile(Protocol::Mysql, &version).unwrap_or_else(
        |error| panic!("{image} reported unsupported live version {version}: {error}"),
    );

    let sql = materialize_password(shared_tenant_user_sql(DATABASE, TENANT), TENANT_PASSWORD);
    let provision = exec_with_input(
        &name,
        ROOT_PASSWORD,
        &["mysql", "--protocol=socket", "-uroot"],
        sql.as_bytes(),
    );
    assert_success(&provision, "tenant provisioning");

    let neighbor_sql = materialize_password(
        shared_tenant_user_sql(NEIGHBOR_DATABASE, NEIGHBOR),
        NEIGHBOR_PASSWORD,
    );
    assert_success(
        &exec_with_input(
            &name,
            ROOT_PASSWORD,
            &["mysql", "--protocol=socket", "-uroot"],
            neighbor_sql.as_bytes(),
        ),
        "neighbor tenant provisioning",
    );

    let plugin = exec_mysql(
        &name,
        ROOT_PASSWORD,
        "root",
        "mysql",
        "SELECT plugin FROM mysql.user WHERE user = 'integration_user'",
    );
    assert_eq!(
        String::from_utf8_lossy(&plugin.stdout).trim(),
        "caching_sha2_password"
    );

    let create = exec_mysql(
        &name,
        TENANT_PASSWORD,
        TENANT,
        DATABASE,
        "CREATE TABLE restore_test (id INT PRIMARY KEY, value VARCHAR(32)); INSERT INTO restore_test VALUES (1, 'before')",
    );
    assert_success(&create, "tenant table creation");

    assert_mysql_engine_telemetry(&name);

    assert_eq!(
        query_mysql(
            &name,
            ROOT_PASSWORD,
            "root",
            "mysql",
            "SELECT @@GLOBAL.log_bin"
        ),
        "0",
        "DBEV disables unused binary logging for its isolated single-node MySQL containers"
    );

    let mut failing_rotation_sql =
        materialize_password(reset_tenant_password_sql(TENANT), ROTATED_TENANT_PASSWORD);
    failing_rotation_sql.push_str("\nSELECT * FROM `dbev_missing_schema`.`dbev_missing_table`;\n");
    let failed_rotation = exec_with_input(
        &name,
        ROOT_PASSWORD,
        &["mysql", "--protocol=socket", "-uroot"],
        failing_rotation_sql.as_bytes(),
    );
    assert!(
        !failed_rotation.status.success(),
        "the injected post-rotation failure unexpectedly succeeded"
    );
    assert_success(
        &exec_mysql(&name, ROTATED_TENANT_PASSWORD, TENANT, DATABASE, "SELECT 1"),
        "credential mutation before the injected failure",
    );

    let rollback_sql = materialize_password(reset_tenant_password_sql(TENANT), TENANT_PASSWORD);
    let rollback = exec_with_input(
        &name,
        ROOT_PASSWORD,
        &["mysql", "--protocol=socket", "-uroot"],
        rollback_sql.as_bytes(),
    );
    assert_success(&rollback, "password rotation rollback");
    assert_success(
        &exec_mysql(&name, TENANT_PASSWORD, TENANT, DATABASE, "SELECT 1"),
        "restored tenant credential",
    );
    assert!(
        !exec_mysql(&name, ROTATED_TENANT_PASSWORD, TENANT, DATABASE, "SELECT 1",)
            .status
            .success(),
        "replacement credential remained valid after rollback"
    );
    assert_eq!(
        query_mysql(
            &name,
            ROOT_PASSWORD,
            "root",
            "mysql",
            "SELECT @@GLOBAL.log_bin"
        ),
        "0",
        "password rotation must leave binary logging disabled"
    );

    let dump = Command::new("docker")
        .args([
            "exec",
            "-e",
            &format!("MYSQL_PWD={TENANT_PASSWORD}"),
            &name,
            "mysqldump",
            "--protocol=socket",
            "-u",
            TENANT,
            "--single-transaction",
            "--no-tablespaces",
            "--set-gtid-purged=OFF",
            DATABASE,
        ])
        .output()
        .expect("run MySQL logical export");
    assert_success(&dump, "logical export");

    let mutate = exec_mysql(
        &name,
        TENANT_PASSWORD,
        TENANT,
        DATABASE,
        "UPDATE restore_test SET value = 'after' WHERE id = 1",
    );
    assert_success(&mutate, "tenant table mutation");

    let restore = exec_with_input(
        &name,
        TENANT_PASSWORD,
        &["mysql", "--protocol=socket", "-u", TENANT, DATABASE],
        &dump.stdout,
    );
    assert_success(&restore, "logical restore");
    let value = exec_mysql(
        &name,
        TENANT_PASSWORD,
        TENANT,
        DATABASE,
        "SELECT value FROM restore_test WHERE id = 1",
    );
    assert_success(&value, "restored value query");
    assert_eq!(String::from_utf8_lossy(&value.stdout).trim(), "before");

    let store = InstanceStore::default();
    let mut metadata = test_support::metadata("inst_mysql_integration", Protocol::Mysql);
    metadata.public.host = "127.0.0.1".to_string();
    metadata.public.port = 0;
    metadata.backend = BackendEndpoint::UnixSocket {
        socket_path: socket_root.path().join("mysqld.sock").display().to_string(),
    };
    metadata.runtime.container_name = name.clone();
    metadata.database.name = DATABASE.to_string();
    metadata.database.username = TENANT.to_string();
    metadata.mysql_native_password_sha1_stage2 =
        Some(native_password_sha1_stage2_hex(TENANT_PASSWORD));
    metadata.mysql_root_password = Some(ROOT_PASSWORD.to_string());
    metadata.tenant_password = Some(TENANT_PASSWORD.to_string());
    store.upsert(metadata).await;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (address, gateway) =
        start_gateway(Protocol::Mysql, store.clone(), None, shutdown_rx.clone()).await;
    let tls_directory = tempfile::tempdir().unwrap();
    let tls = test_tls_acceptor(tls_directory.path());
    let (tls_address, tls_gateway) =
        start_gateway(Protocol::Mysql, store, Some(tls), shutdown_rx).await;

    let routed = run_mariadb_cli(
        address.port(),
        DATABASE,
        TENANT,
        TENANT_PASSWORD,
        "SELECT value FROM restore_test WHERE id = 1",
    );
    assert_success(&routed, "gateway-routed tenant query");
    assert_eq!(String::from_utf8_lossy(&routed.stdout).trim(), "before");
    run_jdbc_smoke(
        address.port(),
        tls_address.port(),
        DATABASE,
        TENANT,
        TENANT_PASSWORD,
    );

    let rejected = run_mariadb_cli(
        address.port(),
        DATABASE,
        TENANT,
        "wrong-password",
        "SELECT 1",
    );
    assert!(
        !rejected.status.success(),
        "gateway accepted a wrong password"
    );

    shutdown_tx.send(true).unwrap();
    gateway.await.unwrap().unwrap();
    tls_gateway.await.unwrap().unwrap();

    drop(container);
}

fn assert_mysql_engine_telemetry(name: &str) {
    let prepare = exec_mysql(
        name,
        ROOT_PASSWORD,
        "root",
        "mysql",
        crate::monitoring::mysql_prepare_sql(),
    );
    assert_success(&prepare, "prepare canonical MySQL engine telemetry");
    let prepare_output =
        String::from_utf8(prepare.stdout).expect("MySQL telemetry output is UTF-8");
    let capabilities = crate::monitoring::parse_mysql_capabilities(&prepare_output)
        .expect("detect MySQL telemetry capabilities");

    for (database, username, password) in [
        (DATABASE, TENANT, TENANT_PASSWORD),
        (NEIGHBOR_DATABASE, NEIGHBOR, NEIGHBOR_PASSWORD),
    ] {
        assert_success(
            &exec_mysql(name, password, username, database, "SELECT 1"),
            "tenant telemetry probe query",
        );
    }

    let collect = exec_mysql(
        name,
        ROOT_PASSWORD,
        "root",
        "mysql",
        crate::monitoring::mysql_collect_sql(capabilities),
    );
    assert_success(&collect, "collect canonical MySQL engine telemetry");
    let collect_output =
        String::from_utf8(collect.stdout).expect("MySQL telemetry output is UTF-8");
    let rows = crate::monitoring::parse_mysql_rows(&collect_output, capabilities)
        .expect("parse canonical MySQL engine telemetry");
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
            &format!("{}:/var/run/mysqld", socket_root.display()),
            "--env",
            &format!("MYSQL_ROOT_PASSWORD={ROOT_PASSWORD}"),
            "--env",
            &format!("MYSQL_DATABASE={DATABASE}"),
            image,
            "--skip-networking=ON",
            "--skip-name-resolve",
            "--skip-mysqlx",
            "--skip-log-bin",
        ])
        .output()
        .expect("start MySQL test container");
    assert_success(&output, "start MySQL test container");
    DockerContainer::started(name)
}

fn materialize_password(sql: String, password: &str) -> String {
    sql.replace(
        super::provision::PASSWORD_B64_PLACEHOLDER,
        &base64::engine::general_purpose::STANDARD.encode(password.as_bytes()),
    )
}

fn wait_until_ready(name: &str) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if Command::new("docker")
            .args([
                "exec",
                "-e",
                &format!("MYSQL_PWD={ROOT_PASSWORD}"),
                name,
                "sh",
                "-c",
                "test \"$(cat /proc/1/comm)\" = mysqld && mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -uroot -N -B -e 'SELECT 1' >/dev/null",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run MySQL readiness probe")
            .success()
        {
            return;
        }
        sleep(Duration::from_millis(250));
    }
    panic!("MySQL test container did not become ready");
}

fn exec_mysql(name: &str, password: &str, user: &str, database: &str, sql: &str) -> Output {
    Command::new("docker")
        .args([
            "exec",
            "-e",
            &format!("MYSQL_PWD={password}"),
            name,
            "mysql",
            "--protocol=socket",
            "-u",
            user,
            "-N",
            "-B",
            database,
            "-e",
            sql,
        ])
        .output()
        .expect("run MySQL query")
}

fn query_mysql(name: &str, password: &str, user: &str, database: &str, sql: &str) -> String {
    let output = exec_mysql(name, password, user, database, sql);
    assert_success(&output, "MySQL query");
    String::from_utf8(output.stdout)
        .expect("MySQL query output is UTF-8")
        .trim()
        .to_string()
}

fn exec_with_input(name: &str, password: &str, command: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new("docker")
        .args(["exec", "-i", "-e", &format!("MYSQL_PWD={password}"), name])
        .args(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start MySQL command");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input)
        .expect("write MySQL input");
    child.wait_with_output().expect("wait for MySQL command")
}

fn assert_success(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
