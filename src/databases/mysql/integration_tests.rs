use std::{
    io::Write,
    process::{Command, Output, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use super::provision::tenant_user_sql;
use crate::{
    gateway::{
        listeners::run_mysql_listener, resolver::RouteResolver, security::GatewayConnectionLimiter,
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

const IMAGE: &str = "mysql:8.4";
const DATABASE: &str = "integration_db";
const TENANT: &str = "integration_user";
const TENANT_PASSWORD: &str = "integration-tenant-password";
const ROOT_PASSWORD: &str = "integration-root-password";

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker, mysql:8.4, and the mariadb CLI"]
async fn mysql_84_provisions_native_tenant_and_round_trips_logical_dump() {
    let name = format!("dbev-mysql-test-{}", uuid::Uuid::new_v4().simple());
    let socket_root = tempfile::tempdir().unwrap();
    let container = TestContainer::start(&name, socket_root.path());
    wait_until_ready(&name);

    let sql = tenant_user_sql(
        DATABASE,
        TENANT,
        &native_password_sha1_stage2_hex(TENANT_PASSWORD),
    )
    .unwrap();
    let provision = exec_with_input(
        &name,
        ROOT_PASSWORD,
        &["mysql", "--protocol=socket", "-uroot"],
        sql.as_bytes(),
    );
    assert_success(&provision, "tenant provisioning");

    let plugin = exec_mysql(
        &name,
        ROOT_PASSWORD,
        "root",
        "mysql",
        "SELECT plugin FROM mysql.user WHERE user = 'integration_user'",
    );
    assert_eq!(
        String::from_utf8_lossy(&plugin.stdout).trim(),
        "mysql_native_password"
    );

    let create = exec_mysql(
        &name,
        TENANT_PASSWORD,
        TENANT,
        DATABASE,
        "CREATE TABLE restore_test (id INT PRIMARY KEY, value VARCHAR(32)); INSERT INTO restore_test VALUES (1, 'before')",
    );
    assert_success(&create, "tenant table creation");

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
    store
        .upsert(InstanceMetadata {
            schema_version: SCHEMA_VERSION,
            instance_id: "inst_mysql_integration".to_string(),
            protocol: Protocol::Mysql,
            status: InstanceStatus::Running,
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
            mariadb_native_password_sha1_stage2: None,
            mariadb_root_password: None,
            mysql_native_password_sha1_stage2: Some(native_password_sha1_stage2_hex(
                TENANT_PASSWORD,
            )),
            mysql_root_password: Some(ROOT_PASSWORD.to_string()),
            mongodb_root_password: None,
            limits: InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        })
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let bind = address.to_string();
    let gateway = tokio::spawn(async move {
        run_mysql_listener(
            listener,
            &bind,
            RouteResolver::new(store, crate::api::resources::ResourceCache::default()),
            None,
            GatewayConnectionLimiter::default(),
            shutdown_rx,
        )
        .await
    });

    let routed = Command::new("mariadb")
        .args([
            "-h",
            "127.0.0.1",
            "-P",
            &address.port().to_string(),
            "-u",
            TENANT,
            &format!("-p{TENANT_PASSWORD}"),
            DATABASE,
            "--skip-ssl",
            "--connect-timeout=5",
            "-N",
            "-B",
            "-e",
            "SELECT value FROM restore_test WHERE id = 1",
        ])
        .output()
        .expect("query through MySQL gateway");
    assert_success(&routed, "gateway-routed tenant query");
    assert_eq!(String::from_utf8_lossy(&routed.stdout).trim(), "before");

    let rejected = Command::new("mariadb")
        .args([
            "-h",
            "127.0.0.1",
            "-P",
            &address.port().to_string(),
            "-u",
            TENANT,
            "-pwrong-password",
            DATABASE,
            "--skip-ssl",
            "--connect-timeout=5",
            "-e",
            "SELECT 1",
        ])
        .output()
        .expect("attempt wrong-password MySQL gateway query");
    assert!(
        !rejected.status.success(),
        "gateway accepted a wrong password"
    );

    shutdown_tx.send(true).unwrap();
    gateway.await.unwrap().unwrap();

    drop(container);
}

struct TestContainer(String);

impl TestContainer {
    fn start(name: &str, socket_root: &std::path::Path) -> Self {
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
                IMAGE,
                "--mysql-native-password=ON",
            ])
            .output()
            .expect("start MySQL test container");
        assert_success(&output, "start MySQL test container");
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
