use std::{
    io::Write,
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use super::provision::provision_tenant_role_sql;

const IMAGE: &str = "postgres:18.4";
const ADMIN: &str = "dbe_admin";
const DATABASE: &str = "integration_db";
const TENANT: &str = "integration_user";
const TENANT_PASSWORD: &str = "integration-tenant-password";

#[test]
#[ignore = "requires a local Docker daemon and postgres:18.4 image"]
fn postgres_18_provisions_a_restricted_database_owner() {
    let name = format!("dbev-postgres-test-{}", uuid::Uuid::new_v4().simple());
    let container = TestContainer::start(&name);
    wait_until_ready(&name);

    let mut child = Command::new("docker")
        .args([
            "exec",
            "-i",
            &name,
            "psql",
            "-X",
            "-U",
            ADMIN,
            "-d",
            DATABASE,
            "-At",
            "-v",
            "ON_ERROR_STOP=1",
            "-v",
            &format!("tenant_password={TENANT_PASSWORD}"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start tenant provisioning psql");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(provision_tenant_role_sql(DATABASE, TENANT).as_bytes())
        .expect("write provisioning SQL");
    let output = child.wait_with_output().expect("wait for provisioning");
    assert!(
        output.status.success(),
        "tenant provisioning failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(
        exec_psql(
            &name,
            ADMIN,
            "SELECT rolsuper::int || ':' || rolcreatedb::int || ':' || rolcreaterole::int || ':' || rolinherit::int || ':' || rolreplication::int || ':' || rolbypassrls::int FROM pg_roles WHERE rolname = 'integration_user'",
        ),
        "0:0:0:0:0:0"
    );
    assert_eq!(
        exec_psql(
            &name,
            ADMIN,
            "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()",
        ),
        TENANT
    );

    let tenant = Command::new("docker")
        .args([
            "exec",
            "-e",
            &format!("PGPASSWORD={TENANT_PASSWORD}"),
            &name,
            "psql",
            "-X",
            "-h",
            "127.0.0.1",
            "-U",
            TENANT,
            "-d",
            DATABASE,
            "-Atqc",
            "SELECT current_user",
        ])
        .output()
        .expect("validate tenant connection");
    assert!(
        tenant.status.success(),
        "tenant connection failed: {}",
        String::from_utf8_lossy(&tenant.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&tenant.stdout).trim(), TENANT);

    drop(container);
}

struct TestContainer(String);

impl TestContainer {
    fn start(name: &str) -> Self {
        let output = Command::new("docker")
            .args([
                "run",
                "--detach",
                "--rm",
                "--name",
                name,
                "--env",
                &format!("POSTGRES_USER={ADMIN}"),
                "--env",
                "POSTGRES_PASSWORD=integration-admin-password",
                "--env",
                &format!("POSTGRES_DB={DATABASE}"),
                IMAGE,
            ])
            .output()
            .expect("start PostgreSQL test container");
        assert!(
            output.status.success(),
            "failed to start PostgreSQL test container: {}",
            String::from_utf8_lossy(&output.stderr)
        );
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
                "exec", name, "psql", "-X", "-U", ADMIN, "-d", DATABASE, "-Atqc", "SELECT 1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run PostgreSQL readiness query")
            .success()
        {
            return;
        }
        sleep(Duration::from_millis(250));
    }
    panic!("PostgreSQL test container did not become ready");
}

fn exec_psql(name: &str, user: &str, sql: &str) -> String {
    let output = Command::new("docker")
        .args([
            "exec", name, "psql", "-X", "-U", user, "-d", DATABASE, "-Atqc", sql,
        ])
        .output()
        .expect("run PostgreSQL query");
    assert!(
        output.status.success(),
        "PostgreSQL query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("PostgreSQL output is utf-8")
        .trim()
        .to_string()
}
