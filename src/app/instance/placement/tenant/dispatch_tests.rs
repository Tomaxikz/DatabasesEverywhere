use super::*;
use crate::{config::DaemonConfig, instance::placement::test_support::runtime};

const TARGET: TenantTarget<'static> = TenantTarget {
    database: "tenant_database",
    username: "tenant_user",
};

fn offline_docker() -> DockerRuntime {
    DockerRuntime::offline_for_tests(&DaemonConfig::default(), false)
}

#[test]
fn backend_dispatch_preserves_engine_specific_credential_clients() {
    for (protocol, expected) in [
        (
            Protocol::Postgres,
            "PGPASSWORD=\"$DBE_TENANT_PASSWORD\" psql -X -h /var/run/postgresql -U 'tenant_user' -d 'tenant_database' -Atqc 'SELECT 1' >/dev/null",
        ),
        (
            Protocol::Mysql,
            "MYSQL_PWD=\"$DBE_TENANT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u 'tenant_user' 'tenant_database' -N -B -e 'SELECT 1' >/dev/null",
        ),
        (
            Protocol::Mariadb,
            "MYSQL_PWD=\"$DBE_TENANT_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -u 'tenant_user' 'tenant_database' -N -B -e 'SELECT 1' >/dev/null",
        ),
        (
            Protocol::Mongodb,
            "mongosh --quiet --host 127.0.0.1 --username 'tenant_user' --password \"$DBE_TENANT_PASSWORD\" --authenticationDatabase 'tenant_database' 'tenant_database' --eval 'quit(db.runCommand({ ping: 1 }).ok === 1 ? 0 : 2)' >/dev/null",
        ),
        (
            Protocol::Clickhouse,
            "clickhouse-client --host 127.0.0.1 --user 'tenant_user' --password \"$DBE_TENANT_PASSWORD\" --database 'tenant_database' --query 'SELECT 1' >/dev/null",
        ),
    ] {
        assert_eq!(
            backends::for_protocol(protocol)
                .unwrap()
                .verify_command(TARGET),
            expected,
            "{protocol}"
        );
    }
}

#[test]
fn verification_quotes_tenant_identifiers_for_every_backend() {
    let target = TenantTarget {
        database: "database'; $(false)",
        username: "user'; $(false)",
    };
    for protocol in Protocol::ALL {
        let Ok(backend) = backends::for_protocol(protocol) else {
            continue;
        };
        let command = backend.verify_command(target);
        assert!(command.contains(&sh_quote(target.database)), "{protocol}");
        assert!(command.contains(&sh_quote(target.username)), "{protocol}");
    }
}

#[tokio::test]
async fn creation_requires_admin_credentials_before_backend_selection() {
    let docker = offline_docker();
    for protocol in Protocol::ALL {
        let runtime = runtime("missing-admin", protocol, "test-image");
        assert!(matches!(
            create(&docker, &runtime, TARGET, "password", &runtime.limits).await,
            Err(TenantEngineError::MissingAdminSecret(id)) if id == "missing-admin"
        ));
    }
}

#[tokio::test]
async fn unsupported_lifecycle_operations_fail_before_docker_access() {
    let docker = offline_docker();
    for protocol in [Protocol::Redis, Protocol::Valkey, Protocol::Qdrant] {
        let mut runtime = runtime("unsupported", protocol, "test-image");
        runtime.admin_secret = Some("admin".into());
        let results = [
            create(&docker, &runtime, TARGET, "password", &runtime.limits).await,
            fence(&docker, &runtime, TARGET).await,
            unfence(&docker, &runtime, TARGET).await,
            drop_tenant(&docker, &runtime, TARGET).await,
            set_quota(&docker, &runtime, TARGET, &runtime.limits).await,
            rotate_password(&docker, &runtime, TARGET, "password").await,
            verify_password(&docker, &runtime, TARGET, "password").await,
        ];
        for result in results {
            assert!(
                matches!(result, Err(TenantEngineError::Unsupported(actual)) if actual == protocol)
            );
        }
        assert!(matches!(
            measure_storage(&docker, &runtime, &[TARGET]).await,
            Err(TenantEngineError::Unsupported(actual)) if actual == protocol
        ));
    }
}

#[tokio::test]
async fn empty_storage_measurement_does_not_require_backend_or_admin() {
    let docker = offline_docker();
    for protocol in Protocol::ALL {
        let runtime = runtime("empty-storage", protocol, "test-image");
        assert_eq!(
            measure_storage(&docker, &runtime, &[]).await.unwrap(),
            Vec::<u64>::new()
        );
    }
}

#[tokio::test]
async fn dedicated_telemetry_is_rejected_before_backend_or_admin_checks() {
    let docker = offline_docker();
    for protocol in Protocol::ALL {
        let mut runtime = runtime("dedicated", protocol, "test-image");
        runtime.deployment_mode = DeploymentMode::Dedicated;
        assert!(matches!(
            telemetry_sql(&docker, &runtime, "SELECT 1").await,
            Err(TenantEngineError::DedicatedTelemetry)
        ));
        assert!(matches!(
            clickhouse_telemetry_window(&docker, &runtime, None, "SELECT 1").await,
            Err(TenantEngineError::DedicatedTelemetry)
        ));
        secure_pool(&docker, &runtime).await.unwrap();
        check_rollback_objects(&docker, &runtime, TARGET)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn mongodb_quota_remains_policy_only_without_an_engine_command() {
    let docker = offline_docker();
    let runtime = runtime("mongodb-quota", Protocol::Mongodb, "test-image");
    set_quota(&docker, &runtime, TARGET, &runtime.limits)
        .await
        .unwrap();
}
