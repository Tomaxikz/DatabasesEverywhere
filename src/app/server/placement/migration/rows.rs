use super::*;

type BackendColumns<'a> = (&'static str, Option<&'a str>, Option<&'a str>, Option<i64>);

pub(super) fn backend_columns(backend: &BackendEndpoint) -> BackendColumns<'_> {
    match backend {
        BackendEndpoint::UnixSocket { socket_path } => {
            ("unix_socket", Some(socket_path.as_str()), None, None)
        }
        BackendEndpoint::DockerTcp { host, port } => (
            "docker_tcp",
            None,
            Some(host.as_str()),
            Some(i64::from(*port)),
        ),
    }
}

pub(super) async fn mark_cutover_committed(
    connection: &mut SqliteConnection,
    migration_id: &str,
    expected_revision: u64,
    next_revision: u64,
    now: &str,
    target_runtime_id: &str,
) -> Result<(), DeploymentMigrationError> {
    let migration = sqlx::query(
        r#"
            UPDATE deployment_migrations
            SET stage = 'cutover_committed', revision = ?1,
                cutover_committed = 1, failure_code = NULL,
                failure_message = NULL, updated_at = ?2
            WHERE migration_id = ?3 AND revision = ?4
              AND stage = 'cutover_pending' AND source_fenced = 1
              AND target_runtime_id = ?5
            "#,
    )
    .bind(u64_to_i64(next_revision)?)
    .bind(now)
    .bind(migration_id)
    .bind(u64_to_i64(expected_revision)?)
    .bind(target_runtime_id)
    .execute(&mut *connection)
    .await?;
    if migration.rows_affected() != 1 {
        return Err(DeploymentMigrationError::StaleRevision {
            expected: expected_revision,
            actual: expected_revision,
        });
    }
    Ok(())
}

pub(super) fn read_migration(
    row: &SqliteRow,
) -> Result<DeploymentMigration, DeploymentMigrationError> {
    let protocol_value: String = row.try_get("protocol")?;
    let protocol = Protocol::from_str(&protocol_value)
        .map_err(|_| DeploymentMigrationError::InvalidValue("protocol", protocol_value.clone()))?;
    let source_mode_value: String = row.try_get("source_mode")?;
    let source_mode = DeploymentMode::parse(&source_mode_value).ok_or_else(|| {
        DeploymentMigrationError::InvalidValue("source_mode", source_mode_value.clone())
    })?;
    let target_mode_value: String = row.try_get("target_mode")?;
    let target_mode = DeploymentMode::parse(&target_mode_value).ok_or_else(|| {
        DeploymentMigrationError::InvalidValue("target_mode", target_mode_value.clone())
    })?;
    let stage_value: String = row.try_get("stage")?;
    let stage = MigrationStage::parse(&stage_value)
        .ok_or_else(|| DeploymentMigrationError::InvalidValue("stage", stage_value.clone()))?;
    let revision: i64 = row.try_get("revision")?;
    Ok(DeploymentMigration {
        target_pool_id: row.try_get("target_pool_id")?,
        target_limits: row
            .try_get::<Option<String>, _>("target_limits_json")?
            .map(|json| serde_json::from_str(&json))
            .transpose()?,
        migration_id: row.try_get("migration_id")?,
        instance_id: row.try_get("instance_id")?,
        protocol,
        source_mode,
        target_mode,
        source_runtime_id: row.try_get("source_runtime_id")?,
        target_runtime_id: row.try_get("target_runtime_id")?,
        stage,
        revision: u64::try_from(revision)
            .map_err(|_| DeploymentMigrationError::InvalidInteger("revision", revision))?,
        source_fenced: row.try_get("source_fenced")?,
        cutover_committed: row.try_get("cutover_committed")?,
        failure_code: row.try_get("failure_code")?,
        failure_message: row.try_get("failure_message")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

pub(super) fn is_unique_error(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|error| error.is_unique_violation())
}

pub(super) fn u64_to_i64(value: u64) -> Result<i64, DeploymentMigrationError> {
    i64::try_from(value).map_err(|_| DeploymentMigrationError::RevisionOverflow)
}
