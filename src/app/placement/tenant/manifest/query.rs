use std::{path::Path, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use secrecy::SecretString;
use tokio::time::Instant;

use super::{ManifestChallenge, ManifestError};
use crate::{
    placement::{DeploymentMode, EngineRuntime},
    runtime::docker::{DockerError, DockerRuntime, ExecRecovery, ExecStreamResult},
    shared::{protocol::Protocol, shell::sh_quote},
};

const EXEC_TRUNCATION_MARKER: &str = "[... earlier output truncated ...]\n";
const ENGINE_TIMEOUT_GRACE: Duration = Duration::from_secs(5);

pub(super) struct ManifestContext<'a> {
    pub docker: &'a DockerRuntime,
    pub runtime: &'a EngineRuntime,
    pub target: super::super::TenantTarget<'a>,
    pub password: &'a str,
    pub challenge: ManifestChallenge,
    pub max_data_bytes: u64,
    pub deadline: Instant,
}

impl ManifestContext<'_> {
    pub(super) fn remaining(&self) -> Result<Duration, ManifestError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ManifestError::Timeout);
        }
        Ok(remaining)
    }

    pub(super) fn engine_timeout(&self) -> Result<Duration, ManifestError> {
        let remaining = self.remaining()?;
        Ok(remaining
            .saturating_sub(ENGINE_TIMEOUT_GRACE)
            .max(Duration::from_secs(1)))
    }

    pub(super) async fn query(&self, statement: &str) -> Result<String, ManifestError> {
        let command = match self.runtime.protocol {
            Protocol::Postgres => format!(
                "set -eu\nprintf %s {} | PGPASSWORD=\"$DBE_TENANT_PASSWORD\" psql -X -A -t -q -h /var/run/postgresql -U {} -d {} -v ON_ERROR_STOP=1",
                sh_quote(statement),
                sh_quote(self.target.username),
                sh_quote(self.target.database),
            ),
            Protocol::Mysql => format!(
                "set -eu\nprintf %s {} | MYSQL_PWD=\"$DBE_TENANT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock --batch --skip-column-names --raw -u {} {}",
                sh_quote(statement),
                sh_quote(self.target.username),
                sh_quote(self.target.database),
            ),
            Protocol::Mariadb => format!(
                "set -eu\nprintf %s {} | MYSQL_PWD=\"$DBE_TENANT_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock --batch --skip-column-names --raw -u {} {}",
                sh_quote(statement),
                sh_quote(self.target.username),
                sh_quote(self.target.database),
            ),
            Protocol::Mongodb => format!(
                "mongosh --quiet --host 127.0.0.1 --username {} --password \"$DBE_TENANT_PASSWORD\" --authenticationDatabase {} {} --eval {}",
                sh_quote(self.target.username),
                sh_quote(self.target.database),
                sh_quote(self.target.database),
                sh_quote(statement),
            ),
            Protocol::Clickhouse => format!(
                "set -eu\nprintf %s {} | CLICKHOUSE_PASSWORD=\"$DBE_TENANT_PASSWORD\" clickhouse-client --host 127.0.0.1 --user {} --database {} --multiquery",
                sh_quote(statement),
                sh_quote(self.target.username),
                sh_quote(self.target.database),
            ),
            protocol => return Err(ManifestError::Unsupported(protocol)),
        };
        self.shell(&command).await
    }

    pub(super) async fn check_scan_bytes(&self, statement: &str) -> Result<(), ManifestError> {
        let output = self.query(statement).await?;
        let bytes = parse_scan_bytes(&output)?;
        if bytes > self.max_data_bytes {
            return Err(ManifestError::DataLimit(self.max_data_bytes));
        }
        Ok(())
    }

    pub(super) async fn shell(&self, command: &str) -> Result<String, ManifestError> {
        let password = SecretString::from(self.password.to_string());
        let timeout = self.remaining()?;
        let result = if self.runtime.deployment_mode == DeploymentMode::Shared {
            self.docker
                .exec_tenant_shell(
                    self.runtime.protocol,
                    &self.runtime.runtime_id,
                    command,
                    &[("DBE_TENANT_PASSWORD", &password)],
                    timeout,
                )
                .await
        } else {
            self.docker
                .exec_shell_with_secrets_timeout(
                    self.runtime.protocol,
                    &self.runtime.runtime_id,
                    command,
                    &[("DBE_TENANT_PASSWORD", &password)],
                    timeout,
                )
                .await
        };
        let output = map_exec(result)?;
        if output.stdout.starts_with(EXEC_TRUNCATION_MARKER) {
            return Err(ManifestError::SchemaLimit(1024 * 1024));
        }
        Ok(output.stdout)
    }

    pub(super) async fn mongo_to_file(
        &self,
        collection: &str,
        output_path: &Path,
        max_bytes: u64,
    ) -> Result<ExecStreamResult, ManifestError> {
        let password = SecretString::from(self.password.to_string());
        let command = format!(
            r#"set -eu
mongodump --quiet \
  --host 127.0.0.1 \
  --username {} \
  --password "$DBE_TENANT_PASSWORD" \
  --authenticationDatabase {} \
  --db {} \
  --collection {} \
  --numParallelCollections=1 \
  --out=-"#,
            sh_quote(self.target.username),
            sh_quote(self.target.database),
            sh_quote(self.target.database),
            sh_quote(collection),
        );
        let recovery = if self.runtime.deployment_mode == DeploymentMode::Shared {
            ExecRecovery::CallerHandles
        } else {
            ExecRecovery::RestartRuntime
        };
        self.docker
            .exec_shell_to_file(
                self.runtime.protocol,
                &self.runtime.runtime_id,
                &command,
                &[("DBE_TENANT_PASSWORD", &password)],
                output_path,
                max_bytes,
                self.remaining()?,
                recovery,
            )
            .await
            .map_err(ManifestError::from)
    }
}

fn parse_scan_bytes(output: &str) -> Result<u64, ManifestError> {
    let mut lines = output.lines().filter(|line| !line.trim().is_empty());
    let line = lines.next().ok_or(ManifestError::InvalidCatalog(
        "missing tenant storage byte count",
    ))?;
    if lines.next().is_some() || line.is_empty() || !line.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ManifestError::InvalidCatalog(
            "invalid tenant storage byte count",
        ));
    }
    line.parse::<u64>()
        .map_err(|_| ManifestError::InvalidCatalog("invalid tenant storage byte count"))
}

pub(super) fn decode_base64(value: &str) -> Result<Vec<u8>, ManifestError> {
    STANDARD
        .decode(value.trim())
        .map_err(|_| ManifestError::InvalidCatalog("invalid base64 catalog field"))
}

pub(super) fn decode_utf8(value: &str) -> Result<String, ManifestError> {
    String::from_utf8(decode_base64(value)?)
        .map_err(|_| ManifestError::InvalidCatalog("catalog field is not UTF-8"))
}

pub(super) fn validate_identifier(value: &str) -> Result<(), ManifestError> {
    if value.is_empty() || value.len() > 1024 || value.contains('\0') {
        return Err(ManifestError::InvalidCatalog("invalid catalog identifier"));
    }
    Ok(())
}

fn map_exec(
    result: Result<crate::runtime::docker::CommandOutput, DockerError>,
) -> Result<crate::runtime::docker::CommandOutput, ManifestError> {
    match result {
        Err(DockerError::ExecTimedOut { .. }) => Err(ManifestError::Timeout),
        result => result.map_err(ManifestError::from),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_byte_count_is_strict_and_bounded_to_one_row() {
        assert_eq!(parse_scan_bytes("42\n").unwrap(), 42);
        assert!(parse_scan_bytes("").is_err());
        assert!(parse_scan_bytes("42\n43\n").is_err());
        assert!(parse_scan_bytes("-1\n").is_err());
        assert!(parse_scan_bytes("18446744073709551616\n").is_err());
    }
}
