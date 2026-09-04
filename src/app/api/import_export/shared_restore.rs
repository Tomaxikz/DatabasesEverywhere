//! Isolated native-client execution for untrusted shared-tenant restores.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use secrecy::{ExposeSecret, SecretString};

use super::{
    ApiError, AppState,
    files::{cleanup_path, prepare_private_dir},
};
use crate::{
    instances::metadata::InstanceMetadata,
    placement::{DeploymentMode, EngineRuntimeStatus},
    runtime::docker::{
        DockerEnv, IMPORT_HELPER_INPUT_PATH, ImportHelperInput, ImportHelperNetwork,
        RemoteImportHelperSpec,
    },
    shared::protocol::Protocol,
};

const SHARED_HELPER_WORK_MARGIN_BYTES: u64 = 1024 * 1024;

#[derive(Debug)]
pub(super) enum RestoreError {
    Failed(ApiError),
    HelperUncertain(ApiError),
}

impl RestoreError {
    pub(super) fn helper_uncertain(&self) -> bool {
        matches!(self, Self::HelperUncertain(_))
    }

    pub(super) fn into_api_error(self) -> ApiError {
        match self {
            Self::Failed(error) | Self::HelperUncertain(error) => error,
        }
    }
}

impl From<ApiError> for RestoreError {
    fn from(error: ApiError) -> Self {
        Self::Failed(error)
    }
}

pub(super) struct RestoreRequest<'a> {
    pub(super) metadata: &'a InstanceMetadata,
    pub(super) script: &'a str,
    pub(super) environment: &'a [(&'static str, &'a SecretString)],
    pub(super) input: &'a PinnedInput,
    pub(super) timeout: Duration,
}

pub(super) async fn run(state: &AppState, request: RestoreRequest<'_>) -> Result<(), RestoreError> {
    let RestoreRequest {
        metadata,
        script,
        environment,
        input,
        timeout,
    } = request;
    let input_bytes = input.size_bytes;
    let sha256 = input.sha256;
    if metadata.deployment_mode != DeploymentMode::Shared {
        return Err(ApiError::Runtime(
            "isolated shared restore received a dedicated instance".to_string(),
        )
        .into());
    }
    let runtime = state
        .placements
        .get(metadata.runtime_id())
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to load shared runtime: {error}")))?
        .ok_or_else(|| ApiError::Runtime("shared restore runtime is missing".to_string()))?;
    if runtime.deployment_mode != DeploymentMode::Shared
        || runtime.protocol != metadata.protocol
        || runtime.status != EngineRuntimeStatus::Running
    {
        return Err(ApiError::Conflict(
            "shared restore runtime is not an eligible running pool".to_string(),
        )
        .into());
    }
    let image = runtime
        .compatibility
        .as_ref()
        .map(|identity| identity.image_id.trim())
        .filter(|image| !image.is_empty())
        .ok_or_else(|| {
            ApiError::Conflict(
                "shared restore runtime has no pinned compatibility image".to_string(),
            )
        })?
        .to_string();
    let helper_script = helper_script(script)?;
    let environment = tenant_environment(metadata.protocol, &metadata.database.name, environment)?;
    let max_work_bytes = helper_work_limit(input_bytes)?;
    let spec = RemoteImportHelperSpec {
        image,
        work_dir: input.root.clone(),
        script: helper_script,
        extra_hosts: Vec::new(),
        timeout,
        max_output_bytes: max_work_bytes,
        network: ImportHelperNetwork::ManagedRuntime {
            protocol: metadata.protocol,
            runtime_id: metadata.runtime_id().to_string(),
        },
        input: Some(ImportHelperInput {
            path: input.input.clone(),
            size_bytes: input_bytes,
            sha256,
        }),
        environment,
        read_only_work_dir: true,
    };
    let result = state.docker.run_import_helper(&spec).await;
    match result {
        Ok(_) => Ok(()),
        Err(error) if error.import_helper_state_uncertain() => {
            let containment = contain_helper(state, metadata, &runtime).await;
            Err(RestoreError::HelperUncertain(ApiError::Runtime(format!(
                "isolated shared restore lost helper cleanup certainty: {error}; containment: {containment}"
            ))))
        }
        Err(error) => Err(RestoreError::Failed(ApiError::Runtime(format!(
            "isolated shared restore failed: {error}"
        )))),
    }
}

async fn contain_helper(
    state: &AppState,
    metadata: &InstanceMetadata,
    runtime: &crate::placement::EngineRuntime,
) -> String {
    crate::api::instances::route_fence::fence(state, &metadata.instance_id).await;
    let target = crate::placement::tenant::TenantTarget {
        database: &metadata.database.name,
        username: &metadata.database.username,
    };
    let fence_error = match crate::placement::tenant::fence(&state.docker, runtime, target).await {
        Ok(()) => {
            return "tenant sessions terminated and login fenced; rollback was blocked".to_string();
        }
        Err(error) => error,
    };

    // The import job retains the runtime operation lock. If a tenant-local
    // database fence cannot be confirmed, contain the complete pool through
    // the single fail-closed path so no helper can race another tenant.
    let containment = crate::api::instances::containment::contain_locked(
        state,
        runtime,
        "shared restore helper cleanup and tenant fencing were both uncertain",
    )
    .await;
    format!(
        "tenant fence failed ({fence_error}); whole-pool containment: {}; contained={}",
        containment.summary(),
        containment.contained()
    )
}

fn helper_script(script: &str) -> Result<String, ApiError> {
    if !script.contains("/dev/stdin") {
        return Err(ApiError::Runtime(
            "shared restore script has no controlled input stream".to_string(),
        ));
    }
    Ok(script.replace("/dev/stdin", IMPORT_HELPER_INPUT_PATH))
}

fn helper_work_limit(input_bytes: u64) -> Result<u64, ApiError> {
    input_bytes
        .checked_add(SHARED_HELPER_WORK_MARGIN_BYTES)
        .ok_or_else(|| ApiError::BadRequest("shared restore workspace size overflowed".to_string()))
}

fn tenant_environment(
    protocol: Protocol,
    database: &str,
    environment: &[(&str, &SecretString)],
) -> Result<Vec<DockerEnv>, ApiError> {
    let database_key = match protocol {
        Protocol::Postgres => "POSTGRES_DB",
        Protocol::Mariadb => "MARIADB_DATABASE",
        Protocol::Mysql => "MYSQL_DATABASE",
        Protocol::Mongodb => "DBE_MONGO_DATABASE",
        Protocol::Clickhouse => "CLICKHOUSE_DB",
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => {
            return Err(ApiError::Conflict(format!(
                "{} cannot use a shared restore helper",
                protocol.as_str()
            )));
        }
    };
    let mut environment = environment
        .iter()
        .filter_map(|(key, value)| {
            let normalized = key.to_ascii_uppercase();
            if normalized.contains("ROOT") || normalized.contains("ADMIN") {
                return Some(Err(ApiError::Conflict(
                    "shared restore refused an administrator credential".to_string(),
                )));
            }
            if *key == database_key {
                return None;
            }
            Some(Ok(DockerEnv {
                key: (*key).to_string(),
                value: SecretString::from(value.expose_secret().to_string()),
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    environment.push(DockerEnv {
        key: database_key.to_string(),
        value: SecretString::from(database.to_string()),
    });
    Ok(environment)
}

pub(super) struct PinnedInput {
    pub(super) root: PathBuf,
    input: PathBuf,
    size_bytes: u64,
    sha256: [u8; 32],
    armed: AtomicBool,
}

impl PinnedInput {
    pub(super) async fn cleanup(&self) -> Result<(), std::io::Error> {
        if self
            .armed
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }
        match tokio::fs::remove_dir_all(&self.root).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => {
                self.armed.store(true, Ordering::Release);
                Err(error)
            }
        }
    }
}

impl Drop for PinnedInput {
    fn drop(&mut self) {
        if !self.armed.swap(false, Ordering::AcqRel) {
            return;
        }
        let path = self.root.clone();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::error!(path = %path.display(), "shared restore sandbox cleanup could not be scheduled");
            return;
        };
        runtime.spawn(async move {
            match tokio::fs::remove_dir_all(&path).await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => tracing::warn!(
                    path = %path.display(),
                    %error,
                    "shared restore sandbox cleanup failed; boot recovery will retry it"
                ),
            }
        });
    }
}

pub(super) async fn pin_input(
    source: &Path,
    sandbox_parent: &Path,
    expected_bytes: u64,
    expected_sha256: &[u8; 32],
) -> Result<PinnedInput, ApiError> {
    let root = sandbox_parent.join(format!(
        ".dbe-shared-restore-{}",
        uuid::Uuid::new_v4().simple()
    ));
    prepare_private_dir(&root, "shared restore sandbox").await?;
    let pinned = root.join("input");
    let source = source.to_path_buf();
    let expected_sha256 = *expected_sha256;
    let checked = tokio::task::spawn_blocking({
        let pinned = pinned.clone();
        move || -> Result<(), std::io::Error> {
            crate::shared::files::copy_private_snapshot(
                &source,
                &pinned,
                expected_bytes,
                &expected_sha256,
            )
        }
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to join input pinning: {error}")))?;
    if let Err(error) = checked {
        cleanup_path(&root).await;
        return Err(ApiError::BadRequest(format!(
            "failed to pin inspected shared restore input: {error}"
        )));
    }
    Ok(PinnedInput {
        root,
        input: pinned,
        size_bytes: expected_bytes,
        sha256: expected_sha256,
        armed: AtomicBool::new(true),
    })
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn helper_reads_only_the_mounted_inspected_input() {
        let script = "set -eu\nmysql < /dev/stdin\ncat /dev/stdin >/tmp/check";
        let rewritten = helper_script(script).unwrap();
        assert!(!rewritten.contains("/dev/stdin"));
        assert_eq!(rewritten.matches(IMPORT_HELPER_INPUT_PATH).count(), 2);
    }

    #[test]
    fn shared_helper_rejects_admin_credentials() {
        let password = SecretString::from("secret".to_string());
        assert!(
            tenant_environment(
                Protocol::Mysql,
                "tenant_db",
                &[("MYSQL_ROOT_PASSWORD", &password)]
            )
            .is_err()
        );
        let environment = tenant_environment(
            Protocol::Mysql,
            "tenant_db",
            &[("DBE_IMPORT_PASSWORD", &password)],
        )
        .unwrap();
        assert_eq!(environment[0].key, "DBE_IMPORT_PASSWORD");
    }

    #[test]
    fn shared_helper_receives_each_tenant_database_name() {
        let stale_database = SecretString::from("dbe_control".to_string());
        for (protocol, key) in [
            (Protocol::Postgres, "POSTGRES_DB"),
            (Protocol::Mariadb, "MARIADB_DATABASE"),
            (Protocol::Mysql, "MYSQL_DATABASE"),
            (Protocol::Mongodb, "DBE_MONGO_DATABASE"),
            (Protocol::Clickhouse, "CLICKHOUSE_DB"),
        ] {
            let environment =
                tenant_environment(protocol, "tenant_db", &[(key, &stale_database)]).unwrap();
            assert_eq!(environment.len(), 1);
            assert_eq!(environment[0].key, key);
            assert_eq!(environment[0].value.expose_secret(), "tenant_db");
        }
        assert!(tenant_environment(Protocol::Redis, "tenant_db", &[]).is_err());
    }

    #[test]
    fn tiny_restore_has_a_bounded_workspace_margin() {
        assert_eq!(
            helper_work_limit(1).unwrap(),
            SHARED_HELPER_WORK_MARGIN_BYTES + 1
        );
        assert!(helper_work_limit(u64::MAX).is_err());
    }

    #[tokio::test]
    async fn pinned_input_survives_source_inode_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("dump.sql");
        std::fs::write(&source, b"SELECT 1;").unwrap();
        let expected: [u8; 32] = Sha256::digest(b"SELECT 1;").into();
        let pinned = pin_input(&source, directory.path(), 9, &expected)
            .await
            .unwrap();

        std::fs::write(&source, b"malicious").unwrap();

        assert_eq!(std::fs::read(&pinned.input).unwrap(), b"SELECT 1;");
        assert_eq!(
            Sha256::digest(std::fs::read(&pinned.input).unwrap()).as_slice(),
            expected
        );
        pinned.cleanup().await.unwrap();
    }

    #[tokio::test]
    async fn dropped_pin_schedules_sandbox_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("dump.sql");
        std::fs::write(&source, b"SELECT 1;").unwrap();
        let root = {
            let expected: [u8; 32] = Sha256::digest(b"SELECT 1;").into();
            let pinned = pin_input(&source, directory.path(), 9, &expected)
                .await
                .unwrap();
            pinned.root.clone()
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while root.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped sandbox pin must be cleaned up");
    }
}
