use std::time::Duration;

use tokio::time::Instant;

use super::TenantTarget;
use crate::{
    placement::EngineRuntime,
    runtime::docker::{DockerError, DockerRuntime},
    shared::protocol::Protocol,
};

mod clickhouse;
mod model;
mod mongodb;
mod mysql;
mod normalize;
mod postgres;
mod query;

pub(crate) use model::{ManifestChallenge, TenantManifest};

use model::CollectedManifest;
use query::ManifestContext;

const MAX_OBJECTS: usize = 4_096;
const MAX_SCHEMA_BYTES: usize = 64 * 1024 * 1024;

pub(crate) async fn measure_manifest(
    docker: &DockerRuntime,
    runtime: &EngineRuntime,
    target: TenantTarget<'_>,
    password: &str,
    challenge: ManifestChallenge,
    max_data_bytes: u64,
    timeout: Duration,
) -> Result<TenantManifest, ManifestError> {
    if timeout.is_zero() {
        return Err(ManifestError::Timeout);
    }
    if max_data_bytes == 0 {
        return Err(ManifestError::DataLimit(0));
    }

    let context = ManifestContext {
        docker,
        runtime,
        target,
        password,
        challenge,
        max_data_bytes,
        deadline: Instant::now() + timeout,
    };
    let collected: CollectedManifest = match runtime.protocol {
        Protocol::Postgres => postgres::collect(&context).await?,
        Protocol::Mysql | Protocol::Mariadb => mysql::collect(&context).await?,
        Protocol::Mongodb => mongodb::collect(&context).await?,
        Protocol::Clickhouse => clickhouse::collect(&context).await?,
        protocol => return Err(ManifestError::Unsupported(protocol)),
    };
    model::finish(runtime.protocol, challenge, collected)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ManifestError {
    #[error("{0} does not support deployment integrity manifests")]
    Unsupported(Protocol),
    #[error("database engine command failed: {0}")]
    Docker(#[from] DockerError),
    #[error("tenant contains more than the supported {0} manifest objects")]
    ObjectLimit(usize),
    #[error("tenant manifest schema exceeds the supported {0}-byte limit")]
    SchemaLimit(usize),
    #[error("tenant manifest data exceeds the supported {0}-byte scan limit")]
    DataLimit(u64),
    #[error("tenant integrity manifest timed out")]
    Timeout,
    #[error("tenant manifest catalog is invalid: {0}")]
    InvalidCatalog(&'static str),
    #[error("tenant manifest cannot safely cover this object: {0}")]
    UnsupportedFeature(String),
    #[error("tenant manifest row count overflowed")]
    RowCountOverflow,
    #[error("tenant manifest I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

impl ManifestError {
    pub(crate) fn is_timeout(&self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::Docker(DockerError::ExecTimedOut { .. })
        )
    }
}
