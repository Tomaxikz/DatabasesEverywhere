mod boot;
mod probe;

use std::fmt;

use crate::databases::protocol::Protocol;

pub(crate) use boot::sync_compatibility;
pub(crate) use probe::{cached_compatibility, probe_instance_compatibility};

/// Increment when the probe command, normalization, or compatibility policy
/// changes in a way that requires every managed container to be checked again.
pub(crate) const COMPATIBILITY_PROBE_REVISION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EngineVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for EngineVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProtocolCapabilities {
    pub postgres_direct_tls: bool,
    pub postgres_cancel_request: bool,
    pub mysql_caching_sha2_backend: bool,
    pub redis_resp3: bool,
    pub mongodb_scram_sha256: bool,
    pub qdrant_rest: bool,
    pub qdrant_grpc: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatibilityProfile {
    pub version: EngineVersion,
    pub capabilities: ProtocolCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompatibilityPolicyError {
    #[error("database version output did not contain a semantic version")]
    Unparseable,
    #[error("{protocol} {version} is outside DBEV's tested compatibility matrix: {supported}")]
    Unsupported {
        protocol: Protocol,
        version: EngineVersion,
        supported: &'static str,
    },
}

pub fn parse_engine_version(value: &str) -> Result<EngineVersion, CompatibilityPolicyError> {
    let start = value
        .find(|character: char| character.is_ascii_digit())
        .ok_or(CompatibilityPolicyError::Unparseable)?;
    let token = value[start..]
        .split(|character: char| !(character.is_ascii_digit() || character == '.'))
        .next()
        .unwrap_or_default();
    let mut components = token.split('.');
    let mut next_component = || {
        components
            .next()
            .and_then(|component| component.parse::<u32>().ok())
    };
    let major = next_component().ok_or(CompatibilityPolicyError::Unparseable)?;
    let minor = next_component().unwrap_or(0);
    let patch = next_component().unwrap_or(0);
    Ok(EngineVersion {
        major,
        minor,
        patch,
    })
}

pub fn compatibility_profile(
    protocol: Protocol,
    normalized_version: &str,
) -> Result<CompatibilityProfile, CompatibilityPolicyError> {
    let engine = protocol.engine();
    let version = parse_engine_version(normalized_version)?;
    if !engine.is_supported_version(version) {
        return Err(CompatibilityPolicyError::Unsupported {
            protocol,
            version,
            supported: engine.supported_versions(),
        });
    }
    Ok(CompatibilityProfile {
        version,
        capabilities: engine.capabilities(version),
    })
}

pub(crate) fn database_version_script(protocol: Protocol) -> &'static str {
    protocol.engine().version_script()
}

pub(crate) fn normalize_database_version(protocol: Protocol, stdout: &str) -> Option<String> {
    let line = stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())?;
    let version = protocol
        .engine()
        .normalize_version(line)
        .trim()
        .trim_end_matches('.');

    (!version.is_empty()).then(|| version.to_string())
}

pub(crate) fn distrib_version(line: &str) -> Option<&str> {
    line.split("Distrib ")
        .nth(1)
        .and_then(|rest| rest.split([',', ' ']).next())
}

#[cfg(test)]
mod tests;
